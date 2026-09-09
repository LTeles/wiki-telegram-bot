import os
import json
import time
import queue
import threading
import re
import html

import requests
from sseclient import SSEClient


# =========================================================
# CONFIGURAÇÃO
# =========================================================

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")

TELEGRAM_CHANNEL = os.environ.get(
    "TELEGRAM_CHANNEL_ID",
    "@ptwiki"
)

if not TELEGRAM_TOKEN:
    raise RuntimeError(
        "TELEGRAM_BOT_TOKEN não configurado."
    )


TELEGRAM_API = (
    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"
)

WIKIMEDIA_STREAM = (
    "https://stream.wikimedia.org/v2/stream/recentchange"
)

WIKIPEDIA_API = (
    "https://pt.wikipedia.org/w/api.php"
)

REVERT_RISK_API = (
    "https://api.wikimedia.org/service/lw/inference/v1/"
    "models/revertrisk-multilingual:predict"
)


# =========================================================
# LIMITES
# =========================================================

# A partir deste risco o bot busca e analisa o diff.
REVERT_RISK_THRESHOLD = 0.35

# Score final mínimo para publicar no Telegram.
VANDALISM_THRESHOLD = 0.55

MAX_DIFF_CHARS = 6000


# =========================================================
# FILAS
# =========================================================

analysis_queue = queue.Queue()
telegram_queue = queue.Queue()


# =========================================================
# USER AGENT
# =========================================================

HEADERS = {
    "User-Agent": (
        "PtWikiVandalismTelegramBot/1.0 "
        "(https://t.me/ptwiki)"
    )
}


# =========================================================
# TELEGRAM - ENVIO
# =========================================================

def send_telegram_message(text, chat_id=None):

    if chat_id is None:
        chat_id = TELEGRAM_CHANNEL

    while True:

        try:

            response = requests.post(
                f"{TELEGRAM_API}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "disable_web_page_preview": True
                },
                timeout=30
            )

            if response.status_code == 429:

                data = response.json()

                retry_after = data.get(
                    "parameters",
                    {}
                ).get(
                    "retry_after",
                    2
                )

                print(
                    f"Rate limit Telegram. "
                    f"Aguardando {retry_after}s."
                )

                time.sleep(retry_after)

                continue

            response.raise_for_status()

            return True

        except Exception as e:

            print(
                "Erro Telegram:",
                e
            )

            time.sleep(5)


def telegram_sender():

    while True:

        message = telegram_queue.get()

        try:

            send_telegram_message(
                message
            )

        finally:

            telegram_queue.task_done()

        # Nunca envia mais de uma mensagem por segundo.
        time.sleep(1)


# =========================================================
# TELEGRAM - COMANDOS
# =========================================================

def telegram_command_listener():

    offset = None

    print(
        "✅ Listener de comandos Telegram iniciado."
    )

    while True:

        try:

            params = {
                "timeout": 30
            }

            if offset is not None:
                params["offset"] = offset

            response = requests.get(
                f"{TELEGRAM_API}/getUpdates",
                params=params,
                timeout=40
            )

            response.raise_for_status()

            data = response.json()

            for update in data.get(
                "result",
                []
            ):

                offset = (
                    update["update_id"]
                    + 1
                )

                message = update.get(
                    "message"
                )

                if not message:
                    continue

                text = message.get(
                    "text",
                    ""
                )

                chat = message.get(
                    "chat",
                    {}
                )

                chat_id = chat.get(
                    "id"
                )

                if not chat_id:
                    continue


                # /start

                if text.startswith(
                    "/start"
                ):

                    send_telegram_message(
                        (
                            "🤖 Bot de monitoramento da "
                            "Wikipédia em português ativo.\n\n"
                            "Acompanho edições em tempo real "
                            "e publico no @ptwiki aquelas "
                            "consideradas possíveis vandalismos."
                        ),
                        chat_id=chat_id
                    )


                # /status

                elif text.startswith(
                    "/status"
                ):

                    send_telegram_message(
                        (
                            "✅ Bot online.\n\n"
                            f"Canal: {TELEGRAM_CHANNEL}\n"
                            f"Triagem Revert Risk: "
                            f"{REVERT_RISK_THRESHOLD:.0%}\n"
                            f"Score para postagem: "
                            f"{VANDALISM_THRESHOLD:.0%}\n"
                            f"Fila de análise: "
                            f"{analysis_queue.qsize()}"
                        ),
                        chat_id=chat_id
                    )


        except Exception as e:

            print(
                "Erro no listener Telegram:",
                e
            )

            time.sleep(5)


# =========================================================
# LIMPEZA DO HTML DO DIFF
# =========================================================

def clean_html(text):

    if not text:
        return ""

    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    text = html.unescape(
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# =========================================================
# BUSCA O DIFF DA EDIÇÃO
# =========================================================

def get_revision_diff(
    old_revision,
    new_revision
):

    params = {
        "action": "compare",
        "format": "json",
        "formatversion": 2,
        "fromrev": old_revision,
        "torev": new_revision,
        "prop": "diff"
    }

    response = requests.get(
        WIKIPEDIA_API,
        params=params,
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    compare = data.get(
        "compare",
        {}
    )

    diff_html = compare.get(
        "body",
        ""
    )

    if not diff_html:

        return {
            "added": "",
            "removed": ""
        }


    added_matches = re.findall(
        r'<td class="diff-addedline"[^>]*>(.*?)</td>',
        diff_html,
        flags=re.I | re.S
    )


    removed_matches = re.findall(
        r'<td class="diff-deletedline"[^>]*>(.*?)</td>',
        diff_html,
        flags=re.I | re.S
    )


    added = "\n".join(
        clean_html(x)
        for x in added_matches
    )


    removed = "\n".join(
        clean_html(x)
        for x in removed_matches
    )


    return {
        "added": added[:MAX_DIFF_CHARS],
        "removed": removed[:MAX_DIFF_CHARS]
    }


# =========================================================
# MODELO REVERT RISK DA WIKIMEDIA
# =========================================================

def get_revert_risk(revision_id):

    try:

        response = requests.post(
            REVERT_RISK_API,
            headers={
                **HEADERS,
                "Content-Type": "application/json"
            },
            json={
                "rev_id": revision_id,
                "lang": "pt"
            },
            timeout=30
        )


        if response.status_code == 429:

            print(
                "Rate limit do Wikimedia Lift Wing."
            )

            return None


        response.raise_for_status()

        data = response.json()


        probability = (
            data
            .get("output", {})
            .get("probabilities", {})
            .get("true")
        )


        if probability is None:

            print(
                "Resposta inesperada do Lift Wing:",
                data
            )

            return None


        return float(
            probability
        )


    except Exception as e:

        print(
            "Erro no Lift Wing:",
            e
        )

        return None


# =========================================================
# REGRAS AUXILIARES
# =========================================================

BAD_WORDS = [
    "merda",
    "porra",
    "caralho",
    "bosta",
    "foda-se",
    "fdp",
    "idiota",
    "imbecil",
    "otário",
    "otario",
    "vagabundo"
]


def profanity_score(text):

    text = text.lower()

    count = sum(
        1
        for word in BAD_WORDS
        if word in text
    )


    if count >= 3:
        return 1.0

    if count == 2:
        return 0.90

    if count == 1:
        return 0.75

    return 0.0


def repetition_score(text):

    if not text:
        return 0.0


    patterns = [
        r"(.)\1{8,}",
        r"[!?]{8,}",
        r"\b(\w{2,5})\1{4,}\b",
        r"(ha){6,}",
        r"(kk){4,}"
    ]


    for pattern in patterns:

        if re.search(
            pattern,
            text.lower()
        ):

            return 0.95


    return 0.0


def destructive_score(
    added,
    removed
):

    added_len = len(
        added.strip()
    )

    removed_len = len(
        removed.strip()
    )


    if (
        removed_len > 1500
        and
        added_len < 100
    ):
        return 0.95


    if (
        removed_len > 700
        and
        added_len < 60
    ):
        return 0.85


    if (
        removed_len > 300
        and
        added_len < 20
    ):
        return 0.75


    return 0.0


def nonsense_score(text):

    text = text.strip()

    if not text:
        return 0.0


    if len(text) >= 10:

        alphabetic = sum(
            1
            for character in text
            if character.isalpha()
        )

        ratio = (
            alphabetic
            /
            len(text)
        )


        if ratio < 0.25:

            return 0.80


    return 0.0


# =========================================================
# CLASSIFICAÇÃO FINAL
# =========================================================

def analyze_vandalism(
    change,
    diff,
    revert_risk
):

    added = diff.get(
        "added",
        ""
    )

    removed = diff.get(
        "removed",
        ""
    )


    profanity = profanity_score(
        added
    )

    repetition = repetition_score(
        added
    )

    destructive = destructive_score(
        added,
        removed
    )

    nonsense = nonsense_score(
        added
    )


    signals = [
        profanity,
        repetition,
        destructive,
        nonsense
    ]


    heuristic = max(
        signals
    )


    # =====================================================
    # NOVA LÓGICA DE SCORE
    #
    # O Revert Risk passa a ser o score-base.
    #
    # Exemplo:
    # Revert Risk 60% = score inicial 60%.
    #
    # Heurísticas fortes acrescentam bônus.
    # =====================================================

    score = revert_risk


    # Um sinal forte de vandalismo:
    # +10 pontos percentuais.

    if heuristic >= 0.75:

        score += 0.10


    strong_signals = sum(
        1
        for signal in signals
        if signal >= 0.75
    )


    # Dois ou mais sinais fortes:
    # +5 pontos adicionais.

    if strong_signals >= 2:

        score += 0.05


    score = min(
        score,
        1.0
    )


    reasons = []


    if revert_risk >= 0.85:

        reasons.append(
            "risco de reversão muito alto"
        )

    elif revert_risk >= 0.70:

        reasons.append(
            "alto risco de reversão"
        )

    elif revert_risk >= 0.55:

        reasons.append(
            "risco de reversão elevado"
        )


    if profanity >= 0.75:

        reasons.append(
            "linguagem ofensiva"
        )


    if repetition >= 0.75:

        reasons.append(
            "repetição anormal"
        )


    if destructive >= 0.75:

        reasons.append(
            "remoção potencialmente destrutiva"
        )


    if nonsense >= 0.75:

        reasons.append(
            "texto possivelmente sem sentido"
        )


    if not reasons:

        reasons.append(
            "edição considerada suspeita pelo modelo"
        )


    return {
        "score": score,
        "revert_risk": revert_risk,
        "heuristic": heuristic,
        "reason": ", ".join(reasons)
    }


# =========================================================
# FORMATA A MENSAGEM DO TELEGRAM
# =========================================================

def format_message(
    change,
    result
):

    title = change.get(
        "title",
        "Sem título"
    )

    user = change.get(
        "user",
        "Desconhecido"
    )

    comment = (
        change.get("comment")
        or
        "Sem resumo"
    )


    revision = change.get(
        "revision",
        {}
    )


    old_revision = revision.get(
        "old"
    )

    new_revision = revision.get(
        "new"
    )


    final_score = round(
        result["score"] * 100
    )


    revert_score = round(
        result["revert_risk"] * 100
    )


    diff_url = (
        "https://pt.wikipedia.org/w/index.php"
        f"?diff={new_revision}"
        f"&oldid={old_revision}"
    )


    return (
        f"🚨 Possível vandalismo — {final_score}%\n\n"
        f"📝 {title}\n"
        f"👤 {user}\n"
        f"💬 {comment}\n\n"
        f"🤖 Risco de reversão Wikimedia: "
        f"{revert_score}%\n"
        f"⚠️ Sinais: {result['reason']}\n\n"
        f"🔗 {diff_url}"
    )


# =========================================================
# WORKER DE ANÁLISE
# =========================================================

def analysis_worker():

    while True:

        change = analysis_queue.get()

        try:

            revision = change.get(
                "revision",
                {}
            )


            old_revision = revision.get(
                "old"
            )

            new_revision = revision.get(
                "new"
            )


            if not old_revision:
                continue

            if not new_revision:
                continue


            revert_risk = get_revert_risk(
                new_revision
            )


            if revert_risk is None:
                continue


            print(
                "Revert Risk:",
                f"{revert_risk:.0%}",
                "|",
                change.get("title")
            )


            # Descarta antes de buscar o diff.

            if (
                revert_risk
                <
                REVERT_RISK_THRESHOLD
            ):

                print(
                    "Descartada na triagem:",
                    f"{revert_risk:.0%}",
                    "|",
                    change.get("title")
                )

                continue


            diff = get_revision_diff(
                old_revision,
                new_revision
            )


            result = analyze_vandalism(
                change,
                diff,
                revert_risk
            )


            print(
                "Score final:",
                f"{result['score']:.0%}",
                "|",
                change.get("title")
            )


            if (
                result["score"]
                >=
                VANDALISM_THRESHOLD
            ):

                message = format_message(
                    change,
                    result
                )


                telegram_queue.put(
                    message
                )


                print(
                    "🚨 Possível vandalismo enviado:",
                    change.get("title")
                )


            else:

                print(
                    "Não atingiu limite de postagem:",
                    f"{result['score']:.0%}",
                    "|",
                    change.get("title")
                )


        except Exception as e:

            print(
                "Erro na análise:",
                e
            )


        finally:

            analysis_queue.task_done()


# =========================================================
# WIKIMEDIA EVENTSTREAMS
# =========================================================

def wikimedia_loop():

    while True:

        try:

            print(
                "Conectando ao Wikimedia EventStreams..."
            )


            response = requests.get(
                WIKIMEDIA_STREAM,
                headers=HEADERS,
                stream=True,
                timeout=90
            )


            response.raise_for_status()


            client = SSEClient(
                response
            )


            print(
                "✅ EventStreams conectado."
            )


            for event in client.events():

                if not event.data:
                    continue


                try:

                    change = json.loads(
                        event.data
                    )

                except json.JSONDecodeError:
                    continue


                # Apenas Wikipédia em português.

                if (
                    change.get("wiki")
                    !=
                    "ptwiki"
                ):
                    continue


                # Apenas edições.

                if (
                    change.get("type")
                    !=
                    "edit"
                ):
                    continue


                # Ignora bots.

                if change.get(
                    "bot",
                    False
                ):
                    continue


                analysis_queue.put(
                    change
                )


                print(
                    "Nova edição:",
                    change.get("title"),
                    "| Fila:",
                    analysis_queue.qsize()
                )


        except Exception as e:

            print(
                "EventStreams desconectado:",
                e
            )


            print(
                "Reconectando em 5 segundos..."
            )


            time.sleep(5)


# =========================================================
# INICIALIZAÇÃO
# =========================================================

def main():

    print(
        "================================="
    )

    print(
        "Detector de vandalismo ptwiki"
    )

    print(
        "Modelo: Wikimedia Revert Risk"
    )

    print(
        "Canal:",
        TELEGRAM_CHANNEL
    )

    print(
        "Triagem Revert Risk:",
        f"{REVERT_RISK_THRESHOLD:.0%}"
    )

    print(
        "Score para postagem:",
        f"{VANDALISM_THRESHOLD:.0%}"
    )

    print(
        "================================="
    )


    telegram_thread = threading.Thread(
        target=telegram_sender,
        daemon=True
    )

    telegram_thread.start()


    analysis_thread = threading.Thread(
        target=analysis_worker,
        daemon=True
    )

    analysis_thread.start()


    command_thread = threading.Thread(
        target=telegram_command_listener,
        daemon=True
    )

    command_thread.start()


    wikimedia_loop()


if __name__ == "__main__":
    main()
