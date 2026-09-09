import os
import json
import time
import queue
import threading
import re
import html
import ipaddress

from datetime import datetime, timezone

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
# LIMITES DE DETECÇÃO
# =========================================================

# A partir deste valor o bot busca o diff.
REVERT_RISK_THRESHOLD = 0.35

# Score final mínimo para postagem.
VANDALISM_THRESHOLD = 0.55

MAX_DIFF_CHARS = 6000


# =========================================================
# FILTRO DE USUÁRIOS
# =========================================================

# Contas com MAIS de 30 dias são ignoradas.
MAX_ACCOUNT_AGE_DAYS = 30

# Contas com MAIS de 10 edições são ignoradas.
MAX_USER_EDITS = 10

# Cache das informações das contas.
USER_CACHE_SECONDS = 3600

user_cache = {}


# =========================================================
# WATCHDOG
# =========================================================

# Se não chegar nenhum evento GLOBAL da Wikimedia
# durante 120 segundos, tenta reconectar.
STREAM_STALL_SECONDS = 120


# =========================================================
# FILAS
# =========================================================

analysis_queue = queue.Queue()
telegram_queue = queue.Queue()


# =========================================================
# ESTADO
# =========================================================

stream_lock = threading.Lock()

stream_connected = False

last_stream_event_at = None
last_ptwiki_edit_at = None

current_stream_response = None


# =========================================================
# USER AGENT
# =========================================================

HEADERS = {
    "User-Agent": (
        "PtWikiVandalismTelegramBot/1.2 "
        "(https://t.me/ptwiki)"
    )
}


# =========================================================
# UTILIDADES
# =========================================================

def format_age(timestamp):

    if timestamp is None:
        return "nunca"

    seconds = int(
        max(
            0,
            time.time() - timestamp
        )
    )

    if seconds < 60:
        return f"há {seconds}s"

    minutes = seconds // 60

    if minutes < 60:
        return f"há {minutes} min"

    hours = minutes // 60
    remaining_minutes = minutes % 60

    return (
        f"há {hours}h "
        f"{remaining_minutes}min"
    )


# =========================================================
# IDENTIFICA IP
# =========================================================

def is_ip_address(username):

    if not username:
        return False

    try:

        ipaddress.ip_address(
            username
        )

        return True

    except ValueError:

        return False


# =========================================================
# CONSULTA INFORMAÇÕES DA CONTA
# =========================================================

def get_user_info(username):

    now = time.time()

    cached = user_cache.get(
        username
    )

    if cached:

        cached_at = cached.get(
            "cached_at",
            0
        )

        if (
            now - cached_at
            <
            USER_CACHE_SECONDS
        ):

            return cached


    try:

        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "users",
                "ususers": username,
                "usprop": (
                    "editcount|registration"
                )
            },
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        users = (
            data
            .get("query", {})
            .get("users", [])
        )


        if not users:

            return None


        user = users[0]


        if "missing" in user:

            return None


        result = {
            "editcount": user.get(
                "editcount",
                0
            ),
            "registration": user.get(
                "registration"
            ),
            "cached_at": now
        }


        user_cache[username] = result


        return result


    except Exception as e:

        print(
            "⚠️ Erro ao consultar usuário:",
            username,
            "|",
            e
        )

        return None


# =========================================================
# DECIDE SE A CONTA DEVE SER AVALIADA
# =========================================================

def should_evaluate_user(username):

    if not username:

        return True


    # -----------------------------------------
    # IPs SEMPRE SÃO AVALIADOS
    # -----------------------------------------

    if is_ip_address(
        username
    ):

        print(
            "🌐 IP:",
            username,
            "| será avaliado"
        )

        return True


    # -----------------------------------------
    # CONSULTA CONTA REGISTRADA
    # -----------------------------------------

    user_info = get_user_info(
        username
    )


    # Em caso de falha na API,
    # preferimos avaliar a edição.
    if user_info is None:

        print(
            "⚠️ Não foi possível verificar a conta:",
            username,
            "| edição será avaliada"
        )

        return True


    editcount = user_info.get(
        "editcount",
        0
    )


    # -----------------------------------------
    # MAIS DE 10 EDIÇÕES
    # -----------------------------------------

    if (
        editcount
        >
        MAX_USER_EDITS
    ):

        print(
            "⏭️ Usuário ignorado:",
            username,
            "|",
            f"{editcount} edições"
        )

        return False


    registration = user_info.get(
        "registration"
    )


    # -----------------------------------------
    # MAIS DE 30 DIAS
    # -----------------------------------------

    if registration:

        try:

            created = (
                datetime
                .fromisoformat(
                    registration.replace(
                        "Z",
                        "+00:00"
                    )
                )
            )


            age_seconds = (
                datetime.now(
                    timezone.utc
                )
                -
                created
            ).total_seconds()


            age_days = (
                age_seconds
                /
                86400
            )


            if (
                age_days
                >
                MAX_ACCOUNT_AGE_DAYS
            ):

                print(
                    "⏭️ Usuário ignorado:",
                    username,
                    "|",
                    f"conta com {age_days:.1f} dias"
                )

                return False


            print(
                "👤 Conta nova:",
                username,
                "|",
                f"{age_days:.1f} dias",
                "|",
                f"{editcount} edições"
            )


        except Exception as e:

            print(
                "⚠️ Erro ao interpretar "
                "data da conta:",
                username,
                "|",
                e
            )


    else:

        print(
            "⚠️ Conta sem data de registro:",
            username,
            "|",
            f"{editcount} edições"
        )


    return True


# =========================================================
# TELEGRAM - ENVIO
# =========================================================

def send_telegram_message(
    text,
    chat_id=None
):

    if chat_id is None:

        chat_id = (
            TELEGRAM_CHANNEL
        )


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

                retry_after = (
                    data
                    .get("parameters", {})
                    .get(
                        "retry_after",
                        2
                    )
                )


                print(
                    "Rate limit Telegram. "
                    f"Aguardando {retry_after}s."
                )


                time.sleep(
                    retry_after
                )

                continue


            response.raise_for_status()

            return True


        except Exception as e:

            print(
                "❌ Erro Telegram:",
                e
            )

            time.sleep(5)


# =========================================================
# FILA DE ENVIO TELEGRAM
# =========================================================

def telegram_sender():

    while True:

        item = (
            telegram_queue.get()
        )


        try:

            message = item[
                "message"
            ]

            title = item[
                "title"
            ]


            send_telegram_message(
                message
            )


            print(
                "✅ Telegram confirmou envio:",
                title
            )


        except Exception as e:

            print(
                "Erro no sender Telegram:",
                e
            )


        finally:

            telegram_queue.task_done()


        # Não envia mais de uma mensagem
        # por segundo.
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

                params[
                    "offset"
                ] = offset


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
                    update[
                        "update_id"
                    ]
                    +
                    1
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


                chat_id = (
                    message
                    .get("chat", {})
                    .get("id")
                )


                if not chat_id:

                    continue


                # =========================================
                # /start
                # =========================================

                if text.startswith(
                    "/start"
                ):

                    send_telegram_message(
                        (
                            "🤖 Monitor de possíveis "
                            "vandalismos da Wikipédia "
                            "em português.\n\n"

                            "✅ Bot ativo.\n"
                            "📡 Monitoramento em tempo real.\n"

                            f"📢 Canal: "
                            f"{TELEGRAM_CHANNEL}"
                        ),
                        chat_id=chat_id
                    )


                # =========================================
                # /status
                # =========================================

                elif text.startswith(
                    "/status"
                ):

                    with stream_lock:

                        connected = (
                            stream_connected
                        )

                        last_stream = (
                            last_stream_event_at
                        )

                        last_ptwiki = (
                            last_ptwiki_edit_at
                        )


                    if connected:

                        stream_status = (
                            "🟢 conectado"
                        )

                    else:

                        stream_status = (
                            "🔴 reconectando"
                        )


                    send_telegram_message(
                        (
                            "🤖 Status do bot\n\n"

                            f"📡 EventStreams: "
                            f"{stream_status}\n"

                            f"🌐 Último evento Wikimedia: "
                            f"{format_age(last_stream)}\n"

                            f"🇵🇹 Última edição ptwiki: "
                            f"{format_age(last_ptwiki)}\n\n"

                            f"👶 Idade máxima da conta: "
                            f"{MAX_ACCOUNT_AGE_DAYS} dias\n"

                            f"✏️ Máximo de edições: "
                            f"{MAX_USER_EDITS}\n\n"

                            f"🔎 Triagem Revert Risk: "
                            f"{REVERT_RISK_THRESHOLD:.0%}\n"

                            f"🚨 Score para postagem: "
                            f"{VANDALISM_THRESHOLD:.0%}\n\n"

                            f"📥 Fila de análise: "
                            f"{analysis_queue.qsize()}\n"

                            f"📤 Fila Telegram: "
                            f"{telegram_queue.qsize()}"
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
# WATCHDOG DO EVENTSTREAMS
# =========================================================

def eventstream_watchdog():

    global stream_connected
    global current_stream_response


    print(
        "✅ Watchdog do EventStreams iniciado."
    )


    while True:

        time.sleep(15)

        response_to_close = None


        with stream_lock:

            if (
                stream_connected
                and
                last_stream_event_at is not None
            ):

                elapsed = (
                    time.time()
                    -
                    last_stream_event_at
                )


                if (
                    elapsed
                    >
                    STREAM_STALL_SECONDS
                ):

                    print(
                        "⚠️ EventStreams sem eventos por "
                        f"{int(elapsed)}s."
                    )


                    print(
                        "🔄 Forçando reconexão..."
                    )


                    response_to_close = (
                        current_stream_response
                    )


                    current_stream_response = (
                        None
                    )

                    stream_connected = (
                        False
                    )


        if response_to_close is not None:

            try:

                response_to_close.close()

            except Exception as e:

                print(
                    "Erro ao fechar stream:",
                    e
                )


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
# BUSCA DIFF
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


    diff_html = (
        data
        .get("compare", {})
        .get(
            "body",
            ""
        )
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
        "added": (
            added[
                :MAX_DIFF_CHARS
            ]
        ),
        "removed": (
            removed[
                :MAX_DIFF_CHARS
            ]
        )
    }


# =========================================================
# WIKIMEDIA REVERT RISK
# =========================================================

def get_revert_risk(
    revision_id
):

    try:

        response = requests.post(
            REVERT_RISK_API,
            headers={
                **HEADERS,
                "Content-Type": (
                    "application/json"
                )
            },
            json={
                "rev_id": revision_id,
                "lang": "pt"
            },
            timeout=30
        )


        if response.status_code == 429:

            print(
                "⚠️ Rate limit Wikimedia Lift Wing."
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
                "Resposta inesperada Lift Wing:",
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
# HEURÍSTICAS
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
# ANÁLISE FINAL
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


    profanity = (
        profanity_score(
            added
        )
    )


    repetition = (
        repetition_score(
            added
        )
    )


    destructive = (
        destructive_score(
            added,
            removed
        )
    )


    nonsense = (
        nonsense_score(
            added
        )
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


    # =========================================
    # SCORE
    # =========================================

    # Revert Risk é o score-base.
    score = revert_risk


    # Um sinal heurístico forte:
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
        "reason": ", ".join(
            reasons
        )
    }


# =========================================================
# FORMATA MENSAGEM TELEGRAM
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
        change.get(
            "comment"
        )
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
        result[
            "score"
        ]
        *
        100
    )


    revert_score = round(
        result[
            "revert_risk"
        ]
        *
        100
    )


    diff_url = (
        "https://pt.wikipedia.org/w/index.php"
        f"?diff={new_revision}"
        f"&oldid={old_revision}"
    )


    return (
        f"🚨 Possível vandalismo — "
        f"{final_score}%\n\n"

        f"📝 {title}\n"
        f"👤 {user}\n"
        f"💬 {comment}\n\n"

        f"🤖 Risco de reversão Wikimedia: "
        f"{revert_score}%\n"

        f"⚠️ Sinais: "
        f"{result['reason']}\n\n"

        f"🔗 {diff_url}"
    )


# =========================================================
# WORKER DE ANÁLISE
# =========================================================

def analysis_worker():

    while True:

        change = (
            analysis_queue.get()
        )


        try:

            revision = change.get(
                "revision",
                {}
            )


            old_revision = (
                revision.get(
                    "old"
                )
            )


            new_revision = (
                revision.get(
                    "new"
                )
            )


            if not old_revision:

                continue


            if not new_revision:

                continue


            # =========================================
            # FILTRO DE USUÁRIO
            # =========================================

            username = change.get(
                "user",
                ""
            )


            if not should_evaluate_user(
                username
            ):

                continue


            # =========================================
            # REVERT RISK
            # =========================================

            revert_risk = (
                get_revert_risk(
                    new_revision
                )
            )


            if revert_risk is None:

                continue


            print(
                "Revert Risk:",
                f"{revert_risk:.1%}",
                "|",
                change.get(
                    "title"
                )
            )


            # =========================================
            # TRIAGEM
            # =========================================

            if (
                revert_risk
                <
                REVERT_RISK_THRESHOLD
            ):

                print(
                    "Descartada na triagem:",
                    f"{revert_risk:.1%}",
                    "|",
                    change.get(
                        "title"
                    )
                )

                continue


            # =========================================
            # DIFF
            # =========================================

            diff = get_revision_diff(
                old_revision,
                new_revision
            )


            result = (
                analyze_vandalism(
                    change,
                    diff,
                    revert_risk
                )
            )


            print(
                "Score final:",
                f"{result['score']:.1%}",
                "|",
                change.get(
                    "title"
                )
            )


            # =========================================
            # TELEGRAM
            # =========================================

            if (
                result["score"]
                >=
                VANDALISM_THRESHOLD
            ):

                telegram_queue.put(
                    {
                        "message": (
                            format_message(
                                change,
                                result
                            )
                        ),

                        "title": (
                            change.get(
                                "title",
                                "Sem título"
                            )
                        )
                    }
                )


                print(
                    "📤 Enfileirada para Telegram:",
                    change.get(
                        "title"
                    )
                )


            else:

                print(
                    "Não atingiu limite:",
                    f"{result['score']:.1%}",
                    "|",
                    change.get(
                        "title"
                    )
                )


        except Exception as e:

            print(
                "❌ Erro na análise:",
                e
            )


        finally:

            analysis_queue.task_done()


# =========================================================
# WIKIMEDIA EVENTSTREAMS
# =========================================================

def wikimedia_loop():

    global stream_connected
    global last_stream_event_at
    global last_ptwiki_edit_at
    global current_stream_response


    while True:

        response = None


        try:

            print(
                "📡 Conectando ao Wikimedia EventStreams..."
            )


            response = requests.get(
                WIKIMEDIA_STREAM,
                headers=HEADERS,
                stream=True,
                timeout=(
                    15,
                    90
                )
            )


            response.raise_for_status()


            with stream_lock:

                current_stream_response = (
                    response
                )

                stream_connected = True

                last_stream_event_at = (
                    time.time()
                )


            client = SSEClient(
                response
            )


            print(
                "✅ EventStreams conectado."
            )


            for event in client.events():

                # Atualizamos para qualquer evento
                # Wikimedia, não só ptwiki.
                with stream_lock:

                    last_stream_event_at = (
                        time.time()
                    )


                if not event.data:

                    continue


                try:

                    change = json.loads(
                        event.data
                    )

                except json.JSONDecodeError:

                    continue


                # =========================================
                # APENAS PTWIKI
                # =========================================

                if (
                    change.get(
                        "wiki"
                    )
                    !=
                    "ptwiki"
                ):

                    continue


                # =========================================
                # APENAS EDIÇÕES
                # =========================================

                if (
                    change.get(
                        "type"
                    )
                    !=
                    "edit"
                ):

                    continue


                # =========================================
                # IGNORA BOTS
                # =========================================

                if change.get(
                    "bot",
                    False
                ):

                    continue


                with stream_lock:

                    last_ptwiki_edit_at = (
                        time.time()
                    )


                analysis_queue.put(
                    change
                )


                print(
                    "Nova edição:",
                    change.get(
                        "title"
                    ),
                    "| Fila:",
                    analysis_queue.qsize()
                )


            print(
                "⚠️ EventStreams encerrou o fluxo."
            )


        except Exception as e:

            print(
                "⚠️ EventStreams desconectado:",
                e
            )


        finally:

            with stream_lock:

                if (
                    current_stream_response
                    is
                    response
                ):

                    current_stream_response = (
                        None
                    )


                stream_connected = False


            if response is not None:

                try:

                    response.close()

                except Exception:

                    pass


        print(
            "🔄 Reconectando em 5 segundos..."
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
        "Idade máxima da conta:",
        f"{MAX_ACCOUNT_AGE_DAYS} dias"
    )

    print(
        "Máximo de edições:",
        MAX_USER_EDITS
    )

    print(
        "Watchdog:",
        f"{STREAM_STALL_SECONDS}s"
    )

    print(
        "================================="
    )


    threading.Thread(
        target=telegram_sender,
        daemon=True
    ).start()


    threading.Thread(
        target=analysis_worker,
        daemon=True
    ).start()


    threading.Thread(
        target=telegram_command_listener,
        daemon=True
    ).start()


    threading.Thread(
        target=eventstream_watchdog,
        daemon=True
    ).start()


    wikimedia_loop()


if __name__ == "__main__":

    main()
