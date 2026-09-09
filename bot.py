import os
import json
import time
import queue
import threading
import re
import html
import ipaddress

from datetime import datetime, timezone
from urllib.parse import quote

import requests
from sseclient import SSEClient


# =========================================================
# CONFIGURAÇÃO
# =========================================================

TELEGRAM_TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN"
)

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
# DETECÇÃO
# =========================================================

REVERT_RISK_THRESHOLD = 0.35

VANDALISM_THRESHOLD = 0.55

MAX_DIFF_CHARS = 6000


# =========================================================
# FILTRO DE CONTAS
# =========================================================

# Mais de 30 dias -> edição normal ignorada.
MAX_ACCOUNT_AGE_DAYS = 30

# Mais de 10 edições -> edição normal ignorada.
MAX_USER_EDITS = 10

USER_CACHE_SECONDS = 3600

user_cache = {}


# =========================================================
# PÁGINAS VIGIADAS
# =========================================================

# Para persistência no Railway,
# monte um Volume em /data.
WATCHLIST_FILE = os.environ.get(
    "WATCHLIST_FILE",
    "/data/watchlist.json"
)

watched_pages = set()

watchlist_lock = threading.Lock()


# =========================================================
# WATCHDOG
# =========================================================

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
        "PtWikiVandalismTelegramBot/1.3 "
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

    if hours < 24:
        return (
            f"há {hours}h "
            f"{remaining_minutes}min"
        )

    days = hours // 24

    return f"há {days} dias"


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
# TELEGRAM - IDENTIFICA O CANAL
# =========================================================

def is_target_channel(chat):

    if not chat:
        return False

    chat_id = chat.get(
        "id"
    )

    username = chat.get(
        "username",
        ""
    )


    if TELEGRAM_CHANNEL.startswith("@"):

        expected = (
            TELEGRAM_CHANNEL[1:]
            .lower()
        )

        return (
            username.lower()
            ==
            expected
        )


    return (
        str(chat_id)
        ==
        str(TELEGRAM_CHANNEL)
    )


# =========================================================
# PERSISTÊNCIA DAS PÁGINAS VIGIADAS
# =========================================================

def save_watchlist_snapshot(snapshot):

    directory = os.path.dirname(
        WATCHLIST_FILE
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )


    temporary_file = (
        WATCHLIST_FILE
        +
        ".tmp"
    )


    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            sorted(snapshot),
            file,
            ensure_ascii=False,
            indent=2
        )


    os.replace(
        temporary_file,
        WATCHLIST_FILE
    )


def load_watchlist():

    global watched_pages


    try:

        if not os.path.exists(
            WATCHLIST_FILE
        ):

            print(
                "👁 Nenhuma lista de páginas "
                "vigiadas encontrada."
            )

            return


        with open(
            WATCHLIST_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )


        if not isinstance(
            data,
            list
        ):

            raise ValueError(
                "Formato inválido da watchlist."
            )


        with watchlist_lock:

            watched_pages = set(
                str(item)
                for item in data
            )


        print(
            "👁 Páginas vigiadas carregadas:",
            len(watched_pages)
        )


    except Exception as e:

        print(
            "⚠️ Erro ao carregar páginas vigiadas:",
            e
        )


def add_watched_page(title):

    with watchlist_lock:

        if title in watched_pages:

            return True, False


        snapshot = set(
            watched_pages
        )

        snapshot.add(
            title
        )


    try:

        save_watchlist_snapshot(
            snapshot
        )

    except Exception as e:

        print(
            "❌ Erro ao salvar página vigiada:",
            e
        )

        return False, False


    with watchlist_lock:

        watched_pages.add(
            title
        )


    return True, True


def remove_watched_page(title):

    with watchlist_lock:

        if title not in watched_pages:

            return True, False


        snapshot = set(
            watched_pages
        )

        snapshot.remove(
            title
        )


    try:

        save_watchlist_snapshot(
            snapshot
        )

    except Exception as e:

        print(
            "❌ Erro ao salvar watchlist:",
            e
        )

        return False, False


    with watchlist_lock:

        watched_pages.discard(
            title
        )


    return True, True


def is_watched_page(title):

    with watchlist_lock:

        return (
            title
            in
            watched_pages
        )


# =========================================================
# NORMALIZA TÍTULO DA WIKIPÉDIA
# =========================================================

def normalize_page_title(title):

    title = title.strip()

    if not title:
        return None


    try:

        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "titles": title
            },
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        pages = (
            data
            .get("query", {})
            .get("pages", [])
        )


        if not pages:

            return None


        canonical_title = (
            pages[0]
            .get("title")
        )


        return canonical_title


    except Exception as e:

        print(
            "⚠️ Erro ao normalizar página:",
            title,
            "|",
            e
        )

        return None


# =========================================================
# INFORMAÇÕES DA CONTA
# =========================================================

def get_user_info(
    username,
    use_cache=True
):

    now = time.time()


    if use_cache:

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
                    "editcount|registration|"
                    "groups|blockinfo"
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
            "name": user.get(
                "name",
                username
            ),

            "editcount": user.get(
                "editcount",
                0
            ),

            "registration": user.get(
                "registration"
            ),

            "groups": user.get(
                "groups",
                []
            ),

            "blockid": user.get(
                "blockid"
            ),

            "blockedby": user.get(
                "blockedby"
            ),

            "blockreason": user.get(
                "blockreason"
            ),

            "blockexpiry": user.get(
                "blockexpiry"
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
# HISTÓRICO DE BLOQUEIOS
# =========================================================

def has_previous_block(username):

    try:

        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "logevents",
                "letype": "block",
                "letitle": (
                    f"Usuário:{username}"
                ),
                "lelimit": 1,
                "leprop": (
                    "ids|title|type|"
                    "user|timestamp|comment|details"
                )
            },
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        events = (
            data
            .get("query", {})
            .get("logevents", [])
        )


        return bool(
            events
        )


    except Exception as e:

        print(
            "⚠️ Erro ao consultar histórico "
            "de bloqueios:",
            username,
            "|",
            e
        )

        return False


# =========================================================
# DIREITOS / GRUPOS
# =========================================================

GROUP_NAMES = {

    "*": "usuário",

    "user": (
        "usuário registrado"
    ),

    "autoconfirmed": (
        "autoconfirmado"
    ),

    "confirmed": (
        "confirmado"
    ),

    "extendedconfirmed": (
        "autoconfirmado estendido"
    ),

    "autoreviewer": (
        "autorrevisor"
    ),

    "rollbacker": (
        "reversor"
    ),

    "eliminator": (
        "eliminador"
    ),

    "sysop": (
        "administrador"
    ),

    "bureaucrat": (
        "burocrata"
    ),

    "interface-admin": (
        "administrador de interface"
    ),

    "accountcreator": (
        "criador de contas"
    ),

    "checkuser": (
        "verificador"
    ),

    "suppress": (
        "oversight"
    ),

    "ipblock-exempt": (
        "isento de bloqueio de IP"
    )
}


def format_groups(groups):

    if not groups:

        return "nenhum grupo especial"


    formatted = []


    for group in groups:

        name = GROUP_NAMES.get(
            group,
            group
        )

        if name not in formatted:

            formatted.append(
                name
            )


    return ", ".join(
        formatted
    )


# =========================================================
# VERIFICA SE É ADMINISTRADOR DA WIKIPÉDIA
# =========================================================

def is_wikipedia_admin(username):

    if is_ip_address(
        username
    ):

        return False


    info = get_user_info(
        username
    )


    # Se a API falhar, preferimos não perder
    # uma edição de página vigiada.
    if info is None:

        print(
            "⚠️ Não foi possível verificar "
            "se é administrador:",
            username
        )

        return False


    groups = info.get(
        "groups",
        []
    )


    return (
        "sysop"
        in
        groups
    )


# =========================================================
# FILTRO NORMAL DAS CONTAS
# =========================================================

def should_evaluate_user(username):

    if not username:
        return True


    # IP sempre é avaliado.
    if is_ip_address(
        username
    ):

        print(
            "🌐 IP:",
            username,
            "| será avaliado"
        )

        return True


    info = get_user_info(
        username
    )


    # Falha da API:
    # preferimos avaliar.
    if info is None:

        print(
            "⚠️ Não foi possível verificar a conta:",
            username,
            "| edição será avaliada"
        )

        return True


    editcount = info.get(
        "editcount",
        0
    )


    # Mais de 10 edições -> ignora.
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


    registration = info.get(
        "registration"
    )


    if registration:

        try:

            created = datetime.fromisoformat(
                registration.replace(
                    "Z",
                    "+00:00"
                )
            )


            age_days = (
                datetime.now(
                    timezone.utc
                )
                -
                created
            ).total_seconds() / 86400


            # Mais de 30 dias -> ignora.
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


    return True


# =========================================================
# TELEGRAM
# =========================================================

def send_telegram_message(
    text,
    chat_id=None,
    parse_mode=None
):

    if chat_id is None:
        chat_id = TELEGRAM_CHANNEL


    while True:

        try:

            payload = {
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": True
            }


            if parse_mode:

                payload[
                    "parse_mode"
                ] = parse_mode


            response = requests.post(
                f"{TELEGRAM_API}/sendMessage",
                json=payload,
                timeout=30
            )


            # -----------------------------------------
            # RATE LIMIT
            # -----------------------------------------

            if response.status_code == 429:

                try:

                    data = response.json()

                    retry_after = (
                        data
                        .get(
                            "parameters",
                            {}
                        )
                        .get(
                            "retry_after",
                            2
                        )
                    )

                except Exception:

                    retry_after = 2


                print(
                    "⚠️ Rate limit Telegram. "
                    f"Aguardando {retry_after}s."
                )

                time.sleep(
                    retry_after
                )

                continue


            # -----------------------------------------
            # ERROS PERMANENTES
            # -----------------------------------------

            if response.status_code in (
                400,
                401,
                403
            ):

                print(
                    "❌ Telegram rejeitou mensagem:",
                    response.status_code,
                    response.text
                )

                return False


            # -----------------------------------------
            # ERRO DO SERVIDOR
            # -----------------------------------------

            if response.status_code >= 500:

                print(
                    "⚠️ Erro temporário Telegram:",
                    response.status_code
                )

                time.sleep(5)

                continue


            response.raise_for_status()

            return True


        except requests.RequestException as e:

            print(
                "⚠️ Erro de rede Telegram:",
                e
            )

            time.sleep(5)


# =========================================================
# SENDER TELEGRAM
# =========================================================

def telegram_sender():

    while True:

        item = telegram_queue.get()


        try:

            message = item[
                "message"
            ]

            title = item[
                "title"
            ]

            parse_mode = item.get(
                "parse_mode"
            )


            success = send_telegram_message(
                message,
                parse_mode=parse_mode
            )


            if success:

                print(
                    "✅ Telegram confirmou envio:",
                    title
                )

            else:

                print(
                    "❌ Falha ao enviar:",
                    title
                )


        except Exception as e:

            print(
                "Erro no sender Telegram:",
                e
            )


        finally:

            telegram_queue.task_done()


        time.sleep(1)


# =========================================================
# /CONTA
# =========================================================

def build_account_message(username):

    info = get_user_info(
        username,
        use_cache=False
    )


    if info is None:

        return (
            "❌ Conta não encontrada: "
            f"{username}"
        ), None


    username = info.get(
        "name",
        username
    )


    editcount = info.get(
        "editcount",
        0
    )


    registration = info.get(
        "registration"
    )


    if registration:

        try:

            created = datetime.fromisoformat(
                registration.replace(
                    "Z",
                    "+00:00"
                )
            )


            age_days = int(
                (
                    datetime.now(
                        timezone.utc
                    )
                    -
                    created
                ).total_seconds()
                /
                86400
            )


            creation_text = (
                f"{age_days} dias"
            )


        except Exception:

            creation_text = (
                "data indisponível"
            )


    else:

        creation_text = (
            "data indisponível"
        )


    groups = format_groups(
        info.get(
            "groups",
            []
        )
    )


    # -----------------------------------------
    # BLOQUEIO
    # -----------------------------------------

    if info.get(
        "blockid"
    ):

        block_status = (
            "🔴 ativo"
        )

    else:

        previous = has_previous_block(
            username
        )

        if previous:

            block_status = (
                "🟡 bloqueio prévio"
            )

        else:

            block_status = (
                "🟢 nenhum"
            )


    encoded_username = quote(
        username.replace(
            " ",
            "_"
        ),
        safe=""
    )


    user_url = (
        "https://pt.wikipedia.org/wiki/"
        f"Usuário:{encoded_username}"
    )


    safe_username = html.escape(
        username
    )

    safe_groups = html.escape(
        groups
    )


    message = (
        f'👤 <a href="{user_url}">'
        f"{safe_username}</a>\n\n"

        f"✏️ Edições na Wikipédia em português: "
        f"{editcount}\n"

        f"📅 Idade da conta: "
        f"{creation_text}\n"

        f"🔑 Direitos de usuário: "
        f"{safe_groups}\n"

        f"🚫 Bloqueio: "
        f"{block_status}"
    )


    return message, "HTML"


# =========================================================
# MENSAGEM /COMANDOS
# =========================================================

def commands_message():

    return (
        "🤖 Comandos disponíveis\n\n"

        "👁 /vigiar Página\n"
        "Adiciona uma página à vigilância.\n\n"

        "🙈 /desvigiar Página\n"
        "Remove uma página da vigilância.\n\n"

        "📋 /vigiadas\n"
        "Lista todas as páginas vigiadas.\n\n"

        "👤 /conta Usuário\n"
        "Mostra informações de uma conta.\n\n"

        "📡 /status\n"
        "Mostra o estado do bot.\n\n"

        "📖 /comandos\n"
        "Mostra esta lista."
    )


# =========================================================
# PROCESSA COMANDOS
# =========================================================

def process_telegram_command(
    message,
    from_channel=False
):

    text = message.get(
        "text",
        ""
    ).strip()


    if not text.startswith("/"):
        return


    chat = message.get(
        "chat",
        {}
    )


    chat_id = chat.get(
        "id"
    )


    if not chat_id:
        return


    first_part, *remaining = (
        text.split(
            maxsplit=1
        )
    )


    command = (
        first_part
        .split("@")[0]
        .lower()
    )


    argument = (
        remaining[0].strip()
        if remaining
        else ""
    )


    # =====================================================
    # /START
    # =====================================================

    if command == "/start":

        send_telegram_message(
            (
                "🤖 Monitor de possíveis vandalismos "
                "da Wikipédia em português.\n\n"
                "Use /comandos para ver os comandos."
            ),
            chat_id=chat_id
        )

        return


    # =====================================================
    # /COMANDOS
    # =====================================================

    if command == "/comandos":

        send_telegram_message(
            commands_message(),
            chat_id=chat_id
        )

        return


    # =====================================================
    # /STATUS
    # =====================================================

    if command == "/status":

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


        with watchlist_lock:

            watch_count = len(
                watched_pages
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

                f"👶 Idade máxima normal: "
                f"{MAX_ACCOUNT_AGE_DAYS} dias\n"

                f"✏️ Máximo de edições: "
                f"{MAX_USER_EDITS}\n"

                f"👁 Páginas vigiadas: "
                f"{watch_count}\n\n"

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

        return


    # =====================================================
    # /CONTA
    # =====================================================

    if command == "/conta":

        if not argument:

            send_telegram_message(
                (
                    "Uso:\n"
                    "/conta Nome do usuário"
                ),
                chat_id=chat_id
            )

            return


        account_message, parse_mode = (
            build_account_message(
                argument
            )
        )


        send_telegram_message(
            account_message,
            chat_id=chat_id,
            parse_mode=parse_mode
        )

        return


    # =====================================================
    # /VIGIADAS
    # =====================================================

    if command == "/vigiadas":

        with watchlist_lock:

            pages = sorted(
                watched_pages,
                key=str.lower
            )


        if not pages:

            text_response = (
                "👁 Nenhuma página está sendo "
                "vigiada atualmente."
            )

        else:

            page_list = "\n".join(
                f"• {page}"
                for page in pages
            )

            text_response = (
                "👁 Páginas vigiadas:\n\n"
                f"{page_list}"
            )


        send_telegram_message(
            text_response,
            chat_id=chat_id
        )

        return


    # =====================================================
    # COMANDOS QUE ALTERAM A WATCHLIST
    # =====================================================

    if command in (
        "/vigiar",
        "/desvigiar"
    ):

        # Estes comandos só podem ser publicados
        # dentro do canal configurado.
        if not from_channel:

            send_telegram_message(
                (
                    "⚠️ Este comando deve ser "
                    "publicado por um administrador "
                    "no canal."
                ),
                chat_id=chat_id
            )

            return


        if not is_target_channel(
            chat
        ):

            return


        if not argument:

            send_telegram_message(
                (
                    "Uso:\n"
                    f"{command} Nome da página"
                ),
                chat_id=chat_id
            )

            return


        title = normalize_page_title(
            argument
        )


        if not title:

            send_telegram_message(
                (
                    "❌ Não foi possível identificar "
                    "essa página."
                ),
                chat_id=chat_id
            )

            return


        # -------------------------------------------------
        # /VIGIAR
        # -------------------------------------------------

        if command == "/vigiar":

            success, added = (
                add_watched_page(
                    title
                )
            )


            if not success:

                send_telegram_message(
                    (
                        "❌ Não foi possível salvar "
                        "a página na lista de vigilância."
                    ),
                    chat_id=chat_id
                )

                return


            if not added:

                send_telegram_message(
                    (
                        f"👁 {title} já está sendo "
                        "vigiada."
                    ),
                    chat_id=chat_id
                )

                return


            send_telegram_message(
                (
                    f"👁 {title} adicionada à vigilância.\n\n"
                    "Toda edição feita nesta página por "
                    "usuário não-bot e não-administrador "
                    "da Wikipédia gerará uma publicação "
                    "neste canal."
                ),
                chat_id=chat_id
            )

            return


        # -------------------------------------------------
        # /DESVIGIAR
        # -------------------------------------------------

        success, removed = (
            remove_watched_page(
                title
            )
        )


        if not success:

            send_telegram_message(
                (
                    "❌ Não foi possível atualizar "
                    "a lista de vigilância."
                ),
                chat_id=chat_id
            )

            return


        if not removed:

            send_telegram_message(
                (
                    f"🙈 {title} não estava "
                    "na lista de páginas vigiadas."
                ),
                chat_id=chat_id
            )

            return


        send_telegram_message(
            (
                f"🙈 {title} removida da vigilância.\n\n"
                "As edições voltarão a seguir "
                "os critérios normais do detector."
            ),
            chat_id=chat_id
        )


# =========================================================
# LISTENER TELEGRAM
# =========================================================

def telegram_command_listener():

    offset = None


    print(
        "✅ Listener de comandos Telegram iniciado."
    )


    while True:

        try:

            params = {
                "timeout": 30,
                "allowed_updates": json.dumps(
                    [
                        "message",
                        "channel_post"
                    ]
                )
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


                # -----------------------------------------
                # MENSAGEM NORMAL / PRIVADA
                # -----------------------------------------

                message = update.get(
                    "message"
                )


                if message:

                    process_telegram_command(
                        message,
                        from_channel=False
                    )


                # -----------------------------------------
                # PUBLICAÇÃO NO CANAL
                # -----------------------------------------

                channel_post = update.get(
                    "channel_post"
                )


                if channel_post:

                    chat = channel_post.get(
                        "chat",
                        {}
                    )


                    if is_target_channel(
                        chat
                    ):

                        process_telegram_command(
                            channel_post,
                            from_channel=True
                        )


        except Exception as e:

            print(
                "Erro no listener Telegram:",
                e
            )

            time.sleep(5)


# =========================================================
# WATCHDOG EVENTSTREAMS
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

                    current_stream_response = None

                    stream_connected = False


        if response_to_close is not None:

            try:

                response_to_close.close()

            except Exception as e:

                print(
                    "Erro ao fechar stream:",
                    e
                )


# =========================================================
# LIMPEZA DO DIFF
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
# DIFF
# =========================================================

def get_revision_diff(
    old_revision,
    new_revision
):

    response = requests.get(
        WIKIPEDIA_API,
        params={
            "action": "compare",
            "format": "json",
            "formatversion": 2,
            "fromrev": old_revision,
            "torev": new_revision,
            "prop": "diff"
        },
        headers=HEADERS,
        timeout=30
    )


    response.raise_for_status()

    data = response.json()


    diff_html = (
        data
        .get("compare", {})
        .get("body", "")
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
# REVERT RISK
# =========================================================

def get_revert_risk(revision_id):

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
# ANÁLISE
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


    score = revert_risk


    if heuristic >= 0.75:

        score += 0.10


    strong_signals = sum(
        1
        for signal in signals
        if signal >= 0.75
    )


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
# MENSAGEM DE VANDALISMO
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
# MENSAGEM DE PÁGINA VIGIADA
# =========================================================

def format_watched_message(
    change
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


    diff_url = (
        "https://pt.wikipedia.org/w/index.php"
        f"?diff={new_revision}"
        f"&oldid={old_revision}"
    )


    return (
        "👁 Edição em página vigiada\n\n"

        f"📝 {title}\n"
        f"👤 {user}\n"
        f"💬 {comment}\n\n"

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


            username = change.get(
                "user",
                ""
            )

            title = change.get(
                "title",
                ""
            )


            # =========================================
            # PÁGINA VIGIADA
            # =========================================

            if is_watched_page(
                title
            ):

                print(
                    "👁 Edição em página vigiada:",
                    title,
                    "|",
                    username
                )


                if is_wikipedia_admin(
                    username
                ):

                    print(
                        "⏭️ Edição vigiada ignorada: "
                        "usuário é administrador |",
                        username
                    )

                    continue


                telegram_queue.put(
                    {
                        "message": (
                            format_watched_message(
                                change
                            )
                        ),
                        "title": title
                    }
                )


                print(
                    "📤 Página vigiada enfileirada:",
                    title
                )


                # Não passa pelo detector normal
                # para evitar postagem duplicada.
                continue


            # =========================================
            # FILTRO NORMAL DE USUÁRIO
            # =========================================

            if not should_evaluate_user(
                username
            ):

                continue


            # =========================================
            # REVERT RISK
            # =========================================

            revert_risk = get_revert_risk(
                new_revision
            )


            if revert_risk is None:
                continue


            print(
                "Revert Risk:",
                f"{revert_risk:.1%}",
                "|",
                title
            )


            if (
                revert_risk
                <
                REVERT_RISK_THRESHOLD
            ):

                print(
                    "Descartada na triagem:",
                    f"{revert_risk:.1%}",
                    "|",
                    title
                )

                continue


            # =========================================
            # DIFF + HEURÍSTICAS
            # =========================================

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
                f"{result['score']:.1%}",
                "|",
                title
            )


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
                        "title": title
                    }
                )


                print(
                    "📤 Enfileirada para Telegram:",
                    title
                )


            else:

                print(
                    "Não atingiu limite:",
                    f"{result['score']:.1%}",
                    "|",
                    title
                )


        except Exception as e:

            print(
                "❌ Erro na análise:",
                e
            )


        finally:

            analysis_queue.task_done()


# =========================================================
# EVENTSTREAMS
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


                if (
                    change.get(
                        "wiki"
                    )
                    !=
                    "ptwiki"
                ):

                    continue


                if (
                    change.get(
                        "type"
                    )
                    !=
                    "edit"
                ):

                    continue


                # Bots nunca entram nem mesmo
                # nas páginas vigiadas.
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
                    is response
                ):

                    current_stream_response = None


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

    load_watchlist()


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
        "Idade máxima normal:",
        f"{MAX_ACCOUNT_AGE_DAYS} dias"
    )

    print(
        "Máximo de edições:",
        MAX_USER_EDITS
    )


    with watchlist_lock:

        print(
            "Páginas vigiadas:",
            len(watched_pages)
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
