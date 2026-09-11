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
# LIMITES
# =========================================================

REVERT_RISK_THRESHOLD = 0.25
VANDALISM_THRESHOLD = 0.45

MAX_DIFF_CHARS = 6000

MAX_ACCOUNT_AGE_DAYS = 60
MAX_USER_EDITS = 50

USER_CACHE_SECONDS = 3600

STREAM_STALL_SECONDS = 120


# =========================================================
# OBSERVAÇÃO DE CONTAS
# =========================================================

OBSERVATION_DURATION_SECONDS = 6 * 60 * 60

OBSERVED_USERS_FILE = os.environ.get(
    "OBSERVED_USERS_FILE",
    "/data/observed_users.json"
)

observed_users = {}
observed_users_lock = threading.Lock()


# =========================================================
# WATCHLIST
# =========================================================

WATCHLIST_FILE = os.environ.get(
    "WATCHLIST_FILE",
    "/data/watchlist.json"
)

watched_pages = set()
watchlist_lock = threading.Lock()


# =========================================================
# CACHE
# =========================================================

user_cache = {}


# =========================================================
# FILAS
# =========================================================

analysis_queue = queue.Queue()
telegram_queue = queue.Queue()


# =========================================================
# EVENTSTREAMS
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
        "PtWikiVandalismTelegramBot/1.6 "
        "(https://t.me/ptwiki)"
    )
}


# =========================================================
# TELEGRAM - WEBHOOK
# =========================================================

def remove_telegram_webhook():

    try:

        response = requests.post(
            f"{TELEGRAM_API}/deleteWebhook",
            json={
                "drop_pending_updates": False
            },
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        if data.get("ok"):

            print(
                "✅ Webhook Telegram removido/desativado."
            )

        else:

            print(
                "⚠️ Resposta inesperada ao remover webhook:",
                data
            )

    except Exception as e:

        print(
            "⚠️ Erro ao remover webhook Telegram:",
            repr(e)
        )


def check_telegram_webhook():

    try:

        response = requests.get(
            f"{TELEGRAM_API}/getWebhookInfo",
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        webhook = (
            data
            .get("result", {})
            .get("url")
        )

        if webhook:

            print(
                "⚠️ Webhook ainda configurado:",
                webhook
            )

        else:

            print(
                "✅ Webhook atual: nenhum"
            )

    except Exception as e:

        print(
            "⚠️ Erro ao verificar webhook:",
            repr(e)
        )


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

    if hours < 24:

        return (
            f"há {hours}h "
            f"{minutes % 60}min"
        )

    days = hours // 24

    return f"há {days} dias"


def format_remaining(seconds):

    seconds = max(
        0,
        int(seconds)
    )

    minutes = seconds // 60

    hours = minutes // 60
    remaining_minutes = minutes % 60

    if hours > 0:

        return (
            f"{hours}h "
            f"{remaining_minutes}min"
        )

    return f"{minutes}min"


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


def username_key(username):

    return (
        username
        .replace("_", " ")
        .strip()
        .casefold()
    )


# =========================================================
# IDENTIFICA CANAL TELEGRAM
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
# TESTE DE ARMAZENAMENTO
# =========================================================

def ensure_storage():

    files = [
        WATCHLIST_FILE,
        OBSERVED_USERS_FILE
    ]

    directories = set(
        os.path.dirname(path)
        for path in files
        if os.path.dirname(path)
    )

    try:

        for directory in directories:

            os.makedirs(
                directory,
                exist_ok=True
            )

            test_file = os.path.join(
                directory,
                ".bot_write_test"
            )

            with open(
                test_file,
                "w",
                encoding="utf-8"
            ) as file:

                file.write("ok")

                file.flush()

                os.fsync(
                    file.fileno()
                )

            os.remove(
                test_file
            )

        print(
            "✅ Armazenamento persistente gravável."
        )

        print(
            "📁 Watchlist:",
            WATCHLIST_FILE
        )

        print(
            "📁 Contas observadas:",
            OBSERVED_USERS_FILE
        )

        return True

    except Exception as e:

        print(
            "❌ Erro no armazenamento:"
        )

        print(
            repr(e)
        )

        return False


# =========================================================
# WATCHLIST
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

    temp_file = (
        WATCHLIST_FILE
        +
        ".tmp"
    )

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            sorted(snapshot),
            file,
            ensure_ascii=False,
            indent=2
        )

        file.flush()

        os.fsync(
            file.fileno()
        )

    os.replace(
        temp_file,
        WATCHLIST_FILE
    )

    print(
        "💾 Watchlist salva:",
        len(snapshot),
        "páginas"
    )


def load_watchlist():

    global watched_pages

    try:

        if not os.path.exists(
            WATCHLIST_FILE
        ):

            print(
                "👁 Watchlist ainda não existe."
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
            "✅ Watchlist carregada:",
            len(watched_pages)
        )

    except Exception as e:

        print(
            "❌ Erro ao carregar watchlist:",
            repr(e)
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
            "❌ Erro ao salvar watchlist:",
            repr(e)
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
            repr(e)
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
            in watched_pages
        )


# =========================================================
# CONTAS OBSERVADAS
# =========================================================

def save_observed_users():

    directory = os.path.dirname(
        OBSERVED_USERS_FILE
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )

    with observed_users_lock:

        data = list(
            observed_users.values()
        )

    temp_file = (
        OBSERVED_USERS_FILE
        +
        ".tmp"
    )

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=2
        )

        file.flush()

        os.fsync(
            file.fileno()
        )

    os.replace(
        temp_file,
        OBSERVED_USERS_FILE
    )

    print(
        "💾 Contas observadas salvas:",
        len(data)
    )


def cleanup_expired_observations():

    now = time.time()

    removed = False

    with observed_users_lock:

        expired_keys = [
            key
            for key, item
            in observed_users.items()
            if item.get(
                "expires_at",
                0
            ) <= now
        ]

        for key in expired_keys:

            user = observed_users[
                key
            ].get(
                "username",
                key
            )

            print(
                "⌛ Observação expirada:",
                user
            )

            del observed_users[
                key
            ]

            removed = True

    if removed:

        try:

            save_observed_users()

        except Exception as e:

            print(
                "⚠️ Erro ao salvar expirações:",
                repr(e)
            )


def load_observed_users():

    global observed_users

    try:

        if not os.path.exists(
            OBSERVED_USERS_FILE
        ):

            print(
                "👁 Nenhuma lista de contas "
                "observadas encontrada."
            )

            return

        with open(
            OBSERVED_USERS_FILE,
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
                "Formato inválido de observed_users.json"
            )

        now = time.time()

        loaded = {}

        for item in data:

            username = item.get(
                "username"
            )

            reason = item.get(
                "reason"
            )

            expires_at = item.get(
                "expires_at",
                0
            )

            if (
                not username
                or
                not reason
                or
                expires_at <= now
            ):

                continue

            loaded[
                username_key(
                    username
                )
            ] = {
                "username": username,
                "reason": reason,
                "expires_at": expires_at
            }

        with observed_users_lock:

            observed_users = loaded

        print(
            "✅ Contas observadas carregadas:",
            len(loaded)
        )

        save_observed_users()

    except Exception as e:

        print(
            "❌ Erro ao carregar contas observadas:",
            repr(e)
        )


def observe_user(
    username,
    reason
):

    expires_at = (
        time.time()
        +
        OBSERVATION_DURATION_SECONDS
    )

    key = username_key(
        username
    )

    with observed_users_lock:

        observed_users[
            key
        ] = {
            "username": username,
            "reason": reason,
            "expires_at": expires_at
        }

    try:

        save_observed_users()

        return True

    except Exception as e:

        print(
            "❌ Erro ao salvar conta observada:",
            repr(e)
        )

        with observed_users_lock:

            observed_users.pop(
                key,
                None
            )

        return False


def stop_observing_user(username):

    key = username_key(
        username
    )

    with observed_users_lock:

        if key not in observed_users:

            return True, False

        backup = observed_users[
            key
        ]

        del observed_users[
            key
        ]

    try:

        save_observed_users()

        return True, True

    except Exception as e:

        print(
            "❌ Erro ao salvar remoção:",
            repr(e)
        )

        with observed_users_lock:

            observed_users[
                key
            ] = backup

        return False, False


def get_observation(username):

    cleanup_expired_observations()

    key = username_key(
        username
    )

    with observed_users_lock:

        item = observed_users.get(
            key
        )

        if not item:

            return None

        return dict(
            item
        )


# =========================================================
# NORMALIZA TÍTULO
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

        pages = (
            response.json()
            .get("query", {})
            .get("pages", [])
        )

        if not pages:

            return None

        page = pages[0]

        if "missing" in page:

            return None

        return page.get(
            "title"
        )

    except Exception as e:

        print(
            "⚠️ Erro ao normalizar página:",
            repr(e)
        )

        return None


# =========================================================
# USUÁRIO WIKIPÉDIA
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

            if (
                now
                -
                cached.get(
                    "cached_at",
                    0
                )
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

        users = (
            response.json()
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
            "cached_at": now
        }

        user_cache[
            username
        ] = result

        return result

    except Exception as e:

        print(
            "⚠️ Erro ao consultar usuário:",
            username,
            repr(e)
        )

        return None


def normalize_username(username):

    username = (
        username
        .replace("_", " ")
        .strip()
    )

    info = get_user_info(
        username,
        use_cache=False
    )

    if info is None:

        return None

    return info.get(
        "name"
    )


# =========================================================
# BLOQUEIOS
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
                "lelimit": 1
            },
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()

        events = (
            response.json()
            .get("query", {})
            .get("logevents", [])
        )

        return bool(
            events
        )

    except Exception:

        return False


# =========================================================
# GRUPOS
# =========================================================

GROUP_NAMES = {

    "*": "usuário",
    "user": "usuário registrado",
    "autoconfirmed": "autoconfirmado",
    "confirmed": "confirmado",
    "extendedconfirmed": "autoconfirmado estendido",
    "autoreviewer": "autorrevisor",
    "rollbacker": "reversor",
    "eliminator": "eliminador",
    "sysop": "administrador",
    "bureaucrat": "burocrata",
    "interface-admin": "administrador de interface",
    "accountcreator": "criador de contas",
    "checkuser": "verificador",
    "suppress": "oversight",
    "ipblock-exempt": "isento de bloqueio de IP"
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


def is_wikipedia_admin(username):

    if is_ip_address(
        username
    ):

        return False

    info = get_user_info(
        username
    )

    if info is None:

        return False

    return (
        "sysop"
        in
        info.get(
            "groups",
            []
        )
    )


# =========================================================
# FILTRO NORMAL DE CONTAS
# =========================================================

def should_evaluate_user(username):

    if not username:

        return True

    if is_ip_address(
        username
    ):

        return True

    info = get_user_info(
        username
    )

    if info is None:

        return True

    editcount = info.get(
        "editcount",
        0
    )

    if editcount > MAX_USER_EDITS:

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

            if age_days > MAX_ACCOUNT_AGE_DAYS:

                return False

        except Exception:

            pass

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

            if response.status_code == 429:

                try:

                    retry_after = (
                        response.json()
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

                time.sleep(
                    retry_after
                )

                continue

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

            if response.status_code >= 500:

                time.sleep(5)

                continue

            response.raise_for_status()

            return True

        except requests.RequestException as e:

            print(
                "⚠️ Erro de rede Telegram:",
                repr(e)
            )

            time.sleep(5)


def telegram_sender():

    while True:

        item = telegram_queue.get()

        try:

            success = send_telegram_message(
                item["message"],
                parse_mode=item.get(
                    "parse_mode"
                )
            )

            if success:

                print(
                    "✅ Telegram confirmou envio:",
                    item["title"]
                )

        except Exception as e:

            print(
                "❌ Erro sender:",
                repr(e)
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
            f"❌ Conta não encontrada: {username}",
            None
        )

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

            creation_text = "indisponível"

    else:

        creation_text = "indisponível"

    groups = format_groups(
        info.get(
            "groups",
            []
        )
    )

    if info.get(
        "blockid"
    ):

        block_status = "🔴 ativo"

    elif has_previous_block(
        username
    ):

        block_status = "🟡 bloqueio prévio"

    else:

        block_status = "🟢 nenhum"

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

    message = (
        f'👤 <a href="{user_url}">'
        f'{html.escape(username)}</a>\n\n'

        f"✏️ Edições na Wikipédia em português: "
        f"{editcount}\n"

        f"📅 Idade da conta: "
        f"{creation_text}\n"

        f"🔑 Direitos de usuário: "
        f"{html.escape(groups)}\n"

        f"🚫 Bloqueio: "
        f"{block_status}"
    )

    return (
        message,
        "HTML"
    )


# =========================================================
# COMANDOS
# =========================================================

def commands_message():

    return (
        "🤖 Comandos disponíveis\n\n"

        "👁 /vigiar Página\n"
        "Vigia uma página.\n\n"

        "🙈 /desvigiar Página\n"
        "Remove uma página da vigilância.\n\n"

        "📋 /vigiadas\n"
        "Lista páginas vigiadas.\n\n"

        "🔎 /observar Usuário motivo\n"
        "Observa uma conta durante 2 horas.\n\n"

        "⛔ /desobservar Usuário\n"
        "Encerra a observação de uma conta.\n\n"

        "📋 /observadas\n"
        "Lista contas atualmente observadas.\n\n"

        "👤 /conta Usuário\n"
        "Consulta uma conta.\n\n"

        "📡 /status\n"
        "Mostra o estado do bot.\n\n"

        "📖 /comandos\n"
        "Mostra esta lista."
    )


# =========================================================
# PROCESSAMENTO DOS COMANDOS
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
                "🤖 Monitor da Wikipédia "
                "em português.\n\n"
                "Use /comandos."
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

        cleanup_expired_observations()

        with stream_lock:

            connected = stream_connected
            last_stream = last_stream_event_at
            last_ptwiki = last_ptwiki_edit_at

        with watchlist_lock:

            watch_count = len(
                watched_pages
            )

        with observed_users_lock:

            observed_count = len(
                observed_users
            )

        stream_status = (
            "🟢 conectado"
            if connected
            else
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

                f"👶 Idade máxima: "
                f"{MAX_ACCOUNT_AGE_DAYS} dias\n"

                f"✏️ Máximo de edições: "
                f"{MAX_USER_EDITS}\n\n"

                f"👁 Páginas vigiadas: "
                f"{watch_count}\n"

                f"🔎 Contas observadas: "
                f"{observed_count}\n\n"

                f"🔎 Triagem: "
                f"{REVERT_RISK_THRESHOLD:.0%}\n"

                f"🚨 Publicação: "
                f"{VANDALISM_THRESHOLD:.0%}\n\n"

                f"📥 Fila análise: "
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
                "Uso: /conta Nome",
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
    # /OBSERVADAS
    # =====================================================

    if command == "/observadas":

        cleanup_expired_observations()

        now = time.time()

        with observed_users_lock:

            items = [
                dict(item)
                for item
                in observed_users.values()
            ]

        if not items:

            send_telegram_message(
                "🔎 Nenhuma conta está sendo observada.",
                chat_id=chat_id
            )

            return

        items.sort(
            key=lambda x:
            x.get(
                "expires_at",
                0
            )
        )

        lines = []

        for item in items:

            remaining_time = (
                item["expires_at"]
                -
                now
            )

            lines.append(
                (
                    f"• {item['username']}\n"
                    f"  ⏳ {format_remaining(remaining_time)}\n"
                    f"  📌 {item['reason']}"
                )
            )

        send_telegram_message(
            (
                "🔎 Contas observadas:\n\n"
                +
                "\n\n".join(
                    lines
                )
            ),
            chat_id=chat_id
        )

        return


    # =====================================================
    # /OBSERVAR
    # =====================================================

    if command == "/observar":

        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):

            send_telegram_message(
                (
                    "⚠️ /observar deve ser publicado "
                    "diretamente no canal."
                ),
                chat_id=chat_id
            )

            return

        parts = argument.split(
            maxsplit=1
        )

        if len(parts) < 2:

            send_telegram_message(
                (
                    "Uso:\n"
                    "/observar Usuário motivo\n\n"
                    "Exemplo:\n"
                    "/observar Teles vandalismo recorrente"
                ),
                chat_id=chat_id
            )

            return

        username_input = parts[0]
        reason = parts[1].strip()

        canonical_username = (
            normalize_username(
                username_input
            )
        )

        if not canonical_username:

            send_telegram_message(
                (
                    "❌ Conta não encontrada: "
                    f"{username_input}"
                ),
                chat_id=chat_id
            )

            return

        if observe_user(
            canonical_username,
            reason
        ):

            send_telegram_message(
                (
                    "🔎 Conta colocada em observação\n\n"

                    f"👤 {canonical_username}\n"
                    f"⏳ Duração: 2 horas\n"
                    f"📌 Motivo: {reason}\n\n"

                    "Toda edição desta conta será "
                    "publicada no canal durante "
                    "esse período."
                ),
                chat_id=chat_id
            )

        else:

            send_telegram_message(
                (
                    "❌ Não foi possível salvar "
                    "a observação."
                ),
                chat_id=chat_id
            )

        return


    # =====================================================
    # /DESOBSERVAR
    # =====================================================

    if command == "/desobservar":

        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):

            send_telegram_message(
                (
                    "⚠️ /desobservar deve ser publicado "
                    "diretamente no canal."
                ),
                chat_id=chat_id
            )

            return

        if not argument:

            send_telegram_message(
                "Uso: /desobservar Usuário",
                chat_id=chat_id
            )

            return

        canonical_username = (
            normalize_username(
                argument
            )
            or
            argument
        )

        success, removed = (
            stop_observing_user(
                canonical_username
            )
        )

        if not success:

            send_telegram_message(
                "❌ Erro ao salvar alteração.",
                chat_id=chat_id
            )

        elif not removed:

            send_telegram_message(
                (
                    f"ℹ️ {canonical_username} "
                    "não estava em observação."
                ),
                chat_id=chat_id
            )

        else:

            send_telegram_message(
                (
                    "⛔ Observação encerrada\n\n"
                    f"👤 {canonical_username}"
                ),
                chat_id=chat_id
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

            response_text = (
                "👁 Nenhuma página está sendo vigiada."
            )

        else:

            response_text = (
                "👁 Páginas vigiadas:\n\n"
                +
                "\n".join(
                    f"• {page}"
                    for page in pages
                )
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )

        return


    # =====================================================
    # /VIGIAR /DESVIGIAR
    # =====================================================

    if command in (
        "/vigiar",
        "/desvigiar"
    ):

        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):

            send_telegram_message(
                (
                    "⚠️ Este comando deve ser "
                    "publicado diretamente no canal."
                ),
                chat_id=chat_id
            )

            return

        if not argument:

            send_telegram_message(
                (
                    f"Uso: {command} "
                    "Nome da página"
                ),
                chat_id=chat_id
            )

            return

        title = normalize_page_title(
            argument
        )

        if not title:

            send_telegram_message(
                "❌ Página não encontrada.",
                chat_id=chat_id
            )

            return

        if command == "/vigiar":

            success, added = add_watched_page(
                title
            )

            if not success:

                send_telegram_message(
                    "❌ Erro ao salvar watchlist.",
                    chat_id=chat_id
                )

            elif not added:

                send_telegram_message(
                    (
                        f"👁 {title} já está "
                        "sendo vigiada."
                    ),
                    chat_id=chat_id
                )

            else:

                send_telegram_message(
                    (
                        f"👁 {title} adicionada "
                        "à vigilância."
                    ),
                    chat_id=chat_id
                )

            return

        success, removed = remove_watched_page(
            title
        )

        if not success:

            send_telegram_message(
                "❌ Erro ao salvar watchlist.",
                chat_id=chat_id
            )

        elif not removed:

            send_telegram_message(
                (
                    f"🙈 {title} não estava "
                    "sendo vigiada."
                ),
                chat_id=chat_id
            )

        else:

            send_telegram_message(
                (
                    f"🙈 {title} removida "
                    "da vigilância."
                ),
                chat_id=chat_id
            )


# =========================================================
# LISTENER TELEGRAM
# =========================================================

def telegram_command_listener():

    offset = None

    print(
        "✅ Listener Telegram iniciado."
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

                params["offset"] = offset

            response = requests.get(
                f"{TELEGRAM_API}/getUpdates",
                params=params,
                timeout=40
            )

            if response.status_code == 409:

                print(
                    "❌ TELEGRAM 409 CONFLICT"
                )

                print(
                    response.text
                )

                time.sleep(30)

                continue

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

                if message:

                    process_telegram_command(
                        message,
                        from_channel=False
                    )

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
                "⚠️ Erro listener Telegram:",
                repr(e)
            )

            time.sleep(5)


# =========================================================
# WATCHDOG
# =========================================================

def eventstream_watchdog():

    global stream_connected
    global current_stream_response

    while True:

        time.sleep(15)

        cleanup_expired_observations()

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

                if elapsed > STREAM_STALL_SECONDS:

                    response_to_close = (
                        current_stream_response
                    )

                    current_stream_response = None
                    stream_connected = False

        if response_to_close:

            try:

                response_to_close.close()

            except Exception:

                pass


# =========================================================
# DIFF
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

    diff_html = (
        response.json()
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
                "Content-Type": "application/json"
            },
            json={
                "rev_id": revision_id,
                "lang": "pt"
            },
            timeout=30
        )

        if response.status_code == 429:

            return None

        response.raise_for_status()

        probability = (
            response.json()
            .get("output", {})
            .get("probabilities", {})
            .get("true")
        )

        if probability is None:

            return None

        return float(
            probability
        )

    except Exception as e:

        print(
            "⚠️ Erro Lift Wing:",
            repr(e)
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

    signals = [
        profanity_score(
            added
        ),
        repetition_score(
            added
        ),
        destructive_score(
            added,
            removed
        ),
        nonsense_score(
            added
        )
    ]

    score = revert_risk

    if max(signals) >= 0.75:

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

    elif revert_risk >= 0.45:

        reasons.append(
            "risco de reversão elevado"
        )

    if signals[0] >= 0.75:

        reasons.append(
            "linguagem ofensiva"
        )

    if signals[1] >= 0.75:

        reasons.append(
            "repetição anormal"
        )

    if signals[2] >= 0.75:

        reasons.append(
            "remoção potencialmente destrutiva"
        )

    if signals[3] >= 0.75:

        reasons.append(
            "texto possivelmente sem sentido"
        )

    if not reasons:

        reasons.append(
            "edição suspeita"
        )

    return {
        "score": score,
        "revert_risk": revert_risk,
        "reason": ", ".join(
            reasons
        )
    }


# =========================================================
# MENSAGENS DE EDIÇÃO
# =========================================================

def build_diff_url(change):

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

    return (
        "https://pt.wikipedia.org/w/index.php"
        f"?diff={new_revision}"
        f"&oldid={old_revision}"
    )


def format_observed_message(
    change,
    observation
):

    return (
        "👁 Edição de conta observada\n\n"

        f"👤 {change.get('user', 'Desconhecido')}\n"

        f"📝 {change.get('title', 'Sem título')}\n"

        f"💬 "
        f"{change.get('comment') or 'Sem resumo'}\n\n"

        f"📌 Motivo: "
        f"{observation['reason']}\n\n"

        f"🔗 {build_diff_url(change)}"
    )


def format_watched_message(change):

    return (
        "👁 Edição em página vigiada\n\n"

        f"📝 {change.get('title', 'Sem título')}\n"

        f"👤 {change.get('user', 'Desconhecido')}\n"

        f"💬 "
        f"{change.get('comment') or 'Sem resumo'}\n\n"

        f"🔗 {build_diff_url(change)}"
    )


def format_message(
    change,
    result
):

    final_score = round(
        result["score"]
        *
        100
    )

    revert_score = round(
        result["revert_risk"]
        *
        100
    )

    return (
        f"🚨 Possível vandalismo — "
        f"{final_score}%\n\n"

        f"📝 {change.get('title', 'Sem título')}\n"

        f"👤 {change.get('user', 'Desconhecido')}\n"

        f"💬 "
        f"{change.get('comment') or 'Sem resumo'}\n\n"

        f"🤖 Risco de reversão Wikimedia: "
        f"{revert_score}%\n"

        f"⚠️ Sinais: "
        f"{result['reason']}\n\n"

        f"🔗 {build_diff_url(change)}"
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


            # =============================================
            # 1. CONTA OBSERVADA
            # =============================================

            observation = get_observation(
                username
            )

            if observation:

                telegram_queue.put(
                    {
                        "message": (
                            format_observed_message(
                                change,
                                observation
                            )
                        ),
                        "title": (
                            f"Conta observada: {username}"
                        )
                    }
                )

                print(
                    "🔎 Edição de conta observada:",
                    username,
                    "|",
                    title
                )

                continue


            # =============================================
            # 2. PÁGINA VIGIADA
            # =============================================

            if is_watched_page(
                title
            ):

                if is_wikipedia_admin(
                    username
                ):

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

                continue


            # =============================================
            # 3. FILTRO NORMAL
            # =============================================

            if not should_evaluate_user(
                username
            ):

                continue


            # =============================================
            # 4. REVERT RISK
            # =============================================

            revert_risk = get_revert_risk(
                new_revision
            )

            if revert_risk is None:

                continue

            print(
                "🤖 Revert Risk:",
                f"{revert_risk:.1%}",
                "|",
                title
            )

            if (
                revert_risk
                <
                REVERT_RISK_THRESHOLD
            ):

                continue


            # =============================================
            # 5. DIFF E HEURÍSTICAS
            # =============================================

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
                "📊 Score final:",
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

        except Exception as e:

            print(
                "❌ Erro análise:",
                repr(e)
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
                    change.get("wiki")
                    !=
                    "ptwiki"
                ):

                    continue

                if (
                    change.get("type")
                    !=
                    "edit"
                ):

                    continue

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

        except Exception as e:

            print(
                "⚠️ EventStreams desconectado:",
                repr(e)
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
# MAIN
# =========================================================

def main():

    print(
        "========================================"
    )

    print(
        "Detector de vandalismo ptwiki"
    )

    print(
        "Versão 1.6"
    )

    print(
        "========================================"
    )

    remove_telegram_webhook()

    time.sleep(1)

    check_telegram_webhook()

    storage_ok = ensure_storage()

    if not storage_ok:

        print(
            "⚠️ Persistência pode não funcionar."
        )

    load_watchlist()
    load_observed_users()

    cleanup_expired_observations()

    print(
        "🔎 Revert Risk mínimo:",
        f"{REVERT_RISK_THRESHOLD:.0%}"
    )

    print(
        "🚨 Publicação:",
        f"{VANDALISM_THRESHOLD:.0%}"
    )

    print(
        "👶 Idade máxima:",
        MAX_ACCOUNT_AGE_DAYS,
        "dias"
    )

    print(
        "✏️ Máximo de edições:",
        MAX_USER_EDITS
    )

    print(
        "⏳ Observação de conta:",
        "2 horas"
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
        target=eventstream_watchdog,
        daemon=True
    ).start()

    threading.Thread(
        target=telegram_command_listener,
        daemon=True
    ).start()

    wikimedia_loop()


if __name__ == "__main__":

    main()
