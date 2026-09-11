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

BOT_VERSION = "1.10"

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHANNEL = os.environ.get("TELEGRAM_CHANNEL_ID", "@ptwiki")

if not TELEGRAM_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN não configurado.")

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"

WIKIMEDIA_STREAM = "https://stream.wikimedia.org/v2/stream/recentchange"
WIKIPEDIA_API = "https://pt.wikipedia.org/w/api.php"
REVERT_RISK_API = (
    "https://api.wikimedia.org/service/lw/inference/v1/"
    "models/revertrisk-multilingual:predict"
)

HEADERS = {
    "User-Agent": (
        f"PtWikiVandalismTelegramBot/{BOT_VERSION} "
        "(https://t.me/ptwiki)"
    )
}


# =========================================================
# LIMITES / INTERVALOS
# =========================================================

REVERT_RISK_THRESHOLD = 0.25
VANDALISM_THRESHOLD = 0.45
MAX_DIFF_CHARS = 6000

MAX_ACCOUNT_AGE_DAYS = 60
MAX_USER_EDITS = 50
USER_CACHE_SECONDS = 3600

STREAM_STALL_SECONDS = 120

OBSERVATION_DURATION_SECONDS = 6 * 60 * 60
IGNORE_DURATION_SECONDS = 6 * 60 * 60

ABUSE_FILTER_POLL_SECONDS = 20
ABUSE_FILTER_BATCH_LIMIT = 500

POSTED_EDIT_CHECK_SECONDS = 90
POSTED_EDIT_TRACK_SECONDS = 48 * 60 * 60


# =========================================================
# ARQUIVOS PERSISTENTES
# =========================================================

WATCHLIST_FILE = os.environ.get(
    "WATCHLIST_FILE",
    "/data/watchlist.json"
)

OBSERVED_USERS_FILE = os.environ.get(
    "OBSERVED_USERS_FILE",
    "/data/observed_users.json"
)

IGNORED_USERS_FILE = os.environ.get(
    "IGNORED_USERS_FILE",
    "/data/ignored_users.json"
)

BOT_VERSION_FILE = os.environ.get(
    "BOT_VERSION_FILE",
    "/data/bot_version.json"
)

ABUSE_FILTERS_FILE = os.environ.get(
    "ABUSE_FILTERS_FILE",
    "/data/abuse_filters.json"
)

ABUSE_FILTER_STATE_FILE = os.environ.get(
    "ABUSE_FILTER_STATE_FILE",
    "/data/abuse_filter_state.json"
)

POSTED_EDITS_FILE = os.environ.get(
    "POSTED_EDITS_FILE",
    "/data/posted_edits.json"
)


# =========================================================
# ESTADO EM MEMÓRIA
# =========================================================

watched_pages = set()
watchlist_lock = threading.Lock()

observed_users = {}
observed_users_lock = threading.Lock()

ignored_users = {}
ignored_users_lock = threading.Lock()

# dict:
# "123" -> {"filter_id": "123", "added_at": 1234567890.0, ...}
watched_abuse_filters = {}
abuse_filters_lock = threading.Lock()

# maior ID de ocorrência do AbuseLog já percorrida
abuse_filter_state = {"last_log_id": 0}
abuse_state_lock = threading.Lock()

# revisão -> metadados da mensagem do Telegram
posted_edits = {}
posted_edits_lock = threading.Lock()

user_cache = {}

analysis_queue = queue.Queue()
block_queue = queue.Queue()
telegram_queue = queue.Queue()

stream_lock = threading.Lock()
stream_connected = False
last_stream_event_at = None
last_ptwiki_edit_at = None
current_stream_response = None

patrol_visibility_supported = None
patrol_visibility_warning_printed = False


# =========================================================
# UTILIDADES DE ARQUIVO
# =========================================================

def atomic_write_json(path, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    temp_file = path + ".tmp"

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=2
        )
        file.flush()
        os.fsync(file.fileno())

    os.replace(temp_file, path)


def load_json(path, default):
    try:
        if not os.path.exists(path):
            return default

        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as e:
        print("⚠️ Erro ao ler", path, ":", repr(e))
        return default


def ensure_storage():
    files = [
        WATCHLIST_FILE,
        OBSERVED_USERS_FILE,
        IGNORED_USERS_FILE,
        BOT_VERSION_FILE,
        ABUSE_FILTERS_FILE,
        ABUSE_FILTER_STATE_FILE,
        POSTED_EDITS_FILE,
    ]

    directories = {
        os.path.dirname(path)
        for path in files
        if os.path.dirname(path)
    }

    try:
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

            test_file = os.path.join(
                directory,
                ".bot_write_test"
            )

            with open(test_file, "w", encoding="utf-8") as file:
                file.write("ok")
                file.flush()
                os.fsync(file.fileno())

            os.remove(test_file)

        print("✅ Armazenamento gravável.")
        print("📁 Watchlist:", WATCHLIST_FILE)
        print("📁 Contas observadas:", OBSERVED_USERS_FILE)
        print("📁 Contas ignoradas:", IGNORED_USERS_FILE)
        print("📁 Filtros de abuso:", ABUSE_FILTERS_FILE)
        print("📁 Estado dos filtros:", ABUSE_FILTER_STATE_FILE)
        print("📁 Edições publicadas:", POSTED_EDITS_FILE)
        print("📁 Versão do bot:", BOT_VERSION_FILE)

        return True

    except Exception as e:
        print("❌ Erro no armazenamento:", repr(e))
        return False


# =========================================================
# UTILIDADES GERAIS
# =========================================================

def format_age(timestamp):
    if timestamp is None:
        return "nunca"

    seconds = int(max(0, time.time() - timestamp))

    if seconds < 60:
        return f"há {seconds}s"

    minutes = seconds // 60

    if minutes < 60:
        return f"há {minutes} min"

    hours = minutes // 60

    if hours < 24:
        return f"há {hours}h {minutes % 60}min"

    return f"há {hours // 24} dias"


def format_remaining(seconds):
    seconds = max(0, int(seconds))
    minutes = seconds // 60
    hours = minutes // 60

    if hours:
        return f"{hours}h {minutes % 60}min"

    return f"{minutes}min"


def parse_mw_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).timestamp()
    except Exception:
        return None


def is_ip_address(username):
    if not username:
        return False

    try:
        ipaddress.ip_address(username)
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


def is_target_channel(chat):
    if not chat:
        return False

    chat_id = chat.get("id")
    username = chat.get("username", "")

    if TELEGRAM_CHANNEL.startswith("@"):
        return (
            username.lower()
            ==
            TELEGRAM_CHANNEL[1:].lower()
        )

    return str(chat_id) == str(TELEGRAM_CHANNEL)


# =========================================================
# TELEGRAM
# =========================================================

def remove_telegram_webhook():
    try:
        response = requests.post(
            f"{TELEGRAM_API}/deleteWebhook",
            json={"drop_pending_updates": False},
            timeout=20
        )
        response.raise_for_status()

        if response.json().get("ok"):
            print("✅ Webhook Telegram removido/desativado.")

    except Exception as e:
        print("⚠️ Erro ao remover webhook Telegram:", repr(e))


def check_telegram_webhook():
    try:
        response = requests.get(
            f"{TELEGRAM_API}/getWebhookInfo",
            timeout=20
        )
        response.raise_for_status()

        webhook = (
            response.json()
            .get("result", {})
            .get("url")
        )

        if webhook:
            print("⚠️ Webhook ainda configurado.")
        else:
            print("✅ Webhook atual: nenhum")

    except Exception as e:
        print("⚠️ Erro ao verificar webhook:", repr(e))


def send_telegram_message(text, chat_id=None, parse_mode=None):
    """
    Retorna o objeto Message do Telegram quando o envio é confirmado.
    Retorna None em erro permanente.
    """

    if chat_id is None:
        chat_id = TELEGRAM_CHANNEL

    while True:
        try:
            payload = {
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }

            if parse_mode:
                payload["parse_mode"] = parse_mode

            response = requests.post(
                f"{TELEGRAM_API}/sendMessage",
                json=payload,
                timeout=30
            )

            if response.status_code == 429:
                try:
                    retry_after = (
                        response.json()
                        .get("parameters", {})
                        .get("retry_after", 2)
                    )
                except Exception:
                    retry_after = 2

                time.sleep(retry_after)
                continue

            if response.status_code in (400, 401, 403):
                print(
                    "❌ Telegram rejeitou mensagem:",
                    response.status_code,
                    response.text
                )
                return None

            if response.status_code >= 500:
                time.sleep(5)
                continue

            response.raise_for_status()

            data = response.json()

            if not data.get("ok"):
                print("❌ Telegram retornou erro:", data)
                return None

            return data.get("result")

        except requests.RequestException as e:
            print("⚠️ Erro de rede Telegram:", repr(e))
            time.sleep(5)


def edit_telegram_message(message_id, text, parse_mode=None):
    while True:
        try:
            payload = {
                "chat_id": TELEGRAM_CHANNEL,
                "message_id": int(message_id),
                "text": text,
                "disable_web_page_preview": True,
            }

            if parse_mode:
                payload["parse_mode"] = parse_mode

            response = requests.post(
                f"{TELEGRAM_API}/editMessageText",
                json=payload,
                timeout=30
            )

            if response.status_code == 429:
                try:
                    retry_after = (
                        response.json()
                        .get("parameters", {})
                        .get("retry_after", 2)
                    )
                except Exception:
                    retry_after = 2

                time.sleep(retry_after)
                continue

            # "message is not modified" não é falha relevante.
            if (
                response.status_code == 400
                and
                "message is not modified" in response.text.lower()
            ):
                return True

            if response.status_code in (400, 401, 403):
                print(
                    "⚠️ Telegram não permitiu editar mensagem:",
                    message_id,
                    response.status_code,
                    response.text
                )
                return False

            if response.status_code >= 500:
                time.sleep(5)
                continue

            response.raise_for_status()
            return bool(response.json().get("ok"))

        except requests.RequestException as e:
            print("⚠️ Erro ao editar mensagem Telegram:", repr(e))
            time.sleep(5)


# =========================================================
# VERSIONAMENTO
# =========================================================

def load_saved_bot_version():
    data = load_json(BOT_VERSION_FILE, {})

    if isinstance(data, dict):
        version = data.get("version")
        if version:
            return str(version)

    return None


def save_bot_version(version):
    atomic_write_json(
        BOT_VERSION_FILE,
        {
            "version": version,
            "updated_at": datetime.now(
                timezone.utc
            ).isoformat()
        }
    )

    print("💾 Versão registrada:", version)


def announce_new_version_if_needed():
    saved_version = load_saved_bot_version()

    print(
        "📦 Versão registrada anteriormente:",
        saved_version or "nenhuma"
    )
    print("🤖 Versão atual:", BOT_VERSION)

    if saved_version == BOT_VERSION:
        print(
            "ℹ️ Versão já anunciada. "
            "Nenhuma mensagem enviada."
        )
        return

    message = (
        "✅ Bot atualizado com sucesso\n\n"
        f"🤖 Versão {BOT_VERSION}"
    )

    sent = send_telegram_message(message)

    if not sent:
        print("⚠️ Não foi possível anunciar a nova versão.")
        return

    try:
        save_bot_version(BOT_VERSION)
        print("✅ Nova versão anunciada e registrada.")
    except Exception as e:
        print(
            "⚠️ Mensagem enviada, mas houve erro "
            "ao registrar a versão:",
            repr(e)
        )


# =========================================================
# WATCHLIST
# =========================================================

def save_watchlist_snapshot(snapshot):
    atomic_write_json(
        WATCHLIST_FILE,
        sorted(snapshot)
    )

    print(
        "💾 Watchlist salva:",
        len(snapshot),
        "páginas"
    )


def load_watchlist():
    global watched_pages

    data = load_json(WATCHLIST_FILE, [])

    if not isinstance(data, list):
        print("❌ Formato inválido da watchlist.")
        return

    with watchlist_lock:
        watched_pages = {
            str(item)
            for item in data
        }

    print("✅ Watchlist carregada:", len(watched_pages))


def add_watched_page(title):
    with watchlist_lock:
        if title in watched_pages:
            return True, False

        snapshot = set(watched_pages)
        snapshot.add(title)

    try:
        save_watchlist_snapshot(snapshot)
    except Exception as e:
        print("❌ Erro ao salvar watchlist:", repr(e))
        return False, False

    with watchlist_lock:
        watched_pages.add(title)

    return True, True


def remove_watched_page(title):
    with watchlist_lock:
        if title not in watched_pages:
            return True, False

        snapshot = set(watched_pages)
        snapshot.remove(title)

    try:
        save_watchlist_snapshot(snapshot)
    except Exception as e:
        print("❌ Erro ao salvar watchlist:", repr(e))
        return False, False

    with watchlist_lock:
        watched_pages.discard(title)

    return True, True


def is_watched_page(title):
    with watchlist_lock:
        return title in watched_pages


# =========================================================
# CONTAS OBSERVADAS
# =========================================================

def save_observed_users():
    with observed_users_lock:
        data = list(observed_users.values())

    atomic_write_json(
        OBSERVED_USERS_FILE,
        data
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
            for key, item in observed_users.items()
            if item.get("expires_at", 0) <= now
        ]

        for key in expired_keys:
            print(
                "⌛ Observação expirada:",
                observed_users[key].get(
                    "username",
                    key
                )
            )
            del observed_users[key]
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

    data = load_json(
        OBSERVED_USERS_FILE,
        []
    )

    if not isinstance(data, list):
        print(
            "❌ Formato inválido de observed_users.json"
        )
        return

    now = time.time()
    loaded = {}

    for item in data:
        if not isinstance(item, dict):
            continue

        username = item.get("username")
        reason = item.get("reason")
        expires_at = item.get("expires_at", 0)

        if (
            not username
            or
            not reason
            or
            expires_at <= now
        ):
            continue

        loaded[username_key(username)] = {
            "username": username,
            "reason": reason,
            "expires_at": expires_at,
        }

    with observed_users_lock:
        observed_users = loaded

    print(
        "✅ Contas observadas carregadas:",
        len(loaded)
    )

    try:
        save_observed_users()
    except Exception:
        pass


def observe_user(username, reason):
    expires_at = (
        time.time()
        +
        OBSERVATION_DURATION_SECONDS
    )

    key = username_key(username)

    with observed_users_lock:
        previous = observed_users.get(key)

        observed_users[key] = {
            "username": username,
            "reason": reason,
            "expires_at": expires_at,
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
            if previous is None:
                observed_users.pop(key, None)
            else:
                observed_users[key] = previous

        return False


def stop_observing_user(username):
    key = username_key(username)

    with observed_users_lock:
        if key not in observed_users:
            return True, False

        backup = observed_users[key]
        del observed_users[key]

    try:
        save_observed_users()
        return True, True

    except Exception as e:
        print(
            "❌ Erro ao salvar remoção:",
            repr(e)
        )

        with observed_users_lock:
            observed_users[key] = backup

        return False, False


def get_observation(username):
    cleanup_expired_observations()

    with observed_users_lock:
        item = observed_users.get(
            username_key(username)
        )

        return dict(item) if item else None


# =========================================================
# CONTAS IGNORADAS TEMPORARIAMENTE
# =========================================================

def save_ignored_users():
    with ignored_users_lock:
        data = list(ignored_users.values())

    atomic_write_json(
        IGNORED_USERS_FILE,
        data
    )

    print(
        "💾 Contas ignoradas salvas:",
        len(data)
    )


def cleanup_expired_ignored_users():
    now = time.time()
    removed = False

    with ignored_users_lock:
        expired_keys = [
            key
            for key, item in ignored_users.items()
            if item.get("expires_at", 0) <= now
        ]

        for key in expired_keys:
            print(
                "⌛ Ignorância temporária expirada:",
                ignored_users[key].get(
                    "username",
                    key
                )
            )
            del ignored_users[key]
            removed = True

    if removed:
        try:
            save_ignored_users()
        except Exception as e:
            print(
                "⚠️ Erro ao salvar expirações "
                "de contas ignoradas:",
                repr(e)
            )


def load_ignored_users():
    global ignored_users

    data = load_json(
        IGNORED_USERS_FILE,
        []
    )

    if not isinstance(data, list):
        print(
            "❌ Formato inválido de ignored_users.json"
        )
        return

    now = time.time()
    loaded = {}

    for item in data:
        if not isinstance(item, dict):
            continue

        username = item.get("username")
        expires_at = item.get("expires_at", 0)

        if (
            not username
            or
            expires_at <= now
        ):
            continue

        loaded[username_key(username)] = {
            "username": username,
            "expires_at": expires_at,
        }

    with ignored_users_lock:
        ignored_users = loaded

    print(
        "✅ Contas ignoradas carregadas:",
        len(loaded)
    )

    try:
        save_ignored_users()
    except Exception:
        pass


def ignore_user(username):
    expires_at = (
        time.time()
        +
        IGNORE_DURATION_SECONDS
    )

    key = username_key(username)

    with ignored_users_lock:
        previous = ignored_users.get(key)

        ignored_users[key] = {
            "username": username,
            "expires_at": expires_at,
        }

    try:
        save_ignored_users()
        return True

    except Exception as e:
        print(
            "❌ Erro ao salvar conta ignorada:",
            repr(e)
        )

        with ignored_users_lock:
            if previous is None:
                ignored_users.pop(key, None)
            else:
                ignored_users[key] = previous

        return False


def stop_ignoring_user(username):
    key = username_key(username)

    with ignored_users_lock:
        if key not in ignored_users:
            return True, False

        backup = ignored_users[key]
        del ignored_users[key]

    try:
        save_ignored_users()
        return True, True

    except Exception as e:
        print(
            "❌ Erro ao salvar remoção "
            "de conta ignorada:",
            repr(e)
        )

        with ignored_users_lock:
            ignored_users[key] = backup

        return False, False


def get_ignored_user(username):
    cleanup_expired_ignored_users()

    with ignored_users_lock:
        item = ignored_users.get(
            username_key(username)
        )

        return dict(item) if item else None


# =========================================================
# FILTROS DE ABUSO
# =========================================================

def normalize_filter_id(value):
    value = str(value).strip().lower()

    if re.fullmatch(r"\d+", value):
        return value

    if re.fullmatch(r"global-\d+", value):
        return value

    return None


def get_abuse_filter_info(filter_id):
    """
    Retorna metadados públicos de filtro local.
    Filtros globais podem não ser consultáveis por este módulo na ptwiki.
    """

    filter_id = normalize_filter_id(filter_id)

    if not filter_id:
        return None

    if filter_id.startswith("global-"):
        return {
            "id": filter_id,
            "description": None,
            "actions": None,
            "global": True,
        }

    try:
        numeric_id = int(filter_id)

        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "abusefilters",
                "abfstartid": numeric_id,
                "abfendid": numeric_id,
                "abfprop": (
                    "id|description|actions|status|private"
                ),
                "abflimit": 1,
            },
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()
        data = response.json()

        if data.get("error"):
            return None

        filters = (
            data
            .get("query", {})
            .get("abusefilters", [])
        )

        if not filters:
            return None

        item = filters[0]

        if str(item.get("id")) != filter_id:
            return None

        return {
            "id": filter_id,
            "description": item.get("description"),
            "actions": item.get("actions"),
            "private": item.get("private"),
            "global": False,
        }

    except Exception as e:
        print(
            "⚠️ Erro ao consultar filtro de abuso",
            filter_id,
            ":",
            repr(e)
        )
        return None


def save_abuse_filters():
    with abuse_filters_lock:
        data = sorted(
            watched_abuse_filters.values(),
            key=lambda x: x["filter_id"]
        )

    atomic_write_json(
        ABUSE_FILTERS_FILE,
        data
    )

    print(
        "💾 Filtros de abuso salvos:",
        len(data)
    )


def load_abuse_filters():
    global watched_abuse_filters

    data = load_json(
        ABUSE_FILTERS_FILE,
        []
    )

    loaded = {}

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                filter_id = normalize_filter_id(item)

                if filter_id:
                    loaded[filter_id] = {
                        "filter_id": filter_id,
                        "added_at": 0,
                        "description": None,
                    }

            elif isinstance(item, dict):
                filter_id = normalize_filter_id(
                    item.get("filter_id", "")
                )

                if not filter_id:
                    continue

                loaded[filter_id] = {
                    "filter_id": filter_id,
                    "added_at": float(
                        item.get("added_at", 0)
                    ),
                    "description": item.get(
                        "description"
                    ),
                }

    with abuse_filters_lock:
        watched_abuse_filters = loaded

    print(
        "✅ Filtros de abuso carregados:",
        len(loaded)
    )


def add_abuse_filter(filter_id):
    filter_id = normalize_filter_id(filter_id)

    if not filter_id:
        return False, False, None

    with abuse_filters_lock:
        if filter_id in watched_abuse_filters:
            return True, False, dict(
                watched_abuse_filters[filter_id]
            )

    info = get_abuse_filter_info(filter_id)

    # Filtro global é aceito mesmo se não conseguirmos ler a descrição.
    if info is None and not filter_id.startswith("global-"):
        return False, False, None

    entry = {
        "filter_id": filter_id,
        "added_at": time.time(),
        "description": (
            info.get("description")
            if info
            else None
        ),
    }

    with abuse_filters_lock:
        watched_abuse_filters[filter_id] = entry

    try:
        save_abuse_filters()
    except Exception as e:
        print(
            "❌ Erro ao salvar filtro de abuso:",
            repr(e)
        )

        with abuse_filters_lock:
            watched_abuse_filters.pop(
                filter_id,
                None
            )

        return False, False, None

    return True, True, entry


def remove_abuse_filter(filter_id):
    filter_id = normalize_filter_id(filter_id)

    if not filter_id:
        return True, False

    with abuse_filters_lock:
        if filter_id not in watched_abuse_filters:
            return True, False

        backup = watched_abuse_filters[filter_id]
        del watched_abuse_filters[filter_id]

    try:
        save_abuse_filters()
        return True, True

    except Exception as e:
        print(
            "❌ Erro ao salvar remoção de filtro:",
            repr(e)
        )

        with abuse_filters_lock:
            watched_abuse_filters[filter_id] = backup

        return False, False


def load_abuse_filter_state():
    global abuse_filter_state

    data = load_json(
        ABUSE_FILTER_STATE_FILE,
        {"last_log_id": 0}
    )

    if not isinstance(data, dict):
        data = {"last_log_id": 0}

    try:
        last_log_id = int(
            data.get("last_log_id", 0)
        )
    except Exception:
        last_log_id = 0

    with abuse_state_lock:
        abuse_filter_state = {
            "last_log_id": max(0, last_log_id)
        }

    print(
        "✅ Último AbuseLog processado:",
        last_log_id
    )


def save_abuse_filter_state(last_log_id):
    with abuse_state_lock:
        abuse_filter_state[
            "last_log_id"
        ] = int(last_log_id)

        data = dict(
            abuse_filter_state
        )

    atomic_write_json(
        ABUSE_FILTER_STATE_FILE,
        data
    )


def extract_abuse_filter_id(entry):
    value = entry.get("filter")

    if isinstance(value, dict):
        value = (
            value.get("id")
            or
            value.get("name")
        )

    if value is None:
        return None

    return normalize_filter_id(value)


def abuse_filter_log_url(log_id):
    return (
        "https://pt.wikipedia.org/wiki/"
        f"Special:AbuseLog/{quote(str(log_id), safe='')}"
    )


def abuse_filter_page_url(filter_id):
    if str(filter_id).startswith("global-"):
        numeric = str(filter_id).split("-", 1)[1]
        return (
            "https://meta.wikimedia.org/wiki/"
            f"Special:AbuseFilter/{quote(numeric, safe='')}"
        )

    return (
        "https://pt.wikipedia.org/wiki/"
        f"Special:AbuseFilter/{quote(str(filter_id), safe='')}"
    )


def format_abuse_filter_message(entry, watched_info):
    log_id = entry.get("id") or entry.get("logid")
    filter_id = extract_abuse_filter_id(entry) or "?"

    description = (
        watched_info.get("description")
        if watched_info
        else None
    )

    user = entry.get("user") or "Desconhecido"
    title = entry.get("title") or "Sem título"
    action = entry.get("action") or "não informada"
    result = entry.get("result") or "registro"

    filter_url = abuse_filter_page_url(filter_id)
    log_url = abuse_filter_log_url(log_id)

    header = (
        f'🛡 <a href="{html.escape(filter_url)}">'
        f"Filtro de abusos {html.escape(str(filter_id))}</a> "
        "acionado"
    )

    if description:
        description_line = (
            "\n📋 "
            +
            html.escape(str(description))
        )
    else:
        description_line = ""

    return (
        f"{header}"
        f"{description_line}\n\n"
        f"👤 Usuário: {html.escape(str(user))}\n"
        f"📝 Página: {html.escape(str(title))}\n"
        f"⚙️ Ação: {html.escape(str(action))}\n"
        f"🚨 Resultado: {html.escape(str(result))}\n\n"
        f'🔗 <a href="{html.escape(log_url)}">'
        "Registro do filtro</a>"
    )


def fetch_abuse_log_entries(filter_ids):
    all_entries = []

    # A API aceita no máximo 50 filtros de uma vez para clientes comuns.
    for start in range(0, len(filter_ids), 50):
        chunk = filter_ids[start:start + 50]

        try:
            response = requests.get(
                WIKIPEDIA_API,
                params={
                    "action": "query",
                    "format": "json",
                    "formatversion": 2,
                    "list": "abuselog",
                    "aflfilter": "|".join(chunk),
                    "afllimit": ABUSE_FILTER_BATCH_LIMIT,
                    "afldir": "older",
                    "aflprop": (
                        "ids|filter|user|title|action|"
                        "result|timestamp|hidden|revid"
                    ),
                },
                headers=HEADERS,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            if data.get("error"):
                print(
                    "⚠️ AbuseLog API:",
                    data["error"]
                )
                continue

            entries = (
                data
                .get("query", {})
                .get("abuselog", [])
            )

            all_entries.extend(entries)

        except Exception as e:
            print(
                "⚠️ Erro ao consultar AbuseLog:",
                repr(e)
            )

    return all_entries


def abuse_filter_monitor():
    print("✅ Monitor de filtros de abuso iniciado.")

    while True:
        try:
            with abuse_filters_lock:
                filters_snapshot = {
                    key: dict(value)
                    for key, value
                    in watched_abuse_filters.items()
                }

            if not filters_snapshot:
                time.sleep(ABUSE_FILTER_POLL_SECONDS)
                continue

            entries = fetch_abuse_log_entries(
                list(filters_snapshot.keys())
            )

            if not entries:
                time.sleep(ABUSE_FILTER_POLL_SECONDS)
                continue

            def entry_id(item):
                try:
                    return int(
                        item.get("id")
                        or
                        item.get("logid")
                        or
                        0
                    )
                except Exception:
                    return 0

            entries.sort(key=entry_id)

            with abuse_state_lock:
                last_log_id = int(
                    abuse_filter_state.get(
                        "last_log_id",
                        0
                    )
                )

            max_seen = last_log_id

            for entry in entries:
                log_id = entry_id(entry)

                if log_id <= 0:
                    continue

                max_seen = max(
                    max_seen,
                    log_id
                )

                if log_id <= last_log_id:
                    continue

                filter_id = extract_abuse_filter_id(
                    entry
                )

                if not filter_id:
                    continue

                watched_info = filters_snapshot.get(
                    filter_id
                )

                if not watched_info:
                    continue

                # Evita publicar ocorrências anteriores ao momento
                # em que o filtro foi adicionado à vigilância.
                event_ts = parse_mw_timestamp(
                    entry.get("timestamp")
                )

                added_at = float(
                    watched_info.get(
                        "added_at",
                        0
                    )
                )

                if (
                    event_ts is not None
                    and
                    added_at
                    and
                    event_ts < added_at - 2
                ):
                    continue

                message = format_abuse_filter_message(
                    entry,
                    watched_info
                )

                telegram_queue.put(
                    {
                        "message": message,
                        "title": (
                            f"Filtro de abuso {filter_id}"
                        ),
                        "parse_mode": "HTML",
                    }
                )

                print(
                    "🛡 Filtro de abuso acionado:",
                    filter_id,
                    "| log:",
                    log_id
                )

            if max_seen > last_log_id:
                try:
                    save_abuse_filter_state(
                        max_seen
                    )
                except Exception as e:
                    print(
                        "⚠️ Erro ao salvar estado do AbuseLog:",
                        repr(e)
                    )

        except Exception as e:
            print(
                "❌ Erro no monitor de filtros de abuso:",
                repr(e)
            )

        time.sleep(ABUSE_FILTER_POLL_SECONDS)


# =========================================================
# EDIÇÕES PUBLICADAS / STATUS POSTERIOR
# =========================================================

def save_posted_edits():
    with posted_edits_lock:
        data = list(
            posted_edits.values()
        )

    atomic_write_json(
        POSTED_EDITS_FILE,
        data
    )


def cleanup_posted_edits(save=True):
    now = time.time()
    removed = False

    with posted_edits_lock:
        expired = [
            key
            for key, item in posted_edits.items()
            if now - float(
                item.get("posted_at", 0)
            ) > POSTED_EDIT_TRACK_SECONDS
        ]

        for key in expired:
            del posted_edits[key]
            removed = True

    if removed and save:
        try:
            save_posted_edits()
        except Exception as e:
            print(
                "⚠️ Erro ao limpar posted_edits:",
                repr(e)
            )


def load_posted_edits():
    global posted_edits

    data = load_json(
        POSTED_EDITS_FILE,
        []
    )

    loaded = {}
    now = time.time()

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue

            try:
                revision_id = int(
                    item.get("revision_id")
                )
                message_id = int(
                    item.get("message_id")
                )
                posted_at = float(
                    item.get("posted_at")
                )
            except Exception:
                continue

            if (
                now - posted_at
                >
                POSTED_EDIT_TRACK_SECONDS
            ):
                continue

            if not item.get("base_message"):
                continue

            loaded[str(revision_id)] = {
                **item,
                "revision_id": revision_id,
                "message_id": message_id,
                "posted_at": posted_at,
            }

    with posted_edits_lock:
        posted_edits = loaded

    print(
        "✅ Edições publicadas carregadas:",
        len(loaded)
    )

    try:
        save_posted_edits()
    except Exception:
        pass


def register_posted_edit(item, telegram_message):
    try:
        revision_id = int(
            item.get("revision_id")
        )

        message_id = int(
            telegram_message.get("message_id")
        )

    except Exception:
        return

    record = {
        "revision_id": revision_id,
        "rcid": item.get("rcid"),
        "title": item.get("page_title"),
        "message_id": message_id,
        "base_message": item.get("message", ""),
        "parse_mode": item.get("parse_mode"),
        "posted_at": time.time(),
        "status": None,
    }

    with posted_edits_lock:
        posted_edits[
            str(revision_id)
        ] = record

    try:
        save_posted_edits()
        print(
            "💾 Revisão registrada para acompanhamento:",
            revision_id,
            "→ Telegram",
            message_id
        )

    except Exception as e:
        print(
            "⚠️ Erro ao persistir revisão publicada:",
            repr(e)
        )


def get_revision_tags(revision_id):
    try:
        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "prop": "revisions",
                "revids": int(revision_id),
                "rvprop": "ids|tags",
            },
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()
        data = response.json()

        if data.get("error"):
            return set()

        pages = (
            data
            .get("query", {})
            .get("pages", [])
        )

        for page in pages:
            revisions = page.get(
                "revisions",
                []
            )

            for revision in revisions:
                if (
                    int(
                        revision.get(
                            "revid",
                            0
                        )
                    )
                    ==
                    int(revision_id)
                ):
                    return set(
                        revision.get(
                            "tags",
                            []
                        )
                    )

    except Exception as e:
        print(
            "⚠️ Erro ao consultar tags da revisão",
            revision_id,
            ":",
            repr(e)
        )

    return set()


def check_revision_patrolled(title, revision_id):
    """
    Retorna:
      True  -> patrulhada
      False -> encontrada e ainda não patrulhada
      None  -> não foi possível determinar

    A propriedade 'patrolled' da API RecentChanges pode exigir
    o direito patrol/patrolmarks. Se a ptwiki não a expuser à
    sessão anônima usada pelo bot, a função degrada sem interromper
    o restante do monitor.
    """

    global patrol_visibility_supported
    global patrol_visibility_warning_printed

    if patrol_visibility_supported is False:
        return None

    try:
        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "recentchanges",
                "rctitle": title,
                "rctype": "edit|new",
                "rcprop": "ids|patrolled|timestamp",
                "rclimit": 500,
            },
            headers=HEADERS,
            timeout=25
        )

        response.raise_for_status()
        data = response.json()

        error = data.get("error")

        if error:
            code = error.get("code", "")

            if code == "rcpermissiondenied":
                patrol_visibility_supported = False

                if not patrol_visibility_warning_printed:
                    patrol_visibility_warning_printed = True
                    print(
                        "⚠️ A API não permite consultar a marca "
                        "de patrulhamento sem autenticação Wikimedia. "
                        "Reversões continuarão sendo acompanhadas."
                    )

                return None

            return None

        patrol_visibility_supported = True

        changes = (
            data
            .get("query", {})
            .get("recentchanges", [])
        )

        for change in changes:
            if (
                int(
                    change.get(
                        "revid",
                        0
                    )
                )
                ==
                int(revision_id)
            ):
                # Quando solicitada, a API inclui a chave
                # "patrolled" nas mudanças patrulhadas.
                return (
                    "patrolled"
                    in change
                    and
                    change.get("patrolled") is not False
                )

        return None

    except Exception as e:
        print(
            "⚠️ Erro ao consultar patrulhamento:",
            revision_id,
            repr(e)
        )
        return None


def message_with_status(record, status):
    base = record.get(
        "base_message",
        ""
    ).rstrip()

    if status == "reverted":
        return (
            base
            +
            "\n\n↩️ Situação: revertida"
        )

    if status == "patrolled":
        return (
            base
            +
            "\n\n✅ Situação: patrulhada"
        )

    return base


def posted_edit_status_monitor():
    print(
        "✅ Monitor de reversões/patrulhamento iniciado."
    )

    while True:
        time.sleep(POSTED_EDIT_CHECK_SECONDS)

        cleanup_posted_edits()

        with posted_edits_lock:
            snapshot = [
                dict(item)
                for item
                in posted_edits.values()
            ]

        changed_any = False

        for record in snapshot:
            revision_id = record["revision_id"]
            current_status = record.get("status")

            # Uma vez revertida, o estado final desejado pelo usuário
            # é "revertida", mesmo que também seja patrulhada.
            if current_status == "reverted":
                continue

            tags = get_revision_tags(
                revision_id
            )

            if "mw-reverted" in tags:
                new_status = "reverted"

            else:
                # Se já está marcada como patrulhada, continuamos
                # verificando somente se posteriormente foi revertida.
                if current_status == "patrolled":
                    continue

                new_status = None

                title = record.get("title")

                if title:
                    patrolled = check_revision_patrolled(
                        title,
                        revision_id
                    )

                    if patrolled is True:
                        new_status = "patrolled"

            if (
                new_status
                and
                new_status != current_status
            ):
                new_text = message_with_status(
                    record,
                    new_status
                )

                success = edit_telegram_message(
                    record["message_id"],
                    new_text,
                    parse_mode=record.get(
                        "parse_mode"
                    )
                )

                if success:
                    with posted_edits_lock:
                        live = posted_edits.get(
                            str(revision_id)
                        )

                        if live:
                            live["status"] = new_status

                    changed_any = True

                    print(
                        "✏️ Mensagem atualizada:",
                        revision_id,
                        "→",
                        new_status
                    )

                time.sleep(1)

        if changed_any:
            try:
                save_posted_edits()
            except Exception as e:
                print(
                    "⚠️ Erro ao salvar status de mensagens:",
                    repr(e)
                )


# =========================================================
# TELEGRAM SENDER
# =========================================================

def telegram_sender():
    while True:
        item = telegram_queue.get()

        try:
            result = send_telegram_message(
                item["message"],
                parse_mode=item.get(
                    "parse_mode"
                )
            )

            if result:
                print(
                    "✅ Telegram confirmou envio:",
                    item["title"]
                )

                if item.get("track_revision"):
                    register_posted_edit(
                        item,
                        result
                    )

        except Exception as e:
            print("❌ Erro sender:", repr(e))

        finally:
            telegram_queue.task_done()

        time.sleep(1)


# =========================================================
# NORMALIZAÇÃO DE PÁGINA / USUÁRIOS
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
                "titles": title,
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

        return page.get("title")

    except Exception as e:
        print(
            "⚠️ Erro ao normalizar página:",
            repr(e)
        )
        return None


def get_user_info(username, use_cache=True):
    now = time.time()

    if use_cache:
        cached = user_cache.get(username)

        if (
            cached
            and
            now - cached.get("cached_at", 0)
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
                ),
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
            "name": user.get("name", username),
            "editcount": user.get("editcount", 0),
            "registration": user.get("registration"),
            "groups": user.get("groups", []),
            "blockid": user.get("blockid"),
            "cached_at": now,
        }

        user_cache[username] = result
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

    return info.get("name")


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
                "letitle": f"Usuário:{username}",
                "lelimit": 1,
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

        return bool(events)

    except Exception:
        return False


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
    "ipblock-exempt": "isento de bloqueio de IP",
}


def format_groups(groups):
    if not groups:
        return "nenhum grupo especial"

    formatted = []

    for group in groups:
        name = GROUP_NAMES.get(group, group)

        if name not in formatted:
            formatted.append(name)

    return ", ".join(formatted)


def is_wikipedia_admin(username):
    if is_ip_address(username):
        return False

    info = get_user_info(username)

    if info is None:
        # Fail-open, como na versão anterior:
        # não perder alertas de páginas vigiadas.
        return False

    return "sysop" in info.get("groups", [])


def should_evaluate_user(username):
    if not username:
        return True

    if is_ip_address(username):
        return True

    info = get_user_info(username)

    if info is None:
        return True

    if info.get("editcount", 0) > MAX_USER_EDITS:
        return False

    registration = info.get("registration")

    if registration:
        try:
            created = datetime.fromisoformat(
                registration.replace(
                    "Z",
                    "+00:00"
                )
            )

            age_days = (
                datetime.now(timezone.utc)
                -
                created
            ).total_seconds() / 86400

            if age_days > MAX_ACCOUNT_AGE_DAYS:
                return False

        except Exception:
            pass

    return True


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

    username = info.get("name", username)
    editcount = info.get("editcount", 0)
    registration = info.get("registration")

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
                    datetime.now(timezone.utc)
                    -
                    created
                ).total_seconds()
                /
                86400
            )

            creation_text = f"{age_days} dias"

        except Exception:
            creation_text = "indisponível"

    else:
        creation_text = "indisponível"

    groups = format_groups(
        info.get("groups", [])
    )

    if info.get("blockid"):
        block_status = "🔴 ativo"
    elif has_previous_block(username):
        block_status = "🟡 bloqueio prévio"
    else:
        block_status = "🟢 nenhum"

    encoded_username = quote(
        username.replace(" ", "_"),
        safe=""
    )

    user_url = (
        "https://pt.wikipedia.org/wiki/"
        f"Usuário:{encoded_username}"
    )

    message = (
        f'👤 <a href="{user_url}">'
        f"{html.escape(username)}</a>\n\n"
        f"✏️ Edições na Wikipédia em português: "
        f"{editcount}\n"
        f"📅 Idade da conta: {creation_text}\n"
        f"🔑 Direitos de usuário: "
        f"{html.escape(groups)}\n"
        f"🚫 Bloqueio: {block_status}"
    )

    return message, "HTML"


# =========================================================
# BLOQUEIOS
# =========================================================

def get_block_log_details(log_id):
    try:
        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "logevents",
                "leids": log_id,
                "leprop": (
                    "ids|title|type|user|"
                    "timestamp|comment|details"
                ),
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

        return events[0] if events else None

    except Exception as e:
        print(
            "⚠️ Erro ao obter detalhes do bloqueio:",
            log_id,
            repr(e)
        )
        return None


def extract_block_target(title):
    if not title:
        return "Desconhecido"

    for prefix in (
        "Usuário:",
        "Usuario:",
        "User:"
    ):
        if title.startswith(prefix):
            return title[len(prefix):]

    return title


def translate_duration_text(value):
    if value is None:
        return "não informada"

    value = str(value).strip()

    if not value:
        return "não informada"

    if value.lower() in (
        "infinite",
        "infinity",
        "indefinite",
        "indefinitely",
        "never",
    ):
        return "indefinido"

    replacements = [
        ("seconds", "segundos"),
        ("second", "segundo"),
        ("minutes", "minutos"),
        ("minute", "minuto"),
        ("hours", "horas"),
        ("hour", "hora"),
        ("days", "dias"),
        ("day", "dia"),
        ("weeks", "semanas"),
        ("week", "semana"),
        ("months", "meses"),
        ("month", "mês"),
        ("years", "anos"),
        ("year", "ano"),
    ]

    translated = value

    for english, portuguese in replacements:
        translated = re.sub(
            rf"\b{english}\b",
            portuguese,
            translated,
            flags=re.I
        )

    return translated


def duration_from_expiry(expiry, timestamp=None):
    if not expiry:
        return "não informada"

    expiry_text = str(expiry).strip()

    if expiry_text.lower() in (
        "infinite",
        "infinity",
        "indefinite",
        "indefinitely",
        "never",
    ):
        return "indefinido"

    if not re.match(
        r"^\d{4}-\d{2}-\d{2}",
        expiry_text
    ):
        return translate_duration_text(
            expiry_text
        )

    try:
        expiry_dt = datetime.fromisoformat(
            expiry_text.replace(
                "Z",
                "+00:00"
            )
        )

        if timestamp:
            start_dt = datetime.fromisoformat(
                str(timestamp).replace(
                    "Z",
                    "+00:00"
                )
            )
        else:
            start_dt = datetime.now(
                timezone.utc
            )

        total_seconds = int(
            (
                expiry_dt
                -
                start_dt
            ).total_seconds()
        )

        if total_seconds <= 0:
            return "expirado"

        days = total_seconds // 86400
        hours = (
            total_seconds % 86400
        ) // 3600
        minutes = (
            total_seconds % 3600
        ) // 60

        if days >= 365:
            years = days // 365
            remaining_days = days % 365

            if remaining_days:
                return (
                    f"{years} ano(s) e "
                    f"{remaining_days} dia(s)"
                )

            return f"{years} ano(s)"

        if days:
            if hours:
                return (
                    f"{days} dia(s) e "
                    f"{hours} hora(s)"
                )

            return f"{days} dia(s)"

        if hours:
            if minutes:
                return (
                    f"{hours} hora(s) e "
                    f"{minutes} minuto(s)"
                )

            return f"{hours} hora(s)"

        return f"{max(1, minutes)} minuto(s)"

    except Exception:
        return translate_duration_text(
            expiry_text
        )


def get_block_duration(event, fallback_change=None):
    params = event.get("params", {})

    if not isinstance(params, dict):
        params = {}

    duration = params.get("duration")

    if duration:
        return translate_duration_text(duration)

    expiry = params.get("expiry")

    if expiry:
        return duration_from_expiry(
            expiry,
            event.get("timestamp")
        )

    if fallback_change:
        stream_params = fallback_change.get(
            "log_params",
            {}
        )

        if isinstance(stream_params, dict):
            duration = stream_params.get("duration")

            if duration:
                return translate_duration_text(
                    duration
                )

            expiry = stream_params.get("expiry")

            if expiry:
                return duration_from_expiry(
                    expiry,
                    fallback_change.get(
                        "timestamp"
                    )
                )

    return "não informada"


def block_log_url(target):
    encoded_target = quote(
        f"Usuário:{target}",
        safe=""
    )

    return (
        "https://pt.wikipedia.org/w/index.php"
        "?title=Special:Log"
        "&type=block"
        f"&page={encoded_target}"
    )


def format_block_message(event, change):
    title = (
        event.get("title")
        or
        change.get("title")
        or
        ""
    )

    target = extract_block_target(title)

    reason = (
        event.get("comment")
        or
        change.get("comment")
        or
        "Motivo não informado"
    )

    blocker = (
        event.get("user")
        or
        change.get("user")
        or
        "Desconhecido"
    )

    duration = get_block_duration(
        event,
        change
    )

    action = (
        event.get("action")
        or
        change.get("log_action")
        or
        "block"
    )

    heading = (
        "🔒 Bloqueio alterado/reaplicado"
        if action == "reblock"
        else
        "🔒 Novo bloqueio aplicado"
    )

    target_url = block_log_url(target)

    return (
        f"{heading}\n\n"
        f'👤 <a href="{target_url}">'
        f"{html.escape(target)}</a>\n"
        f"📌 Motivo: {html.escape(reason)}\n"
        f"⏳ Duração: {html.escape(duration)}\n"
        f"🛡 Aplicado por: "
        f"{html.escape(blocker)}"
    )


def block_worker():
    print("✅ Monitor de bloqueios iniciado.")

    while True:
        change = block_queue.get()

        try:
            log_id = change.get("log_id")

            if not log_id:
                print(
                    "⚠️ Evento de bloqueio sem log_id."
                )
                continue

            details = get_block_log_details(
                log_id
            )

            if details is None:
                continue

            if details.get("type") != "block":
                continue

            action = (
                details.get("action")
                or
                change.get("log_action")
            )

            if action not in ("block", "reblock"):
                continue

            telegram_queue.put(
                {
                    "message": format_block_message(
                        details,
                        change
                    ),
                    "title": "Registro de bloqueio",
                    "parse_mode": "HTML",
                }
            )

            print(
                "🔒 Bloqueio detectado:",
                details.get("title")
            )

        except Exception as e:
            print(
                "❌ Erro no monitor de bloqueios:",
                repr(e)
            )

        finally:
            block_queue.task_done()


# =========================================================
# DIFF / REVERT RISK / HEURÍSTICAS
# =========================================================

def clean_html(text):
    if not text:
        return ""

    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def get_revision_diff(old_revision, new_revision):
    response = requests.get(
        WIKIPEDIA_API,
        params={
            "action": "compare",
            "format": "json",
            "formatversion": 2,
            "fromrev": old_revision,
            "torev": new_revision,
            "prop": "diff",
        },
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()

    diff_html = (
        response.json()
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
        "removed": removed[:MAX_DIFF_CHARS],
    }


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
            print("⚠️ Rate limit Lift Wing.")
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

        return float(probability)

    except Exception as e:
        print("⚠️ Erro Lift Wing:", repr(e))
        return None


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
    "vagabundo",
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
        r"(kk){4,}",
    ]

    for pattern in patterns:
        if re.search(
            pattern,
            text.lower()
        ):
            return 0.95

    return 0.0


def destructive_score(added, removed):
    added_len = len(added.strip())
    removed_len = len(removed.strip())

    if removed_len > 1500 and added_len < 100:
        return 0.95

    if removed_len > 700 and added_len < 60:
        return 0.85

    if removed_len > 300 and added_len < 20:
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

        ratio = alphabetic / len(text)

        if ratio < 0.25:
            return 0.80

    return 0.0


def analyze_vandalism(change, diff, revert_risk):
    added = diff.get("added", "")
    removed = diff.get("removed", "")

    profanity = profanity_score(added)
    repetition = repetition_score(added)
    destructive = destructive_score(
        added,
        removed
    )
    nonsense = nonsense_score(added)

    signals = [
        profanity,
        repetition,
        destructive,
        nonsense,
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

    score = min(score, 1.0)

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

    if profanity >= 0.75:
        reasons.append("linguagem ofensiva")

    if repetition >= 0.75:
        reasons.append("repetição anormal")

    if destructive >= 0.75:
        reasons.append(
            "remoção potencialmente destrutiva"
        )

    if nonsense >= 0.75:
        reasons.append(
            "texto possivelmente sem sentido"
        )

    if not reasons:
        reasons.append("edição suspeita")

    return {
        "score": score,
        "revert_risk": revert_risk,
        "reason": ", ".join(reasons),
    }


# =========================================================
# MENSAGENS DE EDIÇÃO
# =========================================================

def build_diff_url(change):
    revision = change.get("revision", {})
    old_revision = revision.get("old")
    new_revision = revision.get("new")

    return (
        "https://pt.wikipedia.org/w/index.php"
        f"?diff={new_revision}"
        f"&oldid={old_revision}"
    )


def tracked_queue_item(change, message, title):
    revision = change.get("revision", {})

    return {
        "message": message,
        "title": title,
        "track_revision": True,
        "revision_id": revision.get("new"),
        "rcid": change.get("id"),
        "page_title": change.get("title"),
    }


def format_observed_message(change, observation):
    return (
        "👁 Edição de conta observada\n\n"
        f"👤 {change.get('user', 'Desconhecido')}\n"
        f"📝 {change.get('title', 'Sem título')}\n"
        f"💬 {change.get('comment') or 'Sem resumo'}\n\n"
        f"📌 Motivo: {observation['reason']}\n\n"
        f"🔗 {build_diff_url(change)}"
    )


def format_watched_message(change):
    return (
        "👁 Edição em página vigiada\n\n"
        f"📝 {change.get('title', 'Sem título')}\n"
        f"👤 {change.get('user', 'Desconhecido')}\n"
        f"💬 {change.get('comment') or 'Sem resumo'}\n\n"
        f"🔗 {build_diff_url(change)}"
    )


def format_message(change, result):
    final_score = round(
        result["score"] * 100
    )

    revert_score = round(
        result["revert_risk"] * 100
    )

    return (
        f"🚨 Possível vandalismo — "
        f"{final_score}%\n\n"
        f"📝 {change.get('title', 'Sem título')}\n"
        f"👤 {change.get('user', 'Desconhecido')}\n"
        f"💬 {change.get('comment') or 'Sem resumo'}\n\n"
        f"🤖 Risco de reversão Wikimedia: "
        f"{revert_score}%\n"
        f"⚠️ Sinais: {result['reason']}\n\n"
        f"🔗 {build_diff_url(change)}"
    )


# =========================================================
# WORKER DE ANÁLISE
# =========================================================

def analysis_worker():
    print("✅ Worker de análise iniciado.")

    while True:
        change = analysis_queue.get()

        try:
            revision = change.get("revision", {})
            old_revision = revision.get("old")
            new_revision = revision.get("new")

            if not old_revision or not new_revision:
                continue

            username = change.get("user", "")
            title = change.get("title", "")

            # 1. Conta observada
            observation = get_observation(
                username
            )

            if observation:
                message = format_observed_message(
                    change,
                    observation
                )

                telegram_queue.put(
                    tracked_queue_item(
                        change,
                        message,
                        f"Conta observada: {username}"
                    )
                )

                print(
                    "🔎 Edição de conta observada:",
                    username,
                    "|",
                    title
                )
                continue

            # 2. Página vigiada
            if is_watched_page(title):
                if is_wikipedia_admin(username):
                    continue

                message = format_watched_message(
                    change
                )

                telegram_queue.put(
                    tracked_queue_item(
                        change,
                        message,
                        title
                    )
                )

                print(
                    "👁 Edição em página vigiada:",
                    title
                )
                continue

            # 3. Conta temporariamente ignorada
            # A observação e a página vigiada têm prioridade.
            ignored = get_ignored_user(username)

            if ignored:
                print(
                    "🙈 Edição ignorada temporariamente:",
                    username,
                    "|",
                    title
                )
                continue

            # 4. Filtro normal de conta
            if not should_evaluate_user(
                username
            ):
                continue

            # 5. Revert Risk
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

            # 6. Diff + heurísticas
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
                message = format_message(
                    change,
                    result
                )

                telegram_queue.put(
                    tracked_queue_item(
                        change,
                        message,
                        title
                    )
                )

        except Exception as e:
            print(
                "❌ Erro análise:",
                repr(e)
            )

        finally:
            analysis_queue.task_done()


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
        "Observa uma conta durante 6 horas.\n\n"
        "⛔ /desobservar Usuário\n"
        "Encerra a observação de uma conta.\n\n"
        "📋 /observadas\n"
        "Lista contas atualmente observadas.\n\n"
        "🙈 /ignorar Usuário\n"
        "Ignora uma conta durante 6 horas no detector normal.\n\n"
        "👀 /designorar Usuário\n"
        "Encerra a exclusão temporária de uma conta.\n\n"
        "📋 /ignoradas\n"
        "Lista contas temporariamente ignoradas.\n\n"
        "🛡 /vigiarfiltro ID\n"
        "Vigia um filtro de abusos.\n\n"
        "🛑 /desvigiarfiltro ID\n"
        "Remove um filtro da vigilância.\n\n"
        "📋 /filtros\n"
        "Lista filtros de abuso vigiados.\n\n"
        "👤 /conta Usuário\n"
        "Consulta uma conta.\n\n"
        "📡 /status\n"
        "Mostra o estado do bot.\n\n"
        "📖 /comandos\n"
        "Mostra esta lista."
    )


def process_telegram_command(message, from_channel=False):
    text = message.get("text", "").strip()

    if not text.startswith("/"):
        return

    chat = message.get("chat", {})
    chat_id = chat.get("id")

    if not chat_id:
        return

    first_part, *remaining = text.split(
        maxsplit=1
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

    if command == "/comandos":
        send_telegram_message(
            commands_message(),
            chat_id=chat_id
        )
        return

    if command == "/status":
        cleanup_expired_observations()
        cleanup_expired_ignored_users()
        cleanup_posted_edits()

        with stream_lock:
            connected = stream_connected
            last_stream = last_stream_event_at
            last_ptwiki = last_ptwiki_edit_at

        with watchlist_lock:
            watch_count = len(watched_pages)

        with observed_users_lock:
            observed_count = len(
                observed_users
            )

        with ignored_users_lock:
            ignored_count = len(
                ignored_users
            )

        with abuse_filters_lock:
            filter_count = len(
                watched_abuse_filters
            )

        with posted_edits_lock:
            tracked_count = len(
                posted_edits
            )

        if patrol_visibility_supported is True:
            patrol_text = "disponível"
        elif patrol_visibility_supported is False:
            patrol_text = (
                "indisponível sem autenticação"
            )
        else:
            patrol_text = "a verificar"

        stream_status = (
            "🟢 conectado"
            if connected
            else
            "🔴 reconectando"
        )

        send_telegram_message(
            (
                "🤖 Status do bot\n\n"
                f"📦 Versão: {BOT_VERSION}\n\n"
                f"📡 EventStreams: {stream_status}\n"
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
                f"{observed_count}\n"
                f"🙈 Contas ignoradas: "
                f"{ignored_count}\n"
                f"🛡 Filtros de abuso vigiados: "
                f"{filter_count}\n"
                f"📝 Edições acompanhadas: "
                f"{tracked_count}\n"
                f"✅ Patrulhamento: "
                f"{patrol_text}\n"
                f"🔒 Monitor de bloqueios: ativo\n\n"
                f"🔎 Triagem: "
                f"{REVERT_RISK_THRESHOLD:.0%}\n"
                f"🚨 Publicação: "
                f"{VANDALISM_THRESHOLD:.0%}\n\n"
                f"📥 Fila análise: "
                f"{analysis_queue.qsize()}\n"
                f"🔒 Fila bloqueios: "
                f"{block_queue.qsize()}\n"
                f"📤 Fila Telegram: "
                f"{telegram_queue.qsize()}"
            ),
            chat_id=chat_id
        )
        return

    if command == "/conta":
        if not argument:
            send_telegram_message(
                "Uso: /conta Nome",
                chat_id=chat_id
            )
            return

        account_message, parse_mode = (
            build_account_message(argument)
        )

        send_telegram_message(
            account_message,
            chat_id=chat_id,
            parse_mode=parse_mode
        )
        return

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
                (
                    "🔎 Nenhuma conta está "
                    "sendo observada."
                ),
                chat_id=chat_id
            )
            return

        items.sort(
            key=lambda x:
            x.get("expires_at", 0)
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
                    f"  ⏳ "
                    f"{format_remaining(remaining_time)}\n"
                    f"  📌 {item['reason']}"
                )
            )

        send_telegram_message(
            (
                "🔎 Contas observadas:\n\n"
                +
                "\n\n".join(lines)
            ),
            chat_id=chat_id
        )
        return

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

        parts = argument.split(maxsplit=1)

        if len(parts) < 2:
            send_telegram_message(
                (
                    "Uso:\n"
                    "/observar Usuário motivo\n\n"
                    "Para nomes com espaços, use _."
                ),
                chat_id=chat_id
            )
            return

        username_input = parts[0]
        reason = parts[1].strip()

        canonical_username = normalize_username(
            username_input
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
                    f"⏳ Duração: 6 horas\n"
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
            normalize_username(argument)
            or
            argument
        )

        success, removed = (
            stop_observing_user(
                canonical_username
            )
        )

        if not success:
            response_text = (
                "❌ Erro ao salvar alteração."
            )
        elif not removed:
            response_text = (
                f"ℹ️ {canonical_username} "
                "não estava em observação."
            )
        else:
            response_text = (
                "⛔ Observação encerrada\n\n"
                f"👤 {canonical_username}"
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )
        return

    if command == "/ignoradas":
        cleanup_expired_ignored_users()
        now = time.time()

        with ignored_users_lock:
            items = [
                dict(item)
                for item
                in ignored_users.values()
            ]

        if not items:
            send_telegram_message(
                (
                    "🙈 Nenhuma conta está "
                    "temporariamente ignorada."
                ),
                chat_id=chat_id
            )
            return

        items.sort(
            key=lambda x:
            x.get("expires_at", 0)
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
                    f"• {item['username']} — "
                    f"{format_remaining(remaining_time)} restantes"
                )
            )

        send_telegram_message(
            (
                "🙈 Contas temporariamente ignoradas:\n\n"
                +
                "\n".join(lines)
            ),
            chat_id=chat_id
        )
        return

    if command == "/ignorar":
        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):
            send_telegram_message(
                (
                    "⚠️ /ignorar deve ser publicado "
                    "diretamente no canal."
                ),
                chat_id=chat_id
            )
            return

        if not argument:
            send_telegram_message(
                "Uso: /ignorar Nome",
                chat_id=chat_id
            )
            return

        canonical_username = normalize_username(
            argument
        )

        if not canonical_username:
            send_telegram_message(
                (
                    "❌ Conta não encontrada: "
                    f"{argument}"
                ),
                chat_id=chat_id
            )
            return

        if ignore_user(canonical_username):
            send_telegram_message(
                (
                    "🙈 Conta temporariamente ignorada\n\n"
                    f"👤 {canonical_username}\n"
                    "⏳ Duração: 6 horas\n\n"
                    "As edições desta conta não serão "
                    "avaliadas pelo detector normal de "
                    "vandalismo durante esse período.\n\n"
                    "ℹ️ Contas observadas e páginas "
                    "vigiadas continuam tendo prioridade."
                ),
                chat_id=chat_id
            )
        else:
            send_telegram_message(
                (
                    "❌ Não foi possível salvar "
                    "a conta ignorada."
                ),
                chat_id=chat_id
            )
        return

    if command == "/designorar":
        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):
            send_telegram_message(
                (
                    "⚠️ /designorar deve ser publicado "
                    "diretamente no canal."
                ),
                chat_id=chat_id
            )
            return

        if not argument:
            send_telegram_message(
                "Uso: /designorar Nome",
                chat_id=chat_id
            )
            return

        canonical_username = (
            normalize_username(argument)
            or
            argument.replace("_", " ").strip()
        )

        success, removed = stop_ignoring_user(
            canonical_username
        )

        if not success:
            response_text = (
                "❌ Erro ao salvar alteração."
            )
        elif not removed:
            response_text = (
                f"ℹ️ {canonical_username} "
                "não estava na lista de ignoradas."
            )
        else:
            response_text = (
                "👀 Conta removida da lista de ignoradas\n\n"
                f"👤 {canonical_username}\n\n"
                "As próximas edições voltarão a seguir "
                "o fluxo normal de análise."
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )
        return

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

        title = normalize_page_title(argument)

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
                response_text = (
                    "❌ Erro ao salvar watchlist."
                )
            elif not added:
                response_text = (
                    f"👁 {title} já está "
                    "sendo vigiada."
                )
            else:
                response_text = (
                    f"👁 {title} adicionada "
                    "à vigilância."
                )

        else:
            success, removed = (
                remove_watched_page(title)
            )

            if not success:
                response_text = (
                    "❌ Erro ao salvar watchlist."
                )
            elif not removed:
                response_text = (
                    f"🙈 {title} não estava "
                    "sendo vigiada."
                )
            else:
                response_text = (
                    f"🙈 {title} removida "
                    "da vigilância."
                )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )
        return

    if command == "/filtros":
        with abuse_filters_lock:
            filters = [
                dict(item)
                for item
                in watched_abuse_filters.values()
            ]

        filters.sort(
            key=lambda x:
            x["filter_id"]
        )

        if not filters:
            response_text = (
                "🛡 Nenhum filtro de abusos "
                "está sendo vigiado."
            )
        else:
            lines = []

            for item in filters:
                filter_id = item["filter_id"]
                description = item.get(
                    "description"
                )

                if description:
                    lines.append(
                        f"• {filter_id} — {description}"
                    )
                else:
                    lines.append(
                        f"• {filter_id}"
                    )

            response_text = (
                "🛡 Filtros de abusos vigiados:\n\n"
                +
                "\n".join(lines)
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )
        return

    if command == "/vigiarfiltro":
        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):
            send_telegram_message(
                (
                    "⚠️ /vigiarfiltro deve ser publicado "
                    "diretamente no canal."
                ),
                chat_id=chat_id
            )
            return

        filter_id = normalize_filter_id(
            argument
        )

        if not filter_id:
            send_telegram_message(
                (
                    "Uso: /vigiarfiltro ID\n"
                    "Exemplo: /vigiarfiltro 69"
                ),
                chat_id=chat_id
            )
            return

        success, added, info = add_abuse_filter(
            filter_id
        )

        if not success:
            response_text = (
                "❌ Não foi possível localizar ou "
                "salvar esse filtro."
            )
        elif not added:
            response_text = (
                f"🛡 O filtro {filter_id} "
                "já está sendo vigiado."
            )
        else:
            description = (
                info.get("description")
                if info
                else None
            )

            response_text = (
                "🛡 Filtro adicionado à vigilância\n\n"
                f"🔢 Filtro: {filter_id}"
            )

            if description:
                response_text += (
                    f"\n📋 {description}"
                )

            response_text += (
                "\n\nNovas ocorrências desse filtro "
                "serão publicadas no canal."
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )
        return

    if command == "/desvigiarfiltro":
        if (
            not from_channel
            or
            not is_target_channel(chat)
        ):
            send_telegram_message(
                (
                    "⚠️ /desvigiarfiltro deve ser "
                    "publicado diretamente no canal."
                ),
                chat_id=chat_id
            )
            return

        filter_id = normalize_filter_id(
            argument
        )

        if not filter_id:
            send_telegram_message(
                "Uso: /desvigiarfiltro ID",
                chat_id=chat_id
            )
            return

        success, removed = remove_abuse_filter(
            filter_id
        )

        if not success:
            response_text = (
                "❌ Erro ao salvar alteração."
            )
        elif not removed:
            response_text = (
                f"ℹ️ O filtro {filter_id} "
                "não estava sendo vigiado."
            )
        else:
            response_text = (
                f"🛑 Filtro {filter_id} "
                "removido da vigilância."
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id
        )
        return


# =========================================================
# LISTENER TELEGRAM
# =========================================================

def telegram_command_listener():
    offset = None

    print("✅ Listener Telegram iniciado.")

    while True:
        try:
            params = {
                "timeout": 30,
                "allowed_updates": json.dumps(
                    [
                        "message",
                        "channel_post"
                    ]
                ),
            }

            if offset is not None:
                params["offset"] = offset

            response = requests.get(
                f"{TELEGRAM_API}/getUpdates",
                params=params,
                timeout=40
            )

            if response.status_code == 409:
                print("❌ TELEGRAM 409 CONFLICT")
                print(
                    "Resposta Telegram:",
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
                    update["update_id"]
                    +
                    1
                )

                message = update.get("message")

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

                    if is_target_channel(chat):
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
# EVENTSTREAMS WATCHDOG
# =========================================================

def eventstream_watchdog():
    global stream_connected
    global current_stream_response

    print("✅ Watchdog EventStreams iniciado.")

    while True:
        time.sleep(15)
        cleanup_expired_observations()
        cleanup_expired_ignored_users()

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
                    print(
                        "⚠️ EventStreams parado por",
                        int(elapsed),
                        "segundos."
                    )

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
                timeout=(15, 90)
            )

            response.raise_for_status()

            with stream_lock:
                current_stream_response = response
                stream_connected = True
                last_stream_event_at = time.time()

            client = SSEClient(response)

            print("✅ EventStreams conectado.")

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

                if change.get("wiki") != "ptwiki":
                    continue

                # Bloqueios
                if change.get("type") == "log":
                    if (
                        change.get("log_type")
                        ==
                        "block"
                    ):
                        action = change.get(
                            "log_action"
                        )

                        if action in (
                            "block",
                            "reblock"
                        ):
                            block_queue.put(change)

                            print(
                                "🔒 Evento de bloqueio:",
                                change.get("title"),
                                "| ação:",
                                action
                            )

                    continue

                # Edições
                if change.get("type") != "edit":
                    continue

                if change.get("bot", False):
                    continue

                with stream_lock:
                    last_ptwiki_edit_at = (
                        time.time()
                    )

                analysis_queue.put(change)

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

        print("🔄 Reconectando em 5 segundos...")
        time.sleep(5)


# =========================================================
# MAIN
# =========================================================

def main():
    print("========================================")
    print("Detector de vandalismo ptwiki")
    print(f"Versão {BOT_VERSION}")
    print("========================================")

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
    load_ignored_users()
    load_abuse_filters()
    load_abuse_filter_state()
    load_posted_edits()

    cleanup_expired_observations()
    cleanup_expired_ignored_users()
    cleanup_posted_edits()

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
    print("⏳ Observação de conta: 6 horas")
    print("🙈 Ignorar conta: 6 horas")
    print("🔒 Monitor de bloqueios: ativo")
    print(
        "🛡 Monitor de filtros de abuso: ativo"
    )
    print(
        "↩️ Monitor de reversões: ativo"
    )
    print(
        "✅ Monitor de patrulhamento: "
        "tentará usar a API pública"
    )

    threads = [
        ("telegram-sender", telegram_sender),
        ("analysis-worker", analysis_worker),
        ("block-worker", block_worker),
        ("eventstream-watchdog", eventstream_watchdog),
        ("telegram-listener", telegram_command_listener),
        ("abuse-filter-monitor", abuse_filter_monitor),
        ("posted-edit-status", posted_edit_status_monitor),
    ]

    for name, target in threads:
        threading.Thread(
            target=target,
            daemon=True,
            name=name
        ).start()

    time.sleep(2)

    announce_new_version_if_needed()

    wikimedia_loop()


if __name__ == "__main__":
    main()
