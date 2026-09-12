import os
import json
import time
import queue
import threading
import re
import html
import ipaddress

from datetime import datetime, timezone, timedelta
from statistics import median
from urllib.parse import quote
from zoneinfo import ZoneInfo

import requests
from sseclient import SSEClient


# =========================================================
# CONFIGURAÇÃO
# =========================================================

BOT_VERSION = "2.3"

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHANNEL = os.environ.get("TELEGRAM_CHANNEL_ID", "@ptwiki")

if not TELEGRAM_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN não configurado.")

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"

WIKIMEDIA_STREAM = "https://stream.wikimedia.org/v2/stream/recentchange"
WIKIPEDIA_API = "https://pt.wikipedia.org/w/api.php"

WIKIMEDIA_BOT_USERNAME = os.environ.get(
    "WIKIMEDIA_BOT_USERNAME"
)
WIKIMEDIA_BOT_PASSWORD = os.environ.get(
    "WIKIMEDIA_BOT_PASSWORD"
)

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

# Proteção contra flooding em surtos de bloqueios.
# Até 5 bloqueios/rebloqueios por minuto recebem alertas individuais.
# Do 6º em diante, os eventos individuais são suprimidos e uma única
# mensagem direciona ao registro de bloqueios.
MAX_BLOCK_ALERTS_PER_MINUTE = 5

POSTED_EDIT_CHECK_SECONDS = 10
REVISION_STATUS_INTERVAL_SECONDS = 30
POSTED_EDIT_TRACK_SECONDS = 48 * 60 * 60

# Resumo periódico dos alertas ainda pendentes no canal.
PENDING_SUMMARY_INTERVAL_SECONDS = 2 * 60 * 60
PENDING_SUMMARY_MAX_ITEMS = 20

# Patrulhamento: consulta em lote a cada 50s para manter a atualização
# normalmente abaixo de 1 minuto, deixando margem para rede/API/Telegram.
PATROL_REQUEST_INTERVAL_SECONDS = 50
PATROL_RECENTCHANGES_LIMIT = 500

# Reversões são verificadas em lote, reduzindo chamadas individuais.
REVISION_TAG_BATCH_SIZE = 50

DETECTION_STATS_RETENTION_DAYS = 90
DAILY_REPORT_HOUR = 20
DAILY_REPORT_MINUTE = 5
REPORT_TIMEZONE = "America/Sao_Paulo"


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

DETECTION_STATS_FILE = os.environ.get(
    "DETECTION_STATS_FILE",
    "/data/detection_stats.json"
)

PENDING_SUMMARY_STATE_FILE = os.environ.get(
    "PENDING_SUMMARY_STATE_FILE",
    "/data/pending_summary_state.json"
)


# =========================================================
# ESTADO EM MEMÓRIA
# =========================================================

watched_pages = set()
watchlist_lock = threading.Lock()

observed_users = {}
observed_users_lock = threading.Lock()
observed_users_persist_lock = threading.Lock()

ignored_users = {}
ignored_users_lock = threading.Lock()
ignored_users_persist_lock = threading.Lock()

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
posted_edits_persist_lock = threading.Lock()

# Estatísticas dos alertas do detector normal.
# Mantidas separadamente das mensagens acompanhadas por 48h.
detection_stats = {
    "records": [],
    "last_report_date": None,
}
detection_stats_lock = threading.Lock()
detection_stats_persist_lock = threading.Lock()

# Estado do último resumo periódico de pendências.
pending_summary_state = {
    "last_sent_at": 0.0,
    "last_signature": "",
}
pending_summary_lock = threading.Lock()
pending_summary_persist_lock = threading.Lock()

user_cache = {}

analysis_queue = queue.Queue()
block_queue = queue.Queue()
protection_queue = queue.Queue()
page_deletion_queue = queue.Queue()

# Controle de flooding dos alertas de bloqueio.
block_rate_lock = threading.Lock()
block_rate_state = {
    "minute_bucket": None,
    "count": 0,
    "summary_sent": False,
}

telegram_queue = queue.Queue()

stream_lock = threading.Lock()
stream_connected = False
last_stream_event_at = None
last_ptwiki_edit_at = None
current_stream_response = None

patrol_visibility_supported = None
patrol_visibility_warning_printed = False

# Sessão autenticada para leituras que exigem direitos Wikimedia.
wikimedia_session = requests.Session()
wikimedia_session.headers.update(HEADERS)
wikimedia_auth_lock = threading.Lock()
wikimedia_authenticated = False
wikimedia_authenticated_user = None
wikimedia_auth_error = None
wikimedia_rights = set()
wikimedia_groups = set()

# Diagnóstico do acesso de patrulhamento.
patrol_api_test_ok = None
patrol_api_test_code = None
patrol_api_test_info = None

# Controle explícito do teto de patrulhamento.
patrol_request_lock = threading.Lock()
last_patrol_request_at = 0.0


# =========================================================
# UTILIDADES DE ARQUIVO
# =========================================================

def atomic_write_json(path, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    temp_file = (
        f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    )

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
        print("⚠️ Erro ao ler", path, ":", safe_exception(e))
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
        DETECTION_STATS_FILE,
        PENDING_SUMMARY_STATE_FILE,
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
        print("📁 Estatísticas do detector:", DETECTION_STATS_FILE)
        print("📁 Resumo de pendências:", PENDING_SUMMARY_STATE_FILE)
        print("📁 Versão do bot:", BOT_VERSION_FILE)

        return True

    except Exception as e:
        print("❌ Erro no armazenamento:", safe_exception(e))
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


def safe_exception(error):
    """Retorna erro apropriado para log sem expor credenciais."""
    text = repr(error)

    secrets = [
        TELEGRAM_TOKEN,
        WIKIMEDIA_BOT_PASSWORD,
    ]

    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "***REDACTED***")

    # O token do Telegram faz parte da própria URL da Bot API.
    if TELEGRAM_TOKEN:
        text = text.replace(
            f"/bot{TELEGRAM_TOKEN}/",
            "/bot***REDACTED***/",
        )

    return text


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
        print("⚠️ Erro ao remover webhook Telegram:", safe_exception(e))


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
        print("⚠️ Erro ao verificar webhook:", safe_exception(e))


def send_telegram_message(text, chat_id=None, parse_mode=None, reply_markup=None):
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

            if reply_markup:
                payload["reply_markup"] = reply_markup

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
            print("⚠️ Erro de rede Telegram:", safe_exception(e))
            time.sleep(5)


def edit_telegram_message(message_id, text, parse_mode=None, reply_markup=None):
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

            # Reenvia explicitamente o teclado inline ao editar a mensagem.
            # Isso garante que o botão "Observar conta" continue disponível
            # após a mensagem ser marcada como patrulhada ou revertida.
            if reply_markup:
                payload["reply_markup"] = reply_markup

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
            print("⚠️ Erro ao editar mensagem Telegram:", safe_exception(e))
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

    if BOT_VERSION == "2.3":
        message = (
            "✅ Bot atualizado com sucesso\n\n"
            f"🤖 Versão {BOT_VERSION}\n\n"
            "🆕 Novidades da versão 2.3:\n"
            "• corrigido o link dos registros de bloqueio quando o alvo vem como Usuário(a):Nome;\n"
            "• o prefixo do namespace agora é normalizado antes de gerar o link e exibir o alvo, evitando duplicação de Usuário:."
        )
    elif BOT_VERSION == "2.2":
        message = (
            "✅ Bot atualizado com sucesso\n\n"
            f"🤖 Versão {BOT_VERSION}\n\n"
            "🆕 Novidades da versão 2.2:\n"
            "• consultas do AbuseFilter agora reutilizam explicitamente a sessão autenticada do TelesGramBot;\n"
            "• filtros e registros restritos passam a aproveitar os direitos efetivos da conta;\n"
            "• se a sessão expirar, o bot tenta renovar o login automaticamente;\n"
            "• /status agora informa o grupo confirmed e os principais direitos relacionados ao AbuseFilter."
        )
    elif BOT_VERSION == "2.1":
        message = (
            "✅ Bot atualizado com sucesso\n\n"
            f"🤖 Versão {BOT_VERSION}\n\n"
            "🆕 Novidades da versão 2.1:\n"
            "• adicionado monitoramento dos registros de proteção de páginas;\n"
            "• desproteções não geram mensagens;\n"
            "• o alerta informa página, administrador, motivo, nível e duração da proteção;\n"
            "• proteções são alertas independentes e não alteram o status de posts de edições acompanhadas."
        )
    elif BOT_VERSION == "2.0":
        message = (
            "✅ Bot atualizado com sucesso\n\n"
            f"🤖 Versão {BOT_VERSION}\n\n"
            "🆕 Novidades da versão 2.0:\n"
            "• o detector agora também analisa páginas recém-criadas;\n"
            "• novas páginas usam os mesmos filtros, Revert Risk e limiares do detector;\n"
            "• alertas de criação passam a ser acompanhados para reversão, patrulhamento e eliminação;\n"
            "• páginas novas também entram no acompanhamento de pendências e nas estatísticas."
        )
    else:
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
            safe_exception(e)
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
        print("❌ Erro ao salvar watchlist:", safe_exception(e))
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
        print("❌ Erro ao salvar watchlist:", safe_exception(e))
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
    with observed_users_persist_lock:
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
                safe_exception(e)
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
            expires_at <= now
        ):
            continue

        loaded[username_key(username)] = {
            "username": username,
            "reason": reason or "",
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


def observe_user(username, reason=None):
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
            safe_exception(e)
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
            safe_exception(e)
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
    with ignored_users_persist_lock:
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
                safe_exception(e)
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
            safe_exception(e)
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
            safe_exception(e)
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
# LEITURA AUTENTICADA DA API WIKIMEDIA
# =========================================================

def wikimedia_api_get(params, timeout=25, require_auth_when_available=True):
    """
    GET na Action API reutilizando a sessão Bot Password quando ela estiver
    autenticada. Se a sessão expirar, tenta autenticar novamente uma vez.

    Quando não há credenciais/sessão autenticada, preserva o comportamento
    público anterior e faz a consulta anonimamente.
    """
    request_params = dict(params)

    if wikimedia_authenticated and require_auth_when_available:
        # Garante que uma sessão expirada não passe silenciosamente a fazer
        # consultas anônimas, o que é especialmente importante para filtros
        # privados/restritos.
        request_params.setdefault("assert", "user")
        session = wikimedia_session
    else:
        session = requests

    response = session.get(
        WIKIPEDIA_API,
        params=request_params,
        headers=None if session is wikimedia_session else HEADERS,
        timeout=timeout,
    )

    # HTTP 401/403 pode indicar perda da sessão.
    if (
        session is wikimedia_session
        and response.status_code in (401, 403)
    ):
        if wikimedia_login():
            request_params["assert"] = "user"
            response = wikimedia_session.get(
                WIKIPEDIA_API,
                params=request_params,
                timeout=timeout,
            )

    response.raise_for_status()
    data = response.json()

    # Com assert=user, sessão expirada costuma aparecer como erro da API
    # mesmo com HTTP 200. Reautentica uma única vez e repete a chamada.
    error = data.get("error") if isinstance(data, dict) else None
    if (
        session is wikimedia_session
        and isinstance(error, dict)
        and error.get("code") in {
            "assertuserfailed",
            "notloggedin",
            "readapidenied",
        }
    ):
        if wikimedia_login():
            request_params["assert"] = "user"
            response = wikimedia_session.get(
                WIKIPEDIA_API,
                params=request_params,
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json()

    return response, data


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

        response, data = wikimedia_api_get(
            {
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
            timeout=20,
        )

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
            safe_exception(e)
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
            safe_exception(e)
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
            safe_exception(e)
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
            response, data = wikimedia_api_get(
                {
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
                timeout=30,
            )

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
                safe_exception(e)
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
                        safe_exception(e)
                    )

        except Exception as e:
            print(
                "❌ Erro no monitor de filtros de abuso:",
                safe_exception(e)
            )

        time.sleep(ABUSE_FILTER_POLL_SECONDS)


# =========================================================
# ESTATÍSTICAS DO DETECTOR NORMAL
# =========================================================

def save_detection_stats():
    with detection_stats_persist_lock:
        with detection_stats_lock:
            data = {
                "records": list(
                    detection_stats.get("records", [])
                ),
                "last_report_date": detection_stats.get(
                    "last_report_date"
                ),
            }

        atomic_write_json(
            DETECTION_STATS_FILE,
            data
        )


def cleanup_detection_stats(save=True):
    cutoff = (
        time.time()
        -
        DETECTION_STATS_RETENTION_DAYS
        * 24
        * 60
        * 60
    )

    removed = False

    with detection_stats_lock:
        records = detection_stats.get(
            "records",
            []
        )

        kept = [
            item
            for item in records
            if float(
                item.get("posted_at", 0)
            ) >= cutoff
        ]

        if len(kept) != len(records):
            detection_stats["records"] = kept
            removed = True

    if removed and save:
        try:
            save_detection_stats()
        except Exception as e:
            print(
                "⚠️ Erro ao limpar estatísticas:",
                safe_exception(e)
            )


def load_detection_stats():
    global detection_stats

    data = load_json(
        DETECTION_STATS_FILE,
        {
            "records": [],
            "last_report_date": None,
        }
    )

    if not isinstance(data, dict):
        data = {
            "records": [],
            "last_report_date": None,
        }

    raw_records = data.get(
        "records",
        []
    )

    loaded_records = []

    if isinstance(raw_records, list):
        for item in raw_records:
            if not isinstance(item, dict):
                continue

            try:
                revision_id = int(
                    item.get("revision_id")
                )
                posted_at = float(
                    item.get("posted_at")
                )
                score = float(
                    item.get("score")
                )
                revert_risk = float(
                    item.get("revert_risk")
                )
            except Exception:
                continue

            reverted_at = item.get(
                "reverted_at"
            )

            if reverted_at is not None:
                try:
                    reverted_at = float(
                        reverted_at
                    )
                except Exception:
                    reverted_at = None

            loaded_records.append(
                {
                    "revision_id": revision_id,
                    "title": item.get("title"),
                    "posted_at": posted_at,
                    "score": score,
                    "revert_risk": revert_risk,
                    "reverted_at": reverted_at,
                }
            )

    with detection_stats_lock:
        detection_stats = {
            "records": loaded_records,
            "last_report_date": data.get(
                "last_report_date"
            ),
        }

    cleanup_detection_stats(save=False)

    print(
        "✅ Registros estatísticos carregados:",
        len(
            detection_stats.get(
                "records",
                []
            )
        )
    )

    try:
        save_detection_stats()
    except Exception:
        pass


def register_detection_stat(
    revision_id,
    title,
    posted_at,
    score,
    revert_risk
):
    try:
        record = {
            "revision_id": int(revision_id),
            "title": title,
            "posted_at": float(posted_at),
            "score": float(score),
            "revert_risk": float(revert_risk),
            "reverted_at": None,
        }
    except Exception:
        return

    with detection_stats_lock:
        records = detection_stats.setdefault(
            "records",
            []
        )

        existing = next(
            (
                item
                for item in records
                if int(
                    item.get(
                        "revision_id",
                        0
                    )
                )
                ==
                record["revision_id"]
            ),
            None
        )

        if existing is None:
            records.append(record)
        else:
            existing.update(record)

    try:
        save_detection_stats()
    except Exception as e:
        print(
            "⚠️ Erro ao salvar estatística:",
            safe_exception(e)
        )


def mark_detection_stat_reverted(
    revision_id,
    reverted_at
):
    changed = False

    with detection_stats_lock:
        for item in detection_stats.get(
            "records",
            []
        ):
            if (
                int(
                    item.get(
                        "revision_id",
                        0
                    )
                )
                ==
                int(revision_id)
            ):
                if item.get(
                    "reverted_at"
                ) is None:
                    item["reverted_at"] = float(
                        reverted_at
                    )
                    changed = True
                break

    if changed:
        try:
            save_detection_stats()
        except Exception as e:
            print(
                "⚠️ Erro ao salvar reversão estatística:",
                safe_exception(e)
            )


def format_percent(value):
    return (
        f"{value:.1f}"
        .replace(".", ",")
        +
        "%"
    )


def format_minutes(seconds):
    if seconds is None:
        return "—"

    minutes = max(
        0,
        int(round(seconds / 60))
    )

    if minutes < 60:
        return f"{minutes} min"

    hours = minutes // 60
    remaining = minutes % 60

    if remaining:
        return f"{hours}h {remaining}min"

    return f"{hours}h"


def score_band_summary(records, minimum, maximum):
    items = [
        item
        for item in records
        if float(
            item.get("score", 0)
        ) >= minimum
        and
        float(
            item.get("score", 0)
        ) < maximum
    ]

    total = len(items)
    reverted = sum(
        1
        for item in items
        if item.get("reverted_at") is not None
    )

    percent = (
        reverted / total * 100
        if total
        else 0.0
    )

    return total, reverted, percent


def build_daily_detection_report(
    start_timestamp,
    end_timestamp
):
    with detection_stats_lock:
        records = [
            dict(item)
            for item in detection_stats.get(
                "records",
                []
            )
            if float(
                item.get("posted_at", 0)
            ) >= start_timestamp
            and
            float(
                item.get("posted_at", 0)
            ) < end_timestamp
        ]

    total = len(records)

    reverted_records = [
        item
        for item in records
        if item.get("reverted_at") is not None
    ]

    reverted = len(reverted_records)
    pending = total - reverted

    reverted_pct = (
        reverted / total * 100
        if total
        else 0.0
    )

    pending_pct = (
        pending / total * 100
        if total
        else 0.0
    )

    avg_risk = (
        sum(
            float(
                item.get(
                    "revert_risk",
                    0
                )
            )
            for item in records
        )
        /
        total
        *
        100
        if total
        else 0.0
    )

    avg_score = (
        sum(
            float(
                item.get(
                    "score",
                    0
                )
            )
            for item in records
        )
        /
        total
        *
        100
        if total
        else 0.0
    )

    reversal_times = [
        max(
            0,
            float(
                item["reverted_at"]
            )
            -
            float(
                item["posted_at"]
            )
        )
        for item in reverted_records
    ]

    median_reversal = (
        median(reversal_times)
        if reversal_times
        else None
    )

    bands = [
        ("45–59%", 0.45, 0.60),
        ("60–79%", 0.60, 0.80),
        ("80–100%", 0.80, 1.000001),
    ]

    band_lines = []

    for label, minimum, maximum in bands:
        band_total, band_reverted, band_pct = (
            score_band_summary(
                records,
                minimum,
                maximum
            )
        )

        band_lines.append(
            (
                f"• {label}: "
                f"{band_total} alertas • "
                f"{band_reverted} revertidas "
                f"({format_percent(band_pct)})"
            )
        )

    tz = ZoneInfo(REPORT_TIMEZONE)

    start_dt = datetime.fromtimestamp(
        start_timestamp,
        tz
    )

    end_dt = datetime.fromtimestamp(
        end_timestamp,
        tz
    )

    period_text = (
        start_dt.strftime(
            "%d/%m %H:%M"
        )
        +
        " → "
        +
        end_dt.strftime(
            "%d/%m %H:%M"
        )
        +
        " (Brasília)"
    )

    return (
        "📊 Relatório diário — detector de vandalismo\n\n"
        f"🕐 Período: {period_text}\n\n"
        f"🚨 Alertas de possível vandalismo: {total}\n"
        f"↩️ Edições revertidas: "
        f"{reverted} ({format_percent(reverted_pct)})\n"
        f"⏳ Ainda não revertidas: "
        f"{pending} ({format_percent(pending_pct)})\n\n"
        f"🤖 Revert Risk médio: "
        f"{format_percent(avg_risk)}\n"
        f"🎯 Score médio final: "
        f"{format_percent(avg_score)}\n"
        f"⏱ Mediana até detecção da reversão: "
        f"{format_minutes(median_reversal)}\n\n"
        "📈 Por faixa de score:\n"
        +
        "\n".join(band_lines)
        +
        "\n\n"
        "ℹ️ Considera apenas alertas do detector normal. "
        "“Ainda não revertida” pode mudar durante as "
        "48 horas de acompanhamento."
    )


def daily_detection_report_scheduler():
    print(
        "✅ Relatório diário agendado para "
        "20:05 (horário de Brasília)."
    )

    tz = ZoneInfo(
        REPORT_TIMEZONE
    )

    while True:
        try:
            cleanup_detection_stats()

            now = datetime.now(tz)

            report_end = now.replace(
                hour=DAILY_REPORT_HOUR,
                minute=DAILY_REPORT_MINUTE,
                second=0,
                microsecond=0
            )

            report_date = report_end.date().isoformat()

            with detection_stats_lock:
                last_report_date = (
                    detection_stats.get(
                        "last_report_date"
                    )
                )

            if (
                now >= report_end
                and
                last_report_date
                !=
                report_date
            ):
                end_timestamp = (
                    report_end.timestamp()
                )

                start_timestamp = (
                    report_end
                    -
                    timedelta(hours=24)
                ).timestamp()

                message = (
                    build_daily_detection_report(
                        start_timestamp,
                        end_timestamp
                    )
                )

                sent = send_telegram_message(
                    message
                )

                if sent:
                    with detection_stats_lock:
                        detection_stats[
                            "last_report_date"
                        ] = report_date

                    save_detection_stats()

                    print(
                        "📊 Relatório diário publicado:",
                        report_date
                    )
                else:
                    print(
                        "⚠️ Falha ao publicar relatório diário."
                    )

        except Exception as e:
            print(
                "⚠️ Erro no relatório diário:",
                safe_exception(e)
            )

        time.sleep(30)


# =========================================================
# EDIÇÕES PUBLICADAS / STATUS POSTERIOR
# =========================================================

def save_posted_edits():
    with posted_edits_persist_lock:
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
                safe_exception(e)
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

    posted_at = time.time()

    record = {
        "revision_id": revision_id,
        "rcid": item.get("rcid"),
        "title": item.get("page_title"),
        "username": item.get("username"),
        "edit_comment": item.get("edit_comment"),
        "diff_url": item.get("diff_url"),
        "revert_risk": (
            item.get("stats_payload", {}).get("revert_risk")
            if isinstance(item.get("stats_payload"), dict)
            else None
        ),
        "message_id": message_id,
        "base_message": item.get("message", ""),
        "parse_mode": item.get("parse_mode"),
        "reply_markup": item.get("reply_markup"),
        "posted_at": posted_at,
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
            safe_exception(e)
        )

    stats_payload = item.get(
        "stats_payload"
    )

    if isinstance(stats_payload, dict):
        register_detection_stat(
            revision_id=revision_id,
            title=item.get("page_title"),
            posted_at=posted_at,
            score=stats_payload.get("score"),
            revert_risk=stats_payload.get(
                "revert_risk"
            ),
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
            safe_exception(e)
        )

    return set()


def test_patrol_visibility_access():
    """
    Testa diretamente se a sessão autenticada consegue pedir
    rcprop=patrolled no RecentChanges.

    Esta chamada diagnóstica também conta para o intervalo de patrulhamento:
    após executá-la, o próximo lote normal só poderá ocorrer 50s depois.
    """

    global patrol_api_test_ok
    global patrol_api_test_code
    global patrol_api_test_info
    global patrol_visibility_supported
    global last_patrol_request_at

    try:
        # Reserva o ciclo antes da chamada. Assim o teste de inicialização
        # não permite uma segunda chamada antes do intervalo configurado.
        with patrol_request_lock:
            last_patrol_request_at = time.monotonic()

        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "recentchanges",
                "rctype": "edit|new",
                "rcprop": "ids|patrolled|timestamp",
                "rclimit": 1,
                "rcdir": "older",
            },
            timeout=25
        )
        response.raise_for_status()
        data = response.json()
        error = data.get("error")

        if error:
            patrol_api_test_ok = False
            patrol_api_test_code = str(
                error.get("code") or "erro_desconhecido"
            )
            patrol_api_test_info = str(
                error.get("info") or "sem detalhes"
            )
            patrol_visibility_supported = False

            print(
                "❌ Teste rcprop=patrolled falhou:",
                patrol_api_test_code,
                "-",
                patrol_api_test_info
            )
            return False

        patrol_api_test_ok = True
        patrol_api_test_code = "ok"
        patrol_api_test_info = "rcprop=patrolled aceito pela API"
        patrol_visibility_supported = True

        print(
            "✅ Teste rcprop=patrolled: API permitiu a leitura."
        )
        return True

    except Exception as e:
        patrol_api_test_ok = False
        patrol_api_test_code = "exception"
        patrol_api_test_info = str(e)
        patrol_visibility_supported = False
        print(
            "❌ Exceção no teste rcprop=patrolled:",
            safe_exception(e)
        )
        return False


def wikimedia_login():
    """
    Autentica uma sessão persistente usando Bot Password.

    Depois do login:
    1. consulta os direitos efetivos da sessão;
    2. registra patrol, patrolmarks e autopatrol individualmente;
    3. testa de fato rcprop=patrolled no RecentChanges.

    O teste real da API é a fonte final para definir se a leitura de
    patrulhamento está disponível. Isso evita falsos negativos causados
    apenas pela interpretação da lista de direitos.
    """

    global wikimedia_authenticated
    global wikimedia_authenticated_user
    global wikimedia_auth_error
    global wikimedia_rights
    global wikimedia_groups
    global patrol_visibility_supported
    global patrol_api_test_ok
    global patrol_api_test_code
    global patrol_api_test_info

    patrol_api_test_ok = None
    patrol_api_test_code = None
    patrol_api_test_info = None

    if not WIKIMEDIA_BOT_USERNAME or not WIKIMEDIA_BOT_PASSWORD:
        wikimedia_authenticated = False
        wikimedia_authenticated_user = None
        wikimedia_rights = set()
        wikimedia_groups = set()
        wikimedia_auth_error = (
            "credenciais Wikimedia não configuradas"
        )
        patrol_visibility_supported = False
        print(
            "⚠️ WIKIMEDIA_BOT_USERNAME/WIKIMEDIA_BOT_PASSWORD "
            "não configurados."
        )
        return False

    with wikimedia_auth_lock:
        try:
            token_response = wikimedia_session.get(
                WIKIPEDIA_API,
                params={
                    "action": "query",
                    "meta": "tokens",
                    "type": "login",
                    "format": "json",
                    "formatversion": 2,
                },
                timeout=25
            )
            token_response.raise_for_status()
            token_data = token_response.json()
            login_token = (
                token_data
                .get("query", {})
                .get("tokens", {})
                .get("logintoken")
            )

            if not login_token:
                raise RuntimeError(
                    "token de login não retornado"
                )

            login_response = wikimedia_session.post(
                WIKIPEDIA_API,
                data={
                    "action": "login",
                    "lgname": WIKIMEDIA_BOT_USERNAME,
                    "lgpassword": WIKIMEDIA_BOT_PASSWORD,
                    "lgtoken": login_token,
                    "format": "json",
                    "formatversion": 2,
                },
                timeout=25
            )
            login_response.raise_for_status()
            login_data = login_response.json()

            login_result = (
                login_data
                .get("login", {})
                .get("result")
            )

            if login_result != "Success":
                reason = (
                    login_data
                    .get("login", {})
                    .get("reason")
                    or
                    login_result
                    or
                    "falha desconhecida"
                )
                raise RuntimeError(
                    f"login Wikimedia falhou: {reason}"
                )

            user_response = wikimedia_session.get(
                WIKIPEDIA_API,
                params={
                    "action": "query",
                    "meta": "userinfo",
                    "uiprop": "rights|groups",
                    "format": "json",
                    "formatversion": 2,
                },
                timeout=25
            )
            user_response.raise_for_status()
            user_data = user_response.json()
            userinfo = (
                user_data
                .get("query", {})
                .get("userinfo", {})
            )

            wikimedia_authenticated_user = userinfo.get("name")
            wikimedia_rights = set(
                userinfo.get("rights", [])
            )
            wikimedia_groups = set(
                userinfo.get("groups", [])
            )
            wikimedia_authenticated = not bool(
                userinfo.get("anon")
            )

            if not wikimedia_authenticated:
                raise RuntimeError(
                    "sessão permaneceu anônima após login"
                )

            print(
                "✅ Wikimedia autenticada como:",
                wikimedia_authenticated_user
            )
            print(
                "🔎 Direitos efetivos da sessão:"
            )
            print(
                "   patrol =",
                "sim" if "patrol" in wikimedia_rights else "não"
            )
            print(
                "   patrolmarks =",
                "sim" if "patrolmarks" in wikimedia_rights else "não"
            )
            print(
                "   autopatrol =",
                "sim" if "autopatrol" in wikimedia_rights else "não"
            )
            print(
                "   grupo confirmed =",
                "sim" if "confirmed" in wikimedia_groups else "não"
            )
            for right in (
                "abusefilter-view",
                "abusefilter-view-private",
                "abusefilter-log",
                "abusefilter-log-detail",
                "abusefilter-log-private",
                "abusefilter-access-protected-vars",
                "abusefilter-protected-vars-log",
            ):
                print(
                    f"   {right} =",
                    "sim" if right in wikimedia_rights else "não"
                )

            # O teste prático é deliberadamente executado mesmo se a lista
            # de rights não contiver patrol/patrolmarks. A resposta real do
            # RecentChanges é a fonte definitiva para o bot.
            test_ok = test_patrol_visibility_access()

            if test_ok:
                wikimedia_auth_error = None
                print(
                    "✅ Direito de leitura de patrulhamento disponível."
                )
            else:
                wikimedia_auth_error = (
                    "rcprop=patrolled recusado: "
                    f"{patrol_api_test_code}: {patrol_api_test_info}"
                )

            return True

        except Exception as e:
            wikimedia_authenticated = False
            wikimedia_authenticated_user = None
            wikimedia_rights = set()
            wikimedia_groups = set()
            patrol_visibility_supported = False
            wikimedia_auth_error = str(e)
            patrol_api_test_ok = False
            patrol_api_test_code = "login_error"
            patrol_api_test_info = str(e)
            print(
                "❌ Falha no login Wikimedia:",
                safe_exception(e)
            )
            return False

def get_revision_tags_batch(revision_ids):
    """
    Consulta tags de várias revisões em uma única chamada.
    O lote é limitado a REVISION_TAG_BATCH_SIZE para manter a
    requisição pequena e previsível.
    """

    ids = []

    for revision_id in revision_ids:
        try:
            value = int(revision_id)
        except Exception:
            continue

        if value not in ids:
            ids.append(value)

        if len(ids) >= REVISION_TAG_BATCH_SIZE:
            break

    if not ids:
        return {}

    try:
        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "prop": "revisions",
                "revids": "|".join(
                    str(value)
                    for value in ids
                ),
                "rvprop": "ids|tags",
            },
            timeout=25
        )
        response.raise_for_status()
        data = response.json()

        result = {
            value: set()
            for value in ids
        }

        for page in (
            data
            .get("query", {})
            .get("pages", [])
        ):
            for revision in page.get("revisions", []):
                try:
                    revid = int(
                        revision.get("revid")
                    )
                except Exception:
                    continue

                result[revid] = set(
                    revision.get("tags", [])
                )

        return result

    except Exception as e:
        print(
            "⚠️ Erro na consulta em lote de tags:",
            safe_exception(e)
        )
        return {}


def get_patrol_status_batch(records):
    """
    Faz no máximo uma solicitação de patrulhamento a cada 50 segundos.

    A chamada busca até 500 mudanças recentes de uma vez e compara
    localmente os revids/rcids com as mensagens acompanhadas.
    Isso evita uma requisição por edição.
    """

    global last_patrol_request_at
    global patrol_visibility_supported
    global patrol_visibility_warning_printed

    if not wikimedia_authenticated:
        return {}

    if patrol_visibility_supported is not True:
        return {}

    now = time.monotonic()

    with patrol_request_lock:
        elapsed = now - last_patrol_request_at

        if elapsed < PATROL_REQUEST_INTERVAL_SECONDS:
            return {}

        # Reserva o ciclo antes da chamada para impedir que duas
        # threads disparem requisições simultâneas por acidente.
        last_patrol_request_at = now

    try:
        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "recentchanges",
                "rctype": "edit|new",
                "rcprop": "ids|patrolled|timestamp",
                "rclimit": PATROL_RECENTCHANGES_LIMIT,
                "rcdir": "older",
            },
            timeout=25
        )

        if response.status_code in (401, 403):
            print(
                "⚠️ Sessão Wikimedia perdeu autenticação; tentando novo login."
            )
            if wikimedia_login():
                patrol_visibility_warning_printed = False
            return {}

        response.raise_for_status()
        data = response.json()

        error = data.get("error")

        if error:
            code = error.get("code", "")
            info = error.get("info", "")

            if code == "rcpermissiondenied":
                print(
                    "⚠️ rcprop=patrolled recusado; tentando renovar a sessão Wikimedia."
                )
                if wikimedia_login():
                    patrol_visibility_warning_printed = False
                    return {}
                patrol_visibility_supported = False

            if not patrol_visibility_warning_printed:
                patrol_visibility_warning_printed = True
                print(
                    "⚠️ Falha ao ler patrulhamento:",
                    code,
                    info
                )

            return {}

        changes = (
            data
            .get("query", {})
            .get("recentchanges", [])
        )

        tracked_ids = {
            int(record["revision_id"])
            for record in records
            if record.get("revision_id") is not None
        }

        result = {}

        for change in changes:
            try:
                revid = int(
                    change.get("revid", 0)
                )
            except Exception:
                continue

            if revid not in tracked_ids:
                continue

            result[revid] = (
                "patrolled" in change
                and
                change.get("patrolled") is not False
            )

        return result

    except Exception as e:
        print(
            "⚠️ Erro na consulta em lote de patrulhamento:",
            safe_exception(e)
        )
        return {}


def get_reverter_username(title, revision_id):
    """Tenta identificar quem realizou a reversão sem presumir um nome.

    Procura revisões posteriores próximas e usa sinais explícitos do MediaWiki
    (tags de rollback/undo e comentários de reversão). Se não houver evidência
    suficiente, retorna None. Esta consulta só ocorre depois de a revisão já
    ter sido confirmada como revertida.
    """
    try:
        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "prop": "revisions",
                "titles": title,
                "rvprop": "ids|user|comment|tags|timestamp",
                "rvdir": "newer",
                "rvstartid": int(revision_id),
                "rvlimit": 20,
            },
            headers=HEADERS,
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("error"):
            return None

        pages = data.get("query", {}).get("pages", [])
        for page in pages:
            revisions = page.get("revisions", [])
            for rev in revisions:
                try:
                    rid = int(rev.get("revid"))
                except Exception:
                    continue
                if rid == int(revision_id):
                    continue

                tags = set(rev.get("tags") or [])
                comment = (rev.get("comment") or "").casefold()
                explicit_tag = bool(tags.intersection({
                    "mw-rollback", "mw-undo", "mw-manual-revert"
                }))
                explicit_comment = any(x in comment for x in (
                    "reverteu", "revertida", "revertido", "desfeita",
                    "desfeito", "desfazer", "rollback"
                ))
                if explicit_tag or explicit_comment:
                    return rev.get("user") or None
    except Exception as e:
        print("⚠️ Não foi possível identificar quem reverteu:", safe_exception(e))
    return None


def message_with_status(record, status, reverter=None, deleter=None):
    title = record.get("title") or "Sem título"
    username = record.get("username") or "Desconhecido"
    comment = record.get("edit_comment") or "Sem resumo"
    risk = record.get("revert_risk")
    diff_url = record.get("diff_url") or ""

    risk_line = ""
    if risk is not None:
        try:
            risk_line = f"\n🤖 Risco de reversão: {round(float(risk) * 100)}%\n"
        except Exception:
            pass

    if status == "reverted":
        reverter_line = f"\nRevertido por: {reverter}" if reverter else ""
        return (
            "↩️ Possível vandalismo revertido\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"🔗 {diff_url}"
            f"{reverter_line}"
        )

    if status == "patrolled":
        return (
            "✅ Possível vandalismo patrulhado\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"🔗 {diff_url}"
        )

    if status == "deleted":
        deleter_line = f"\nEliminada por: {deleter}" if deleter else ""
        return (
            "🗑️ Página eliminada após alerta de possível vandalismo\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"🔗 {diff_url}"
            f"{deleter_line}"
        )

    return record.get("base_message", "").rstrip()


def posted_edit_status_monitor():
    print(
        "✅ Monitor de reversões/patrulhamento iniciado."
    )
    print(
        "🔄 Patrulhamento em lote: máximo de 1 chamada a cada 50s."
    )

    last_revision_check_at = 0.0

    while True:
        time.sleep(POSTED_EDIT_CHECK_SECONDS)

        cleanup_posted_edits()

        with posted_edits_lock:
            snapshot = [
                dict(item)
                for item
                in posted_edits.values()
            ]

        active = [
            record
            for record in snapshot
            if record.get("status") not in ("reverted", "deleted")
        ]

        if not active:
            continue

        # -------- Reversões em lote --------
        # O loop acorda a cada 10s, mas as consultas de tags são feitas
        # a cada 30s. Todas as revisões acompanhadas entram no mesmo ciclo,
        # divididas em lotes de até 50 IDs por solicitação.
        tags_by_revision = {}
        now_monotonic = time.monotonic()

        if (
            now_monotonic - last_revision_check_at
            >= REVISION_STATUS_INTERVAL_SECONDS
        ):
            last_revision_check_at = now_monotonic

            for batch_start in range(0, len(active), REVISION_TAG_BATCH_SIZE):
                revision_batch = active[
                    batch_start:batch_start + REVISION_TAG_BATCH_SIZE
                ]
                batch_result = get_revision_tags_batch(
                    [
                        record["revision_id"]
                        for record in revision_batch
                    ]
                )
                tags_by_revision.update(batch_result)

        # -------- Patrulhamento em lote --------
        # Teto rígido: no máximo uma chamada à API a cada 50 s.
        patrol_by_revision = get_patrol_status_batch(
            active
        )

        changed_any = False

        for record in active:
            revision_id = int(
                record["revision_id"]
            )
            current_status = record.get("status")
            new_status = None

            tags = tags_by_revision.get(
                revision_id
            )

            if tags and "mw-reverted" in tags:
                new_status = "reverted"

            elif current_status != "patrolled":
                if patrol_by_revision.get(revision_id) is True:
                    new_status = "patrolled"

            if (
                new_status
                and
                new_status != current_status
            ):
                # Para não atrasar a atualização principal, uma reversão
                # é publicada imediatamente sem esperar a consulta opcional
                # que tenta descobrir quem reverteu. O nome é acrescentado
                # em uma segunda edição logo depois, se puder ser identificado.
                new_text = message_with_status(
                    record,
                    new_status,
                    reverter=None
                )

                # Mantém o botão de observação mesmo depois que o texto
                # da mensagem é alterado para "patrulhado" ou "revertido".
                # O fallback cobre registros criados em versões anteriores,
                # que ainda não tinham reply_markup persistido no JSON.
                status_reply_markup = record.get("reply_markup")
                if not status_reply_markup:
                    status_reply_markup = {
                        "inline_keyboard": [[{
                            "text": "🔎 Observar conta (6h)",
                            "callback_data": f"observe:{revision_id}",
                        }]]
                    }

                success = edit_telegram_message(
                    record["message_id"],
                    new_text,
                    parse_mode=record.get(
                        "parse_mode"
                    ),
                    reply_markup=status_reply_markup
                )

                if success:
                    with posted_edits_lock:
                        live = posted_edits.get(
                            str(revision_id)
                        )

                        if live:
                            live["status"] = new_status

                    changed_any = True

                    if new_status == "reverted":
                        mark_detection_stat_reverted(
                            revision_id,
                            time.time()
                        )

                    print(
                        "✏️ Mensagem atualizada:",
                        revision_id,
                        "→",
                        new_status
                    )

                    if new_status == "reverted":
                        reverter = get_reverter_username(
                            record.get("title") or "",
                            revision_id
                        )
                        if reverter:
                            enriched_text = message_with_status(
                                record,
                                "reverted",
                                reverter=reverter
                            )
                            edit_telegram_message(
                                record["message_id"],
                                enriched_text,
                                parse_mode=record.get("parse_mode"),
                                reply_markup=status_reply_markup
                            )

                time.sleep(1)

        if changed_any:
            try:
                save_posted_edits()
            except Exception as e:
                print(
                    "⚠️ Erro ao salvar status de mensagens:",
                    safe_exception(e)
                )


# =========================================================
# ELIMINAÇÃO DE PÁGINAS / ALERTAS PENDENTES
# =========================================================

def page_title_key(title):
    return str(title or "").replace("_", " ").strip().casefold()


def page_deletion_worker():
    """Atualiza imediatamente alertas pendentes quando a página é eliminada.

    A informação vem do mesmo EventStreams já conectado pelo bot. Portanto,
    este recurso não acrescenta polling nem consultas periódicas à Action API.
    """
    print("✅ Monitor de eliminação de páginas iniciado.")

    while True:
        change = page_deletion_queue.get()
        try:
            title = str(change.get("title") or "").strip()
            deleter = str(change.get("user") or "").strip() or None

            if not title:
                continue

            title_key = page_title_key(title)

            with posted_edits_lock:
                matches = [
                    dict(item)
                    for item in posted_edits.values()
                    if not item.get("status")
                    and page_title_key(item.get("title")) == title_key
                ]

            if not matches:
                continue

            changed_any = False

            for record in matches:
                revision_id = int(record["revision_id"])

                status_reply_markup = record.get("reply_markup")
                if not status_reply_markup:
                    status_reply_markup = {
                        "inline_keyboard": [[{
                            "text": "🔎 Observar conta (6h)",
                            "callback_data": f"observe:{revision_id}",
                        }]]
                    }

                new_text = message_with_status(
                    record,
                    "deleted",
                    deleter=deleter
                )

                success = edit_telegram_message(
                    record["message_id"],
                    new_text,
                    parse_mode=record.get("parse_mode"),
                    reply_markup=status_reply_markup
                )

                if success:
                    with posted_edits_lock:
                        live = posted_edits.get(str(revision_id))
                        if live and not live.get("status"):
                            live["status"] = "deleted"
                            live["deleted_by"] = deleter
                            live["deleted_at"] = time.time()

                    changed_any = True
                    print(
                        "🗑️ Alerta marcado como página eliminada:",
                        revision_id,
                        "|",
                        title,
                        "| por:",
                        deleter or "não informado"
                    )

                time.sleep(1)

            if changed_any:
                try:
                    save_posted_edits()
                except Exception as e:
                    print(
                        "⚠️ Erro ao salvar status de página eliminada:",
                        safe_exception(e)
                    )

        except Exception as e:
            print("⚠️ Erro ao processar eliminação de página:", safe_exception(e))
        finally:
            page_deletion_queue.task_done()


# =========================================================
# RESUMO PERIÓDICO DE ALERTAS PENDENTES
# =========================================================

def load_pending_summary_state():
    global pending_summary_state
    data = load_json(PENDING_SUMMARY_STATE_FILE, {})
    loaded = {"last_sent_at": 0.0, "last_signature": ""}
    if isinstance(data, dict):
        try:
            loaded["last_sent_at"] = float(data.get("last_sent_at", 0) or 0)
        except Exception:
            pass
        signature = data.get("last_signature", "")
        if isinstance(signature, str):
            loaded["last_signature"] = signature
    with pending_summary_lock:
        pending_summary_state = loaded
    print("✅ Estado do resumo de pendências carregado.")


def save_pending_summary_state():
    with pending_summary_persist_lock:
        with pending_summary_lock:
            data = dict(pending_summary_state)
        atomic_write_json(PENDING_SUMMARY_STATE_FILE, data)


def telegram_post_url(message_id):
    channel = str(TELEGRAM_CHANNEL or "").strip()
    if channel.startswith("@"):
        username = channel[1:]
        if username:
            return f"https://t.me/{username}/{int(message_id)}"
    return None


def get_pending_posted_edits():
    cleanup_posted_edits()
    now = time.time()
    with posted_edits_lock:
        items = [
            dict(item)
            for item in posted_edits.values()
            if not item.get("status")
            and now - float(item.get("posted_at", 0)) <= POSTED_EDIT_TRACK_SECONDS
        ]
    items.sort(key=lambda item: float(item.get("posted_at", 0)), reverse=True)
    return items


def pending_summary_signature(items):
    values = []
    for item in items:
        try:
            revision_id = int(item.get("revision_id"))
            message_id = int(item.get("message_id"))
        except Exception:
            continue
        values.append(f"{revision_id}:{message_id}")
    return "|".join(values)


def build_pending_summary_message(items):
    total = len(items)
    visible = items[:PENDING_SUMMARY_MAX_ITEMS]
    lines = []
    for item in visible:
        link = telegram_post_url(item.get("message_id"))
        if not link:
            continue
        title = str(item.get("title") or "Sem título")
        username = str(item.get("username") or "Desconhecido")
        label = html.escape(f"{title} — {username}")
        lines.append(f'• <a href="{html.escape(link, quote=True)}">{label}</a>')
    if not lines:
        return None
    extra = total - len(visible)
    extra_line = f"\n\n➕ {extra} outros alertas pendentes." if extra > 0 else ""
    plural = "s" if total != 1 else ""
    return (
        "🕒 <b>Alertas ainda pendentes</b>\n\n"
        f"🚨 {total} alerta{plural} ainda sem reversão ou patrulhamento:\n\n"
        + "\n".join(lines)
        + extra_line
        + "\n\n⏳ Considerados apenas alertas das últimas 48h."
    )


def pending_alerts_summary_scheduler():
    print("✅ Resumo de pendências: a cada 2 horas, até 20 links, janela de 48h.")
    with pending_summary_lock:
        never_sent = not pending_summary_state.get("last_sent_at")
    if never_sent:
        with pending_summary_lock:
            pending_summary_state["last_sent_at"] = time.time()
        try:
            save_pending_summary_state()
        except Exception:
            pass
    while True:
        time.sleep(60)
        try:
            now = time.time()
            with pending_summary_lock:
                last_sent_at = float(pending_summary_state.get("last_sent_at", 0) or 0)
                last_signature = str(pending_summary_state.get("last_signature", "") or "")
            if now - last_sent_at < PENDING_SUMMARY_INTERVAL_SECONDS:
                continue
            items = get_pending_posted_edits()
            if not items:
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                    pending_summary_state["last_signature"] = ""
                save_pending_summary_state()
                continue
            signature = pending_summary_signature(items)
            if signature == last_signature:
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                save_pending_summary_state()
                print("ℹ️ Resumo de pendências não publicado: lista inalterada.")
                continue
            message = build_pending_summary_message(items)
            if not message:
                print("⚠️ Não foi possível montar links públicos para o resumo de pendências.")
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                save_pending_summary_state()
                continue
            result = send_telegram_message(message, parse_mode="HTML")
            if result:
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                    pending_summary_state["last_signature"] = signature
                save_pending_summary_state()
                print("✅ Resumo de pendências publicado:", len(items), "alertas.")
        except Exception as e:
            print("⚠️ Erro no resumo de pendências:", safe_exception(e))


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
                ),
                reply_markup=item.get("reply_markup")
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
            print("❌ Erro sender:", safe_exception(e))

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
            safe_exception(e)
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
            safe_exception(e)
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
            safe_exception(e)
        )
        return None


def extract_block_target(title):
    if not title:
        return "Desconhecido"

    # O título de eventos de bloqueio pode vir localizado pela wiki.
    # Na ptwiki, além de "Usuário:", alguns eventos podem usar
    # "Usuário(a):". Removemos qualquer prefixo de namespace antes
    # de montar o link para evitar "Usuário:Usuário(a):Nome".
    for prefix in (
        "Usuário(a):",
        "Usuário:",
        "Usuario(a):",
        "Usuario:",
        "User:"
    ):
        if title.casefold().startswith(prefix.casefold()):
            return title[len(prefix):].strip()

    return title.strip()


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


def general_block_log_url():
    return (
        "https://pt.wikipedia.org/w/index.php"
        "?title=Special:Log&type=block"
    )


def format_block_burst_message():
    url = general_block_log_url()

    return (
        "⚠️ <b>Mais de 5 bloqueios no mesmo minuto</b>\n\n"
        "Mais de 5 bloqueios ou reaplicações de bloqueio foram "
        "efetuados neste minuto. Para evitar flooding, os alertas "
        "individuais adicionais foram suprimidos.\n\n"
        f'🔗 <a href="{url}">Ver registro de bloqueios</a>'
    )


def handle_block_event(change):
    """
    Aplica o limite de flooding antes de consultar detalhes do log.

    Os cinco primeiros eventos de cada minuto seguem para block_queue.
    No sexto evento, é enviada uma única mensagem-resumo e o próprio
    evento, assim como os seguintes no mesmo minuto, não gera consulta
    adicional a list=logevents.
    """
    now = time.time()
    minute_bucket = int(now // 60)
    send_summary = False
    allow_individual = False

    with block_rate_lock:
        if block_rate_state["minute_bucket"] != minute_bucket:
            block_rate_state["minute_bucket"] = minute_bucket
            block_rate_state["count"] = 0
            block_rate_state["summary_sent"] = False

        block_rate_state["count"] += 1
        count = block_rate_state["count"]

        if count <= MAX_BLOCK_ALERTS_PER_MINUTE:
            allow_individual = True
        elif not block_rate_state["summary_sent"]:
            block_rate_state["summary_sent"] = True
            send_summary = True

    if allow_individual:
        block_queue.put(change)
        print(
            "🔒 Evento de bloqueio aceito:",
            change.get("title"),
            "| minuto:",
            minute_bucket,
            "| posição:",
            count,
        )
        return

    if send_summary:
        telegram_queue.put(
            {
                "message": format_block_burst_message(),
                "title": "Muitos bloqueios",
                "parse_mode": "HTML",
            }
        )
        print(
            "⚠️ Mais de 5 bloqueios no mesmo minuto; "
            "alertas individuais adicionais suprimidos."
        )
    else:
        print(
            "⏭️ Bloqueio suprimido por limite anti-flood:",
            change.get("title"),
            "| posição:",
            count,
        )


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
                safe_exception(e)
            )

        finally:
            block_queue.task_done()


# =========================================================
# PROTEÇÃO DE PÁGINAS
# =========================================================

PROTECTION_LEVEL_NAMES = {
    "all": "todos os usuários",
    "autoconfirmed": "autoconfirmados",
    "confirmed": "confirmados",
    "extendedconfirmed": "autoconfirmados estendidos",
    "autoreviewer": "autorrevisores",
    "autoreview": "autorrevisores",
    "autopatrolled": "autorrevisores",
    "autoreviewers": "autorrevisores",
    "rollbacker": "reversores",
    "eliminator": "eliminadores",
    "templateeditor": "editores de predefinições",
    "sysop": "administradores",
}

PROTECTION_TYPE_NAMES = {
    "edit": "Edição",
    "move": "Movimentação",
    "create": "Criação",
    "upload": "Envio de arquivo",
}


def get_protection_log_details(log_id):
    """Busca o evento exato no registro de proteção."""
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
            timeout=20,
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
            "⚠️ Erro ao obter detalhes da proteção:",
            log_id,
            safe_exception(e),
        )
        return None


def protection_log_url(title):
    encoded_title = quote(str(title or "").replace(" ", "_"), safe="")
    return (
        "https://pt.wikipedia.org/w/index.php"
        "?title=Special:Log&type=protect"
        f"&page={encoded_title}"
    )


def protection_level_name(level):
    raw = str(level or "").strip()
    if not raw:
        return "nível não informado"
    return PROTECTION_LEVEL_NAMES.get(raw, raw)


def protection_type_name(kind):
    raw = str(kind or "").strip()
    if not raw:
        return "Proteção"
    return PROTECTION_TYPE_NAMES.get(raw, raw.capitalize())


def get_protection_details(event, fallback_change=None):
    """Extrai os níveis de proteção no formato atual da API.

    A Action API normalmente devolve params.details como uma lista de
    {type, level, expiry}. Também aceitamos o mesmo formato vindo do
    EventStreams como fallback para tolerar falhas na consulta adicional.
    """
    sources = [event]
    if fallback_change:
        sources.append(fallback_change)

    for source in sources:
        if not isinstance(source, dict):
            continue

        params = source.get("params")
        if not isinstance(params, dict):
            params = source.get("log_params")
        if not isinstance(params, dict):
            params = {}

        details = params.get("details")
        if details is None:
            details = source.get("details")

        if isinstance(details, list):
            result = []
            for item in details:
                if not isinstance(item, dict):
                    continue
                level = item.get("level")
                # Nível "all" significa sem restrição para aquela ação;
                # não o apresentamos como uma proteção ativa.
                if str(level or "").strip().lower() == "all":
                    continue
                result.append({
                    "type": item.get("type"),
                    "level": level,
                    "expiry": item.get("expiry"),
                })
            if result:
                return result

    return []


def protection_duration(expiry, timestamp=None):
    if expiry is None or str(expiry).strip() == "":
        return "não informada"
    return duration_from_expiry(expiry, timestamp)


def format_protection_message(event, change):
    title = str(
        event.get("title")
        or change.get("title")
        or "Página não informada"
    )
    protector = str(
        event.get("user")
        or change.get("user")
        or "Não informado"
    )
    reason = str(
        event.get("comment")
        or change.get("comment")
        or "Motivo não informado"
    )
    action = str(
        event.get("action")
        or change.get("log_action")
        or "protect"
    )
    timestamp = event.get("timestamp") or change.get("timestamp")
    details = get_protection_details(event, change)

    heading = (
        "🛡️ Proteção de página alterada"
        if action == "modify"
        else "🛡️ Página protegida"
    )

    lines = [
        heading,
        "",
        (
            f'📝 <a href="{protection_log_url(title)}">'
            f"{html.escape(title)}</a>"
        ),
        f"🛡 Administrador: {html.escape(protector)}",
        f"📌 Motivo: {html.escape(reason)}",
    ]

    if details:
        lines.extend(["", "🔐 Proteção:"])
        for detail in details:
            kind = protection_type_name(detail.get("type"))
            level = protection_level_name(detail.get("level"))
            duration = protection_duration(
                detail.get("expiry"),
                timestamp,
            )
            lines.append(
                f"• {html.escape(kind)}: "
                f"{html.escape(level)} — "
                f"{html.escape(duration)}"
            )
    else:
        # Não inventa nível/duração quando a API não os forneceu.
        lines.extend([
            "",
            "🔐 Nível/duração: não informados pela API",
        ])

    return "\n".join(lines)


def protection_worker():
    """Publica apenas proteções/alterações de proteção.

    Estes alertas são independentes de posted_edits. Em particular, uma
    proteção da mesma página de um alerta pendente NÃO altera status,
    patrulhamento, reversão, eliminação ou a lista de pendências.
    """
    print("✅ Monitor de proteção de páginas iniciado.")

    while True:
        change = protection_queue.get()
        try:
            log_id = change.get("log_id")
            if not log_id:
                print("⚠️ Evento de proteção sem log_id.")
                continue

            details = get_protection_log_details(log_id)
            if details is None:
                # Sem detalhes confiáveis, não publicamos uma mensagem
                # incompleta nem tentamos inferir níveis de proteção.
                continue

            if details.get("type") != "protect":
                continue

            action = (
                details.get("action")
                or change.get("log_action")
            )

            # Exclui explicitamente desproteções. "protect" cria proteção
            # e "modify" altera uma proteção que continua ativa.
            if action not in ("protect", "modify"):
                continue

            telegram_queue.put({
                "message": format_protection_message(details, change),
                "title": "Registro de proteção",
                "parse_mode": "HTML",
            })

            print(
                "🛡️ Proteção detectada:",
                details.get("title"),
                "| ação:",
                action,
            )

        except Exception as e:
            print(
                "❌ Erro no monitor de proteção:",
                safe_exception(e),
            )
        finally:
            protection_queue.task_done()


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


def get_new_revision_content(revision_id):
    """Obtém o conteúdo de uma revisão que criou uma página."""
    try:
        response = requests.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "prop": "revisions",
                "revids": revision_id,
                "rvprop": "content",
                "rvslots": "main",
            },
            headers=HEADERS,
            timeout=30
        )
        response.raise_for_status()
        pages = response.json().get("query", {}).get("pages", [])
        if not pages:
            return {"added": "", "removed": ""}
        revisions = pages[0].get("revisions", [])
        if not revisions:
            return {"added": "", "removed": ""}
        slots = revisions[0].get("slots", {})
        content = slots.get("main", {}).get("content", "")
        return {
            "added": (content or "")[:MAX_DIFF_CHARS],
            "removed": "",
        }
    except Exception as e:
        print(
            "⚠️ Erro ao obter conteúdo da página nova:",
            safe_exception(e)
        )
        return {"added": "", "removed": ""}


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
        print("⚠️ Erro Lift Wing:", safe_exception(e))
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

    if change.get("type") == "new" or not old_revision:
        return (
            "https://pt.wikipedia.org/w/index.php"
            f"?diff={new_revision}"
        )

    return (
        "https://pt.wikipedia.org/w/index.php"
        f"?diff={new_revision}"
        f"&oldid={old_revision}"
    )


def tracked_queue_item(
    change,
    message,
    title,
    stats_payload=None
):
    revision = change.get("revision", {})

    return {
        "message": message,
        "title": title,
        "track_revision": True,
        "revision_id": revision.get("new"),
        "rcid": change.get("id"),
        "page_title": change.get("title"),
        "username": change.get("user"),
        "edit_comment": change.get("comment") or "Sem resumo",
        "diff_url": build_diff_url(change),
        "stats_payload": stats_payload,
        "reply_markup": {
            "inline_keyboard": [[{
                "text": "🔎 Observar conta (6h)",
                "callback_data": f"observe:{revision.get('new')}",
            }]]
        },
    }


def format_observed_message(change, observation):
    reason = (observation.get("reason") or "").strip()
    reason_line = f"\n📌 Motivo: {reason}\n" if reason else ""
    return (
        "👁 Edição de conta observada\n\n"
        f"👤 {change.get('user', 'Desconhecido')}\n"
        f"📝 {change.get('title', 'Sem título')}\n"
        f"💬 {change.get('comment') or 'Sem resumo'}\n"
        f"{reason_line}\n"
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

    heading = (
        "🆕 Possível vandalismo — página criada"
        if change.get("type") == "new"
        else "🚨 Possível vandalismo"
    )

    return (
        f"{heading}\n\n"
        f"📝 {change.get('title', 'Sem título')}\n"
        f"👤 {change.get('user', 'Desconhecido')}\n"
        f"💬 {change.get('comment') or 'Sem resumo'}\n\n"
        f"🤖 Risco de reversão: {revert_score}%\n\n"
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

            is_new_page = change.get("type") == "new"

            if not new_revision:
                continue

            if not is_new_page and not old_revision:
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
            if is_new_page:
                diff = get_new_revision_content(
                    new_revision
                )
            else:
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
                        title,
                        stats_payload={
                            "score": result["score"],
                            "revert_risk": result[
                                "revert_risk"
                            ],
                        }
                    )
                )

        except Exception as e:
            print(
                "❌ Erro análise:",
                safe_exception(e)
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
        "🔎 /observar Usuário\n"
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
            pending_count = sum(
                1
                for item in posted_edits.values()
                if not item.get("status")
            )

        with detection_stats_lock:
            stats_count = len(
                detection_stats.get(
                    "records",
                    []
                )
            )

        if wikimedia_authenticated:
            auth_text = (
                "autenticada como "
                +
                str(wikimedia_authenticated_user)
            )
        else:
            auth_text = "não autenticada"

        if patrol_visibility_supported is True:
            patrol_text = "disponível"
        elif wikimedia_authenticated:
            patrol_text = "indisponível para esta sessão"
        else:
            patrol_text = "indisponível sem autenticação"

        patrol_right_text = (
            "sim" if "patrol" in wikimedia_rights else "não"
        )
        patrolmarks_right_text = (
            "sim" if "patrolmarks" in wikimedia_rights else "não"
        )
        autopatrol_right_text = (
            "sim" if "autopatrol" in wikimedia_rights else "não"
        )
        confirmed_group_text = (
            "sim" if "confirmed" in wikimedia_groups else "não"
        )
        abuse_right_names = (
            "abusefilter-view",
            "abusefilter-view-private",
            "abusefilter-log",
            "abusefilter-log-detail",
            "abusefilter-log-private",
            "abusefilter-access-protected-vars",
            "abusefilter-protected-vars-log",
        )
        abuse_rights_text = "\n".join(
            f"🔑 Direito {right}: "
            + ("sim" if right in wikimedia_rights else "não")
            for right in abuse_right_names
        )

        if patrol_api_test_ok is True:
            patrol_test_text = "OK"
        elif patrol_api_test_ok is False:
            patrol_test_text = (
                str(patrol_api_test_code or "falhou")
            )
        else:
            patrol_test_text = "não executado"

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
                f"🕒 Alertas pendentes: "
                f"{pending_count}\n"
                f"📌 Resumo de pendências: a cada 2h "
                f"(máx. 20 links, 48h)\n"
                f"📊 Registros estatísticos (90d): "
                f"{stats_count}\n"
                f"🕗 Relatório diário: 20:05 (Brasília)\n"
                f"🔐 Wikimedia: {auth_text}\n"
                f"✅ Patrulhamento: {patrol_text}\n"
                f"🔑 Direito patrol: {patrol_right_text}\n"
                f"🔑 Direito patrolmarks: {patrolmarks_right_text}\n"
                f"🔑 Direito autopatrol: {autopatrol_right_text}\n"
                f"👥 Grupo confirmed: {confirmed_group_text}\n"
                f"🔐 AbuseFilter: consultas usam a sessão autenticada quando disponível\n"
                f"{abuse_rights_text}\n"
                f"🧪 Teste rcprop=patrolled: {patrol_test_text}\n"
                f"🔄 Patrulhamento: lote a cada 50s "
                f"(até ~72 chamadas/h)\n"
                f"⏱ Atualização de status: alvo < 60s\n"
                f"🔒 Monitor de bloqueios: ativo\n"
                f"🛡️ Monitor de proteção de páginas: ativo\n\n"
                f"🔎 Triagem: "
                f"{REVERT_RISK_THRESHOLD:.0%}\n"
                f"🚨 Publicação: "
                f"{VANDALISM_THRESHOLD:.0%}\n\n"
                f"📥 Fila análise: "
                f"{analysis_queue.qsize()}\n"
                f"🔒 Fila bloqueios: "
                f"{block_queue.qsize()}\n"
                f"🛡️ Fila proteções: "
                f"{protection_queue.qsize()}\n"
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
                    f"{format_remaining(remaining_time)}"
                    + (f"\n  📌 {item.get('reason')}" if item.get('reason') else "")
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

        username_input = argument.strip()

        if not username_input:
            send_telegram_message(
                (
                    "Uso:\n"
                    "/observar Usuário\n\n"
                    "Para nomes com espaços, use _."
                ),
                chat_id=chat_id
            )
            return

        reason = ""

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
                    f"⏳ Duração: 6 horas\n\n"
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


def answer_callback_query(callback_query_id, text=None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    try:
        requests.post(
            f"{TELEGRAM_API}/answerCallbackQuery",
            json=payload,
            timeout=20
        )
    except Exception as e:
        print("⚠️ Erro ao responder callback:", safe_exception(e))


def telegram_user_is_channel_admin(user_id):
    """Valida no Telegram se quem clicou é administrador do canal.

    O botão aparece em um canal público, portanto não podemos confiar apenas
    no fato de o callback ter vindo de uma mensagem do canal: qualquer
    assinante consegue tocar em um botão inline.
    """
    try:
        response = requests.get(
            f"{TELEGRAM_API}/getChatMember",
            params={
                "chat_id": TELEGRAM_CHANNEL,
                "user_id": int(user_id),
            },
            timeout=20,
        )

        if response.status_code in (400, 401, 403):
            print(
                "⚠️ Não foi possível validar administrador do canal:",
                response.status_code,
                response.text,
            )
            return False

        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            return False

        member = data.get("result", {})
        status = member.get("status")
        return status in ("creator", "administrator")

    except Exception as e:
        print(
            "⚠️ Erro ao validar administrador do Telegram:",
            safe_exception(e),
        )
        # Falha fechada: se não pudermos comprovar a permissão, não
        # alteramos a lista de contas observadas.
        return False


def process_observe_callback(callback):
    callback_id = callback.get("id")
    data = callback.get("data", "")
    if not data.startswith("observe:"):
        answer_callback_query(callback_id)
        return

    callback_message = callback.get("message") or {}
    callback_chat = callback_message.get("chat") or {}

    if not is_target_channel(callback_chat):
        answer_callback_query(
            callback_id,
            "Este botão só funciona no canal configurado."
        )
        return

    clicker = callback.get("from") or {}
    clicker_id = clicker.get("id")

    if not clicker_id or not telegram_user_is_channel_admin(clicker_id):
        answer_callback_query(
            callback_id,
            "Apenas administradores do canal podem observar contas."
        )
        return

    revision_id = data.split(":", 1)[1]
    with posted_edits_lock:
        record = posted_edits.get(str(revision_id))

    if not record or not record.get("username"):
        answer_callback_query(
            callback_id,
            "Não encontrei a conta deste alerta."
        )
        return

    username = record["username"]
    if observe_user(username):
        answer_callback_query(
            callback_id,
            f"{username} em observação por 6 horas."
        )
        send_telegram_message(
            "🔎 Conta colocada em observação\n\n"
            f"👤 {username}\n"
            "⏳ Duração: 6 horas",
            chat_id=TELEGRAM_CHANNEL
        )
    else:
        answer_callback_query(
            callback_id,
            "Não foi possível salvar a observação."
        )


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
                        "channel_post",
                        "callback_query"
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

                callback = update.get("callback_query")

                if callback:
                    process_observe_callback(callback)
                    continue

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
                safe_exception(e)
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

                # Logs: bloqueios e eliminações de páginas.
                if change.get("type") == "log":
                    log_type = change.get("log_type")
                    action = change.get("log_action")

                    if log_type == "block":
                        if action in (
                            "block",
                            "reblock"
                        ):
                            handle_block_event(change)

                    elif log_type == "protect":
                        # Registra somente proteção e alteração de uma
                        # proteção existente. Desproteções são ignoradas.
                        if action in ("protect", "modify"):
                            protection_queue.put(change)
                            print(
                                "🛡️ Evento de proteção de página:",
                                change.get("title"),
                                "| ação:",
                                action,
                                "| por:",
                                change.get("user"),
                            )

                    elif (
                        log_type == "delete"
                        and action == "delete"
                    ):
                        page_deletion_queue.put(change)
                        print(
                            "🗑️ Evento de eliminação de página:",
                            change.get("title"),
                            "| por:",
                            change.get("user")
                        )

                    continue

                # Edições e criação de páginas
                if change.get("type") not in ("edit", "new"):
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
                safe_exception(e)
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
    load_detection_stats()
    load_pending_summary_state()

    cleanup_expired_observations()
    cleanup_expired_ignored_users()
    cleanup_posted_edits()
    cleanup_detection_stats()

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
    print("🛡️ Monitor de proteção de páginas: ativo")
    print(
        "🛡 Monitor de filtros de abuso: ativo"
    )
    print(
        "🔐 AbuseFilter: usa sessão autenticada Wikimedia quando disponível"
    )
    print(
        "↩️ Monitor de reversões: ativo"
    )
    wikimedia_login()

    print(
        "✅ Monitor de patrulhamento: "
        "sessão autenticada quando configurada"
    )
    print(
        "🔄 Patrulhamento em lote: máximo de "
        "1 chamada a cada 50s"
    )
    print(
        "📊 Relatório diário: 20:05 "
        "(horário de Brasília)"
    )
    print(
        "🗃 Histórico estatístico: 90 dias"
    )
    print(
        "🕒 Resumo de pendências: a cada 2 horas, "
        "máx. 20 links, janela de 48h"
    )

    threads = [
        ("telegram-sender", telegram_sender),
        ("analysis-worker", analysis_worker),
        ("block-worker", block_worker),
        ("protection-worker", protection_worker),
        ("page-deletion-worker", page_deletion_worker),
        ("eventstream-watchdog", eventstream_watchdog),
        ("telegram-listener", telegram_command_listener),
        ("abuse-filter-monitor", abuse_filter_monitor),
        ("posted-edit-status", posted_edit_status_monitor),
        ("daily-detection-report", daily_detection_report_scheduler),
        ("pending-alerts-summary", pending_alerts_summary_scheduler),
    ]

    for name, target in threads:
        threading.Thread(
            target=target,
            daemon=True,
            name=name
        ).start()

    time.sleep(2)

    # A indisponibilidade do Telegram não deve impedir a conexão ao
    # EventStreams. O anúncio de versão roda isolado do fluxo principal.
    threading.Thread(
        target=announce_new_version_if_needed,
        daemon=True,
        name="version-announcement",
    ).start()

    wikimedia_loop()


if __name__ == "__main__":
    main()
