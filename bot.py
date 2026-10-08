import os
import json
import time
import queue
import threading
import re
import difflib
import unicodedata
import html
import ipaddress
import secrets
import math
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from datetime import datetime, timezone, timedelta
from statistics import median
from collections import Counter, defaultdict
from urllib.parse import quote, parse_qs, urlparse, urlencode
from zoneinfo import ZoneInfo

import requests
from sseclient import SSEClient

DATA_DIR = os.environ.get("TOOL_DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

def data_path(filename):
    return os.path.join(DATA_DIR, filename)

# =========================================================
# CONFIGURAÇÃO
# =========================================================

BOT_VERSION = "3.36"
BOT_BUILD = "3.36-ptwiki-high-risk-delay"

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


# Limite compartilhado entre threads para leituras da Action API. Não altera
# Telegram, EventStreams nem o limite independente de escrita (desativada).
# Ao receber 429, interrompe imediatamente novas consultas durante o cooldown;
# não faz retries em massa nem mantém o listener do Telegram bloqueado.
_wiki_read_lock = threading.Lock()
_wiki_next_read_at = 0.0
_wiki_cooldown_until = 0.0
_wiki_original_request = requests.sessions.Session.request


def _wiki_controlled_request(session, method, url, **kwargs):
    global _wiki_next_read_at, _wiki_cooldown_until
    from email.utils import parsedate_to_datetime
    from datetime import datetime as _datetime, timezone as _timezone

    is_action_api = (
        str(url).startswith("https://pt.wikipedia.org/w/api.php")
        and str(method).upper() == "GET"
    )
    if not is_action_api:
        return _wiki_original_request(session, method, url, **kwargs)

    # A trava protege somente a reserva de horário; nunca uma operação de rede.
    with _wiki_read_lock:
        now = time.monotonic()
        if now < _wiki_cooldown_until:
            raise requests.exceptions.HTTPError(
                "Wikipédia: HTTP 429; aguardando cooldown global de leitura"
            )
        reserved = max(now, _wiki_next_read_at)
        _wiki_next_read_at = reserved + 1.25
    if reserved > now:
        time.sleep(reserved - now)
    with _wiki_read_lock:
        if time.monotonic() < _wiki_cooldown_until:
            raise requests.exceptions.HTTPError(
                "Wikipédia: HTTP 429; aguardando cooldown global de leitura"
            )
    response = _wiki_original_request(session, method, url, **kwargs)
    if response.status_code == 429:
        retry = response.headers.get("Retry-After", "")
        seconds = 120.0
        try:
            seconds = float(retry)
        except (ValueError, TypeError):
            try:
                parsed = parsedate_to_datetime(retry)
                seconds = (parsed - _datetime.now(_timezone.utc)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                pass
        seconds = max(60.0, min(seconds, 900.0))
        with _wiki_read_lock:
            _wiki_cooldown_until = max(_wiki_cooldown_until, time.monotonic() + seconds)
            _wiki_next_read_at = max(_wiki_next_read_at, _wiki_cooldown_until)
        print(f"⚠️ Wikipédia HTTP 429: leituras suspensas por {seconds:.0f}s (Retry-After respeitado).")
    return response


requests.sessions.Session.request = _wiki_controlled_request


# =========================================================
# ESCRITA NA WIKIPÉDIA — PREPARADA, MAS DESATIVADA
# =========================================================

# Trava deliberadamente hardcoded. Nesta versão não existe variável de
# ambiente capaz de habilitar escrita por acidente.
WIKI_WRITE_ENABLED = True

# Regra de segurança solicitada: mesmo quando a escrita for liberada numa
# versão futura, o bot somente poderá editar títulos iniciados exatamente por:
WIKI_ALLOWED_TITLE_PREFIX = "Usuário:TelesGramBot/"
WIKI_STATUS_TITLE = "Usuário:TelesGramBot/Status"
WIKI_STATISTICS_TITLE = "Usuário:TelesGramBot/Estatísticas"
WIKI_ADJUSTMENTS_TITLE = "Usuário:TelesGramBot/Ajustes"
WIKI_HIGH_RISK_TITLE = "Usuário:TelesGramBot/Edições de alto risco"
WIKI_HIGH_RISK_ARCHIVE_PREFIX = WIKI_HIGH_RISK_TITLE + "/"
WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE = WIKI_HIGH_RISK_ARCHIVE_PREFIX + "Arquivo"
WIKI_HIGH_RISK_HEADER_TITLE = WIKI_HIGH_RISK_ARCHIVE_PREFIX + "Cabeçalho"
WIKI_HIGH_RISK_MANUAL_TITLE = "Usuário:TelesGramBot/Revisões manuais"
WIKI_HIGH_RISK_ENTRY_TEMPLATE_TITLE = "Usuário:TelesGramBot/Predefinição/Edição de alto risco"
WIKI_CREATE_ENABLED = True
WIKI_WRITE_INTERVAL_SECONDS = 60 * 60
WIKI_STATUS_INTERVAL_SECONDS = 6 * 60 * 60
WIKI_WRITE_QUEUE_FILE = data_path("wiki_write_queue.json")
WIKI_WRITE_CONTROL_FILE = data_path("wiki_write_control.json")
WIKI_WRITE_LOCK = threading.RLock()
GENERAL_PRIORITY_FACTOR = 0.90  # Redução geral de 10% na prioridade, sem alterar o Revert Risk.
WIKI_PENDING_PAGES_FILE = data_path("wiki_pending_pages.json")

# Relatórios que serão usados quando a publicação for futuramente ativada.
WIKI_DAILY_REPORT_PREFIX = "Usuário:TelesGramBot/Relatórios/Diário/"
WIKI_MONTHLY_REPORT_PREFIX = "Usuário:TelesGramBot/Relatórios/Mensal/"



# =========================================================
# LIMITES / INTERVALOS
# =========================================================

REVERT_RISK_THRESHOLD = 0.25
VANDALISM_THRESHOLD = 0.50
MAX_DIFF_CHARS = 6000

MAX_ACCOUNT_AGE_DAYS = 60
MAX_USER_EDITS = 50
USER_CACHE_SECONDS = 3600

STREAM_STALL_SECONDS = 120

OBSERVATION_DURATION_SECONDS = 6 * 60 * 60
TEMP_WATCH_DURATION_SECONDS = 6 * 60 * 60
IGNORE_DURATION_SECONDS = 6 * 60 * 60

ABUSE_FILTER_POLL_SECONDS = 20
ABUSE_FILTER_USER_COOLDOWN_SECONDS = 5 * 60
ABUSE_FILTER_BATCH_LIMIT = 500

# Proteção contra flooding em surtos de bloqueios.
# Até 5 bloqueios/rebloqueios por minuto recebem alertas individuais.
# Do 6º em diante, os eventos individuais são suprimidos e uma única
# mensagem direciona ao registro de bloqueios.
MAX_BLOCK_ALERTS_PER_MINUTE = 5

# A mesma política é aplicada aos registros de proteção de páginas.
MAX_PROTECTION_ALERTS_PER_MINUTE = 5

POSTED_EDIT_CHECK_SECONDS = 10  # legado; pollers usam intervalos próprios
REVISION_STATUS_INTERVAL_SECONDS = 30
POSTED_EDIT_TRACK_SECONDS = 48 * 60 * 60

# Resumo periódico dos alertas ainda pendentes no canal.
PENDING_SUMMARY_INTERVAL_SECONDS = 2 * 60 * 60
PENDING_SUMMARY_MAX_ITEMS = 10
PENDING_COMMAND_PAGE_SIZE = 5
PENDING_RECONCILE_INTERVAL_SECONDS = 30 * 60
PENDING_PAGE_BATCH_SIZE = 50

# Patrulhamento: intervalo mínimo de 30s; sem consultas quando indisponível.
PATROL_REQUEST_INTERVAL_SECONDS = 30
PATROL_RECENTCHANGES_LIMIT = 500

# Reversões são verificadas em lote, reduzindo chamadas individuais.
REVISION_TAG_BATCH_SIZE = 50
DIRECT_UNDO_CHECKS_PER_CYCLE = 4
DIRECT_UNDO_RECHECK_SECONDS = 5 * 60

DETECTION_STATS_RETENTION_DAYS = 90
DAILY_REPORT_HOUR = 20
DAILY_REPORT_MINUTE = 5
REPORT_TIMEZONE = "America/Sao_Paulo"


# =========================================================
# ARQUIVOS PERSISTENTES
# =========================================================

WATCHLIST_FILE = os.environ.get(
    "WATCHLIST_FILE",
    data_path("watchlist.json")
)

OBSERVED_USERS_FILE = os.environ.get(
    "OBSERVED_USERS_FILE",
    data_path("observed_users.json")
)

POST_BLOCK_OBSERVATIONS_FILE = os.environ.get(
    "POST_BLOCK_OBSERVATIONS_FILE",
    data_path("post_block_observations.json")
)

TEMP_WATCHLIST_FILE = os.environ.get(
    "TEMP_WATCHLIST_FILE",
    data_path("temporary_watchlist.json")
)

IGNORED_USERS_FILE = os.environ.get(
    "IGNORED_USERS_FILE",
    data_path("ignored_users.json")
)

BOT_VERSION_FILE = os.environ.get(
    "BOT_VERSION_FILE",
    data_path("bot_version.json")
)

ABUSE_FILTERS_FILE = os.environ.get(
    "ABUSE_FILTERS_FILE",
    data_path("abuse_filters.json")
)

ABUSE_FILTER_STATE_FILE = os.environ.get(
    "ABUSE_FILTER_STATE_FILE",
    data_path("abuse_filter_state.json")
)

POSTED_EDITS_FILE = os.environ.get(
    "POSTED_EDITS_FILE",
    data_path("posted_edits.json")
)
POSTED_EDITS_BACKUP_FILE = POSTED_EDITS_FILE + ".backup"

DETECTION_STATS_FILE = os.environ.get(
    "DETECTION_STATS_FILE",
    data_path("detection_stats.json")
)

PENDING_SUMMARY_STATE_FILE = os.environ.get(
    "PENDING_SUMMARY_STATE_FILE",
    data_path("pending_summary_state.json")
)

REVERSIBLE_ACTIONS_FILE = os.environ.get(
    "REVERSIBLE_ACTIONS_FILE",
    data_path("reversible_actions.json")
)


COMMUNITY_STATS_FILE = os.environ.get(
    "COMMUNITY_STATS_FILE",
    data_path("community_stats.json")
)

FALSE_POSITIVES_FILE = os.environ.get(
    "FALSE_POSITIVES_FILE",
    data_path("false_positives.json")
)

FALSE_NEGATIVES_FILE = os.environ.get(
    "FALSE_NEGATIVES_FILE",
    data_path("false_negatives.json")
)

WIKI_REPORT_PREVIEW_FILE = os.environ.get(
    "WIKI_REPORT_PREVIEW_FILE",
    data_path("wiki_report_preview.txt")
)


# =========================================================
# ESTADO EM MEMÓRIA
# =========================================================

watched_pages = set()
watchlist_lock = threading.Lock()

temporary_watched_pages = {}
temporary_watchlist_lock = threading.Lock()
temporary_watchlist_persist_lock = threading.Lock()

observed_users = {}
observed_users_lock = threading.Lock()
observed_users_persist_lock = threading.Lock()

# Observações automáticas agendadas para começar quando um bloqueio
# temporário terminar. Persistidas separadamente para sobreviver a
# reinicializações/redeploys.
post_block_observations = {}
post_block_observations_lock = threading.Lock()
post_block_observations_persist_lock = threading.Lock()

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

# Anti-flood: uma publicação por combinação filtro + usuário a cada 5 min.
# Ocorrências suprimidas não renovam o cooldown.
abuse_filter_user_cooldowns = {}
abuse_filter_user_cooldowns_lock = threading.Lock()

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

# Botões de reversão ("desfazer/refazer") exibidos nas mensagens de
# confirmação das ações administrativas.
reversible_actions = {}
reversible_actions_lock = threading.Lock()
reversible_actions_persist_lock = threading.Lock()
REVERSIBLE_ACTION_TTL_SECONDS = 48 * 60 * 60


# Histórico de ações de manutenção usadas nos relatórios comunitários.
# Eventos são coletados independentemente da escrita na Wikipédia.
community_stats = {
    "events": [],
    "last_preview_date": None,
}
community_stats_lock = threading.Lock()
community_stats_persist_lock = threading.Lock()
COMMUNITY_STATS_RETENTION_DAYS = 400

# Casos marcados manualmente como falsos positivos.
# Ficam fora das estatísticas do detector/canal e permanecem nesta fila
# até que um administrador confirme que o ajuste correspondente no bot
# foi concluído.
false_positives = {}
false_negatives = {}
false_negatives_lock = threading.Lock()
false_negatives_persist_lock = threading.Lock()
false_positives_lock = threading.Lock()
false_positives_persist_lock = threading.Lock()
FALSE_POSITIVE_PAGE_SIZE = 10

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

# Controle de flooding dos alertas de proteção de páginas.
protection_rate_lock = threading.Lock()
protection_rate_state = {
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
        POST_BLOCK_OBSERVATIONS_FILE,
        TEMP_WATCHLIST_FILE,
        IGNORED_USERS_FILE,
        BOT_VERSION_FILE,
        ABUSE_FILTERS_FILE,
        ABUSE_FILTER_STATE_FILE,
        POSTED_EDITS_FILE,
        DETECTION_STATS_FILE,
        PENDING_SUMMARY_STATE_FILE,
        REVERSIBLE_ACTIONS_FILE,
        COMMUNITY_STATS_FILE,
        FALSE_POSITIVES_FILE,
        FALSE_NEGATIVES_FILE,
        WIKI_REPORT_PREVIEW_FILE,
        WIKI_WRITE_QUEUE_FILE,
        WIKI_WRITE_CONTROL_FILE,
        HIGH_RISK_ARCHIVE_FILE,
        HIGH_RISK_CANDIDATES_FILE,
        HIGH_RISK_WRITE_CONTROL_FILE,
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
        print("📁 Observações pós-bloqueio:", POST_BLOCK_OBSERVATIONS_FILE)
        print("📁 Vigilância temporária:", TEMP_WATCHLIST_FILE)
        print("📁 Contas ignoradas:", IGNORED_USERS_FILE)
        print("📁 Filtros de abuso:", ABUSE_FILTERS_FILE)
        print("📁 Estado dos filtros:", ABUSE_FILTER_STATE_FILE)
        print("📁 Edições publicadas:", POSTED_EDITS_FILE)
        print("📁 Estatísticas do detector:", DETECTION_STATS_FILE)
        print("📁 Resumo de pendências:", PENDING_SUMMARY_STATE_FILE)
        print("📁 Ações reversíveis:", REVERSIBLE_ACTIONS_FILE)
        print("📁 Estatísticas comunitárias:", COMMUNITY_STATS_FILE)
        print("📁 Falsos positivos:", FALSE_POSITIVES_FILE)
        print("📁 Prévia de relatório wiki:", WIKI_REPORT_PREVIEW_FILE)
        print("📁 Fila de alto risco da ptwiki:", HIGH_RISK_CANDIDATES_FILE)
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


def safe_log_text(value, max_length=1200):
    """Sanitiza texto antes de gravá-lo em logs.

    Remove credenciais conhecidas, caracteres de controle que poderiam
    falsificar/quebrar linhas de log e limita o tamanho para evitar que
    respostas externas causem flooding nos logs.
    """
    text = str(value)

    secrets = [
        TELEGRAM_TOKEN,
        WIKIMEDIA_BOT_PASSWORD,
        OAUTH_CLIENT_SECRET,
    ]

    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "***REDACTED***")

    if TELEGRAM_TOKEN:
        text = text.replace(
            f"/bot{TELEGRAM_TOKEN}/",
            "/bot***REDACTED***/",
        )

    # Preserva tabulação e espaço, mas neutraliza CR/LF e outros controles.
    text = "".join(
        ch if (ch == "\t" or ord(ch) >= 32) else " "
        for ch in text
    )

    if len(text) > max_length:
        text = text[:max_length] + "…[truncado]"

    return text


def safe_exception(error):
    """Retorna exceção apropriada para log sem expor credenciais."""
    return safe_log_text(repr(error))


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


def send_telegram_message(text, chat_id=None, parse_mode=None, reply_markup=None, reply_to_message_id=None):
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

            if reply_to_message_id:
                payload["reply_parameters"] = {
                    "message_id": int(reply_to_message_id),
                    "allow_sending_without_reply": True,
                }

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
                    safe_log_text(response.text)
                )
                return None

            if response.status_code >= 500:
                time.sleep(5)
                continue

            response.raise_for_status()

            data = response.json()

            if not data.get("ok"):
                print("❌ Telegram retornou erro:", safe_log_text(data))
                return None

            return data.get("result")

        except requests.RequestException as e:
            print("⚠️ Erro de rede Telegram:", safe_exception(e))
            time.sleep(5)


def edit_telegram_message(message_id, text, parse_mode=None, reply_markup=None):
    # Retorno False permite persistir uma tentativa de recuperação em vez de travar o monitor.
    for attempt in range(4):
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

                time.sleep(min(max(float(retry_after), 1.0), 10.0))
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
                    safe_log_text(response.text)
                )
                return False

            if response.status_code >= 500:
                time.sleep(2)
                continue

            response.raise_for_status()
            return bool(response.json().get("ok"))

        except requests.RequestException as e:
            print("⚠️ Erro ao editar mensagem Telegram:", safe_exception(e))
            time.sleep(2)

    print("⚠️ Telegram: limite de tentativas ao editar mensagem:", message_id)
    return False


def edit_telegram_message_in_chat(chat_id, message_id, text, parse_mode=None, reply_markup=None):
    try:
        payload = {
            "chat_id": chat_id,
            "message_id": int(message_id),
            "text": text,
            "disable_web_page_preview": True,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup

        response = requests.post(
            f"{TELEGRAM_API}/editMessageText",
            json=payload,
            timeout=30,
        )
        if response.status_code == 400 and "message is not modified" in response.text.lower():
            return True
        response.raise_for_status()
        data = response.json()
        return bool(data.get("ok"))
    except Exception as e:
        print("⚠️ Erro ao paginar pendentes:", safe_exception(e))
        return False



# =========================================================
# ESTATÍSTICAS COMUNITÁRIAS E RELATÓRIOS WIKI
# =========================================================

def save_community_stats():
    with community_stats_persist_lock:
        with community_stats_lock:
            data = {
                "events": list(community_stats.get("events", [])),
                "last_preview_date": community_stats.get("last_preview_date"),
            }
        atomic_write_json(COMMUNITY_STATS_FILE, data)


def cleanup_community_stats(save=True):
    cutoff = time.time() - COMMUNITY_STATS_RETENTION_DAYS * 86400
    changed = False

    with community_stats_lock:
        old = community_stats.get("events", [])
        kept = []
        for item in old:
            try:
                ts = float(item.get("timestamp", 0))
            except Exception:
                continue
            if ts >= cutoff:
                kept.append(item)

        if len(kept) != len(old):
            community_stats["events"] = kept
            changed = True

    if changed and save:
        try:
            save_community_stats()
        except Exception as e:
            print("⚠️ Erro ao limpar estatísticas comunitárias:", safe_exception(e))


def save_false_positives():
    with false_positives_persist_lock:
        with false_positives_lock:
            data = {
                "items": list(false_positives.values())
            }
        atomic_write_json(FALSE_POSITIVES_FILE, data)


def load_false_positives():
    global false_positives

    data = load_json(FALSE_POSITIVES_FILE, {"items": []})
    loaded = {}

    items = data.get("items", []) if isinstance(data, dict) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            revision_id = int(item.get("revision_id"))
        except Exception:
            continue

        normalized = dict(item)
        normalized["revision_id"] = revision_id
        loaded[str(revision_id)] = normalized

    with false_positives_lock:
        false_positives = loaded

    print(
        "✅ Falsos positivos carregados:",
        len(loaded),
        "| pendentes de ajuste:",
        sum(1 for item in loaded.values() if not item.get("resolved_at"))
    )


def save_false_negatives():
    with false_negatives_persist_lock:
        with false_negatives_lock:
            data = {"items": list(false_negatives.values())}
        atomic_write_json(FALSE_NEGATIVES_FILE, data)


def load_false_negatives():
    global false_negatives
    data = load_json(FALSE_NEGATIVES_FILE, {"items": []})
    loaded = {}
    for item in data.get("items", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        try:
            rid = int(item.get("revision_id"))
        except Exception:
            continue
        item = dict(item)
        item["revision_id"] = rid
        loaded[str(rid)] = item
    with false_negatives_lock:
        false_negatives = loaded
    print("✅ Falsos negativos carregados:", len(loaded), "| aguardando ajuste:", sum(1 for x in loaded.values() if not x.get("resolved_at")))


def normalize_similarity_name(value):
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def strong_title_creator_similarity(title, username):
    a = normalize_similarity_name(str(title or "").split(":", 1)[-1])
    b = normalize_similarity_name(username)
    if min(len(a), len(b)) < 5:
        return False, 0.0
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    containment = min(len(a), len(b)) / max(len(a), len(b)) if (a in b or b in a) else 0.0
    similarity = max(ratio, containment)
    return similarity >= 0.86, similarity


def new_page_promotional_signals(change, diff):
    if change.get("type") != "new":
        return {"bonus": 0.0, "signals": []}
    added = str(diff.get("added", "") or "").casefold()
    if not added:
        return {"bonus": 0.0, "signals": []}
    signals, bonus = [], 0.0
    has_ref = any(x in added for x in ("<ref", "{{citar ", "{{cite ", "== referências ==", "== referencias =="))
    if not has_ref and len(added) >= 180:
        signals.append("página nova sem referências aparentes")
        bonus += 0.05
    terms = ("empresa", "agência", "agencia", "marketing", "marca", "serviços", "servicos", "clientes", "fundada", "fundado", "sede", "startup", "negócio", "negocio", "empreendimento", "loja", "consultoria", "grupo empresarial")
    hits = sum(1 for term in terms if term in added)
    if hits >= 2:
        signals.append("múltiplos sinais de texto institucional/promocional")
        bonus += min(0.10, 0.04 + 0.02 * hits)
    close, similarity = strong_title_creator_similarity(change.get("title"), change.get("user"))
    if close:
        signals.append(f"forte semelhança título↔criador ({similarity:.0%})")
        bonus += 0.08
    # Um único indício nunca recebe bônus forte. O ganho relevante exige combinação contextual.
    if len(signals) < 2:
        bonus = min(bonus, 0.04)
    return {"bonus": min(0.20, bonus), "signals": signals}


def fetch_revision_for_calibration(revision_id):
    response = requests.get(WIKIPEDIA_API, params={"action":"query","format":"json","formatversion":2,"prop":"revisions","revids":int(revision_id),"rvprop":"ids|timestamp|user|comment|content","rvslots":"main"}, headers=HEADERS, timeout=30)
    response.raise_for_status()
    pages = response.json().get("query", {}).get("pages", [])
    if not pages or pages[0].get("missing"):
        raise ValueError("revisão não encontrada")
    page=pages[0]; revs=page.get("revisions", [])
    if not revs: raise ValueError("revisão não encontrada")
    rev=revs[0]
    response = requests.get(WIKIPEDIA_API, params={"action":"query","format":"json","formatversion":2,"prop":"revisions","pageids":page.get("pageid"),"rvdir":"newer","rvlimit":1,"rvprop":"ids"}, headers=HEADERS, timeout=30)
    response.raise_for_status()
    fp=response.json().get("query",{}).get("pages",[])
    fr=(fp[0].get("revisions",[]) if fp else [])
    is_new=bool(fr and int(fr[0].get("revid") or 0)==int(revision_id))
    content=((rev.get("slots") or {}).get("main") or {}).get("content", "") or ""
    return page, rev, is_new, {"added":content[:MAX_DIFF_CHARS], "removed":""}


def register_false_negative(revision_id, actor):
    rid=int(revision_id)
    page, rev, is_new, diff = fetch_revision_for_calibration(rid)
    rr=get_revert_risk(rid)
    change={"type":"new" if is_new else "edit", "title":page.get("title") or "", "user":rev.get("user") or ""}
    promo=new_page_promotional_signals(change,diff)
    item={"revision_id":rid,"title":change["title"],"username":change["user"],"edit_comment":rev.get("comment") or "","revision_timestamp":rev.get("timestamp"),"is_new_page":is_new,"revert_risk":rr,"promotional_bonus":promo["bonus"],"promotional_signals":promo["signals"],"reported_at":time.time(),"reported_by":actor,"resolved_at":None,"resolved_by":None}
    with false_negatives_lock:
        false_negatives[str(rid)]=item
    save_false_negatives()
    return item


def false_negative_metrics():
    with false_negatives_lock:
        items=list(false_negatives.values())
    return {"total":len(items),"resolved":sum(bool(x.get("resolved_at")) for x in items),"unresolved":sum(not x.get("resolved_at") for x in items)}


def telegram_actor_mention(record):
    """Return an HTML mention for the original false-positive reporter when possible."""
    username = str(record.get("marked_by_username") or "").strip().lstrip("@")
    user_id = record.get("marked_by_user_id")
    label = html.escape(str(record.get("marked_by") or "administrador"))
    if user_id:
        try:
            return f'<a href="tg://user?id={int(user_id)}">{label}</a>'
        except (ValueError, TypeError):
            pass
    if username and all(c.isalnum() or c == "_" for c in username):
        return f'<a href="https://t.me/{html.escape(username)}">@{html.escape(username)}</a>'
    return label


def unresolved_false_positives():
    with false_positives_lock:
        items = [
            dict(item)
            for item in false_positives.values()
            if not item.get("resolved_at")
        ]

    def safe_marked_at(item):
        try:
            return float(item.get("marked_at") or 0)
        except (TypeError, ValueError):
            return 0.0

    items.sort(key=safe_marked_at)
    return items


def false_positive_revision_ids():
    with false_positives_lock:
        return {
            int(item.get("revision_id"))
            for item in false_positives.values()
            if item.get("revision_id") is not None
        }


def register_false_positive(record, actor, reporter_user_id=None, reporter_username=None):
    revision_id = int(record["revision_id"])
    now = time.time()

    item = {
        "revision_id": revision_id,
        "title": record.get("title"),
        "username": record.get("username"),
        "edit_comment": record.get("edit_comment"),
        "diff_url": record.get("diff_url"),
        "revert_risk": record.get("revert_risk"),
        "final_score": record.get("final_score"),
        "telegram_message_id": record.get("message_id"),
        "alert_kind": record.get("alert_kind"),
        "posted_at": record.get("posted_at"),
        "marked_at": now,
        "marked_by": actor,
        "marked_by_user_id": reporter_user_id,
        "marked_by_username": reporter_username,
        "resolved_at": None,
        "resolved_by": None,
    }

    with false_positives_lock:
        false_positives[str(revision_id)] = item

    save_false_positives()
    return item


def mark_false_positive_fixed(revision_id, actor):
    key = str(int(revision_id))
    now = time.time()

    with false_positives_lock:
        item = false_positives.get(key)
        if not item:
            return None, "not_found"
        if item.get("resolved_at"):
            return dict(item), "already_resolved"

        item["resolved_at"] = now
        item["resolved_by"] = actor
        result = dict(item)

    save_false_positives()
    return result, "resolved"


def false_positive_message(item, fixed=False):
    title = article_link_html(item.get("title") or "Sem título")
    username = user_contributions_link_html(
        item.get("username") or "Desconhecido"
    )
    comment = html.escape(
        str(item.get("edit_comment") or "Sem resumo")
    )
    diff_url = item.get("diff_url") or ""
    edit_link = edit_link_html(diff_url)

    risk_line = ""
    if item.get("revert_risk") is not None:
        try:
            risk_line = (
                f"\n🤖 Risco de reversão: "
                f"{round(float(item['revert_risk']) * 100)}%\n"
            )
        except Exception:
            pass

    if fixed:
        actor = html.escape(
            str(item.get("resolved_by") or "administrador do canal")
        )
        return (
            "✅ Falso positivo revisado\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}\n"
            f"🛠 Concluído por: {actor}"
        )

    actor = html.escape(
        str(item.get("marked_by") or "administrador do canal")
    )
    return (
        "⚠️ Possível edição incorreta marcada como falso positivo\n"
        "Edição encaminhada para verificação.\n\n"
        f"📝 {title}\n"
        f"👤 {username}\n"
        f"💬 {comment}\n"
        f"{risk_line}\n"
        f"{edit_link}\n"
        f"🏷 Marcado por: {actor}"
    )


def false_positive_management_metrics(start_ts, end_ts):
    with false_positives_lock:
        items = [dict(item) for item in false_positives.values()]

    def ts(item, field):
        try:
            return float(item.get(field) or 0)
        except (TypeError, ValueError):
            return 0.0

    reported = [
        item for item in items
        if start_ts <= ts(item, "marked_at") < end_ts
    ]
    adjusted = [
        item for item in items
        if ts(item, "resolved_at") > 0
        and start_ts <= ts(item, "resolved_at") < end_ts
    ]
    backlog_at_end = [
        item for item in items
        if ts(item, "marked_at") < end_ts
        and (
            ts(item, "resolved_at") == 0
            or ts(item, "resolved_at") >= end_ts
        )
    ]
    closed_from_reported = [
        item for item in reported
        if 0 < ts(item, "resolved_at") < end_ts
    ]
    close_rate = (
        len(closed_from_reported) / len(reported) * 100
        if reported else 0.0
    )

    adjustment_times = []
    for item in adjusted:
        marked_at = ts(item, "marked_at")
        resolved_at = ts(item, "resolved_at")
        if marked_at and resolved_at >= marked_at:
            adjustment_times.append(resolved_at - marked_at)

    reporter_counts = Counter(
        str(item.get("marked_by") or "administrador não identificado")
        for item in reported
    )

    return {
        "reported": len(reported),
        "adjusted": len(adjusted),
        "backlog": len(backlog_at_end),
        "close_rate": close_rate,
        "median_adjustment_seconds": median(adjustment_times) if adjustment_times else None,
        "reporter_counts": reporter_counts,
    }

def wikitext_false_positive_reporters(counter, top=5):
    rows = counter.most_common(top)
    if not rows:
        return "''Nenhum falso positivo foi reportado no período.''"

    lines = [
        '{| class="wikitable sortable"',
        "! Posição !! Editor/administrador !! Falsos positivos reportados",
    ]
    medals = ["🥇", "🥈", "🥉"]

    for index, (actor, count) in enumerate(rows, start=1):
        medal = medals[index - 1] if index <= 3 else str(index)
        lines.extend([
            "|-",
            f"| {medal} || {actor} || {count}",
        ])

    lines.append("|}")
    return "\n".join(lines)


def false_positive_list_message(page=0):
    items = unresolved_false_positives()
    total = len(items)

    now = time.time()
    tz = ZoneInfo(REPORT_TIMEZONE)
    now_dt = datetime.fromtimestamp(now, tz)
    month_start = now_dt.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    metrics = false_positive_management_metrics(
        month_start.timestamp(),
        now,
    )

    summary = (
        "📊 <b>Gestão no mês atual</b>\n"
        f"🏷 Reportados: {metrics['reported']}\n"
        f"🛠 Ajustados: {metrics['adjusted']}\n"
        f"📥 Backlog atual: {total}\n\n"
    )

    if total == 0:
        return (
            "🏷 <b>Falsos positivos pendentes de ajuste</b>\n\n"
            + summary
            + "✅ Nenhum falso positivo aguardando correção no bot."
        )

    pages = max(1, math.ceil(total / FALSE_POSITIVE_PAGE_SIZE))
    page = max(0, min(int(page), pages - 1))
    start = page * FALSE_POSITIVE_PAGE_SIZE
    visible = items[start:start + FALSE_POSITIVE_PAGE_SIZE]

    blocks = []
    for number, item in enumerate(visible, start=start + 1):
        revision_id = int(item["revision_id"])
        title = html.escape(str(item.get("title") or "Sem título"))
        username = html.escape(str(item.get("username") or "Desconhecido"))
        marked_by = html.escape(
            str(item.get("marked_by") or "administrador")
        )
        link = telegram_post_url(item.get("telegram_message_id"))
        link_line = (
            f'\n🔗 <a href="{html.escape(link, quote=True)}">Ver aviso</a>'
            if link else ""
        )

        blocks.append(
            f"{number}. <b>{title}</b> — {username}\n"
            f"🆔 Revisão: <code>{revision_id}</code>\n"
            f"🏷 Marcado por: {marked_by}"
            f"{link_line}\n"
            f"✅ Após ajustar o bot: <code>/resolverfalso {revision_id}</code>"
        )

    return (
        "🏷 <b>Falsos positivos pendentes de ajuste</b>\n\n"
        + summary
        + "\n\n".join(blocks)
        + f"\n\n📄 Página {page + 1}/{pages} · {total} pendentes"
        + (
            "\nUse <code>/falsospositivos N</code> para outra página."
            if pages > 1 else ""
        )
    )


def load_community_stats():
    global community_stats

    if not os.path.isfile(COMMUNITY_STATS_FILE):
        print("⛔ Arquivo de estatísticas comunitárias ausente:", COMMUNITY_STATS_FILE,
              "— não criar arquivo vazio automaticamente; conferir volume persistente.")
        return
    try:
        with open(COMMUNITY_STATS_FILE, "r", encoding="utf-8") as source:
            data = json.load(source)
        if not isinstance(data, dict) or not isinstance(data.get("events"), list):
            raise ValueError("formato inválido: campo events não é lista")
    except (OSError, ValueError, TypeError) as exc:
        print("⛔ Falha ao carregar estatísticas; arquivo original preservado:", safe_exception(exc))
        return

    loaded = []
    if isinstance(data, dict):
        for item in data.get("events", []):
            if not isinstance(item, dict):
                continue
            try:
                item = dict(item)
                item["timestamp"] = float(item.get("timestamp", 0))
            except Exception:
                continue
            loaded.append(item)

    with community_stats_lock:
        community_stats = {
            "events": loaded,
            "last_preview_date": (
                data.get("last_preview_date")
                if isinstance(data, dict)
                else None
            ),
        }

    if data["events"] and not loaded:
        print("⛔ Eventos comunitários inválidos: arquivo original preservado; publicação bloqueada.")
        with community_stats_lock:
            community_stats["events"] = []
        return
    cleanup_community_stats(save=False)
    try:
        save_community_stats()
    except Exception:
        pass

    print("✅ Eventos comunitários carregados:", len(loaded))


def record_community_event(
    kind,
    actor=None,
    title=None,
    timestamp=None,
    revision_id=None,
    latency=None,
    categories=None,
    metadata=None,
):
    event = {
        "kind": str(kind or "").strip(),
        "actor": str(actor).strip() if actor else None,
        "title": str(title).strip() if title else None,
        "timestamp": float(timestamp or time.time()),
        "revision_id": int(revision_id) if revision_id is not None else None,
        "latency": float(latency) if latency is not None else None,
        "categories": [
            str(value)
            for value in (categories or [])
            if value
        ][:30],
        "metadata": dict(metadata or {}),
    }

    # Deduplicação simples para eventos associados a revisão/log.
    dedupe = (
        event["kind"],
        event.get("revision_id"),
        event.get("actor"),
        event.get("title"),
    )

    with community_stats_lock:
        for old in reversed(community_stats.get("events", [])[-500:]):
            old_key = (
                old.get("kind"),
                old.get("revision_id"),
                old.get("actor"),
                old.get("title"),
            )
            if event.get("revision_id") is not None and old_key == dedupe:
                return False

        community_stats.setdefault("events", []).append(event)

    try:
        save_community_stats()
    except Exception as e:
        print("⚠️ Erro ao persistir evento comunitário:", safe_exception(e))
        return False

    return True


def get_page_categories(title):
    """Categorias atuais da página, usadas apenas após caso confirmado."""
    if not title:
        return []

    try:
        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "prop": "categories",
                "titles": title,
                "cllimit": 50,
                "clshow": "!hidden",
            },
            timeout=18,
        )
        response.raise_for_status()
        pages = response.json().get("query", {}).get("pages", [])
        if not pages:
            return []

        result = []
        for item in pages[0].get("categories", []):
            name = str(item.get("title") or "")
            if name.startswith("Categoria:"):
                name = name[len("Categoria:"):]
            if name:
                result.append(name)
        return result[:30]

    except Exception as e:
        print("⚠️ Não foi possível obter categorias da página:", safe_exception(e))
        return []


def get_patroller_username(title, revision_id):
    """Identifica o patrulhador pelo log de patrol quando disponível."""
    try:
        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "logevents",
                "letype": "patrol",
                "letitle": title,
                "leprop": "title|user|timestamp|type|details",
                "lelimit": 20,
            },
            timeout=18,
        )
        response.raise_for_status()

        for event in response.json().get("query", {}).get("logevents", []):
            params = event.get("params") or {}
            try:
                current_revision = int(
                    params.get("curid")
                    or params.get("cur_id")
                    or 0
                )
            except Exception:
                current_revision = 0

            auto = params.get("auto")
            if current_revision == int(revision_id) and not auto:
                return event.get("user") or None

    except Exception as e:
        print("⚠️ Não foi possível identificar patrulhador:", safe_exception(e))

    return None


def wiki_writing_paused():
    """Persisted operator override; fail closed if control file is unreadable."""
    try:
        state = load_json(WIKI_WRITE_CONTROL_FILE, {"paused": False})
        if not isinstance(state, dict):
            return True
        return bool(state.get("paused", False))
    except Exception as exc:
        print("⚠️ Não foi possível ler controle da escrita wiki:", safe_exception(exc))
        return True


def set_wiki_writing_paused(paused):
    with WIKI_WRITE_LOCK:
        atomic_write_json(WIKI_WRITE_CONTROL_FILE, {"paused": bool(paused)})


def wiki_write_status_snapshot():
    """Read effective writing state and pending edit count from persistent state."""
    with WIKI_WRITE_LOCK:
        paused = wiki_writing_paused()
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        pending = state.get("pending", []) if isinstance(state, dict) else []
        return (bool(WIKI_WRITE_ENABLED and not paused), len(pending) if isinstance(pending, list) else 0)


def wiki_title_is_allowed(title):
    return (
        isinstance(title, str)
        and title.startswith(WIKI_ALLOWED_TITLE_PREFIX)
        and len(title) > len(WIKI_ALLOWED_TITLE_PREFIX)
    )


def wiki_high_risk_title_is_allowed(title):
    """Allow only the fixed high-risk pages and ISO-dated daily archives."""
    if title in {
        WIKI_HIGH_RISK_TITLE,
        WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE,
        WIKI_HIGH_RISK_HEADER_TITLE,
        WIKI_HIGH_RISK_MANUAL_TITLE,
        WIKI_HIGH_RISK_ENTRY_TEMPLATE_TITLE,
    }:
        return True
    if not isinstance(title, str) or not title.startswith(WIKI_HIGH_RISK_ARCHIVE_PREFIX):
        return False
    suffix = title[len(WIKI_HIGH_RISK_ARCHIVE_PREFIX):]
    try:
        return datetime.strptime(suffix, "%Y-%m-%d").strftime("%Y-%m-%d") == suffix
    except ValueError:
        return False


def get_wikimedia_csrf_token():
    if not wikimedia_authenticated:
        raise RuntimeError("sessão Wikimedia não autenticada")

    response = wikimedia_session.get(
        WIKIPEDIA_API,
        params={
            "action": "query",
            "meta": "tokens",
            "type": "csrf",
            "format": "json",
            "formatversion": 2,
        },
        timeout=25,
    )
    response.raise_for_status()
    data = response.json()
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict) and error.get("code") in {"notloggedin", "assertuserfailed", "readapidenied"}:
        if not wikimedia_login():
            raise RuntimeError("Falha ao renovar sessão para token CSRF: " + str(error))
        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={"action": "query", "meta": "tokens", "type": "csrf", "format": "json", "formatversion": 2, "assert": "user"},
            timeout=25,
        )
        response.raise_for_status()
        data = response.json()
    if data.get("error"):
        raise RuntimeError("Falha ao obter token CSRF: " + str(data["error"]))
    token = data.get("query", {}).get("tokens", {}).get("csrftoken")
    if not token or token == "+\\":
        raise RuntimeError("token CSRF não retornado")
    return token


def wiki_page_exists(title):
    _response, data = wikimedia_api_get({"action":"query","format":"json","formatversion":2,"titles":title})
    if data.get("error"):
        raise RuntimeError("Falha ao consultar existência da página: " + str(data["error"]))
    pages = ((data or {}).get("query") or {}).get("pages") or []
    if not pages:
        raise RuntimeError("Resposta da API sem dados da página; criação bloqueada por segurança")
    return not bool(pages[0].get("missing"))


def wiki_page_write_context(title):
    """Return the base revision and timestamps needed for conflict-safe writes."""
    _response, data = wikimedia_api_get({
        "action": "query", "format": "json", "formatversion": 2,
        "prop": "revisions", "titles": title, "rvlimit": 1,
        "rvprop": "ids|timestamp", "curtimestamp": 1,
    })
    if data.get("error"):
        raise RuntimeError("Falha ao consultar base da página: " + str(data["error"]))
    pages = ((data or {}).get("query") or {}).get("pages") or []
    if not pages:
        raise RuntimeError("Resposta da API sem contexto da página")
    page = pages[0]
    missing = bool(page.get("missing") is True or "missing" in page)
    revisions = page.get("revisions") or []
    revision = revisions[0] if revisions else {}
    return {
        "exists": not missing,
        "revid": int(revision.get("revid") or 0),
        "timestamp": revision.get("timestamp"),
        "starttimestamp": data.get("curtimestamp"),
    }


def wiki_report_creation_allowed(title):
    if not isinstance(title, str):
        return False
    for prefix, pattern in (
        (WIKI_DAILY_REPORT_PREFIX, r"[0-9]{4}-[0-9]{2}-[0-9]{2}"),
        (WIKI_MONTHLY_REPORT_PREFIX, r"[0-9]{4}-[0-9]{2}"),
    ):
        if not title.startswith(prefix):
            continue
        suffix = title[len(prefix):]
        if not re.fullmatch(pattern, suffix):
            return False
        try:
            if prefix == WIKI_DAILY_REPORT_PREFIX:
                return datetime.strptime(suffix, "%Y-%m-%d").strftime("%Y-%m-%d") == suffix
            return datetime.strptime(suffix, "%Y-%m").strftime("%Y-%m") == suffix
        except ValueError:
            return False
    return False


def wiki_pending_pages_snapshot():
    """Persistent inventory independent of the actual publication queue."""
    data = load_json(WIKI_PENDING_PAGES_FILE, {"titles": []})
    titles = data.get("titles", []) if isinstance(data, dict) else []
    return sorted({title for title in titles if isinstance(title, str) and wiki_title_is_allowed(title)})


def mark_wiki_page_pending(title):
    if not wiki_title_is_allowed(title):
        raise PermissionError("Título wiki não autorizado")
    with WIKI_WRITE_LOCK:
        titles = set(wiki_pending_pages_snapshot())
        titles.add(title)
        atomic_write_json(WIKI_PENDING_PAGES_FILE, {"titles": sorted(titles)})


def mark_wiki_page_published(title):
    with WIKI_WRITE_LOCK:
        titles = set(wiki_pending_pages_snapshot())
        titles.discard(title)
        atomic_write_json(WIKI_PENDING_PAGES_FILE, {"titles": sorted(titles)})


def wiki_statistics_publication_safe(wikitext):
    """Fail closed: never replace a populated wiki report with empty local data."""
    if not isinstance(wikitext, str) or not wikitext.strip():
        return False
    with community_stats_lock:
        events_count = len(community_stats.get("events", []))
    if events_count == 0:
        print("⛔ Estatísticas wiki bloqueadas: nenhum evento comunitário carregado; verificar volume /data e COMMUNITY_STATS_FILE.")
        return False
    # Also reject a stale zeroed payload already persisted in the write queue.
    if "* Reversões identificadas: 0" in wikitext and "* Patrulhamentos identificados: 0" in wikitext and "* Eliminações identificadas: 0" in wikitext and "Sem alertas suficientes para as distribuições." in wikitext:
        print("⛔ Estatísticas wiki bloqueadas: relatório zerado/incompleto.")
        return False
    return True


def queue_wiki_edit(
    title,
    wikitext,
    summary,
    *,
    write_class="general",
    priority=False,
    publication_revision_ids=None,
):
    """Coalesce pending writes by title; no network access here."""
    if not wiki_title_is_allowed(title):
        raise PermissionError("Título fora das subpáginas autorizadas")
    if not isinstance(wikitext, str) or not wikitext.strip():
        raise ValueError("Conteúdo wiki vazio")
    if title == WIKI_STATISTICS_TITLE and not wiki_statistics_publication_safe(wikitext):
        return False
    if write_class not in {"general", "high_risk"}:
        raise ValueError("Classe de escrita wiki inválida")
    if write_class == "high_risk" and not wiki_high_risk_title_is_allowed(title):
        raise PermissionError("Título fora da lista de alto risco autorizada")
    digest = hashlib.sha256(wikitext.encode("utf-8")).hexdigest()
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        if not isinstance(state, dict):
            state = {"pending": [], "last_attempt": 0}
        current = next(
            (item for item in state.get("pending", []) if item.get("title") == title),
            None,
        )
        if (
            isinstance(current, dict)
            and current.get("digest") == digest
            and current.get("write_class", "general") == write_class
        ):
            return False
        if (state.get("published_hashes") or {}).get(title) == digest:
            return False
        mark_wiki_page_pending(title)
        pending = [item for item in state.get("pending", []) if item.get("title") != title]
        item = {
            "title": title,
            "text": wikitext,
            "summary": summary,
            "write_class": write_class,
            "digest": digest,
        }
        if publication_revision_ids:
            item["publication_revision_ids"] = sorted({
                int(value) for value in publication_revision_ids
            })
        if priority:
            pending.insert(0, item)
        else:
            pending.append(item)
        state["pending"] = pending
        atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
    return True


def wiki_spamblacklist_retry_text(wikitext, error):
    """Neutraliza somente termos explicitamente apontados pela API spamblacklist."""
    if not isinstance(error, dict) or error.get("code") != "spamblacklist":
        return None
    matches = error.get("spamblacklist", {}).get("matches") or error.get("matches") or []
    if isinstance(matches, str):
        matches = [matches]
    cleaned = str(wikitext)
    changed = False
    for match in matches:
        term = str(match or "").strip()
        if not term:
            continue
        replacement = term.replace(".", "&#46;")
        if replacement == term:
            replacement = "&#8203;".join(term)
        pattern = re.compile(re.escape(term), re.I)
        cleaned2, count = pattern.subn(replacement, cleaned)
        if count:
            cleaned, changed = cleaned2, True
    return cleaned if changed else None


def wiki_write_interval_seconds(write_class):
    if write_class == "high_risk":
        return WIKI_HIGH_RISK_WRITE_INTERVAL_SECONDS
    return WIKI_WRITE_INTERVAL_SECONDS


def wiki_last_attempt(state, write_class):
    attempts = state.get("last_attempts") if isinstance(state, dict) else None
    if isinstance(attempts, dict) and attempts.get(write_class) is not None:
        return float(attempts.get(write_class) or 0)
    if write_class == "general":
        return float((state or {}).get("last_attempt") or 0)
    return 0.0


def wiki_edit_page(title, wikitext, summary, write_class="general"):
    """Single guarded write entry point, called only by the queue worker."""
    if not WIKI_WRITE_ENABLED or wiki_writing_paused():
        return False
    if not wiki_title_is_allowed(title):
        raise PermissionError("Título wiki não autorizado")
    if write_class == "high_risk" and not wiki_high_risk_title_is_allowed(title):
        raise PermissionError("Título de alto risco não autorizado")
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        interval = wiki_write_interval_seconds(write_class)
        if wiki_writing_paused() or time.time() - wiki_last_attempt(state, write_class) < interval:
            return False
        # Reserve the slot BEFORE any remote operation; crashes cannot cause a burst.
        reserved_at = time.time()
        state.setdefault("last_attempts", {})[write_class] = reserved_at
        if write_class == "general":
            state["last_attempt"] = reserved_at
        atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
        context = wiki_page_write_context(title)
        exists = context["exists"]
        create = not exists
        if create and not (
            WIKI_CREATE_ENABLED
            and (
                title in (WIKI_STATUS_TITLE, WIKI_STATISTICS_TITLE, WIKI_ADJUSTMENTS_TITLE)
                or wiki_report_creation_allowed(title)
                or wiki_high_risk_title_is_allowed(title)
            )
        ):
            print("📄 Página ausente; criação bloqueada:", title)
            return False
        # A deletion log is a hard stop for any attempt to recreate a page.
        if create and get_latest_deletion_log(title):
            print("⛔ Página eliminada; recriação automática proibida:", title)
            return False
        if not wikimedia_authenticated and not wikimedia_login():
            raise RuntimeError("Falha ao autenticar sessão de escrita Wikimedia")
        token = get_wikimedia_csrf_token()
        payload = {
            "action": "edit", "format": "json", "formatversion": 2,
            "title": title, "text": wikitext, "summary": summary,
            "token": token, "assert": "bot", "assertuser": wikimedia_authenticated_user,
            "bot": 1, "maxlag": 5,
        }
        if context.get("starttimestamp"):
            payload["starttimestamp"] = context["starttimestamp"]
        if exists:
            payload["baserevid"] = context["revid"]
            if context.get("timestamp"):
                payload["basetimestamp"] = context["timestamp"]
        payload["createonly" if create else "nocreate"] = 1
        response = wikimedia_session.post(WIKIPEDIA_API, data=payload, timeout=35)
        response.raise_for_status()
        data = response.json()
        error = data.get("error")
        if isinstance(error, dict) and error.get("code") in {"notloggedin", "assertuserfailed", "assertnameduserfailed", "badtoken", "invalidcsrf", "assertbotfailed"}:
            if not wikimedia_login():
                raise RuntimeError("Sessão wiki expirada e relogin falhou: " + str(error))
            payload["token"] = get_wikimedia_csrf_token()
            payload["assertuser"] = wikimedia_authenticated_user
            response = wikimedia_session.post(WIKIPEDIA_API, data=payload, timeout=35)
            response.raise_for_status()
            data = response.json()
        if data.get("error"):
            error = data["error"]
            retry_text = wiki_spamblacklist_retry_text(wikitext, error)
            if retry_text is not None:
                print("🛡️ Spamblacklist detectada; neutralizando somente o termo bloqueado e tentando uma vez.")
                payload["text"] = retry_text
                payload["token"] = get_wikimedia_csrf_token()
                response = wikimedia_session.post(WIKIPEDIA_API, data=payload, timeout=35)
                response.raise_for_status()
                data = response.json()
                if data.get("error"):
                    raise RuntimeError("API edit recusou publicação após retry spam-safe: " + str(data["error"]))
            else:
                raise RuntimeError("API edit recusou publicação: " + str(error))
        if data.get("edit", {}).get("result") != "Success":
            raise RuntimeError("API edit não confirmou sucesso: " + str(data.get("edit")))
        return True


def process_wiki_write_queue_once():
    if not WIKI_WRITE_ENABLED or wiki_writing_paused():
        return False
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        pending = state.get("pending", [])
        if wiki_writing_paused() or not pending:
            return False
        now = time.time()
        due = [
            (0 if item.get("write_class") == "high_risk" else 1, index, item)
            for index, item in enumerate(pending)
            if now - wiki_last_attempt(
                state, item.get("write_class", "general")
            ) >= wiki_write_interval_seconds(item.get("write_class", "general"))
            and (
                item.get("write_class") != "high_risk"
                or not high_risk_writing_paused()
            )
        ]
        if not due:
            return False
        _priority, item_index, item = min(due, key=lambda value: (value[0], value[1]))
        queued_item = item
        if item.get("title") == WIKI_STATISTICS_TITLE and not wiki_statistics_publication_safe(item.get("text")):
            # Discard stale unsafe report; preserve all other queued writes.
            state["pending"].pop(item_index)
            atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            print("⛔ Relatório de estatísticas inseguro removido da fila; demais publicações preservadas.")
            return False
        try:
            item = prepare_high_risk_write_item(item)
            success = wiki_edit_page(
                item["title"], item["text"], item["summary"],
                write_class=item.get("write_class", "general"),
            )
        except Exception as exc:
            print("⚠️ Falha na escrita wiki:", safe_exception(exc))
            state = load_json(WIKI_WRITE_QUEUE_FILE, state)
            state["write_failures"] = [x for x in state.get("write_failures", []) if isinstance(x, (int, float)) and time.time() - x <= 86400][-99:] + [time.time()]
            atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            # Notificação única da primeira falha, persistente entre reinícios.
            if not state.get("first_error_notified"):
                state = load_json(WIKI_WRITE_QUEUE_FILE, state)
                if not state.get("first_error_notified"):
                    state["first_error_notified"] = True
                    atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
                    send_telegram_message(
                        "⚠️ Primeira falha na publicação wiki: "
                        + html.escape(str(item.get("title", "")))
                        + " — " + html.escape(safe_exception(exc)),
                        parse_mode="HTML",
                    )
            return False
        if success:
            print("✅ Publicação wiki confirmada:", item["title"])
            state = load_json(WIKI_WRITE_QUEUE_FILE, state)
            state["last_success_at"] = time.time()
            state.setdefault("published_hashes", {})[item["title"]] = hashlib.sha256(
                item["text"].encode("utf-8")
            ).hexdigest()
            atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            # Never remove a newer, coalesced update of the same page.
            if queued_item in state.get("pending", []):
                state["pending"].remove(queued_item)
                atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
                mark_wiki_page_published(item["title"])
            # A coalesced replacement may already be queued, but the edit just
            # confirmed by the API still published these exact candidates.
            if item.get("publication_revision_ids"):
                mark_high_risk_candidates_published(
                    item["publication_revision_ids"],
                    published_at=time.time(),
                )
            if item["title"] == WIKI_HIGH_RISK_TITLE:
                purge_high_risk_main_page()
        return success


def wiki_write_queue_worker():
    wiki_record_release()
    try:
        queue_current_adjustments_log()
    except Exception as exc:
        print("⚠️ Falha ao preparar /Ajustes:", safe_exception(exc))
    mark_wiki_page_pending(WIKI_STATUS_TITLE)
    mark_wiki_page_pending(WIKI_STATISTICS_TITLE)
    mark_wiki_page_pending("Usuário:TelesGramBot/Sobre")  # Inventário apenas; sem criação/publicação automática.
    # O agendamento usa relógio persistido: reiniciar não provoca publicação extra.
    while True:
        try:
            state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
            legacy_title = "Usuário:TelesGramBot/Revisores"
            if any(item.get("title") == legacy_title for item in state.get("pending", [])):
                with WIKI_WRITE_LOCK:
                    state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
                    state["pending"] = [item for item in state.get("pending", []) if item.get("title") != legacy_title]
                    atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            last_status = float(state.get("last_status_enqueued") or 0)
            if WIKI_WRITE_ENABLED and not wiki_writing_paused() and time.time() - last_status >= WIKI_STATUS_INTERVAL_SECONDS:
                queue_wiki_edit(
                    WIKI_STATISTICS_TITLE,
                    build_wiki_statistics_wikitext(),
                    "Atualizando estatísticas agregadas do TelesGramBot",
                )
                queue_wiki_edit(
                    WIKI_STATUS_TITLE,
                    build_wiki_status_wikitext(),
                    "Atualizando status periódico do TelesGramBot",
                )
                with WIKI_WRITE_LOCK:
                    state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
                    state["last_status_enqueued"] = time.time()
                    atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            # As estatísticas são atualizadas junto com o status, respeitando a mesma fila e limite de escrita.
            process_wiki_write_queue_once()
        except Exception as exc:
            print("⚠️ Falha no agendador de escrita wiki:", safe_exception(exc))
        time.sleep(30)


def community_events_between(start_ts, end_ts):
    with community_stats_lock:
        return [
            dict(item)
            for item in community_stats.get("events", [])
            if start_ts <= float(item.get("timestamp", 0)) < end_ts
        ]


def wiki_user_link(username):
    if not username:
        return "—"
    name = str(username).replace("|", "&#124;")
    return f"[[Usuário:{name}|{name}]]"


def wiki_page_link(title):
    if not title:
        return "—"
    value = str(title).replace("|", "&#124;")
    return f"[[{value}]]"


def ranking_counts(events, kind, limit=3):
    counts = Counter(
        item.get("actor")
        for item in events
        if item.get("kind") == kind and item.get("actor")
    )
    return counts.most_common(limit)


def ranking_fast_reverters(events, limit=3, minimum=3):
    values = defaultdict(list)
    for item in events:
        if (
            item.get("kind") == "revert"
            and item.get("actor")
            and item.get("latency") is not None
        ):
            values[item["actor"]].append(float(item["latency"]))

    ranking = []
    for actor, times in values.items():
        if len(times) >= minimum:
            ranking.append((actor, median(times), len(times)))

    ranking.sort(key=lambda item: (item[1], -item[2], item[0].casefold()))
    return ranking[:limit]


def wikitext_ranking_table(title, ranking, value_label="Ações"):
    lines = [
        f"=== {title} ===",
        '{| class="wikitable sortable"',
        "! Pos. !! Editor !! " + value_label,
    ]

    medals = ["🥇", "🥈", "🥉"]
    if not ranking:
        lines.append("|-")
        lines.append("| colspan=\"3\" | ''Sem dados suficientes.''")
    else:
        for index, item in enumerate(ranking[:3]):
            actor = item[0]
            value = item[1]
            lines.extend([
                "|-",
                f"| {medals[index]} {index + 1} || {wiki_user_link(actor)} || {value}",
            ])

    lines.append("|}")
    return "\n".join(lines)


def wikitext_fast_reverters_table(ranking):
    lines = [
        "=== Reversões mais rápidas ===",
        "''Mediana do tempo entre o alerta do bot e a detecção da reversão; mínimo de 3 reversões no período.''",
        '{| class="wikitable sortable"',
        "! Pos. !! Editor !! Mediana !! Reversões",
    ]

    medals = ["🥇", "🥈", "🥉"]
    if not ranking:
        lines.extend(["|-", "| colspan=\"4\" | ''Sem dados suficientes.''"])
    else:
        for index, (actor, seconds, count) in enumerate(ranking[:3]):
            lines.extend([
                "|-",
                f"| {medals[index]} {index + 1} || {wiki_user_link(actor)} || "
                f"{format_minutes(seconds)} || {count}",
            ])

    lines.append("|}")
    return "\n".join(lines)


def wikitext_counter_table(title, counter, label, top=10):
    lines = [
        f"=== {title} ===",
        '{| class="wikitable sortable"',
        f"! Pos. !! {label} !! Casos !! Visual",
    ]

    values = counter.most_common(top)
    maximum = values[0][1] if values else 1

    if not values:
        lines.extend(["|-", "| colspan=\"4\" | ''Sem dados suficientes.''"])
    else:
        for index, (name, count) in enumerate(values, 1):
            bars = max(1, round((count / maximum) * 12))
            visual = "█" * bars
            display = (
                wiki_page_link(name)
                if label == "Página"
                else str(name).replace("|", "&#124;")
            )
            lines.extend([
                "|-",
                f"| {index} || {display} || {count} || <code>{visual}</code>",
            ])

    lines.append("|}")
    return "\n".join(lines)


def channel_check_level(percent):
    """
    Classificação simples e transparente da cobertura de resposta observada.
    Não representa visualização do Telegram; mede ações detectadas na Wikipédia.
    """
    if percent >= 85:
        return "Muito alto"
    if percent >= 70:
        return "Alto"
    if percent >= 50:
        return "Moderado"
    if percent >= 30:
        return "Baixo"
    return "Muito baixo"


def channel_capacity_level(percent, pending_count):
    """
    Capacidade observada de absorver a demanda de alertas.
    Usa a fração de alertas elegíveis que recebeu resposta comunitária.
    """
    if percent >= 85 and pending_count <= 3:
        return "Folga"
    if percent >= 70:
        return "Adequada"
    if percent >= 50:
        return "Pressionada"
    return "Sobrecarregada"


def channel_response_metrics(start_ts, end_ts):
    """
    Calcula resposta aos posts realmente publicados pelo bot.

    - alerta: post acompanhado enviado ao Telegram;
    - ação comunitária: revertido por outro editor, patrulhado ou eliminado;
    - autorreversão: resolvida pelo próprio autor, portanto sai da demanda
      comunitária e não melhora artificialmente o índice do canal.
    """
    events = community_events_between(start_ts, end_ts)

    alerts = {}
    actions = {}
    self_reverts = set()
    action_times = []

    for item in events:
        try:
            revision_id = int(item.get("revision_id"))
        except Exception:
            continue

        kind = item.get("kind")

        if kind == "alert":
            alerts[revision_id] = item

        elif kind in ("revert", "patrol", "delete", "resolved_no_action"):
            # Uma revisão conta uma única vez como respondida, mesmo que tenha
            # mais de uma ação posterior.
            previous = actions.get(revision_id)
            if previous is None or float(item.get("timestamp", 0)) < float(previous.get("timestamp", 0)):
                actions[revision_id] = item

        elif kind == "self_revert":
            self_reverts.add(revision_id)

    false_positive_ids = false_positive_revision_ids()

    eligible_ids = [
        revision_id
        for revision_id in alerts
        if revision_id not in self_reverts
        and revision_id not in false_positive_ids
    ]

    handled_ids = [
        revision_id
        for revision_id in eligible_ids
        if revision_id in actions
    ]

    pending_ids = [
        revision_id
        for revision_id in eligible_ids
        if revision_id not in actions
    ]

    for revision_id in handled_ids:
        alert_ts = float(alerts[revision_id].get("timestamp", 0))
        action_ts = float(actions[revision_id].get("timestamp", 0))
        if alert_ts and action_ts >= alert_ts:
            action_times.append(action_ts - alert_ts)

    total = len(alerts)
    eligible = len(eligible_ids)
    handled = len(handled_ids)
    pending = len(pending_ids)
    self_reverted = len(self_reverts.intersection(alerts.keys()))

    reversed_count = sum(
        1
        for revision_id in handled_ids
        if actions[revision_id].get("kind") == "revert"
    )
    patrolled_count = sum(
        1
        for revision_id in handled_ids
        if actions[revision_id].get("kind") == "patrol"
    )
    deleted_count = sum(
        1
        for revision_id in handled_ids
        if actions[revision_id].get("kind") == "delete"
    )
    resolved_no_action = sum(
        1
        for revision_id in handled_ids
        if actions[revision_id].get("kind") == "resolved_no_action"
    )

    handled_pct = handled / eligible * 100 if eligible else 0.0
    pending_pct = pending / eligible * 100 if eligible else 0.0
    median_action = median(action_times) if action_times else None

    period_hours = max((end_ts - start_ts) / 3600.0, 0.001)
    alerts_per_hour = total / period_hours
    actions_per_hour = handled / period_hours

    return {
        "posts": total,
        "eligible": eligible,
        "handled": handled,
        "handled_pct": handled_pct,
        "pending": pending,
        "pending_pct": pending_pct,
        "self_reverted": self_reverted,
        "reversed": reversed_count,
        "patrolled": patrolled_count,
        "deleted": deleted_count,
        "resolved_no_action": resolved_no_action,
        "median_action_seconds": median_action,
        "alerts_per_hour": alerts_per_hour,
        "actions_per_hour": actions_per_hour,
        "check_level": channel_check_level(handled_pct),
        "capacity_level": channel_capacity_level(handled_pct, pending),
    }


def format_channel_response_summary(metrics):
    return (
        f"👀 Posts vistos com desfecho: "
        f"{metrics['handled']}/{metrics['eligible']} "
        f"({format_percent(metrics['handled_pct'])})\n"
        f"↩️ Revertidos: {metrics['reversed']}\n"
        f"🛡️ Patrulhados: {metrics['patrolled']}\n"
        f"✅ Vistos sem ação necessária: {metrics['resolved_no_action']}\n"
        f"🗑️ Eliminados: {metrics['deleted']}\n"
        f"📥 Ainda sem desfecho: {metrics['pending']} "
        f"({format_percent(metrics['pending_pct'])})\n"
        f"↩️ Autorrevertidos: {metrics['self_reverted']} "
        f"(não contam como resposta comunitária)\n"
        f"🔎 Nível de checagem: {metrics['check_level']}\n"
        f"⚙️ Capacidade observada: {metrics['capacity_level']} "
        f"({metrics['actions_per_hour']:.1f} respostas/h para "
        f"{metrics['alerts_per_hour']:.1f} alertas/h)\n"
        f"⏱ Mediana até primeiro desfecho: "
        f"{format_minutes(metrics['median_action_seconds'])}"
    )



def build_wiki_community_report(start_ts, end_ts, period_label):
    events = community_events_between(start_ts, end_ts)
    response_metrics = channel_response_metrics(start_ts, end_ts)
    false_positive_metrics = false_positive_management_metrics(start_ts, end_ts)

    reversions = ranking_counts(events, "revert")
    patrols = ranking_counts(events, "patrol")
    protections = ranking_counts(events, "protect")
    blocks = ranking_counts(events, "block")
    deletions = ranking_counts(events, "delete")
    fast = ranking_fast_reverters(events)

    vandal_pages = Counter()
    vandal_categories = Counter()

    # "revert" e "delete" são tratados como desfechos confirmados dos alertas.
    for item in events:
        if item.get("kind") not in ("revert", "delete"):
            continue
        if item.get("title"):
            vandal_pages[item["title"]] += 1
        for category in item.get("categories") or []:
            vandal_categories[category] += 1

    total_reverts = sum(1 for x in events if x.get("kind") == "revert")
    total_patrols = sum(1 for x in events if x.get("kind") == "patrol")
    total_protections = sum(1 for x in events if x.get("kind") == "protect")
    total_blocks = sum(1 for x in events if x.get("kind") == "block")
    total_deletions = sum(1 for x in events if x.get("kind") == "delete")
    total_resolved_no_action = sum(
        1 for x in events if x.get("kind") == "resolved_no_action"
    )

    return "\n\n".join([
        f"= Relatório de manutenção e análise de edições incorretas — {period_label} =",
        "''Relatório experimental produzido pelo TelesGramBot. "
        "Os rankings descrevem somente eventos observados pelo bot e não devem "
        "ser interpretados como avaliação global de mérito dos editores.''",
        "== Resumo ==",
        '{| class="wikitable"',
        "! Indicador !! Total",
        "|-",
        f"| Reversões detectadas || {total_reverts}",
        "|-",
        f"| Patrulhamentos identificados || {total_patrols}",
        "|-",
        f"| Proteções/alterações de proteção || {total_protections}",
        "|-",
        f"| Bloqueios/rebloqueios || {total_blocks}",
        "|-",
        f"| Eliminações ligadas a alertas || {total_deletions}",
        "|-",
        f"| Vistos sem ação necessária || {total_resolved_no_action}",
        "|-",
        f"| Posts acompanhados pelo canal || {response_metrics['posts']}",
        "|-",
        f"| Posts elegíveis para resposta comunitária || {response_metrics['eligible']}",
        "|-",
        f"| Posts com ação detectada || {response_metrics['handled']} ({format_percent(response_metrics['handled_pct'])})",
        "|-",
        f"| Nível de checagem || {response_metrics['check_level']}",
        "|-",
        f"| Capacidade observada || {response_metrics['capacity_level']}",
        "|-",
        f"| Falsos positivos reportados || {false_positive_metrics['reported']}",
        "|-",
        f"| Falsos positivos com ajuste concluído || {false_positive_metrics['adjusted']}",
        "|-",
        f"| Falsos positivos aguardando ajuste ao fim do período || {false_positive_metrics['backlog']}",
        "|}",
        "== Capacidade de resposta do canal ==",
        '{| class="wikitable"',
        "! Indicador !! Resultado",
        "|-",
        f"| Posts vistos com desfecho || {response_metrics['handled']} de {response_metrics['eligible']} ({format_percent(response_metrics['handled_pct'])})",
        "|-",
        f"| Revertidos || {response_metrics['reversed']}",
        "|-",
        f"| Patrulhados || {response_metrics['patrolled']}",
        "|-",
        f"| Vistos sem ação necessária || {response_metrics['resolved_no_action']}",
        "|-",
        f"| Eliminados || {response_metrics['deleted']}",
        "|-",
        f"| Ainda sem desfecho || {response_metrics['pending']} ({format_percent(response_metrics['pending_pct'])})",
        "|-",
        f"| Autorreversões || {response_metrics['self_reverted']}",
        "|-",
        f"| Alertas por hora || {response_metrics['alerts_per_hour']:.1f}",
        "|-",
        f"| Respostas por hora || {response_metrics['actions_per_hour']:.1f}",
        "|-",
        f"| Mediana até primeira ação || {format_minutes(response_metrics['median_action_seconds'])}",
        "|}",
        "''O Telegram não fornece ao bot uma lista de quem leu cada post. "
        "Por isso, o nível de checagem é uma estimativa baseada em ações "
        "observáveis na Wikipédia, não uma taxa literal de visualização.''",
        "== Gestão de falsos positivos e melhoria do detector ==",
        '{| class="wikitable"',
        "! Indicador !! Resultado",
        "|-",
        f"| Reportados no período || {false_positive_metrics['reported']}",
        "|-",
        f"| Ajustes concluídos no período || {false_positive_metrics['adjusted']}",
        "|-",
        f"| Aguardando ajuste ao fim do período || {false_positive_metrics['backlog']}",
        "|-",
        f"| Taxa de fechamento dos reportados no período || {format_percent(false_positive_metrics['close_rate'])}",
        "|-",
        f"| Mediana entre reporte e ajuste || {format_minutes(false_positive_metrics['median_adjustment_seconds'])}",
        "|}",
        "''Cada falso positivo confirmado alimenta um ciclo de melhoria do detector. "
        "Isso significa revisão e ajuste das regras do bot; não há retreinamento automático do modelo.''",
        "== Reconhecimento de trabalho de manutenção ==",
        wikitext_ranking_table("Mais reversões", reversions, "Reversões"),
        wikitext_fast_reverters_table(fast),
        wikitext_ranking_table("Mais patrulhamentos", patrols, "Patrulhamentos"),
        wikitext_ranking_table("Mais proteções", protections, "Proteções"),
        wikitext_ranking_table("Mais bloqueios", blocks, "Bloqueios"),
        wikitext_ranking_table("Mais eliminações ligadas a alertas", deletions, "Eliminações"),
        "== Onde ocorreram edições incorretas confirmadas ==",
        wikitext_counter_table(
            "Páginas com mais ocorrências",
            vandal_pages,
            "Página",
            top=10,
        ),
        wikitext_counter_table(
            "Categorias mais afetadas",
            vandal_categories,
            "Categoria",
            top=10,
        ),
        "== Metodologia ==",
        "* Reversão: alerta acompanhado pelo bot que recebeu confirmação de reversão.",
        "* Rapidez: mediana do tempo entre publicação do alerta e detecção da reversão; "
        "exige pelo menos três reversões no período.",
        "* Patrulhamento: somente quando o bot consegue relacionar o evento ao registro de patrulha e identificar o executor.",
        "* Proteções, bloqueios e eliminações: baseados nos registros públicos da Wikipédia observados pelo bot.",
        "* Categorias: capturadas da página quando o caso confirmado é processado; podem não estar disponíveis após eliminação.",
        "* Nível de checagem: percentual dos alertas elegíveis que receberam reversão por terceiro, patrulhamento, eliminação ou resolução manual sem ação necessária.",
        "* Patrulhamento: desfecho próprio e separado, indicando que a edição foi marcada como patrulhada na Wikipédia.",
        "* Resolução sem ação necessária: confirmação manual por administrador do canal de que a edição foi vista e não exige intervenção; não é tratada como patrulhamento.",
        "* Falso positivo: edição marcada por administrador como edição válida; o diff entra como exemplo dessa classe no arquivo de padrões.",
        "* Padrões de IA: revertidas/eliminadas são exemplos de edições incorretas; patrulhadas/falsos positivos são exemplos de edições válidas. A semelhança é informativa e não altera o risco nem as regras do detector.",
        "* Faixas de checagem: muito alto ≥85%; alto 70–84%; moderado 50–69%; baixo 30–49%; muito baixo <30%.",
        "* Capacidade observada: folga quando ≥85% e backlog muito pequeno; adequada ≥70%; pressionada 50–69%; sobrecarregada <50%.",
        "* Autorreversões são retiradas da demanda comunitária e não melhoram artificialmente o índice.",
        "* Os dados começam a ser coletados a partir da implantação desta versão; não há reconstrução histórica automática.",
    ])


def wiki_state_label(enabled):
    color = "#006400" if enabled else "#8B0000"
    return f'<span style="color:{color};font-weight:bold">{"Habilitada" if enabled else "Desabilitada"}</span>'


def wiki_safe_username(username):
    # Apenas nomes obtidos de eventos wiki; nunca nomes/IDs de operadores Telegram.
    name = str(username or "").strip()
    if not name or any(ch in name for ch in "\n\r[]{}|<>"):
        return None
    return name[:255]


def wiki_review_events():
    with community_stats_lock:
        return [dict(x) for x in community_stats.get("events", []) if isinstance(x, dict)]


def build_wiki_reviewers_wikitext():
    totals = defaultdict(Counter)
    for event in wiki_review_events():
        kind = event.get("kind")
        if kind not in ("patrol", "delete", "revert"):
            continue
        actor = wiki_safe_username(event.get("actor"))
        if actor:
            totals[actor][kind] += 1
    ranking = sorted(totals.items(), key=lambda x: (-sum(x[1].values()), x[0].casefold()))[:20]
    lines = ["=== Revisores — 20 maiores totais observados ===",
             "''Somente ações públicas da Wikipédia registradas pelo bot; não é um ranking histórico completo. "
             "Os eventos são retidos por até 400 dias. Nenhuma identidade do Telegram é publicada.''",
             '{| class="wikitable sortable"',
             "! Pos. !! Conta da Wikipédia !! Patrulhas !! Eliminações !! Reversões !! Total"]
    for position, (actor, counts) in enumerate(ranking, 1):
        patrol, delete, revert = (counts[k] for k in ("patrol", "delete", "revert"))
        lines += ["|-", f"| {position} || {wiki_user_link(actor)} || {patrol} || {delete} || {revert} || {patrol + delete + revert}"]
    if not ranking:
        lines += ["|-", '| colspan="6" | Nenhuma ação identificada.']
    lines += ["|}", "''Cada evento registrado conta uma vez; ações não observadas não são estimadas.''"]
    return "\n".join(lines)


def wiki_observed_block_status(names):
    """Consulta pública, em lote; falha = não verificado, nunca 'não bloqueada'."""
    result = {name: "Não verificado" for name in names}
    if not names:
        return result
    for offset in range(0, len(names), 50):
        batch = names[offset:offset + 50]
        try:
            _, data = wikimedia_api_get({"action": "query", "format": "json", "formatversion": 2,
                                         "list": "blocks", "bkusers": "|".join(batch), "bklimit": "max",
                                         "bkprop": "user|restrictions"}, timeout=25)
            if data.get("error"):
                continue
            blocks = (data.get("query") or {}).get("blocks", [])
            for name in batch:
                result[name] = "Não bloqueada"
            for block in blocks:
                name = block.get("user")
                if name in result:
                    result[name] = "Bloqueio parcial" if block.get("restrictions") else "Bloqueada"
        except Exception as exc:
            print("⚠️ Falha ao consultar bloqueios para relatório:", safe_exception(exc))
    return result


def build_wiki_observations_wikitext():
    now = time.time()
    with observed_users_lock:
        observations = [dict(item) for item in observed_users.values()
                        if float(item.get("expires_at") or 0) > now]
    observations.sort(key=lambda item: str(item.get("username") or "").casefold())
    names = [name for item in observations if (name := wiki_safe_username(item.get("username")))]
    statuses = wiki_observed_block_status(names)
    lines = ["=== Contas em observação ===", "''Somente contas da Wikipédia. Nenhum observador ou identificador do Telegram é divulgado.''",
             '{| class="wikitable sortable"', "! Conta !! Bloqueio na última consulta !! Tempo restante na geração"]
    for item in observations:
        name = wiki_safe_username(item.get("username"))
        if not name:
            continue
        status = statuses.get(name, "Não verificado")
        color = "#8B0000" if status in ("Bloqueada", "Bloqueio parcial") else ("#006400" if status == "Não bloqueada" else "#8B6508")
        remaining = max(0, int(float(item["expires_at"]) - now))
        lines += ["|-", f'| {wiki_user_link(name)} || <span style="color:{color}">{status}</span> || {remaining // 3600}h {(remaining % 3600) // 60:02d}min']
    if not names:
        lines += ["|-", '| colspan="3" | Nenhuma conta em observação.']
    lines += ["|}"]
    return "\n".join(lines)


# Histórico explícito: nunca inferir notas de versões anteriores.
WIKI_RELEASE_NOTES = {
    "2.46": "Tempo de reversão, desfechos, classificações, saúde operacional, tendências e histórico diário de versões.",
    "2.49": "Aprendizagem supervisionada de padrões nos desfechos da lista de alto risco; semelhança informativa, sem alterar a pontuação.",
    "2.50": "Calibração de traduções equivalentes de datas em referências e mudanças exclusivamente de espaços/linhas vazias.",
    "2.51": "Calibração de inclusão isolada de wikilinks e remoção de referências conforme justificativa; correção das notas de versão e atualização do anúncio no Telegram.",
    "2.52": "Controles independentes de pausa e retomada da escrita na Wikipédia em português e na Test Wikipedia, com estado persistente e filas preservadas.",
    "2.53": "Correção do anúncio de versão no Telegram: confirmação de entrega, recuperação de estado incompleto e novas tentativas automáticas após falhas.",
    "2.54": "Calibração de alterações isoladas no número de filhos (+1 com cautela; saltos maiores suspeitos) e acréscimos curtos de prosa contextual, sem validar automaticamente fatos.",
    "2.55": "Cada nova versão publica um anúncio novo no Telegram, preservando mensagens anteriores; confirmação persistente e novas tentativas após falhas, sem republicação retroativa.",
    "2.56": "Proteção contra publicação de estatísticas vazias, descarte de relatórios zerados na fila e preservação do arquivo original quando a leitura falha.",
    "2.57": "Correção da captura das diferenças para a lista de alto risco na Test Wikipedia, com parser compatível com classes adicionais do MediaWiki e fallback pelo conteúdo das revisões.",
    "2.58": "Visualização lado a lado do diferencial, destaque dos trechos alterados e variação em bytes.",
    "2.59": "Saldo de bytes em destaque na segunda linha e reforço da recuperação das atualizações de estado no Telegram.",
    "2.60": "Lista de alto risco da Test Wikipedia passa a aceitar edições acima de 80%; mantém amarelo até 95%, vermelho acima de 95% e azul para revisadas. Corrige a identificação persistente do anúncio de cada nova versão no Telegram.",
    "2.61": "Revisão manual das edições de alto risco por usuários autorizados, com validação de grupos na ptwiki, resolução por revid e opção de desfazer.",
    "2.62": "Revisões manuais consolidadas em uma única página na Test Wiki, usando novas seções para reduzir criação de subpáginas e evitar regravação concorrente; teste temporariamente liberado a todos os usuários.",
    "2.63": "Revisão manual também nos arquivos dos últimos 30 dias, carregamento silencioso fora das páginas de alto risco, atualização prioritária após decisão e limpeza semanal da página única de revisões manuais.",
    "3.0": "Revisão manual segura via OAuth 2.0 Wikimedia: o revisor é autenticado no servidor, grupos da ptwiki são validados no backend, e o TelesGramBot executa as atualizações técnicas na Wiki e no Telegram.",
    "3.08": "Proteção contra spamblacklist nas prévias publicadas na Test Wiki, com neutralização segura de domínios e uma única nova tentativa de escrita quando necessário.",
    "3.09": "Proteção da persistência dos posts acompanhados no Telegram entre deploys e reinícios, com backup e diagnóstico de restauração.",
    "3.10": "Calendário por data com amarelo para dias com revisões pendentes e azul para dias sem pendências; cartões com layout mais estável, percentual maior e data/hora sob o indicador de risco.",
    "3.11": "Correção definitiva das notas de versão no Telegram e registro das mudanças recentes, preservando as melhorias da 3.10.",
    "3.12": "Purge automático da página principal após publicação, percentual de risco mais legível e terminologia pública revisada para edição válida, edição incorreta e risco de erro.",
    "3.13": "Cabeçalho com atalhos centralizados para os sete dias mais recentes, caixas amarelas para dias com pendências e azuis para dias sem pendências.",
    "3.14": "Corrige falha NoneType no registro de alertas do sender e faz decisões manuais na página de revisão resolverem automaticamente a pendência sem ação adicional no Telegram.",
    "3.15": "Corrige o layout da prévia Antes/Depois para conter textos, URLs, referências e sequências longas dentro do cartão, sem alterar as demais funcionalidades da 3.14.",
    "3.16": "Integra o botão Falso positivo da revisão Wiki ao mesmo fluxo de falsos positivos do Telegram, preservando lista e resolução existentes.",
    "3.17": "Aumenta somente o percentual no indicador de risco e consolida reversões por terceiros como exemplos de vandalismo ou erro no aprendizado, mantendo autorreversões excluídas.",
    "3.18": "Amplia novamente o percentual de risco e corrige o alinhamento do indicador para mantê-lo dentro do cartão.",
    "3.19": "Exibe o estado de bloqueio da conta ao lado de Estado enquanto o caso está pendente e congela o último estado após a resolução.",
    "3.20": "Reduz e contém o indicador percentual dentro do cartão de alto risco, preservando legibilidade e demais funções da 3.19.",
    "3.21": "Adiciona monitoramento de páginas novas por heurísticas locais, mantendo Revert Risk apenas para edições de páginas existentes.",
    "3.22": "Corrige o monitoramento de filtros de abuso vigiados, associando cada ocorrência diretamente ao ID do filtro consultado.",
    "3.23": "Restaura as descrições dos anúncios de versão e torna a desmarcação de falso positivo transacional, sem perder a marcação quando a atualização do Telegram falha.",
    "3.24": "Calibra páginas novas com redutores imediatos por interwikis via Wikidata, referências e imagens, exibindo os sinais positivos no alerta.",
    "3.25": "Impede adicionar filtros de abuso privados à vigilância e informa que a restrição decorre dos direitos atuais da conta TelesGramBot.",
    "3.26": "Centraliza a estrutura visual dos cartões de alto risco em uma predefinição reutilizável na TestWiki, reduzindo o wikitext repetido sem alterar revisão, risco ou sincronização.",
    "3.27": "Corrige a passagem de parâmetros para a predefinição de alto risco: pipes usam {{!}} e o temporizador é construído pela própria predefinição, evitando erro de expressão e vazamento de parâmetros no cartão.",
    "3.28": "Neutraliza chaves e pipes do conteúdo variável antes de passá-lo à predefinição, impedindo que wikitext presente no diff encerre a chamada do cartão ou seja interpretado como novos parâmetros.",
    "3.29": "Melhora a separação visual dos cartões com espaçamento, cantos discretos e sombra suave, e evita dupla codificação das entidades HTML exibidas na prévia dos diffs.",
    "3.30": "Adiciona anti-flood aos filtros de abuso vigiados: no máximo um post por combinação filtro e usuário a cada 5 minutos, sem renovar a janela quando ocorrências adicionais são ignoradas.",
    "3.31": "Prioriza no topo da lista de alto risco as edições pendentes, ordenadas pelo maior percentual de risco, recua o indicador percentual da borda direita, liga o nome da conta nos alertas de filtro às contribuições e coloca automaticamente em observação por 6 horas as contas que geram alertas publicados de filtros vigiados; mensagens posteriores dessa observação mantêm o botão Desobservar; e os posts de edições exibem abaixo do sumário a variação em bytes, com indicador verde para acréscimo e vermelho para remoção.",
    "3.32": "Adiciona links para páginas nas confirmações de vigilância no Telegram e cria log administrativo padronizado de alterações em /Ajustes, integrado ao limite global de uma edição por hora na ptwiki.",
    "3.33": "Calibra edições estruturadas legítimas: parâmetros de predefinição, preenchimento de datas, desambiguação de wikilinks e adição de referências válidas passam a reduzir o risco sem mascarar alterações adicionais.",
    "3.34": "Amplia a calibração contextual para wikilinks cosméticos, trocas plausíveis de nomes, mídia e reformatação de infobox, pequenas variações numéricas, grandes adições construtivas com fontes e comentários assinados em discussão; corrige também o redutor de desambiguação da 3.33.",
    "3.35": "Impede que apóstrofos do diferencial alterem a formatação dos cartões seguintes e melhora /Ajustes com data, indicação única de UTC e legenda explicada somente para as categorias.",
    "3.36": "Prepara a lista de alto risco para a ptwiki com fila persistente de duas horas, revalidação comunitária e publicação desativada por padrão até a conclusão do modo de observação.",
}
WIKI_RELEASE_HISTORY_FILE = data_path("wiki_release_history.json")


def telegram_page_link_html(title):
    """Link HTML seguro para uma página da Wikipédia em português."""
    clean_title = normalize_page_title(title) or str(title or "").strip()
    encoded_title = quote(clean_title.replace(" ", "_"), safe="/:()")
    url = f"https://pt.wikipedia.org/wiki/{encoded_title}"
    return f'<a href="{html.escape(url, quote=True)}">{html.escape(clean_title)}</a>'


def fetch_wiki_page_wikitext(title):
    """Lê o wikitext atual de uma subpágina autorizada; página ausente retorna vazio."""
    if not wiki_title_is_allowed(title):
        raise PermissionError("Título wiki não autorizado")
    _response, data = wikimedia_api_get({
        "action": "query", "format": "json", "formatversion": 2,
        "prop": "revisions", "titles": title, "rvprop": "content", "rvslots": "main",
    })
    if data.get("error"):
        raise RuntimeError("Falha ao ler página wiki: " + str(data["error"]))
    pages = ((data or {}).get("query") or {}).get("pages") or []
    if not pages or pages[0].get("missing"):
        return ""
    revisions = pages[0].get("revisions") or []
    if not revisions:
        return ""
    slot = (revisions[0].get("slots") or {}).get("main") or {}
    return str(slot.get("content") or "")


def queue_current_adjustments_log():
    """Prepara o registro curto desta versão; a fila global decide quando a ptwiki pode ser editada."""
    marker = f"[v{BOT_VERSION}]"
    current = fetch_wiki_page_wikitext(WIKI_ADJUSTMENTS_TITLE)
    if marker in current:
        return False
    now_utc = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M")
    version_entries = {
        "3.32": [
            ("#3366cc", "💬", "TG-WATCH", "CHANGED", "Confirmação de vigilância agora vincula o título à página."),
            ("#14866d", "📋", "WIKI-LOG", "ADDED", "Log administrativo de ajustes integrado à fila global da ptwiki."),
        ],
        "3.33": [
            ("#7a4e00", "🎯", "RISK-CAL", "CHANGED", "Reduz risco em parâmetros wiki, datas preenchidas, links desambiguados e referências estruturadas."),
        ],
        "3.34": [
            ("#7a4e00", "🎯", "RISK-CAL", "CHANGED", "Refina wikilinks, nomes, infoboxes, números, grandes acréscimos com fontes e discussões assinadas."),
            ("#3366cc", "🖥️", "WIKI-UI", "CHANGED", "Ajustes remove ponto duplicado e ganha legenda compacta de códigos e estados."),
            ("#b32424", "🐛", "FIX", "FIXED", "Corrigido redutor de desambiguação da 3.33 no analisador de edições."),
        ],
        "3.35": [
            ("#b32424", "🐛", "FIX", "FIXED", "A prévia Antes/Depois neutraliza apóstrofos sem perder o destaque das diferenças."),
            ("#3366cc", "🖥️", "WIKI-UI", "CHANGED", "Ajustes passa a exibir data e hora, com UTC indicado uma única vez e legenda explicada das categorias."),
        ],
        "3.36": [
            ("#7a4e00", "🎯", "RISK-QUEUE", "ADDED", "Edições de alto risco aguardam duas horas e são revalidadas antes da publicação."),
            ("#3366cc", "🖥️", "WIKI-PT", "CHANGED", "Lista de alto risco preparada para subpáginas controladas da ptwiki, com ativação explícita."),
            ("#b32424", "🛡️", "SAFE-WRITE", "ADDED", "Escritas usam fila única, conflito de edição, maxlag e confirmação de identidade do bot."),
        ],
    }
    specs = version_entries.get(BOT_VERSION, [
        ("#72777d", "⚙️", "CORE", "CHANGED", WIKI_RELEASE_NOTES.get(BOT_VERSION, "Ajustes internos do bot.")),
    ])
    entries = [
        f"* <span style=\"color:{color}\">{now_utc}</span> {emoji} '''{code}''' {marker} {status} — {message}"
        for color, emoji, code, status, message in specs[:3]
    ]
    header = "== Registro de ajustes =="
    legend = (
        "<small>'''Categorias:''' "
        "🎯 RISK-CAL = calibração de risco · "
        "💬 TG = Telegram · "
        "🛡️ SEC = segurança · "
        "🖥️ WIKI-UI = interface na Wikipédia · "
        "⚙️ CORE = núcleo do bot · "
        "📊 METRIC = métricas · "
        "🐛 FIX = correções · "
        "🚀 INFRA = infraestrutura.<br>"
        "''Datas e horários em UTC.''</small>"
    )
    body = current.strip()
    if body.startswith(header):
        body = body[len(header):].lstrip()
        body = re.sub(r"^<small>'''Categorias:'''[\s\S]*?</small>\s*", "", body, count=1)
        body = re.sub(r'(?m)^(\*\s*<span\s+style="color:[^"]+">)•\s*', r'\1', body)
    new_text = header + "\n\n" + legend + "\n\n" + "\n".join(entries)
    if body:
        new_text += "\n" + body
    return queue_wiki_edit(
        WIKI_ADJUSTMENTS_TITLE,
        new_text,
        f"Registrando ajustes administrativos do TelesGramBot {BOT_VERSION}",
    )


def wiki_record_release():
    """Registra esta versão no volume persistente, sem duplicar em reinícios."""
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_RELEASE_HISTORY_FILE, {"releases": []})
        releases = state.get("releases", [])
        if not isinstance(releases, list):
            releases = []
        if not any(isinstance(x, dict) and x.get("build") == BOT_BUILD for x in releases):
            releases.append({"version": BOT_VERSION, "build": BOT_BUILD,
                             "timestamp": time.time(), "notes": WIKI_RELEASE_NOTES.get(BOT_VERSION, "Alterações não descritas para esta versão.")})
            atomic_write_json(WIKI_RELEASE_HISTORY_FILE, {"releases": releases[-150:]})


def wiki_daily_release_wikitext():
    tz = ZoneInfo(REPORT_TIMEZONE)
    today = datetime.now(tz).date()
    entries = load_json(WIKI_RELEASE_HISTORY_FILE, {"releases": []}).get("releases", [])
    rows = []
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            moment = datetime.fromtimestamp(float(item["timestamp"]), tz)
        except (KeyError, ValueError, TypeError, OverflowError):
            continue
        if moment.date() == today:
            version = str(item.get("version", "")).replace("|", "&#124;")
            notes = str(item.get("notes", "Sem descrição registrada.")).replace("|", "&#124;").replace("<", "&lt;")
            rows.append((moment, version, notes))
    lines = ["=== Atualizações do dia ===", "''Versões registradas pelo bot no volume persistente; histórico anterior não é reconstruído.''",
             '{| class="wikitable"', "! Horário (Brasília) !! Versão !! Alterações"]
    for moment, version, notes in sorted(rows, reverse=True):
        lines.extend(["|-", f"| {moment:%H:%M} || {version} || {notes}"])
    if not rows:
        lines.extend(["|-", '| colspan="3" | Nenhuma versão registrada hoje.'])
    return "\n".join(lines + ["|}"])


def wiki_health_wikitext():
    now = time.time()
    with stream_lock:
        last = last_stream_event_at
        connected = current_stream_response is not None and last is not None and now - last <= STREAM_STALL_SECONDS
    state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": []})
    pending = state.get("pending", [])
    pending = pending if isinstance(pending, list) else []
    latest = state.get("last_success_at")
    failures = state.get("write_failures", [])
    failures = [x for x in failures if isinstance(x, (int, float)) and now - x <= 86400] if isinstance(failures, list) else []
    last_label = datetime.fromtimestamp(last, ZoneInfo(REPORT_TIMEZONE)).strftime("%d/%m/%Y %H:%M:%S") if last else "Não registrado"
    success_label = datetime.fromtimestamp(latest, ZoneInfo(REPORT_TIMEZONE)).strftime("%d/%m/%Y %H:%M:%S") if latest else "Não registrado"
    return "\n".join(["=== Saúde do robô ===",
        f"* EventStreams: {wiki_state_label(connected)} (conexão com atividade recente; não garante processamento de todas as edições)",
        f"* Último evento recebido: {last_label} (horário de Brasília)",
        f"* Última publicação wiki confirmada: {success_label} (horário de Brasília)",
        f"* Falhas de escrita wiki nas últimas 24 horas: {len(failures)} (somente falhas registradas desde esta versão)",
        f"* Páginas na fila de escrita: {len(pending)}"])


def wiki_extended_statistics_wikitext():
    now = time.time()
    with community_stats_lock:
        events = [dict(e) for e in community_stats.get("events", []) if isinstance(e, dict)]
    with detection_stats_lock:
        detections = [dict(d) for d in detection_stats.get("records", []) if isinstance(d, dict)]
    with false_positives_lock:
        fp = [dict(x) for x in false_positives.values()]
    with false_negatives_lock:
        fn = [dict(x) for x in false_negatives.values()]
    # Desfecho prioritário e exclusivo por revisão; nunca equiparar reversão a vandalismo confirmado.
    alerts = {}
    outcomes = defaultdict(set)
    for event in events:
        rid = event.get("revision_id")
        if rid is None:
            continue
        kind = event.get("kind")
        if kind == "alert":
            alerts[rid] = event
        elif kind in ("revert", "self_revert", "patrol", "delete", "resolved_no_action"):
            outcomes[rid].add(kind)
    counts = Counter()
    for rid in alerts:
        kinds = outcomes[rid]
        if "self_revert" in kinds:
            counts["Autorrevertidas"] += 1
        elif "revert" in kinds:
            counts["Revertidas"] += 1
        elif "delete" in kinds or "patrol" in kinds or "resolved_no_action" in kinds:
            counts["Mantidas/revisadas sem reversão"] += 1
        else:
            counts["Pendentes sem desfecho registrado"] += 1
    # Tempo real edição -> reversão quando o detector reteve ambos os timestamps.
    durations = []
    for item in detections:
        try:
            start, end = float(item["posted_at"]), float(item["reverted_at"])
            if 0 <= end - start <= 400 * 86400:
                durations.append(end - start)
        except (KeyError, ValueError, TypeError):
            pass
    med = format_minutes(median(durations)) if durations else "Dados insuficientes"
    pct = f"{100 * sum(x <= 600 for x in durations) / len(durations):.1f}%" if durations else "Dados insuficientes"
    lines = ["=== Tempo até a reversão ===",
        "''Medido do registro do alerta até a reversão identificada, não necessariamente desde a edição original. Somente casos com ambos os horários disponíveis.''",
        f"* Reversões com tempos válidos: {len(durations)}", f"* Mediana: {med}",
        f"* Revertidas em até 10 minutos (entre as reversões com tempo válido): {pct}",
        "=== Destino dos alertas ===",
        "''Amostra: alertas publicados e retidos no histórico comunitário; categorias exclusivas, sem inferir vandalismo confirmado.''"]
    for label in ("Revertidas", "Mantidas/revisadas sem reversão", "Pendentes sem desfecho registrado", "Autorrevertidas"):
        n = counts[label]
        lines.append(f"* {label}: {n} ({100*n/len(alerts):.1f}%)" if alerts else f"* {label}: 0 (sem alertas registrados)")
    lines += ["=== Classificação humana e falsos positivos ===",
        f"* Falsos positivos reportados: {len(fp)}",
        f"* Falsos positivos com ajuste registrado: {sum(bool(x.get('resolved_at')) for x in fp)}",
        f"* Falsos negativos reportados: {len(fn)}",
        f"* Alertas sem classificação humana explícita: {sum(rid not in {x.get('revision_id') for x in fp} for rid in alerts)} (não implica acerto do algoritmo)",
        "* Precisão do algoritmo: não calculável com segurança sem classificação humana completa e amostra representativa.",
        "=== Curiosidades e tendências ===",
        "''Somente alertas observados pelo bot; distribuição não representa todas as edições da Wikipédia. Horário de Brasília.''"]
    tz = ZoneInfo(REPORT_TIMEZONE)
    hours, weekdays, months, pages = Counter(), Counter(), Counter(), Counter()
    for event in alerts.values():
        try:
            dt = datetime.fromtimestamp(float(event["timestamp"]), tz)
        except (KeyError, ValueError, TypeError, OverflowError):
            continue
        hours[f"{dt.hour:02d}:00–{dt.hour:02d}:59"] += 1
        weekdays[("Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo")[dt.weekday()]] += 1
        months[dt.strftime("%Y-%m")] += 1
        if event.get("title"):
            pages[str(event["title"])] += 1
    lines.append("==== Horários ====")
    lines.extend(f"* {key}: {value}" for key, value in sorted(hours.items()))
    lines.append("==== Dias da semana ====")
    lines.extend(f"* {key}: {value}" for key, value in weekdays.most_common())
    lines.append("==== Evolução mensal ====")
    lines.extend(f"* {key}: {value}" for key, value in sorted(months.items()))
    lines.append("==== Artigos/páginas mais sinalizados ====")
    lines.extend(f"* {wiki_page_link(title)}: {count}" for title, count in pages.most_common(10))
    if not alerts:
        lines.append("''Sem alertas suficientes para as distribuições.''")
    return "\n".join(lines)


def build_wiki_status_wikitext():
    writing_enabled, queued_edits = wiki_write_status_snapshot()
    pending_titles = wiki_pending_pages_snapshot()
    pending_lines = "\n".join("* [[" + title + "]]" for title in pending_titles) or "* Nenhuma página registrada"
    return "\n".join([
        "== Status do TelesGramBot ==",
        f"* Versão: {BOT_VERSION}",
        f"* Escrita na Wikipédia: {wiki_state_label(writing_enabled)}",
        f"* Criação de subpáginas autorizadas: {wiki_state_label(WIKI_CREATE_ENABLED)}",
        f"* Edições na fila de publicação: {queued_edits}",
        f"* Páginas aguardando atualização: {len(pending_titles)}",
        "* Intervalo mínimo entre tentativas de escrita: 60 minutos",
        "* Atualização programada do status: a cada 6 horas",
        wiki_health_wikitext(),
        wiki_daily_release_wikitext(),
        "=== Páginas e relatórios ===", pending_lines,
        f"* [[{WIKI_STATISTICS_TITLE}|Estatísticas, revisores e contas observadas]]",
        "=== Projetos e dependências ===",
        "* Criação limitada às páginas Status, Estatísticas e relatórios diários e mensais previstos.",
    ])


def build_wiki_statistics_wikitext():
    now = time.time()
    events = wiki_review_events()
    kinds = Counter(x.get("kind") for x in events)
    with false_positives_lock:
        fp_items = [dict(x) for x in false_positives.values()]
    with observed_users_lock:
        observed_count = sum(float(x.get("expires_at") or 0) > now for x in observed_users.values())
    return "\n".join([
        "== Estatísticas do TelesGramBot ==",
        "''Dados observados pelo bot dentro da janela de retenção. Ações não registradas não são estimadas.''",
        "=== Atividade agregada ===",
        f"* Falsos positivos registrados: {len(fp_items)}",
        f"* Falsos positivos com ajuste concluído: {sum(bool(x.get('resolved_at')) for x in fp_items)}",
        f"* Reversões identificadas: {kinds['revert']}",
        f"* Patrulhamentos identificados: {kinds['patrol']}",
        f"* Eliminações identificadas: {kinds['delete']}",
        f"* Resoluções sem ação necessária: {kinds['resolved_no_action']}",
        f"* Contas atualmente observadas: {observed_count}",
        "''Nenhum nome, @ ou identificador de operadores do Telegram é divulgado.''",
        wiki_extended_statistics_wikitext(),
        build_wiki_reviewers_wikitext(),
        build_wiki_observations_wikitext(),
    ])


def build_wiki_daily_and_monthly_previews(now=None):
    tz = ZoneInfo(REPORT_TIMEZONE)
    now = now or datetime.now(tz)

    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1)
    month_start = day_start.replace(day=1)

    if month_start.month == 12:
        next_month = month_start.replace(
            year=month_start.year + 1,
            month=1,
        )
    else:
        next_month = month_start.replace(month=month_start.month + 1)

    daily_title = WIKI_DAILY_REPORT_PREFIX + day_start.strftime("%Y-%m-%d")
    monthly_title = WIKI_MONTHLY_REPORT_PREFIX + month_start.strftime("%Y-%m")
    mark_wiki_page_pending(daily_title)
    mark_wiki_page_pending(monthly_title)

    daily_text = build_wiki_community_report(
        day_start.timestamp(),
        day_end.timestamp(),
        day_start.strftime("%d/%m/%Y"),
    )
    monthly_text = build_wiki_community_report(
        month_start.timestamp(),
        next_month.timestamp(),
        month_start.strftime("%m/%Y"),
    )

    preview = (
        f"<!-- TÍTULO DIÁRIO: {daily_title} -->\n"
        + daily_text
        + "\n\n"
        + f"<!-- TÍTULO MENSAL: {monthly_title} -->\n"
        + monthly_text
    )

    directory = os.path.dirname(WIKI_REPORT_PREVIEW_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)

    temp = WIKI_REPORT_PREVIEW_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as file:
        file.write(preview)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temp, WIKI_REPORT_PREVIEW_FILE)

    with community_stats_lock:
        community_stats["last_preview_date"] = now.date().isoformat()
    save_community_stats()

    # Chamadas deliberadamente bloqueadas nesta versão. Mantidas aqui para
    # deixar o fluxo de publicação pronto para uma futura liberação explícita.
    if WIKI_WRITE_ENABLED:
        queue_wiki_edit(
            daily_title,
            daily_text,
            "Atualizando relatório diário de manutenção e análise de edições incorretas",
        )
        queue_wiki_edit(
            monthly_title,
            monthly_text,
            "Atualizando painel mensal de manutenção e análise de edições incorretas",
        )

    return daily_title, monthly_title


# =========================================================
# VERSIONAMENTO
# =========================================================

def load_saved_bot_version():
    data = load_json(BOT_VERSION_FILE, {})

    if isinstance(data, dict):
        # Arquivos antigos guardavam apenas `version`. O fallback mantém
        # compatibilidade e faz a primeira build nova ser anunciada.
        build = data.get("build")
        if build:
            return str(build)
        version = data.get("version")
        if version:
            return str(version)

    return None


def save_bot_version(version, build=None):
    atomic_write_json(
        BOT_VERSION_FILE,
        {
            "version": version,
            "build": build or version,
            "updated_at": datetime.now(
                timezone.utc
            ).isoformat()
        }
    )

    print("💾 Versão/build registrada:", version, build or version)


_version_announcement_lock = threading.Lock()


def announce_new_version_if_needed():
    """Publica anúncio NOVO por build, sem editar anúncios de versões anteriores."""
    if not _version_announcement_lock.acquire(blocking=False):
        print("ℹ️ Anúncio de versão já em andamento; tentativa simultânea ignorada.")
        return False
    try:
        state = load_json(BOT_VERSION_FILE, {})
        if not isinstance(state, dict):
            state = {}
        # O ID é a confirmação persistente da build registrada. Não republicar
        # builds já anunciadas nem tentar recuperar anúncios de versões antigas.
        previous_id = state.get("announcement_message_id")
        # A identidade do anúncio inclui versão + build. Assim, mesmo que uma
        # build seja reutilizada por engano em uma versão futura, a nova versão
        # ainda gera uma postagem própria. Reinícios da mesma versão/build não
        # duplicam o anúncio.
        release_key = f"{BOT_VERSION}|{BOT_BUILD}"
        saved_release_key = state.get("announcement_release_key")
        if saved_release_key == release_key and previous_id:
            print("ℹ️ Anúncio desta versão/build já confirmado; ID:", previous_id)
            return True
        notes = WIKI_RELEASE_NOTES.get(BOT_VERSION, "Alterações desta versão não registradas.")
        message = (
            f"🤖 <b>TelesGramBot {html.escape(BOT_VERSION)}</b>\n"
            f"🔧 Build: <code>{html.escape(BOT_BUILD)}</code>\n\n"
            f"<b>Novidades desta versão</b>\n• {html.escape(notes)}"
        )
        # Uma build nova deve sempre usar sendMessage: editMessageText altera
        # o anúncio antigo sem criar postagem visível no final do canal.
        sent = send_telegram_message(message, parse_mode="HTML")
        if not isinstance(sent, dict) or not sent.get("message_id"):
            print("⚠️ Novo anúncio não confirmado pelo Telegram; nova tentativa em 5 minutos.")
            return False
        message_id = int(sent["message_id"])
        print("✅ Novo anúncio publicado:", message_id)
        # Persistir apenas após confirmação da API. Se a persistência falhar,
        # o worker poderá repetir; a mensagem anterior nunca será modificada.
        state.update({"version": BOT_VERSION, "build": BOT_BUILD,
                      "announcement_release_key": release_key,
                      "updated_at": datetime.now(timezone.utc).isoformat(),
                      "announcement_message_id": message_id})
        try:
            atomic_write_json(BOT_VERSION_FILE, state)
        except Exception as exc:
            print("⚠️ Anúncio entregue, mas estado não persistido; pode ser repetido após reinício:", safe_exception(exc))
            return False
        print("✅ Anúncio da versão confirmado e ID persistido:", message_id)
        return True
    finally:
        _version_announcement_lock.release()


def version_announcement_worker():
    """Recupera falhas transitórias sem bloquear EventStreams ou outros workers."""
    while True:
        try:
            if announce_new_version_if_needed():
                return
        except Exception as exc:
            print("⚠️ Falha inesperada no anúncio da versão; nova tentativa em 5 minutos:", safe_exception(exc))
        time.sleep(300)


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
        if title in watched_pages:
            return True

    return get_temporary_watch(title) is not None


# =========================================================
# VIGILÂNCIA TEMPORÁRIA DE PÁGINAS
# =========================================================

def temp_watch_key(title):
    return str(title or "").replace("_", " ").strip().casefold()


def save_temporary_watchlist():
    with temporary_watchlist_persist_lock:
        with temporary_watchlist_lock:
            data = list(temporary_watched_pages.values())
        atomic_write_json(TEMP_WATCHLIST_FILE, data)
    print("💾 Vigilâncias temporárias salvas:", len(data))


def load_temporary_watchlist():
    global temporary_watched_pages
    data = load_json(TEMP_WATCHLIST_FILE, [])
    if not isinstance(data, list):
        print("❌ Formato inválido de temporary_watchlist.json")
        return
    now = time.time()
    loaded = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        expires_at = float(item.get("expires_at") or 0)
        if not title or expires_at <= now:
            continue
        loaded[temp_watch_key(title)] = {
            "title": title,
            "expires_at": expires_at,
        }
    with temporary_watchlist_lock:
        temporary_watched_pages = loaded
    print("✅ Vigilâncias temporárias carregadas:", len(loaded))
    try:
        save_temporary_watchlist()
    except Exception:
        pass


def cleanup_expired_temporary_watches():
    now = time.time()
    removed = False
    with temporary_watchlist_lock:
        expired = [
            key for key, item in temporary_watched_pages.items()
            if item.get("expires_at", 0) <= now
        ]
        for key in expired:
            print("⌛ Vigilância temporária expirada:", temporary_watched_pages[key].get("title", key))
            del temporary_watched_pages[key]
            removed = True
    if removed:
        try:
            save_temporary_watchlist()
        except Exception as e:
            print("⚠️ Erro ao salvar expiração de vigilância:", safe_exception(e))


def add_temporary_watched_page(title):
    expires_at = time.time() + TEMP_WATCH_DURATION_SECONDS
    key = temp_watch_key(title)
    with temporary_watchlist_lock:
        previous = temporary_watched_pages.get(key)
        temporary_watched_pages[key] = {
            "title": title,
            "expires_at": expires_at,
        }
    try:
        save_temporary_watchlist()
        return True
    except Exception as e:
        print("❌ Erro ao salvar vigilância temporária:", safe_exception(e))
        with temporary_watchlist_lock:
            if previous is None:
                temporary_watched_pages.pop(key, None)
            else:
                temporary_watched_pages[key] = previous
        return False


def remove_temporary_watched_page(title):
    key = temp_watch_key(title)
    with temporary_watchlist_lock:
        if key not in temporary_watched_pages:
            return True, False
        backup = temporary_watched_pages.pop(key)
    try:
        save_temporary_watchlist()
        return True, True
    except Exception as e:
        print("❌ Erro ao remover vigilância temporária:", safe_exception(e))
        with temporary_watchlist_lock:
            temporary_watched_pages[key] = backup
        return False, False


def get_temporary_watch(title):
    cleanup_expired_temporary_watches()
    with temporary_watchlist_lock:
        item = temporary_watched_pages.get(temp_watch_key(title))
        return dict(item) if item else None


def remove_any_watched_page(title):
    """Remove vigilância permanente e/ou temporária da página."""
    perm_success, perm_removed = remove_watched_page(title)
    temp_success, temp_removed = remove_temporary_watched_page(title)
    return (perm_success and temp_success), (perm_removed or temp_removed)

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
