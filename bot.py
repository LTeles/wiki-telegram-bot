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

from datetime import datetime, timezone, timedelta
from statistics import median
from collections import Counter, defaultdict
from urllib.parse import quote, parse_qs, urlparse
from zoneinfo import ZoneInfo

import requests
from sseclient import SSEClient


# =========================================================
# CONFIGURAÇÃO
# =========================================================

BOT_VERSION = "2.57"
BOT_BUILD = "2.57-testwiki-diff-fallback"

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
WIKI_CREATE_ENABLED = True
WIKI_WRITE_INTERVAL_SECONDS = 60 * 60
WIKI_STATUS_INTERVAL_SECONDS = 6 * 60 * 60
WIKI_WRITE_QUEUE_FILE = "/data/wiki_write_queue.json"
WIKI_WRITE_CONTROL_FILE = "/data/wiki_write_control.json"
WIKI_WRITE_LOCK = threading.RLock()
GENERAL_PRIORITY_FACTOR = 0.90  # Redução geral de 10% na prioridade, sem alterar o Revert Risk.
WIKI_PENDING_PAGES_FILE = "/data/wiki_pending_pages.json"

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
    "/data/watchlist.json"
)

OBSERVED_USERS_FILE = os.environ.get(
    "OBSERVED_USERS_FILE",
    "/data/observed_users.json"
)

POST_BLOCK_OBSERVATIONS_FILE = os.environ.get(
    "POST_BLOCK_OBSERVATIONS_FILE",
    "/data/post_block_observations.json"
)

TEMP_WATCHLIST_FILE = os.environ.get(
    "TEMP_WATCHLIST_FILE",
    "/data/temporary_watchlist.json"
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

REVERSIBLE_ACTIONS_FILE = os.environ.get(
    "REVERSIBLE_ACTIONS_FILE",
    "/data/reversible_actions.json"
)


COMMUNITY_STATS_FILE = os.environ.get(
    "COMMUNITY_STATS_FILE",
    "/data/community_stats.json"
)

FALSE_POSITIVES_FILE = os.environ.get(
    "FALSE_POSITIVES_FILE",
    "/data/false_positives.json"
)

FALSE_NEGATIVES_FILE = os.environ.get(
    "FALSE_NEGATIVES_FILE",
    "/data/false_negatives.json"
)

WIKI_REPORT_PREVIEW_FILE = os.environ.get(
    "WIKI_REPORT_PREVIEW_FILE",
    "/data/wiki_report_preview.txt"
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
        "⚠️ Possível vandalismo marcado como falso positivo\n"
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


def queue_wiki_edit(title, wikitext, summary):
    """Coalesce pending writes by title; no network access here."""
    if not wiki_title_is_allowed(title):
        raise PermissionError("Título fora das subpáginas autorizadas")
    if not isinstance(wikitext, str) or not wikitext.strip():
        raise ValueError("Conteúdo wiki vazio")
    if title == WIKI_STATISTICS_TITLE and not wiki_statistics_publication_safe(wikitext):
        return False
    mark_wiki_page_pending(title)
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        if not isinstance(state, dict):
            state = {"pending": [], "last_attempt": 0}
        pending = [item for item in state.get("pending", []) if item.get("title") != title]
        pending.append({"title": title, "text": wikitext, "summary": summary})
        state["pending"] = pending
        atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
    return True


def wiki_edit_page(title, wikitext, summary):
    """Single guarded write entry point, called only by the queue worker."""
    if not WIKI_WRITE_ENABLED or wiki_writing_paused():
        return False
    if not wiki_title_is_allowed(title):
        raise PermissionError("Título wiki não autorizado")
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        if wiki_writing_paused() or time.time() - float(state.get("last_attempt") or 0) < WIKI_WRITE_INTERVAL_SECONDS:
            return False
        # Reserve the slot BEFORE any remote operation; crashes cannot cause a burst.
        state["last_attempt"] = time.time()
        atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
        exists = wiki_page_exists(title)
        create = not exists
        if create and not (WIKI_CREATE_ENABLED and (title in (WIKI_STATUS_TITLE, WIKI_STATISTICS_TITLE) or wiki_report_creation_allowed(title))):
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
            "token": token, "assert": "user", "bot": 1,
        }
        payload["createonly" if create else "nocreate"] = 1
        response = wikimedia_session.post(WIKIPEDIA_API, data=payload, timeout=35)
        response.raise_for_status()
        data = response.json()
        error = data.get("error")
        if isinstance(error, dict) and error.get("code") in {"notloggedin", "assertuserfailed", "badtoken", "invalidcsrf", "assertbotfailed"}:
            if not wikimedia_login():
                raise RuntimeError("Sessão wiki expirada e relogin falhou: " + str(error))
            payload["token"] = get_wikimedia_csrf_token()
            response = wikimedia_session.post(WIKIPEDIA_API, data=payload, timeout=35)
            response.raise_for_status()
            data = response.json()
        if data.get("error"):
            raise RuntimeError("API edit recusou publicação: " + str(data["error"]))
        if data.get("edit", {}).get("result") != "Success":
            raise RuntimeError("API edit não confirmou sucesso: " + str(data.get("edit")))
        return True


def process_wiki_write_queue_once():
    if not WIKI_WRITE_ENABLED or wiki_writing_paused():
        return False
    with WIKI_WRITE_LOCK:
        state = load_json(WIKI_WRITE_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        pending = state.get("pending", [])
        if wiki_writing_paused() or not pending or time.time() - float(state.get("last_attempt") or 0) < WIKI_WRITE_INTERVAL_SECONDS:
            return False
        item = pending[0]
        if item.get("title") == WIKI_STATISTICS_TITLE and not wiki_statistics_publication_safe(item.get("text")):
            # Discard stale unsafe report; preserve all other queued writes.
            state["pending"].pop(0)
            atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            print("⛔ Relatório de estatísticas inseguro removido da fila; demais publicações preservadas.")
            return False
        try:
            success = wiki_edit_page(item["title"], item["text"], item["summary"])
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
            atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
            # Never remove a newer, coalesced update of the same page.
            if state.get("pending") and state["pending"][0] == item:
                state["pending"].pop(0)
                atomic_write_json(WIKI_WRITE_QUEUE_FILE, state)
                mark_wiki_page_published(item["title"])
        return success


def wiki_write_queue_worker():
    wiki_record_release()
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
        f"= Relatório de manutenção e combate a vandalismo — {period_label} =",
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
        "== Onde o vandalismo confirmado apareceu ==",
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
        "* Falso positivo: edição marcada por administrador como sem vandalismo; o diff entra como exemplo dessa classe no arquivo de padrões.",
        "* Padrões de IA: revertidas/eliminadas são exemplos de vandalismo; patrulhadas/falsos positivos são exemplos sem vandalismo. A semelhança é informativa e não altera o risco nem as regras do detector.",
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
}
WIKI_RELEASE_HISTORY_FILE = "/data/wiki_release_history.json"


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
            "Atualizando relatório diário de manutenção e combate a vandalismo",
        )
        queue_wiki_edit(
            monthly_title,
            monthly_text,
            "Atualizando painel mensal de manutenção e combate a vandalismo",
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
        if load_saved_bot_version() == BOT_BUILD and previous_id:
            print("ℹ️ Anúncio desta build já confirmado; ID:", previous_id)
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
            "observer_mention": item.get("observer_mention"),
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


def observe_user(username, reason=None, observer_mention=None):
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
            "observer_mention": observer_mention,
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
# OBSERVAÇÃO AUTOMÁTICA APÓS BLOQUEIO
# =========================================================

def save_post_block_observations():
    with post_block_observations_persist_lock:
        with post_block_observations_lock:
            data = list(post_block_observations.values())

        atomic_write_json(
            POST_BLOCK_OBSERVATIONS_FILE,
            data
        )


def load_post_block_observations():
    global post_block_observations

    data = load_json(
        POST_BLOCK_OBSERVATIONS_FILE,
        []
    )

    if not isinstance(data, list):
        print("❌ Formato inválido de post_block_observations.json")
        return

    loaded = {}
    for item in data:
        if not isinstance(item, dict):
            continue

        username = str(item.get("username") or "").strip()
        starts_at = item.get("starts_at")

        try:
            starts_at = float(starts_at)
        except (TypeError, ValueError):
            continue

        if not username:
            continue

        loaded[username_key(username)] = {
            "username": username,
            "starts_at": starts_at,
            "scheduled_at": float(item.get("scheduled_at") or time.time()),
            "source": "block",
        }

    with post_block_observations_lock:
        post_block_observations = loaded

    print(
        "✅ Observações pós-bloqueio carregadas:",
        len(loaded)
    )


def block_expiry_timestamp(event, fallback_change=None):
    candidates = []

    params = event.get("params", {})
    if isinstance(params, dict):
        candidates.append(params.get("expiry"))

    if fallback_change:
        stream_params = fallback_change.get("log_params", {})
        if isinstance(stream_params, dict):
            candidates.append(stream_params.get("expiry"))

    for expiry in candidates:
        if expiry is None:
            continue

        expiry_text = str(expiry).strip()
        if not expiry_text:
            continue

        if expiry_text.casefold() in (
            "infinite",
            "infinity",
            "indefinite",
            "indefinitely",
            "never",
        ):
            return None

        try:
            return datetime.fromisoformat(
                expiry_text.replace("Z", "+00:00")
            ).timestamp()
        except Exception:
            continue

    return None


def schedule_post_block_observation(username, starts_at):
    if not username or is_ip_address(username):
        return False

    key = username_key(username)
    item = {
        "username": username,
        "starts_at": float(starts_at),
        "scheduled_at": time.time(),
        "source": "block",
    }

    with post_block_observations_lock:
        previous = post_block_observations.get(key)
        post_block_observations[key] = item

    try:
        save_post_block_observations()
        return True
    except Exception as e:
        print(
            "❌ Erro ao salvar observação pós-bloqueio:",
            safe_exception(e)
        )
        with post_block_observations_lock:
            if previous is None:
                post_block_observations.pop(key, None)
            else:
                post_block_observations[key] = previous
        return False


def cancel_post_block_observation(username):
    key = username_key(username)

    with post_block_observations_lock:
        previous = post_block_observations.pop(key, None)

    if previous is None:
        return None

    try:
        save_post_block_observations()
    except Exception as e:
        print(
            "⚠️ Erro ao persistir cancelamento pós-bloqueio:",
            safe_exception(e)
        )

    return previous


def start_automatic_observation(username, reason):
    if not username or is_ip_address(username):
        return False

    if not observe_user(username, reason):
        return False

    telegram_queue.put({
        "message": (
            "🔎 Observação automática iniciada\n\n"
            f"👤 {user_contributions_link_html(username)}\n"
            "⏳ Duração: 6 horas\n"
            f"📌 Motivo: {html.escape(reason)}"
        ),
        "title": "Observação automática",
        "parse_mode": "HTML",
    })

    print(
        "🔎 Observação automática iniciada:",
        username,
        "|",
        reason
    )
    return True


def activate_due_post_block_observations():
    now = time.time()

    with post_block_observations_lock:
        due = [
            dict(item)
            for item in post_block_observations.values()
            if float(item.get("starts_at") or 0) <= now
        ]

    for item in due:
        username = item.get("username")
        if not username:
            continue

        # Remove primeiro do agendamento. Se a ativação falhar, o item é
        # recolocado para nova tentativa no próximo ciclo.
        removed = cancel_post_block_observation(username)
        if removed is None:
            continue

        if not start_automatic_observation(
            username,
            "término de bloqueio"
        ):
            schedule_post_block_observation(
                username,
                now + 60
            )


def post_block_observation_scheduler():
    print("✅ Agendador de observação pós-bloqueio iniciado.")

    while True:
        try:
            activate_due_post_block_observations()
        except Exception as e:
            print(
                "⚠️ Erro no agendador pós-bloqueio:",
                safe_exception(e)
            )

        time.sleep(15)


def handle_unblock_for_observation(change):
    target = extract_block_target(
        change.get("title") or ""
    )

    if not target or target == "Desconhecido":
        return

    if is_ip_address(target):
        return

    scheduled = cancel_post_block_observation(target)

    # Só inicia automaticamente no desbloqueio se havia uma observação
    # pós-bloqueio programada para aquela conta. Assim, desbloqueios de
    # contas que nunca entraram nessa automação não criam observações.
    if scheduled:
        start_automatic_observation(
            scheduled.get("username") or target,
            "desbloqueio antecipado"
        )


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
        f'🛡 <a href="{html.escape(filter_url, quote=True)}">'
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
        f'🔗 <a href="{html.escape(log_url, quote=True)}">'
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
            "patrolled_at": None,
            "resolved_no_action_at": None,
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


def remove_detection_stat(revision_id):
    """Remove uma revisão das estatísticas do detector.

    Usado para autorreversões: elas continuam registradas em posted_edits
    para que a mensagem possa exibir o desfecho, mas não contam como acerto,
    erro ou pendência estatística do detector.
    """
    changed = False

    with detection_stats_lock:
        records = detection_stats.get("records", [])
        kept = []

        for item in records:
            try:
                same_revision = int(item.get("revision_id", 0)) == int(revision_id)
            except Exception:
                same_revision = False

            if same_revision:
                changed = True
                continue

            kept.append(item)

        if changed:
            detection_stats["records"] = kept

    if changed:
        try:
            save_detection_stats()
        except Exception as e:
            print(
                "⚠️ Erro ao remover autorreversão das estatísticas:",
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


def mark_detection_stat_patrolled(revision_id, patrolled_at):
    changed = False

    with detection_stats_lock:
        for item in detection_stats.get("records", []):
            if int(item.get("revision_id", 0)) == int(revision_id):
                if item.get("patrolled_at") is None:
                    item["patrolled_at"] = float(patrolled_at)
                    changed = True
                break

    if changed:
        try:
            save_detection_stats()
        except Exception as e:
            print(
                "⚠️ Erro ao salvar patrulhamento estatístico:",
                safe_exception(e)
            )


def mark_detection_stat_resolved_no_action(revision_id, resolved_at):
    changed = False

    with detection_stats_lock:
        for item in detection_stats.get("records", []):
            if int(item.get("revision_id", 0)) == int(revision_id):
                if item.get("resolved_no_action_at") is None:
                    item["resolved_no_action_at"] = float(resolved_at)
                    changed = True
                break

    if changed:
        try:
            save_detection_stats()
        except Exception as e:
            print(
                "⚠️ Erro ao salvar resolução estatística:",
                safe_exception(e)
            )


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

    patrolled_records = [
        item
        for item in records
        if item.get("patrolled_at") is not None
        and item.get("reverted_at") is None
    ]
    patrolled = len(patrolled_records)

    resolved_no_action_records = [
        item
        for item in records
        if item.get("resolved_no_action_at") is not None
        and item.get("reverted_at") is None
        and item.get("patrolled_at") is None
    ]
    resolved_no_action = len(resolved_no_action_records)

    pending = max(
        0,
        total - reverted - patrolled - resolved_no_action
    )

    reverted_pct = (
        reverted / total * 100
        if total
        else 0.0
    )

    patrolled_pct = (
        patrolled / total * 100
        if total
        else 0.0
    )

    resolved_no_action_pct = (
        resolved_no_action / total * 100
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

    response_metrics = channel_response_metrics(
        start_timestamp,
        end_timestamp
    )
    false_positive_metrics = false_positive_management_metrics(
        start_timestamp,
        end_timestamp
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
        f"🛡️ Edições patrulhadas: "
        f"{patrolled} ({format_percent(patrolled_pct)})\n"
        f"✅ Resolvidas sem ação necessária: "
        f"{resolved_no_action} ({format_percent(resolved_no_action_pct)})\n"
        f"⏳ Ainda pendentes: "
        f"{pending} ({format_percent(pending_pct)})\n\n"
        f"🤖 Revert Risk médio: "
        f"{format_percent(avg_risk)}\n"
        f"🎯 Score médio final: "
        f"{format_percent(avg_score)}\n"
        f"⏱ Mediana até detecção da reversão: "
        f"{format_minutes(median_reversal)}\n\n"
        "👥 Resposta da comunidade aos posts do canal:\n"
        f"{format_channel_response_summary(response_metrics)}\n\n"
        "🏷 Gestão de falsos positivos:\n"
        f"• Reportados: {false_positive_metrics['reported']}\n"
        f"• Ajustes concluídos: {false_positive_metrics['adjusted']}\n"
        f"• Backlog ao fim do período: {false_positive_metrics['backlog']}\n\n"
        "📈 Por faixa de score:\n"
        +
        "\n".join(band_lines)
        +
        "\n\n"
        "ℹ️ As métricas do detector consideram apenas alertas normais. "
        "A seção de resposta do canal considera todos os posts acompanhados "
        "(detector, contas observadas e páginas vigiadas). "
        "O bot não sabe quem visualizou uma mensagem no Telegram; "
        "‘checagem’ é uma estimativa baseada em ações detectadas na Wikipédia. "
        "Os estados podem mudar durante as 48 horas de acompanhamento."
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
            cleanup_community_stats()

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

                    try:
                        daily_title, monthly_title = (
                            build_wiki_daily_and_monthly_previews(now)
                        )
                        print(
                            "📝 Prévia wiki atualizada:",
                            daily_title,
                            "|",
                            monthly_title,
                        )
                    except Exception as e:
                        print(
                            "⚠️ Erro ao gerar prévia wiki:",
                            safe_exception(e)
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
        "diff_added": item.get("stats_payload", {}).get("diff_added", ""),
        "diff_removed": item.get("stats_payload", {}).get("diff_removed", ""),
        "risk_reasons": item.get("stats_payload", {}).get("risk_reasons", ""),
        "final_score": (
            item.get("stats_payload", {}).get("score")
            if isinstance(item.get("stats_payload"), dict)
            else None
        ),
        "message_id": message_id,
        "base_message": item.get("message", ""),
        "parse_mode": item.get("parse_mode"),
        "reply_markup": item.get("reply_markup"),
        "alert_kind": item.get("alert_kind", "normal"),
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

        record_community_event(
            "alert",
            actor=None,
            title=item.get("page_title"),
            timestamp=posted_at,
            revision_id=revision_id,
            metadata={
                "alert_kind": item.get("alert_kind", "normal"),
                "telegram_message_id": message_id,
            },
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
    Faz no máximo uma solicitação de patrulhamento a cada 30 segundos.

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


def verify_direct_undo(title, revision_id):
    """Confirm adjacent undo by content hashes, even when mw-reverted is delayed.

    Returns the actual reverting username only if the immediate next revision
    has an undo/revert tag AND restores the SHA1 of the revision preceding the
    alerted edit. No guess based solely on a generic revert tag.
    """
    try:
        response = requests.get(WIKIPEDIA_API, params={
            "action": "query", "format": "json", "formatversion": 2,
            "prop": "revisions", "titles": title,
            "rvprop": "ids|sha1|user|tags", "rvdir": "older",
            "rvstartid": int(revision_id), "rvlimit": 2,
        }, headers=HEADERS, timeout=20)
        response.raise_for_status()
        pages = response.json().get("query", {}).get("pages", [])
        before = pages[0].get("revisions", []) if pages else []
        if len(before) < 2 or int(before[0].get("revid", -1)) != int(revision_id):
            return None
        previous_hash = before[1].get("sha1")
        if not previous_hash:
            return None
        response = requests.get(WIKIPEDIA_API, params={
            "action": "query", "format": "json", "formatversion": 2,
            "prop": "revisions", "titles": title,
            "rvprop": "ids|sha1|user|tags", "rvdir": "newer",
            "rvstartid": int(revision_id), "rvlimit": 2,
        }, headers=HEADERS, timeout=20)
        response.raise_for_status()
        pages = response.json().get("query", {}).get("pages", [])
        after = pages[0].get("revisions", []) if pages else []
        if len(after) < 2 or int(after[0].get("revid", -1)) != int(revision_id):
            return None
        undo = after[1]
        if not ({"mw-undo", "mw-rollback", "mw-manual-revert"} & set(undo.get("tags") or [])):
            return None
        if undo.get("sha1") != previous_hash:
            return None
        return undo.get("user") or None
    except Exception as exc:
        print("⚠️ Falha ao confirmar desfazer direto:", safe_exception(exc))
        return None


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

                # MediaWiki pode devolver tanto tags internas (mw-*) quanto
                # nomes/variações localizadas. Normalizamos para reconhecer
                # também reversões manuais, que são comuns em autorreversões.
                tags = {
                    str(tag).strip().casefold()
                    for tag in (rev.get("tags") or [])
                }
                comment = (rev.get("comment") or "").casefold()

                explicit_tag = bool(tags.intersection({
                    "mw-rollback",
                    "mw-undo",
                    "mw-manual-revert",
                    "manual revert",
                    "reversão manual",
                    "reversao manual",
                })) or any(
                    ("manual" in tag and ("revert" in tag or "revers" in tag))
                    for tag in tags
                )

                explicit_comment = any(x in comment for x in (
                    "reverteu", "revertida", "revertido", "desfeita",
                    "desfeito", "desfazer", "rollback",
                    "reversão manual", "reversao manual",
                ))

                if explicit_tag or explicit_comment:
                    # Retorna o autor da revisão que efetivamente realizou a
                    # reversão. O monitor já compara este nome ao autor da
                    # revisão alertada; se forem iguais, registra self_reverted.
                    return rev.get("user") or None
    except Exception as e:
        print("⚠️ Não foi possível identificar quem reverteu:", safe_exception(e))
    return None


def observation_remaining_line(username):
    observation = get_observation(username)
    if not observation:
        return ""

    try:
        remaining = float(observation.get("expires_at") or 0) - time.time()
    except Exception:
        return ""

    if remaining <= 0:
        return ""

    return f"\n⏳ Tempo restante de observação: {format_remaining(remaining)}"


def message_with_status(record, status, reverter=None, deleter=None, patroller=None):
    title = article_link_html(record.get("title") or "Sem título")
    username = user_contributions_link_html(record.get("username") or "Desconhecido")
    comment = html.escape(str(record.get("edit_comment") or "Sem resumo"))
    risk = record.get("revert_risk")
    diff_url = record.get("diff_url") or ""

    risk_line = ""
    if risk is not None:
        try:
            risk_line = f"\n🤖 Risco de reversão: {round(float(risk) * 100)}%\n"
        except Exception:
            pass

    edit_link = edit_link_html(diff_url)

    if status == "self_reverted":
        return (
            "↩️ Edição autorrevertida\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}"
        )

    if status == "reverted":
        reverter_line = (
            f"\nRevertido por: {html.escape(str(reverter))}" if reverter else ""
        )

        if record.get("alert_kind") == "observed":
            remaining_line = observation_remaining_line(
                record.get("username") or ""
            )
            return (
                "↩️ Edição de conta observada revertida\n\n"
                f"📝 {title}\n"
                f"👤 {username}\n"
                f"💬 {comment}\n"
                f"{risk_line}\n"
                f"{edit_link}"
                f"{reverter_line}"
                f"{remaining_line}"
            )

        return (
            "↩️ Possível vandalismo revertido\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}"
            f"{reverter_line}"
        )

    if status == "patrolled":
        patroller_line = (
            f"\nPatrulhada por: {user_contributions_link_html(patroller)}"
            if patroller else ""
        )
        return (
            "✅ Possível vandalismo patrulhado\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}"
            f"{patroller_line}"
        )

    if status == "false_positive":
        false_item = {
            "title": record.get("title"),
            "username": record.get("username"),
            "edit_comment": record.get("edit_comment"),
            "diff_url": record.get("diff_url"),
            "revert_risk": record.get("revert_risk"),
            "marked_by": record.get("false_positive_by"),
        }
        return false_positive_message(false_item, fixed=False)

    if status == "resolved_no_action":
        resolver = record.get("resolved_by")
        resolver_line = (
            f"\nVisto por: {html.escape(str(resolver))}"
            if resolver
            else ""
        )
        return (
            "✅ Edição vista — nenhuma ação necessária\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}"
            f"{resolver_line}"
        )

    if status == "deleted":
        deleter_line = (
            f"\nEliminada por: {html.escape(str(deleter))}" if deleter else ""
        )
        return (
            "🗑️ Página eliminada após alerta de possível vandalismo\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}"
            f"{deleter_line}"
        )

    return record.get("base_message", "").rstrip()


# Estado da entrega visual é independente da resolução lógica da revisão.
# Só avisos marcados explicitamente após esta versão entram na recuperação.
TELEGRAM_STATUS_RETRY_LIMIT = 5
TELEGRAM_STATUS_RETRY_DELAYS = (60, 180, 600, 1800, 3600)
TERMINAL_ALERT_STATUSES = ("reverted", "self_reverted", "patrolled", "deleted")


def record_status_delivery(revision_id, success):
    """Persiste o resultado sem recolocar uma revisão resolvida nas pendências."""
    with posted_edits_lock:
        live = posted_edits.get(str(revision_id))
        if not live:
            return
        if success:
            live.pop("status_telegram_retry", None)
        elif live.get("status") in TERMINAL_ALERT_STATUSES:
            live["status_telegram_retry"] = {
                "attempts": 1,
                "next_at": time.time() + TELEGRAM_STATUS_RETRY_DELAYS[0],
                "status": live["status"],
            }
    save_posted_edits()


def retry_failed_status_messages():
    """Reconstitui texto/teclado do estado salvo; não consulta nem edita a wiki."""
    now = time.time()
    with posted_edits_lock:
        due = [dict(item) for item in posted_edits.values()
               if isinstance(item.get("status_telegram_retry"), dict)
               and float(item["status_telegram_retry"].get("next_at", float("inf"))) <= now]
    for item in due[:5]:
        revision_id = str(item.get("revision_id"))
        with posted_edits_lock:
            live = posted_edits.get(revision_id)
            if not live:
                continue
            retry = live.get("status_telegram_retry")
            if not isinstance(retry, dict) or retry.get("status") != live.get("status"):
                live.pop("status_telegram_retry", None)
                continue
            attempts = int(retry.get("attempts", 1))
            if attempts >= TELEGRAM_STATUS_RETRY_LIMIT:
                print("⚠️ Atualização visual esgotou tentativas:", revision_id)
                live.pop("status_telegram_retry", None)
                continue
            current = dict(live)
        status = current["status"]
        text = message_with_status(current, status,
                                   reverter=current.get("reverted_by"),
                                   deleter=current.get("deleted_by"))
        markup = tracked_edit_reply_markup(
            int(revision_id), current.get("alert_kind", "normal"),
            include_resolution_buttons=False)
        if status in ("reverted", "self_reverted"):
            reversal_diagnostic("telegram_recuperacao_iniciada", revision_id, tentativa=attempts)
        retry_started = time.monotonic()
        success = edit_telegram_message(current["message_id"], text,
                                        parse_mode="HTML", reply_markup=markup)
        if status in ("reverted", "self_reverted"):
            reversal_diagnostic("telegram_recuperacao_concluida", revision_id,
                                sucesso=success, duracao_s=round(time.monotonic() - retry_started, 3))
        with posted_edits_lock:
            live = posted_edits.get(revision_id)
            if not live or not isinstance(live.get("status_telegram_retry"), dict):
                continue
            if live.get("status") != status:
                live.pop("status_telegram_retry", None)
            elif success:
                live.pop("status_telegram_retry", None)
                print("✅ Aviso atualizado após nova tentativa:", revision_id)
            else:
                next_attempts = attempts + 1
                if next_attempts >= TELEGRAM_STATUS_RETRY_LIMIT:
                    live.pop("status_telegram_retry", None)
                    print("⚠️ Atualização visual esgotou tentativas:", revision_id)
                else:
                    live["status_telegram_retry"] = {
                        "attempts": next_attempts,
                        "next_at": time.time() + TELEGRAM_STATUS_RETRY_DELAYS[
                            min(next_attempts - 1, len(TELEGRAM_STATUS_RETRY_DELAYS) - 1)],
                        "status": status,
                    }
        save_posted_edits()


REVERSAL_LOG_SUMMARY_INTERVAL_SECONDS = 900
_reversal_log_counters = {"consultas": 0, "reversoes": 0, "telegram_sucesso": 0, "telegram_falha": 0, "erros": 0}
_reversal_log_lock = threading.Lock()
_reversal_log_last_summary = time.monotonic()
_direct_undo_last_checked = {}
_direct_undo_check_lock = threading.Lock()


def reversal_diagnostic(stage, revision_id=None, **details):
    """Record operational outcomes, not every normal poll; never log Telegram identities."""
    global _reversal_log_last_summary
    quiet = {"ciclo_iniciado", "consulta_tags_iniciada", "consulta_tags_concluida",
             "reversao_identificada",
             "telegram_edicao_iniciada", "telegram_recuperacao_iniciada"}
    with _reversal_log_lock:
        if stage == "consulta_tags_concluida":
            _reversal_log_counters["consultas"] += 1
        elif stage == "reversao_confirmada":
            _reversal_log_counters["reversoes"] += 1
        elif stage in ("telegram_edicao_concluida", "telegram_recuperacao_concluida"):
            key = "telegram_sucesso" if details.get("sucesso") else "telegram_falha"
            _reversal_log_counters[key] += 1
        elif "erro" in stage or "falha" in stage:
            _reversal_log_counters["erros"] += 1
        now = time.monotonic()
        summary = None
        if now - _reversal_log_last_summary >= REVERSAL_LOG_SUMMARY_INTERVAL_SECONDS:
            summary = dict(_reversal_log_counters)
            for key in _reversal_log_counters:
                _reversal_log_counters[key] = 0
            _reversal_log_last_summary = now
    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    if summary is not None:
        print(f"📊 REVERSAO_RESUMO utc={stamp} periodo_s=900 "
              + " ".join(f"{key}={value}" for key, value in summary.items()), flush=True)
    if stage in quiet or (stage == "telegram_recuperacao_concluida" and details.get("sucesso")):
        return
    extra = " ".join(f"{key}={value}" for key, value in details.items())
    print(f"🔎 REVERSAO_DIAG utc={stamp} etapa={stage} revisao={revision_id or '-'} {extra}", flush=True)


def _select_direct_undo_candidates(active, tags_by_revision, now=None):
    """Prioriza etiquetas e limita a frequência do fallback de desfazer."""
    if now is None:
        now = time.monotonic()

    active_ids = {int(record["revision_id"]) for record in active}
    tagged = []
    remaining = []
    for record in active:
        revision_id = int(record["revision_id"])
        tags = tags_by_revision.get(revision_id) or []
        if "mw-reverted" in tags:
            tagged.append(record)
        else:
            remaining.append(record)

    candidates = set()
    with _direct_undo_check_lock:
        for revision_id in list(_direct_undo_last_checked):
            if revision_id not in active_ids:
                _direct_undo_last_checked.pop(revision_id, None)

        for record in remaining:
            revision_id = int(record["revision_id"])
            # O fallback destina-se apenas a revisões cuja consulta em lote
            # não retornou etiqueta alguma.
            if tags_by_revision.get(revision_id):
                continue
            last_checked = _direct_undo_last_checked.get(revision_id)
            if (
                last_checked is not None
                and now - last_checked < DIRECT_UNDO_RECHECK_SECONDS
            ):
                continue
            candidates.add(revision_id)
            _direct_undo_last_checked[revision_id] = now
            if len(candidates) >= DIRECT_UNDO_CHECKS_PER_CYCLE:
                break

    return tagged + remaining, candidates


def _process_posted_statuses(
    active,
    tags_by_revision=None,
    patrol_by_revision=None,
    direct_undo_candidates=None,
):
    """Resolve a snapshot; recheck live state under lock before committing."""
    tags_by_revision = tags_by_revision or {}
    patrol_by_revision = patrol_by_revision or {}
    direct_undo_candidates = direct_undo_candidates or set()
    changed_any = False

    for record in active:
        revision_id = int(
            record["revision_id"]
        )
        current_status = record.get("status")
        new_status = None
        reversal_source = None
        direct_undo_author = None

        tags = tags_by_revision.get(
            revision_id
        )

        if tags and "mw-reverted" in tags:
            new_status = "reverted"
            reversal_source = "tag"
        elif revision_id in direct_undo_candidates:
            direct_undo_author = verify_direct_undo(
                record.get("title") or "", revision_id
            )
            if direct_undo_author:
                new_status = "reverted"
                reversal_source = "desfazer_direto"

        if new_status is None and current_status != "patrolled":
            if patrol_by_revision.get(revision_id) is True:
                new_status = "patrolled"

        if (
            new_status
            and
            new_status != current_status
        ):
            if new_status == "reverted":
                reversal_diagnostic("reversao_identificada", revision_id,
                                    origem=reversal_source)
            reverter = None

            # Quando a revisão foi revertida, identifica primeiro o autor
            # da reversão para distinguir uma reversão comum de uma
            # autorreversão. A comparação usa a mesma normalização de nomes
            # já empregada pelo bot (espaços/underscores e casefold).
            if new_status == "reverted":
                if reversal_source == "desfazer_direto":
                    reverter = direct_undo_author
                else:
                    reverter = get_reverter_username(
                        record.get("title") or "", revision_id
                    )

                if (
                    reverter
                    and username_key(reverter)
                    == username_key(record.get("username"))
                ):
                    new_status = "self_reverted"

            if new_status in ("reverted", "self_reverted"):
                reversal_diagnostic("reversao_confirmada", revision_id,
                                    status=new_status, autor_identificado=bool(reverter))

            patroller = None
            if new_status == "patrolled":
                patroller = get_patroller_username(
                    record.get("title") or "", revision_id
                )
            new_text = message_with_status(
                record,
                new_status,
                reverter=reverter if new_status == "reverted" else None,
                patroller=patroller,
            )

            # Após um desfecho, Resolver/Falso + deixam de ser aplicáveis.
            # Mantém apenas os controles de conta/página.
            status_reply_markup = tracked_edit_reply_markup(
                revision_id,
                record.get("alert_kind", "normal"),
                include_resolution_buttons=False
            )

            # Persistir a resolução ANTES da atualização visual no Telegram.
            # Falha de edição da mensagem não pode manter o alerta pendente.
            with posted_edits_lock:
                live = posted_edits.get(str(revision_id))
                if not live or live.get("status") in (
                    "reverted", "self_reverted", "deleted",
                    "resolved_no_action", "false_positive"
                ):
                    continue
                live["status"] = new_status
                if reverter:
                    live["reverted_by"] = reverter
                if new_status in ("reverted", "self_reverted"):
                    live["reverted_at"] = time.time()
                elif new_status == "patrolled":
                    live["patrolled_at"] = time.time()
                    if patroller:
                        live["patrolled_by"] = patroller

            # A gravação não depende do sucesso da API do Telegram.
            save_posted_edits()
            changed_any = True
            if new_status in ("reverted", "self_reverted"):
                reversal_diagnostic("telegram_edicao_iniciada", revision_id)
                telegram_edit_started = time.monotonic()
            success = edit_telegram_message(
                record["message_id"],
                new_text,
                parse_mode="HTML",
                reply_markup=status_reply_markup
            )
            record_status_delivery(revision_id, success)
            if new_status in ("reverted", "self_reverted"):
                reversal_diagnostic("telegram_edicao_concluida", revision_id,
                                    sucesso=success,
                                    duracao_s=round(time.monotonic() - telegram_edit_started, 3))
            if not success:
                print("⚠️ Estado resolvido salvo; atualização visual agendada:", revision_id)

            # Contabilizar o desfecho mesmo quando a mensagem não é editável.
            if True:
                if new_status == "self_reverted":
                    # Uma autorreversão não conta como resposta da comunidade.
                    # Ela é registrada separadamente para não inflar a
                    # capacidade de checagem do canal.
                    remove_detection_stat(revision_id)
                    record_community_event(
                        "self_revert",
                        actor=record.get("username"),
                        title=record.get("title"),
                        timestamp=time.time(),
                        revision_id=revision_id,
                    )

                elif new_status == "reverted":
                    event_time = time.time()
                    mark_detection_stat_reverted(
                        revision_id,
                        event_time
                    )
                    record_community_event(
                        "revert",
                        actor=reverter,
                        title=record.get("title"),
                        timestamp=event_time,
                        revision_id=revision_id,
                        latency=max(
                            0,
                            event_time - float(record.get("posted_at", event_time))
                        ),
                        categories=get_page_categories(record.get("title")),
                    )

                elif new_status == "patrolled":
                    event_time = time.time()
                    mark_detection_stat_patrolled(
                        revision_id,
                        event_time
                    )
                    record_community_event(
                        "patrol",
                        actor=patroller,
                        title=record.get("title"),
                        timestamp=event_time,
                        revision_id=revision_id,
                        latency=max(
                            0,
                            event_time - float(
                                record.get("posted_at", event_time)
                            )
                        ),
                    )

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
                safe_exception(e)
            )



# Consultas e processamento separados: chamadas individuais à API, retries e
# edições no Telegram não seguram o relógio de 30 segundos dos dois pollers.
# Fila de capacidade 1: resultados novos substituem um snapshot antigo ainda
# não iniciado; o worker sempre revalida o status atual antes de editar.
_reversal_results = queue.Queue(maxsize=1)
_patrol_results = queue.Queue(maxsize=1)


def _publish_latest_result(result_queue, payload):
    try:
        result_queue.put_nowait(payload)
    except queue.Full:
        try:
            result_queue.get_nowait()
            result_queue.task_done()
        except queue.Empty:
            pass
        try:
            result_queue.put_nowait(payload)
        except queue.Full:
            pass


def _reversal_result_worker():
    while True:
        active, tags = _reversal_results.get()
        try:
            ordered_active, direct_undo_candidates = (
                _select_direct_undo_candidates(active, tags)
            )
            _process_posted_statuses(
                ordered_active,
                tags_by_revision=tags,
                direct_undo_candidates=direct_undo_candidates,
            )
        except Exception as exc:
            print("⚠️ Erro ao processar reversões:", safe_exception(exc), flush=True)
        finally:
            _reversal_results.task_done()


def _patrol_result_worker():
    while True:
        active, statuses = _patrol_results.get()
        try:
            _process_posted_statuses(active, patrol_by_revision=statuses)
        except Exception as exc:
            print("⚠️ Erro ao processar patrulhamento:", safe_exception(exc), flush=True)
        finally:
            _patrol_results.task_done()


def _posted_status_maintenance():
    while True:
        try:
            cleanup_posted_edits()
            retry_failed_status_messages()
        except Exception as exc:
            print("⚠️ Manutenção de avisos:", safe_exception(exc), flush=True)
        time.sleep(30)


def _posted_edit_status_monitor_loop():
    print("✅ Consultas de reversões independentes a cada 30s.")
    next_check = time.monotonic()
    last_revision_check_at = None
    while True:
        wait = next_check - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        started = time.monotonic()
        # Não cria consultas paralelas; se o ciclo ultrapassar 30s,
        # reinicia imediatamente e registra o atraso real.
        next_check = started + REVISION_STATUS_INTERVAL_SECONDS
        with posted_edits_lock:
            active = [dict(item) for item in posted_edits.values()
                      if item.get("status") not in (
                          "reverted", "self_reverted", "deleted",
                          "resolved_no_action", "false_positive")]
        if not active:
            continue
        reversal_diagnostic("ciclo_iniciado", pendentes=len(active),
                            segundos_desde_ultima_consulta=round(started - last_revision_check_at, 1)
                            if last_revision_check_at is not None else "primeira")
        last_revision_check_at = started
        reversal_diagnostic("consulta_tags_iniciada", pendentes=len(active))
        tags_by_revision = {}
        for batch_start in range(0, len(active), REVISION_TAG_BATCH_SIZE):
            revision_batch = active[batch_start:batch_start + REVISION_TAG_BATCH_SIZE]
            tags_by_revision.update(get_revision_tags_batch(
                [record["revision_id"] for record in revision_batch]))
        reversal_diagnostic("consulta_tags_concluida",
                            revisoes_retornadas=len(tags_by_revision),
                            duracao_s=round(time.monotonic() - started, 3))
        if tags_by_revision:
            _publish_latest_result(_reversal_results, (active, tags_by_revision))
        if time.monotonic() > next_check:
            reversal_diagnostic("ciclo_excedeu_intervalo",
                                duracao_s=round(time.monotonic() - started, 3),
                                lotes=(len(active) + REVISION_TAG_BATCH_SIZE - 1) // REVISION_TAG_BATCH_SIZE)


def _posted_edit_patrol_monitor_loop():
    print("✅ Consultas de patrulhamento independentes a cada 30s.")
    next_check = time.monotonic()
    while True:
        wait = next_check - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        started = time.monotonic()
        next_check = started + PATROL_REQUEST_INTERVAL_SECONDS
        # Não registra consultas fictícias quando falta autenticação/permissão.
        if not wikimedia_authenticated or patrol_visibility_supported is not True:
            continue
        with posted_edits_lock:
            active = [dict(item) for item in posted_edits.values()
                      if item.get("status") not in (
                          "reverted", "self_reverted", "deleted",
                          "resolved_no_action", "false_positive", "patrolled")]
        if not active:
            continue
        statuses = get_patrol_status_batch(active)
        if statuses:
            _publish_latest_result(_patrol_results, (active, statuses))
        if time.monotonic() > next_check:
            print("⚠️ PATRULHA_DIAG etapa=ciclo_excedeu_intervalo duracao_s=",
                  round(time.monotonic() - started, 3), flush=True)


def posted_edit_patrol_monitor():
    while True:
        try:
            _posted_edit_patrol_monitor_loop()
        except Exception as exc:
            print("❌ Monitor de patrulhamento interrompido:", safe_exception(exc))
        time.sleep(15)



def posted_edit_status_monitor():
    """Reinicia somente o monitor de desfechos se uma exceção inesperada ocorrer.

    Sem esta proteção, uma exceção encerra silenciosamente a thread daemon,
    enquanto o restante do bot continua enviando alertas.
    """
    while True:
        try:
            _posted_edit_status_monitor_loop()
            print("⚠️ Monitor de reversões retornou inesperadamente; reiniciando em 15s.")
        except Exception as exc:
            print("❌ Monitor de reversões interrompido; reiniciando em 15s:", safe_exception(exc))
        time.sleep(15)


# =========================================================
# ELIMINAÇÃO DE PÁGINAS / ALERTAS PENDENTES
# =========================================================

def page_title_key(title):
    return str(title or "").replace("_", " ").strip().casefold()


def mark_pending_title_deleted(title, deleter=None, deleted_at=None):
    """
    Resolve todos os alertas pendentes de um título confirmado como eliminado.

    O status persistente é atualizado mesmo se o Telegram não permitir editar
    uma mensagem antiga. Assim, um caso já resolvido nunca continua aparecendo
    em /pendentes apenas por falha de edição da mensagem original.
    """
    title = str(title or "").strip()
    if not title:
        return 0

    title_key = page_title_key(title)
    deleted_at = float(deleted_at or time.time())

    with posted_edits_lock:
        matches = [
            dict(item)
            for item in posted_edits.values()
            if not item.get("status")
            and page_title_key(item.get("title")) == title_key
        ]

    if not matches:
        return 0

    resolved = 0

    for record in matches:
        revision_id = int(record["revision_id"])

        # Primeiro persiste a resolução lógica.
        with posted_edits_lock:
            live = posted_edits.get(str(revision_id))
            if live and not live.get("status"):
                live["status"] = "deleted"
                live["deleted_by"] = deleter
                live["deleted_at"] = deleted_at
                resolved += 1

        # Persistir antes de contatar o Telegram para sobreviver a reinícios.
        save_posted_edits()

        # Depois tenta refletir o estado na mensagem original.
        status_reply_markup = tracked_edit_reply_markup(
            revision_id,
            record.get("alert_kind", "normal"),
            include_resolution_buttons=False
        )

        new_text = message_with_status(
            record,
            "deleted",
            deleter=deleter
        )

        success = edit_telegram_message(
            record["message_id"],
            new_text,
            parse_mode="HTML",
            reply_markup=status_reply_markup
        )

        record_status_delivery(revision_id, success)
        if success:
            print(
                "🗑️ Alerta marcado como página eliminada:",
                revision_id,
                "|",
                title,
                "| por:",
                deleter or "não informado"
            )
        else:
            print(
                "ℹ️ Página eliminada confirmada; status removido das pendências "
                "mesmo sem conseguir editar a mensagem Telegram:",
                revision_id,
                "|",
                title
            )

        time.sleep(0.3)

    if resolved:
        try:
            save_posted_edits()
        except Exception as e:
            print(
                "⚠️ Erro ao salvar status de página eliminada:",
                safe_exception(e)
            )

        record_community_event(
            "delete",
            actor=deleter,
            title=title,
            timestamp=deleted_at,
            revision_id=matches[0].get("revision_id") if matches else None,
            categories=[],
            metadata={"alerts_resolved": resolved},
        )

    return resolved


def page_deletion_worker():
    """Atualiza alertas pendentes assim que EventStreams informa eliminação."""
    print("✅ Monitor de eliminação de páginas iniciado.")

    while True:
        change = page_deletion_queue.get()
        try:
            title = str(change.get("title") or "").strip()
            deleter = str(change.get("user") or "").strip() or None

            if title:
                mark_pending_title_deleted(
                    title,
                    deleter=deleter,
                    deleted_at=time.time(),
                )

        except Exception as e:
            print("⚠️ Erro ao processar eliminação de página:", safe_exception(e))
        finally:
            page_deletion_queue.task_done()


def get_missing_pending_titles(titles):
    """
    Consulta existência atual dos títulos em lotes.
    Retorna apenas títulos que a API informa como inexistentes.
    """
    unique = []
    seen = set()

    for title in titles:
        title = str(title or "").strip()
        key = page_title_key(title)
        if title and key not in seen:
            seen.add(key)
            unique.append(title)

    missing = []

    for start in range(0, len(unique), PENDING_PAGE_BATCH_SIZE):
        batch = unique[start:start + PENDING_PAGE_BATCH_SIZE]

        try:
            response = wikimedia_session.get(
                WIKIPEDIA_API,
                params={
                    "action": "query",
                    "format": "json",
                    "formatversion": 2,
                    "prop": "info",
                    "titles": "|".join(batch),
                },
                timeout=25,
            )
            response.raise_for_status()
            data = response.json()

            for page in data.get("query", {}).get("pages", []):
                if page.get("missing") is True or "missing" in page:
                    title = str(page.get("title") or "").strip()
                    if title:
                        missing.append(title)

        except Exception as e:
            print(
                "⚠️ Erro ao verificar existência de páginas pendentes:",
                safe_exception(e)
            )

    return missing


def get_latest_deletion_log(title):
    """
    Confirma que um título inexistente foi realmente eliminado.
    Evita classificar como 'deleted' um título ausente por outros motivos
    (por exemplo, movimentação sem deixar redirecionamento).
    """
    try:
        response = wikimedia_session.get(
            WIKIPEDIA_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": 2,
                "list": "logevents",
                "letype": "delete",
                "leaction": "delete/delete",
                "letitle": title,
                "leprop": "title|user|timestamp|type|details",
                "lelimit": 1,
                "ledir": "older",
            },
            timeout=25,
        )
        response.raise_for_status()
        events = response.json().get("query", {}).get("logevents", [])

        if not events:
            return None

        event = events[0]
        return {
            "title": str(event.get("title") or title),
            "user": str(event.get("user") or "").strip() or None,
            "timestamp": event.get("timestamp"),
        }

    except Exception as e:
        print(
            "⚠️ Erro ao consultar registro de eliminação:",
            safe_exception(e)
        )
        return None


def parse_mediawiki_timestamp(value):
    if not value:
        return None
    try:
        return datetime.strptime(
            str(value),
            "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def reconcile_pending_resolutions():
    """
    Revisão complementar das pendências.

    Reversão e patrulhamento continuam sendo tratados pelos monitores
    existentes. Aqui procuramos especialmente eliminações que possam ter
    ocorrido enquanto o bot estava offline ou durante um redeploy.
    """
    items = get_pending_posted_edits()

    if not items:
        return {
            "checked": 0,
            "missing": 0,
            "deleted_titles": 0,
            "resolved_alerts": 0,
        }

    titles = [
        item.get("title")
        for item in items
        if item.get("title")
    ]

    missing_titles = get_missing_pending_titles(titles)
    deleted_titles = 0
    resolved_alerts = 0

    for title in missing_titles:
        deletion = get_latest_deletion_log(title)

        # Só encerra como eliminada quando há confirmação no log.
        if not deletion:
            continue

        deleted_titles += 1
        resolved_alerts += mark_pending_title_deleted(
            deletion.get("title") or title,
            deleter=deletion.get("user"),
            deleted_at=parse_mediawiki_timestamp(
                deletion.get("timestamp")
            ) or time.time(),
        )

    return {
        "checked": len(items),
        "missing": len(missing_titles),
        "deleted_titles": deleted_titles,
        "resolved_alerts": resolved_alerts,
    }


def pending_resolution_reconciliation_scheduler():
    """
    Faz uma revisão logo após o início e depois a cada 30 minutos.
    Isso recupera eliminações perdidas em períodos de indisponibilidade.
    """
    time.sleep(8)

    while True:
        try:
            result = reconcile_pending_resolutions()
            if result["resolved_alerts"]:
                print(
                    "🧹 Reconciliação de pendências:",
                    result["resolved_alerts"],
                    "alerta(s) removido(s) como página eliminada."
                )
        except Exception as e:
            print(
                "⚠️ Erro na reconciliação de pendências:",
                safe_exception(e)
            )

        time.sleep(PENDING_RECONCILE_INTERVAL_SECONDS)


def manual_pending_reconciliation(chat_id):
    try:
        send_telegram_message(
            "🔎 Revisando avisos pendentes e procurando páginas eliminadas...",
            chat_id=chat_id,
        )

        result = reconcile_pending_resolutions()

        send_telegram_message(
            (
                "🧹 Revisão de pendências concluída\n\n"
                f"📋 Pendências verificadas: {result['checked']}\n"
                f"❓ Títulos atualmente inexistentes: {result['missing']}\n"
                f"🗑️ Páginas com eliminação confirmada: {result['deleted_titles']}\n"
                f"✅ Avisos removidos das pendências: {result['resolved_alerts']}\n\n"
                "↩️ Reversões e ✅ patrulhamentos continuam sendo tratados "
                "pelos monitores normais do bot."
            ),
            chat_id=chat_id,
        )

    except Exception as e:
        send_telegram_message(
            "❌ Não foi possível concluir a revisão das pendências.",
            chat_id=chat_id,
        )
        print(
            "⚠️ Erro na revisão manual de pendências:",
            safe_exception(e)
        )


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
    # Visão geral padrão: cronológica, do mais antigo para o mais recente.
    items.sort(key=lambda item: float(item.get("posted_at", 0)))
    return items


def detection_score_map():
    """Mapa revision_id -> (score final, revert risk) para compatibilidade
    com alertas antigos que ainda não têm final_score salvo em posted_edits."""
    result = {}
    with detection_stats_lock:
        for item in detection_stats.get("records", []):
            try:
                rid = int(item.get("revision_id"))
            except Exception:
                continue
            result[rid] = (
                item.get("score"),
                item.get("revert_risk"),
            )
    return result


def pending_item_risk_values(item, score_map=None):
    score = item.get("final_score")
    risk = item.get("revert_risk")

    try:
        rid = int(item.get("revision_id"))
    except Exception:
        rid = None

    if score_map is not None and rid in score_map:
        old_score, old_risk = score_map[rid]
        if score is None:
            score = old_score
        if risk is None:
            risk = old_risk

    try:
        score = float(score) if score is not None else None
    except Exception:
        score = None

    try:
        risk = float(risk) if risk is not None else None
    except Exception:
        risk = None

    return score, risk


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


def pending_kind_label(item):
    kind = str(item.get("alert_kind") or "normal")
    if kind == "observed":
        return " · 👤 conta observada"
    if kind == "watched":
        return " · 👁 página vigiada"
    return ""


def pending_item_html(item, number=None, score_map=None):
    link = telegram_post_url(item.get("message_id"))
    if not link:
        return None

    title = html.escape(str(item.get("title") or "Sem título"))
    username = html.escape(str(item.get("username") or "Desconhecido"))
    age = format_age(float(item.get("posted_at", 0) or 0))
    score, risk = pending_item_risk_values(item, score_map)

    prefix = f"{number}. " if number is not None else "• "
    line1 = f'{prefix}<b>{title}</b> — {username}{pending_kind_label(item)}'

    details = []
    if risk is not None:
        details.append(f"🤖 Risco de reversão: {risk:.0%}")
    if score is not None and (risk is None or abs(score - risk) >= 0.005):
        details.append(f"🎯 Score: {score:.0%}")
    details.append(f"⏳ {age}")
    line2 = " · ".join(details)
    line3 = f'🔗 <a href="{html.escape(link, quote=True)}">Ver aviso</a>'

    return f"{line1}\n{line2}\n{line3}"


def build_pending_page(items, page=0):
    total = len(items)
    if total == 0:
        return "🕒 <b>Avisos pendentes</b>\n\n✅ Nenhum aviso pendente.", None

    pages = max(1, (total + PENDING_COMMAND_PAGE_SIZE - 1) // PENDING_COMMAND_PAGE_SIZE)
    page = max(0, min(int(page), pages - 1))
    start = page * PENDING_COMMAND_PAGE_SIZE
    visible = items[start:start + PENDING_COMMAND_PAGE_SIZE]
    score_map = detection_score_map()

    blocks = []
    for offset, item in enumerate(visible, start=start + 1):
        rendered = pending_item_html(item, number=offset, score_map=score_map)
        if rendered:
            blocks.append(rendered)

    text = (
        "🕒 <b>Avisos pendentes</b>\n"
        "Ordem: mais antigo → mais recente\n\n"
        + "\n\n".join(blocks)
        + f"\n\n📄 Página {page + 1}/{pages} · {total} avisos pendentes"
    )

    buttons = []
    row = []
    if page > 0:
        row.append({"text": "◀️ Anterior", "callback_data": f"pend:{page - 1}"})
    if page < pages - 1:
        row.append({"text": "Próxima ▶️", "callback_data": f"pend:{page + 1}"})
    if row:
        buttons.append(row)

    markup = {"inline_keyboard": buttons} if buttons else None
    return text, markup


def prioritized_pending_items(items):
    score_map = detection_score_map()

    def key(item):
        score, risk = pending_item_risk_values(item, score_map)
        has_detector_value = score is not None or risk is not None
        return (
            0 if has_detector_value else 1,
            -(score if score is not None else -1),
            -(risk if risk is not None else -1),
            float(item.get("posted_at", 0)),
        )

    return sorted(items, key=key)


def build_pending_summary_message(items):
    total = len(items)
    prioritized = prioritized_pending_items(items)
    visible = prioritized[:PENDING_SUMMARY_MAX_ITEMS]
    score_map = detection_score_map()

    blocks = []
    for number, item in enumerate(visible, start=1):
        rendered = pending_item_html(item, number=number, score_map=score_map)
        if rendered:
            blocks.append(rendered)

    if not blocks:
        return None

    return (
        "⚠️ <b>Avisos pendentes prioritários</b>\n"
        "Ordem: maior prioridade de risco\n\n"
        + "\n\n".join(blocks)
        + f"\n\n📊 <b>{total} avisos pendentes no total</b>"
        + f"\nExibindo os {len(blocks)} de maior prioridade."
    )


def pending_alerts_summary_scheduler():
    print("✅ Resumo de pendências: a cada 2 horas, top 10 por prioridade, janela de 48h.")
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

            # Assinatura da fila inteira. Se nada mudou, não repete o resumo.
            signature = pending_summary_signature(items)
            if signature == last_signature:
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                save_pending_summary_state()
                print("ℹ️ Resumo de pendências não publicado: lista inalterada.")
                continue

            # Revalidar contra o estado atual, pois o monitor pode ter
            # encerrado alertas enquanto o resumo era preparado.
            current_ids = {
                str(item.get("revision_id")) for item in get_pending_posted_edits()
            }
            items = [
                item for item in items
                if str(item.get("revision_id")) in current_ids
            ]
            if not items:
                continue
            signature = pending_summary_signature(items)
            message = build_pending_summary_message(items)
            if not message:
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                save_pending_summary_state()
                continue

            result = send_telegram_message(
                message,
                parse_mode="HTML",
                reply_markup={
                    "inline_keyboard": [
                        [
                            {
                                "text": "📋 Ver todos os pendentes",
                                "callback_data": "pend:0",
                            }
                        ]
                    ]
                },
            )
            if result:
                with pending_summary_lock:
                    pending_summary_state["last_sent_at"] = now
                    pending_summary_state["last_signature"] = signature
                save_pending_summary_state()
                print("✅ Resumo prioritário de pendências publicado:", len(items), "alertas.")

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
# AÇÕES REVERSÍVEIS / BOTÕES DE DESFAZER
# =========================================================

def save_reversible_actions():
    with reversible_actions_persist_lock:
        with reversible_actions_lock:
            data = list(reversible_actions.values())
        atomic_write_json(REVERSIBLE_ACTIONS_FILE, data)


def cleanup_reversible_actions(save=True):
    cutoff = time.time() - REVERSIBLE_ACTION_TTL_SECONDS

    with reversible_actions_lock:
        expired = [
            token
            for token, item in reversible_actions.items()
            if float(item.get("created_at") or 0) < cutoff
        ]
        for token in expired:
            reversible_actions.pop(token, None)

    if expired and save:
        try:
            save_reversible_actions()
        except Exception as e:
            print(
                "⚠️ Erro ao limpar ações reversíveis:",
                safe_exception(e)
            )


def load_reversible_actions():
    global reversible_actions

    data = load_json(REVERSIBLE_ACTIONS_FILE, [])
    loaded = {}
    cutoff = time.time() - REVERSIBLE_ACTION_TTL_SECONDS

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token") or "").strip()
            action = str(item.get("action") or "").strip()
            target = str(item.get("target") or "").strip()
            created_at = float(item.get("created_at") or 0)

            if not token or not action or not target or created_at < cutoff:
                continue

            loaded[token] = {
                "token": token,
                "action": action,
                "target": target,
                "created_at": created_at,
            }

    with reversible_actions_lock:
        reversible_actions = loaded

    print("✅ Ações reversíveis carregadas:", len(loaded))

    try:
        save_reversible_actions()
    except Exception:
        pass


def reversible_action_markup(action, target, label):
    """
    Cria um botão persistente para executar a ação oposta.
    O callback carrega apenas um token curto; alvo e ação ficam em /data.
    """
    cleanup_reversible_actions(save=False)

    token = secrets.token_hex(8)
    item = {
        "token": token,
        "action": str(action),
        "target": str(target),
        "created_at": time.time(),
    }

    with reversible_actions_lock:
        reversible_actions[token] = item

    try:
        save_reversible_actions()
    except Exception as e:
        print(
            "⚠️ Não foi possível persistir botão reversível:",
            safe_exception(e)
        )

    return {
        "inline_keyboard": [
            [
                {
                    "text": label,
                    "callback_data": f"act:{token}",
                }
            ]
        ]
    }


def get_reversible_action(token):
    cleanup_reversible_actions()

    with reversible_actions_lock:
        item = reversible_actions.get(token)
        return dict(item) if item else None


def inverse_action_spec(action):
    mapping = {
        "observe": ("unobserve", "⛔ Desobservar"),
        "unobserve": ("observe", "🔎 Observar novamente (6h)"),
        "ignore": ("unignore", "👀 Deixar de ignorar"),
        "unignore": ("ignore", "🙈 Ignorar novamente (6h)"),
        "watch_perm": ("unwatch", "🙈 Desvigiar"),
        "watch_temp": ("unwatch", "🙈 Desvigiar"),
        "unwatch": ("watch_perm", "👁 Vigiar novamente"),
        "watch_filter": ("unwatch_filter", "🛑 Desvigiar filtro"),
        "unwatch_filter": ("watch_filter", "🛡 Vigiar filtro novamente"),
    }
    return mapping.get(action)


def execute_reversible_action(action, target):
    """
    Executa uma ação pedida por botão de desfazer/refazer.
    Retorna (success, changed, message, parse_mode).
    """
    if action == "observe":
        username = normalize_username(target) or target
        success = observe_user(username)
        return (
            success,
            success,
            (
                "🔎 Conta colocada em observação\n\n"
                f"👤 {user_contributions_link_html(username)}\n"
                "⏳ Duração: 6 horas"
            ),
            "HTML",
        )

    if action == "unobserve":
        username = normalize_username(target) or target
        success, removed = stop_observing_user(username)
        return (
            success,
            removed,
            (
                "⛔ Observação encerrada\n\n"
                f"👤 {user_contributions_link_html(username)}"
            ),
            "HTML",
        )

    if action == "ignore":
        username = normalize_username(target) or target
        success = ignore_user(username)
        return (
            success,
            success,
            (
                "🙈 Conta temporariamente ignorada\n\n"
                f"👤 {user_contributions_link_html(username)}\n"
                "⏳ Duração: 6 horas"
            ),
            "HTML",
        )

    if action == "unignore":
        username = normalize_username(target) or target
        success, removed = stop_ignoring_user(username)
        return (
            success,
            removed,
            (
                "👀 Conta removida da lista de ignoradas\n\n"
                f"👤 {user_contributions_link_html(username)}"
            ),
            "HTML",
        )

    if action == "watch_perm":
        title = normalize_page_title(target) or target
        success, added = add_watched_page(title)
        return (
            success,
            added,
            f"👁 {title} adicionada à vigilância.",
            None,
        )

    if action == "watch_temp":
        title = normalize_page_title(target) or target
        success = add_temporary_watched_page(title)
        return (
            success,
            success,
            (
                "👁 Página colocada em vigilância\n\n"
                f"📝 {title}\n"
                "⏳ Duração: 6 horas"
            ),
            None,
        )

    if action == "unwatch":
        title = normalize_page_title(target) or target
        success, removed = remove_any_watched_page(title)
        return (
            success,
            removed,
            f"🙈 {title} removida da vigilância.",
            None,
        )

    if action == "watch_filter":
        filter_id = normalize_filter_id(target)
        success, added, info = add_abuse_filter(filter_id)
        description = info.get("description") if info else None
        message = (
            "🛡 Filtro adicionado à vigilância\n\n"
            f"🔢 Filtro: {filter_id}"
        )
        if description:
            message += f"\n📋 {description}"
        return success, added, message, None

    if action == "unwatch_filter":
        filter_id = normalize_filter_id(target)
        success, removed = remove_abuse_filter(filter_id)
        return (
            success,
            removed,
            f"🛑 Filtro {filter_id} removido da vigilância.",
            None,
        )

    return False, False, "❌ Ação desconhecida.", None


def process_reversible_action_callback(callback, token):
    callback_id = callback.get("id")
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
            "Apenas administradores do canal podem executar esta ação."
        )
        return

    item = get_reversible_action(token)
    if not item:
        answer_callback_query(
            callback_id,
            "Este botão expirou ou não está mais disponível."
        )
        return

    action = item["action"]
    target = item["target"]

    success, changed, message, parse_mode = execute_reversible_action(
        action,
        target
    )

    if not success:
        answer_callback_query(callback_id, "Não foi possível executar a ação.")
        return

    if not changed:
        answer_callback_query(
            callback_id,
            "A situação já estava nesse estado."
        )
        return

    answer_callback_query(callback_id, "Ação executada.")

    inverse = inverse_action_spec(action)
    reply_markup = None
    if inverse:
        inverse_action, label = inverse

        # Se desfizermos uma vigilância temporária, o botão de refazer deve
        # restaurar também o caráter temporário.
        if action == "unwatch":
            # Botões criados a partir de "watch_temp" usam alvo especial
            # apenas quando explicitamente solicitado pelo chamador.
            pass

        reply_markup = reversible_action_markup(
            inverse_action,
            target,
            label
        )

    actor = telegram_person_display_name(clicker)
    if actor:
        if parse_mode == "HTML":
            message += f"\n\n👮 Ação por {html.escape(actor)}"
        else:
            message += f"\n\n👮 Ação por {actor}"

    send_telegram_message(
        message,
        chat_id=TELEGRAM_CHANNEL,
        parse_mode=parse_mode,
        reply_markup=reply_markup,
    )


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


def get_user_info(username, use_cache=True, raise_on_error=False):
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

        data = response.json()
        if data.get("error") or "query" not in data:
            raise ValueError("Resposta inesperada da API de usuários: " + str(data.get("error", "sem query")))
        users = data["query"].get("users", [])

        if not users:
            raise ValueError("API não retornou a lista de usuários")

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
        if raise_on_error:
            raise
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
    try:
        info = get_user_info(
            username,
            use_cache=False,
            raise_on_error=True
        )
    except Exception:
        return (
            "⚠️ Não foi possível consultar a Wikipédia agora. "
            "Tente novamente em alguns instantes.",
            None
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

    # Codificar o título completo uma única vez. Não codificar o nome
    # separadamente e depois recodificar a URL na formatação do Telegram.
    user_title = "Usuário:" + username.replace(" ", "_")
    user_url = "https://pt.wikipedia.org/wiki/" + quote(user_title, safe=":")

    message = (
        f'👤 <a href="{html.escape(user_url, quote=True)}">'
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
        f'🔗 <a href="{html.escape(url, quote=True)}">Ver registro de bloqueios</a>'
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
        "🔒 Bloqueio aplicado"
    )

    target_url = block_log_url(target)

    automatic_line = ""
    if event.get("_post_block_observation_scheduled"):
        automatic_line = (
            "\n\n🔎 Observação automática programada\n"
            "A conta será observada por 6 horas após o término do bloqueio."
        )

    return (
        f"{heading}\n\n"
        f'👤 <a href="{html.escape(target_url, quote=True)}">'
        f"{html.escape(target)}</a>\n"
        f"📌 Motivo: {html.escape(reason)}\n"
        f"⏳ Duração: {html.escape(duration)}\n"
        f"🛡 Aplicado por: "
        f"{html.escape(blocker)}"
        f"{automatic_line}"
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

            target = extract_block_target(
                details.get("title")
                or change.get("title")
                or ""
            )

            expiry_at = block_expiry_timestamp(
                details,
                change
            )

            scheduled = False

            # Apenas contas registradas. IPs/faixas e bloqueios indefinidos
            # ficam fora da automação.
            if (
                target
                and target != "Desconhecido"
                and not is_ip_address(target)
                and expiry_at is not None
            ):
                canonical_target = normalize_username(target)

                if canonical_target:
                    scheduled = schedule_post_block_observation(
                        canonical_target,
                        expiry_at
                    )

            details["_post_block_observation_scheduled"] = scheduled

            record_community_event(
                "block",
                actor=details.get("user"),
                title=target,
                timestamp=parse_mediawiki_timestamp(details.get("timestamp")) or time.time(),
                revision_id=details.get("logid") or log_id,
                metadata={"action": action},
            )

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


def general_protection_log_url():
    return (
        "https://pt.wikipedia.org/w/index.php"
        "?title=Special:Log&type=protect"
    )


def format_protection_burst_message():
    url = general_protection_log_url()
    return (
        "⚠️ <b>Mais de 5 proteções no mesmo minuto</b>\n\n"
        "Mais de 5 proteções ou alterações de proteção foram "
        "efetuadas neste minuto. Para evitar flooding, os alertas "
        "individuais adicionais foram suprimidos.\n\n"
        f'🔗 <a href="{html.escape(url, quote=True)}">Ver registro de proteções</a>'
    )


def handle_protection_event(change):
    """Aplica anti-flood antes de consultar detalhes do registro.

    Os cinco primeiros eventos do minuto são processados normalmente.
    O sexto gera um único resumo, e o sexto e os seguintes não entram
    na fila nem provocam consulta adicional a list=logevents.
    """
    now = time.time()
    minute_bucket = int(now // 60)
    send_summary = False
    allow_individual = False

    with protection_rate_lock:
        if protection_rate_state["minute_bucket"] != minute_bucket:
            protection_rate_state["minute_bucket"] = minute_bucket
            protection_rate_state["count"] = 0
            protection_rate_state["summary_sent"] = False

        protection_rate_state["count"] += 1
        count = protection_rate_state["count"]

        if count <= MAX_PROTECTION_ALERTS_PER_MINUTE:
            allow_individual = True
        elif not protection_rate_state["summary_sent"]:
            protection_rate_state["summary_sent"] = True
            send_summary = True

    if allow_individual:
        protection_queue.put(change)
        print(
            "🛡️ Evento de proteção aceito:",
            change.get("title"),
            "| minuto:", minute_bucket,
            "| posição:", count,
        )
        return

    if send_summary:
        telegram_queue.put({
            "message": format_protection_burst_message(),
            "title": "Muitas proteções",
            "parse_mode": "HTML",
        })
        print(
            "⚠️ Mais de 5 proteções no mesmo minuto; "
            "alertas individuais adicionais suprimidos."
        )
    else:
        print(
            "⏭️ Proteção suprimida por limite anti-flood:",
            change.get("title"),
            "| posição:", count,
        )


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
            f'📝 <a href="{html.escape(protection_log_url(title), quote=True)}">'
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

            record_community_event(
                "protect",
                actor=details.get("user"),
                title=details.get("title") or change.get("title"),
                timestamp=parse_mediawiki_timestamp(details.get("timestamp")) or time.time(),
                revision_id=details.get("logid") or log_id,
                metadata={"action": action},
            )

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


def _revision_content_for_diff(revision_id):
    """Obtém wikitext de uma revisão para fallback da comparação."""
    response = requests.get(WIKIPEDIA_API, params={"action":"query","format":"json","formatversion":2,"prop":"revisions","revids":int(revision_id),"rvprop":"content","rvslots":"main"}, headers=HEADERS, timeout=30)
    response.raise_for_status()
    pages = response.json().get("query", {}).get("pages", [])
    if not pages: return ""
    revisions = pages[0].get("revisions", [])
    if not revisions: return ""
    return str(revisions[0].get("slots", {}).get("main", {}).get("content", "") or "")


def _content_diff_fallback(old_revision, new_revision):
    """Reconstrói trechos adicionados/removidos quando o HTML de compare muda."""
    try:
        old_text = _revision_content_for_diff(old_revision); new_text = _revision_content_for_diff(new_revision)
        old_lines, new_lines = old_text.splitlines(), new_text.splitlines()
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
        removed, added = [], []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ("delete", "replace"): removed.extend(old_lines[i1:i2])
            if tag in ("insert", "replace"): added.extend(new_lines[j1:j2])
        added_text = "\n".join(added)[:MAX_DIFF_CHARS]; removed_text = "\n".join(removed)[:MAX_DIFF_CHARS]
        print("🧩 Diff reconstruído pelo conteúdo das revisões:", old_revision, "→", new_revision, "| adicionados:", len(added_text), "| removidos:", len(removed_text))
        return {"added":added_text,"removed":removed_text,"has_diff_cells":bool(added_text or removed_text),"whitespace_changed":bool(added_text or removed_text) and added_text == removed_text}
    except Exception as exc:
        print("⚠️ Falha ao reconstruir diff pelo conteúdo:", old_revision, "→", new_revision, "|", safe_exception(exc))
        return {"added":"","removed":"","has_diff_cells":False,"whitespace_changed":False}


def get_revision_diff(old_revision, new_revision):
    try:
        response = requests.get(WIKIPEDIA_API, params={"action":"compare","format":"json","formatversion":2,"fromrev":old_revision,"torev":new_revision,"prop":"diff"}, headers=HEADERS, timeout=30)
        response.raise_for_status()
        diff_html = response.json().get("compare", {}).get("body", "") or ""
        added_matches = re.findall(r"<td\b[^>]*class=[\"'][^\"']*\bdiff-addedline\b[^\"']*[\"'][^>]*>(.*?)</td>", diff_html, flags=re.I|re.S)
        removed_matches = re.findall(r"<td\b[^>]*class=[\"'][^\"']*\bdiff-deletedline\b[^\"']*[\"'][^>]*>(.*?)</td>", diff_html, flags=re.I|re.S)
        added = "\n".join(clean_html(x) for x in added_matches); removed = "\n".join(clean_html(x) for x in removed_matches)
        if added_matches or removed_matches:
            return {"added":added[:MAX_DIFF_CHARS],"removed":removed[:MAX_DIFF_CHARS],"has_diff_cells":True,"whitespace_changed":added == removed}
        print("⚠️ Compare sem células de diff reconhecíveis; usando fallback:", old_revision, "→", new_revision, "| html:", len(diff_html))
        return _content_diff_fallback(old_revision, new_revision)
    except Exception as exc:
        print("⚠️ Erro na API compare; usando fallback:", old_revision, "→", new_revision, "|", safe_exception(exc))
        return _content_diff_fallback(old_revision, new_revision)


def get_revert_risk(revision_id):
    """Retorna probabilidade ou None; nunca interpreta ausência de score como zero."""
    try:
        # bool é subtipo de int em Python, mas não é identificador de revisão.
        if isinstance(revision_id, bool):
            raise ValueError("rev_id booleano")
        rev_id = int(revision_id)
        if rev_id <= 0:
            raise ValueError("rev_id não positivo")
    except (TypeError, ValueError, OverflowError) as exc:
        print("⚠️ Lift Wing: revisão inválida:", repr(revision_id), safe_exception(exc))
        return None

    try:
        response = requests.post(
            REVERT_RISK_API,
            headers={**HEADERS, "Content-Type": "application/json"},
            json={"rev_id": rev_id, "lang": "pt"},
            timeout=30,
        )
        if response.status_code == 422:
            # Não repetir automaticamente: a resposta explica a revisão rejeitada.
            # Não registrar cabeçalhos de autenticação ou tokens.
            detail = (response.text or "").replace("\r", " ").replace("\n", " ")[:600]
            print(f"⚠️ Lift Wing HTTP 422 rev_id={rev_id} lang=pt resposta={detail!r}")
            return None
        if response.status_code == 429:
            print(f"⚠️ Rate limit Lift Wing rev_id={rev_id}.")
            return None
        response.raise_for_status()
        probability = response.json().get("output", {}).get("probabilities", {}).get("true")
        if probability is None:
            print(f"⚠️ Lift Wing sem probabilidade rev_id={rev_id}.")
            return None
        score = float(probability)
        if not 0.0 <= score <= 1.0:
            print(f"⚠️ Lift Wing probabilidade fora do intervalo rev_id={rev_id}.")
            return None
        return score
    except Exception as exc:
        print(f"⚠️ Erro Lift Wing rev_id={rev_id}:", safe_exception(exc))
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


def normalized_diff_lines(value):
    lines = []
    for raw in str(value or "").splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if line:
            lines.append(line)
    return lines


# Calibração conservadora: mudanças cosméticas e tradução de datas em fontes.
# Nenhuma destas regras modifica a previsão original do modelo Revert Risk.
_REFERENCE_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5,
    "june": 6, "july": 7, "august": 8, "september": 9,
    "october": 10, "november": 11, "december": 12,
    "janeiro": 1, "fevereiro": 2, "março": 3, "marco": 3,
    "abril": 4, "maio": 5, "junho": 6, "julho": 7, "agosto": 8,
    "setembro": 9, "outubro": 10, "novembro": 11, "dezembro": 12,
}


def _canonical_reference_dates(text):
    """Substitui SOMENTE datas de acesso e datas bibliográficas válidas."""
    text = str(text or "")
    found = []

    def canonical(year, month, day):
        try:
            return datetime(int(year), int(month), int(day)).strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            return None

    def access_iso(match):
        date = canonical(match.group(1), match.group(2), match.group(3))
        if date is None:
            return match.group(0)
        found.append(("access", date))
        return "__ACCESS_DATE_" + date + "__"

    def access_br(match):
        date = canonical(match.group(3), match.group(2), match.group(1))
        if date is None:
            return match.group(0)
        found.append(("access", date))
        return "__ACCESS_DATE_" + date + "__"

    text = re.sub(r"\bRetrieved\s+(\d{4})-(\d{1,2})-(\d{1,2})\b", access_iso, text, flags=re.I)
    text = re.sub(r"\bAcessad[oa]\s+em\s+(\d{1,2})/(\d{1,2})/(\d{4})\b", access_br, text, flags=re.I)

    def textual_date(match):
        first, month_name, year = match.group(1), match.group(2), match.group(3)
        date = canonical(year, _REFERENCE_MONTHS[month_name.casefold()], first)
        if date is None:
            return match.group(0)
        found.append(("bibliographic", date))
        return "__BIB_DATE_" + date + "__"

    months = "|".join(sorted(map(re.escape, _REFERENCE_MONTHS), key=len, reverse=True))
    # Datas textuais: "July 15, 2014" ou "15 de julho de 2014".
    def english_date(match):
        date = canonical(match.group(3), _REFERENCE_MONTHS[match.group(1).casefold()], match.group(2))
        if date is None:
            return match.group(0)
        found.append(("bibliographic", date))
        return "__BIB_DATE_" + date + "__"

    text = re.sub(rf"\b({months})\s+(\d{{1,2}}),?\s+(\d{{4}})\b", english_date, text, flags=re.I)
    text = re.sub(rf"\b(\d{{1,2}})\s+de\s+({months})\s+de\s+(\d{{4}})\b", textual_date, text, flags=re.I)
    return text, found


def reference_date_priority_adjustment(diff):
    """Desconto apenas se TODAS as mudanças forem traduções de datas equivalentes.

    Exige evidência bibliográfica, datas válidas e ao menos uma data traduzida;
    datas alteradas, remoção de fontes e alterações adicionais não se beneficiam.
    """
    old = " ".join(normalized_diff_lines(diff.get("removed", "")))
    new = " ".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or max(len(old), len(new)) > MAX_DIFF_CHARS:
        return None
    old_canonical, old_dates = _canonical_reference_dates(old)
    new_canonical, new_dates = _canonical_reference_dates(new)
    if not old_dates or not new_dates or old == new or old_dates != new_dates:
        return None
    if not any(kind == "access" for kind, _ in old_dates + new_dates):
        return None
    if not (re.search(r"<ref\b|\{\{\s*(?:citar|cite|refer[êe]ncia)", old + new, re.I)
            or re.search(r"\b(?:Retrieved|Acessad[oa]\s+em)\b", old + new, re.I)):
        return None
    # Só tolera espaços adjacentes aos marcadores de datas, não reescreve prosa.
    def compact(value):
        return re.sub(r"\s+", " ", value).strip()
    if compact(old_canonical) != compact(new_canonical):
        return None
    return {"factor": 0.55, "reason": "tradução de datas equivalentes em referência; conteúdo preservado"}


def isolated_wikilink_priority_adjustment(diff):
    """Desconto apenas para envolver texto existente em um wikilink simples."""
    old = " ".join(normalized_diff_lines(diff.get("removed", "")))
    new = " ".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or len(old) > MAX_DIFF_CHARS or len(new) > MAX_DIFF_CHARS:
        return None
    # Apenas um wikilink novo, sem âncoras, pipes, namespaces ou alteração de texto.
    matches = list(re.finditer(r"\[\[([^\[\]\n|#:{}<>]{3,100})\]\]", new))
    if len(matches) != 1 or "[[" in old or "]]" in old:
        return None
    target = matches[0].group(1)
    if not target.strip() or target != target.strip() or ":" in target:
        return None
    restored = new[:matches[0].start()] + target + new[matches[0].end():]
    if restored != old:
        return None
    return {"factor": 0.55, "reason": "inclusão isolada de link interno; texto preservado"}


def reference_removal_priority_adjustment(change, diff):
    """Sinal contextual, não prova de vandalismo; só referências inteiras removidas."""
    if change.get("type") == "new":
        return None
    removed = str(diff.get("removed") or "")
    added = str(diff.get("added") or "")
    refs_removed = re.findall(r"<ref\b[^>]*>.*?</ref\s*>|<ref\b[^>]*/\s*>", removed, re.I | re.S)
    if not refs_removed:
        return None
    # Não penalizar referência movida ou substituída no mesmo diferencial.
    if re.search(r"<ref\b", added, re.I):
        return None
    # Sem sumário explicativo há suspeita adicional; sumário não garante legitimidade.
    comment = str(change.get("comment") or "").strip()
    generic = bool(re.fullmatch(r"(?:ajustes?|ediç(?:ão|ões)|edit|fix|correç(?:ão|ões)|update|atualizaç(?:ão|ões)|minor|pequena edição|/*[^*]*\*/)?[.! ]*", comment, re.I))
    if not comment or generic:
        return {"bonus": 0.12, "reason": "referência removida sem sumário explicativo; verificar fonte e contexto"}
    explanatory = bool(re.search(r"(?:refer[êe]ncia|fonte|link|url|citaç|duplicad|inválid|inval|quebrad|mort[oa]|substitu|remov|retir|desatualiz)", comment, re.I))
    if explanatory:
        return {"bonus": 0.025, "reason": "referência removida com justificativa no sumário; conferir justificativa"}
    return {"bonus": 0.08, "reason": "referência removida; sumário não explica a remoção"}


def whitespace_only_priority_adjustment(diff):
    """Confirma mudança exclusivamente de linhas vazias/espaços, sem texto removido."""
    if not diff.get("has_diff_cells"):
        return None
    old = str(diff.get("removed") or "")
    new = str(diff.get("added") or "")
    if old == new and not diff.get("whitespace_changed"):
        return None
    if re.sub(r"\s+", "", old) != re.sub(r"\s+", "", new):
        return None
    # Não remover espaços dentro de palavras ou parâmetros: apenas linhas vazias
    # e diferenças de indentação/espaçamento no começo/fim das linhas.
    old_lines = [line.strip() for line in old.splitlines() if line.strip()]
    new_lines = [line.strip() for line in new.splitlines() if line.strip()]
    if old_lines != new_lines:
        return None
    return {"factor": 0.30, "reason": "alteração exclusivamente cosmética de linhas vazias/espaçamento"}


def orthographic_priority_adjustment(diff):
    """Reduz prioridade somente para até três alterações de pontuação/acentuação.

    Exige palavras idênticas após remover apenas acentos e pontuação;
    não equipara palavras diferentes, números, negações ou conteúdo removido.
    """
    import difflib
    old = " ".join(normalized_diff_lines(diff.get("removed", "")))
    new = " ".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or max(len(old), len(new)) > 2000:
        return None
    if re.search(r"\d", old + new):
        return None
    def canonical(value):
        import unicodedata
        decomposed = unicodedata.normalize("NFD", value)
        without_accents = "".join(c for c in decomposed if unicodedata.category(c) != "Mn")
        return re.sub(r"[^\w]+", " ", without_accents, flags=re.UNICODE).strip().casefold()
    if canonical(old) != canonical(new):
        return None
    edits = [(old[a:b], new[c:d]) for op, a, b, c, d in
             difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
             if op != "equal"]
    if not 1 <= len(edits) <= 3 or any(max(len(a), len(b)) > 3 for a, b in edits):
        return None
    return {"factor": 0.85, "reason": "correção mínima de pontuação/acentuação; conferir contexto"}


def equivalent_wikimarkup_priority_adjustment(diff):
    """Reduz prioridade só quando a mudança isolada é aspas wiki de ênfase.

    Preserva literalmente texto, links, números e demais marcações; não tenta
    inferir equivalência visual para mudanças de conteúdo ou de estilo real.
    """
    old = "\n".join(normalized_diff_lines(diff.get("removed", "")))
    new = "\n".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or max(len(old), len(new)) > 500:
        return None
    # Apenas sequências de apóstrofos que representam marcação wiki (2 a 5).
    # O restante do conteúdo deve ser byte a byte idêntico, inclusive links.
    def without_emphasis(value):
        return re.sub(r"(?<!')'{2,5}(?!')", "", value)
    if old == new or without_emphasis(old) != without_emphasis(new):
        return None
    if not re.search(r"(?<!')'{2,5}(?!')", old + new):
        return None
    # Conservar apenas mudanças locais de marcação: não aceitar a remoção
    # de toda a ênfase ou mudanças que alterem o conjunto de estilos.
    def marks(value):
        return sorted(re.findall(r"(?<!')'{2,5}(?!')", value))
    if marks(old) != marks(new):
        return None
    return {"factor": 0.85, "reason": "marcação wiki de ênfase equivalente; conferir contexto"}


def minimal_text_priority_adjustment(diff):
    """Redutor moderado de prioridade para uma única mudança lexical curta.

    Não altera o Revert Risk original nem trata a edição como legítima.
    Exclui números, negações e mudanças com mais de um trecho modificado.
    """
    import difflib
    old = " ".join(normalized_diff_lines(diff.get("removed", "")))
    new = " ".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or len(old) > 500 or len(new) > 500:
        return None
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    edits = [(old[a:b], new[c:d]) for op, a, b, c, d in matcher.get_opcodes()
             if op != "equal"]
    if len(edits) != 1:
        return None
    before, after = edits[0]
    if max(len(before), len(after)) > 16 or any(ch.isdigit() for ch in before + after):
        return None
    if not re.fullmatch(r"[\wÀ-ÿ-]*", before) or not re.fullmatch(r"[\wÀ-ÿ-]*", after):
        return None
    if not before and not after:
        return None
    # Negações podem inverter inteiramente o sentido da frase.
    if re.search(r"\b(?:não|nao|nunca|jamais|sem)\b", before + " " + after, re.I):
        return None
    # Somente um pequeno ajuste na prioridade, sem blindar alterações factuais.
    return {"factor": 0.85, "reason": "alteração lexical mínima; conferir contexto factual"}


def children_count_priority_adjustment(change, diff):
    """Avalia apenas uma troca isolada no parâmetro numérico |filhos da infocaixa."""
    if change.get("type") == "new":
        return None
    old = "\n".join(normalized_diff_lines(diff.get("removed", "")))
    new = "\n".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or max(len(old), len(new)) > 600:
        return None
    pattern = r"(?im)(?P<prefix>^\s*\|\s*filhos\s*=\s*)(?P<number>\d{1,2})(?P<suffix>\s*$)"
    before = list(re.finditer(pattern, old))
    after = list(re.finditer(pattern, new))
    if len(before) != 1 or len(after) != 1:
        return None
    a, b = before[0], after[0]
    # A única mudança admissível é o valor numérico; outras linhas intactas.
    if old[:a.start("number")] != new[:b.start("number")]:
        return None
    if old[a.end("number"):] != new[b.end("number") :]:
        return None
    delta = int(b.group("number")) - int(a.group("number"))
    if delta == 1:
        return {"factor": 0.80, "reason": "acréscimo isolado de um filho na infocaixa; informação não verificada"}
    if delta > 1:
        return {"bonus": min(0.12, 0.04 + 0.02 * (delta - 1)),
                "reason": "aumento de vários filhos na infocaixa; verificar informação biográfica"}
    return None


def contextual_prose_addition_adjustment(change, diff):
    """Redução modesta para uma inserção curta em prosa, sem supor veracidade."""
    import difflib
    if change.get("type") == "new":
        return None
    old = "\n".join(normalized_diff_lines(diff.get("removed", "")))
    new = "\n".join(normalized_diff_lines(diff.get("added", "")))
    if not old or not new or len(old) < 70 or max(len(old), len(new)) > MAX_DIFF_CHARS:
        return None
    if re.search(r"<ref\b|\{\{|\[\[|https?://|www\.", old + new, re.I):
        return None
    edits = [(tag, i, j, k, l) for tag, i, j, k, l in
             difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
             if tag != "equal"]
    if len(edits) != 1 or edits[0][0] != "insert":
        return None
    _, i, j, k, l = edits[0]
    addition = new[k:l]
    if not 8 <= len(addition.strip()) <= 90 or len(addition.split()) > 16:
        return None
    # Exige prosa dentro de uma frase, não acréscimo de seção ou conteúdo isolado.
    if i < 20 or i > len(old) - 15 or not old[i - 1].isalnum() and old[i - 1] not in ' ,;:':
        return None
    if re.search(r"[<>={}\[\]{}|#@]|\b(?:não|nunca|jamais|sem)\b", addition, re.I):
        return None
    if re.search(r"(?:https?://|www\.|\b(?:compre|clique|telegram|whatsapp)\b)", addition, re.I):
        return None
    if not re.search(r"[A-Za-zÀ-ÿ]", addition):
        return None
    return {"factor": 0.85, "reason": "acréscimo curto de prosa contextual; fatos não verificados"}


def contextual_priority_calibration(change, diff, strong_signals):
    """Conservative contextual discount; never stacks with other discounts."""
    if change.get("type") == "new" or strong_signals:
        return None
    title = str(change.get("title") or "").replace("_", " ").strip()
    folded = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode().casefold()
    added = str(diff.get("added") or "")
    removed = str(diff.get("removed") or "")
    # User pages: only literal punctuation/accent edits, no new links or promotion.
    if folded.startswith(("usuario:", "usuaria:", "usuario(a):")) and not folded.startswith(("usuario discussao:", "usuaria discussao:")):
        adjustment = orthographic_priority_adjustment(diff)
        if (adjustment and not count_external_links(added + removed)
                and not re.search(r"(?:www\.|@|\b(?:instagram|whatsapp|telegram|compre|contrate|patrocinad[oa]|empresa|servicos?)\b)", added + removed, re.I)
                and not re.search(r"\[\[|\{\{|<[^>]+>", added + removed)):
            return {"factor": 0.70, "reason": "correção trivial em página de usuário; conferir contexto"}
    # Community conversations: append-only signed comments, not arbitrary project pages.
    community = is_discussion_namespace(change)
    if not community or removed.strip() or not added.strip():
        return None
    body = discussion_comment_body(added)
    if (not looks_like_signed_discussion_comment(added) or len(body) < 12
            or count_external_links(body) or max(profanity_score(body), repetition_score(body), nonsense_score(body)) >= 0.75
            or re.search(r"(?:www\.|\b(?:compre|contrate|patrocinad[oa]|whatsapp|instagram)\b)", body, re.I)):
        return None
    help_page = any(x in folded for x in (
        "ajuda:", "wikipedia:cafe dos novatos", "wikipedia:pedidos/", "wikipedia:esplanada/"))
    help_request = bool(re.search(
        r"\b(?:peco ajuda|peço ajuda|preciso de (?:ajuda|orientacao|orientação)|"
        r"sou nov[oa]|como faco|como faço|agradeco sugestoes|agradeço sugestões|"
        r"avaliacao|avaliação|podem me ajudar|alguma duvida|alguma dúvida)\b", body, re.I))
    if help_page and help_request:
        return {"factor": 0.70, "reason": "pedido de ajuda assinado em espaço comunitário"}
    return {"factor": 0.70, "reason": "comentário assinado em espaço de discussão"}


def benign_technical_change(diff):
    """
    Reconhece alterações técnicas mínimas e de baixo risco.

    Nesta primeira versão o redutor é deliberadamente conservador:
    - poucas linhas alteradas;
    - pouca diferença textual;
    - nenhuma heurística forte de vandalismo;
    - mudança isolada de dimensão em px ou pequena alteração numérica
      dentro de um parâmetro de predefinição/infobox.

    O objetivo é reduzir falsos positivos como 250px -> 270px sem
    transformar qualquer mudança numérica em edição automaticamente segura.
    """
    added = normalized_diff_lines(diff.get("added", ""))
    removed = normalized_diff_lines(diff.get("removed", ""))

    if not added or not removed:
        return None

    if len(added) > 3 or len(removed) > 3:
        return None

    added_text = "\n".join(added)
    removed_text = "\n".join(removed)

    if len(added_text) > 500 or len(removed_text) > 500:
        return None

    # Não aplica redutor quando o próprio conteúdo já contém sinal forte.
    signals = [
        profanity_score(added_text),
        repetition_score(added_text),
        destructive_score(added_text, removed_text),
        nonsense_score(added_text),
    ]
    if max(signals) >= 0.75:
        return None

    def skeleton(value):
        # Mantém a estrutura e substitui números por marcador.
        value = value.casefold()
        value = re.sub(r"(?<![\w])\d+(?:[.,]\d+)?(?=\s*px\b)", "<num>", value)
        value = re.sub(r"(?<![\w])\d+(?:[.,]\d+)?(?![\w])", "<num>", value)
        return re.sub(r"\s+", " ", value).strip()

    # Caso mais seguro: uma única linha em que apenas o número mudou.
    if len(added) == 1 and len(removed) == 1:
        old = removed[0]
        new = added[0]

        px_old = re.search(r"(?<!\w)(\d{1,4})\s*px\b", old, flags=re.I)
        px_new = re.search(r"(?<!\w)(\d{1,4})\s*px\b", new, flags=re.I)

        if px_old and px_new and skeleton(old) == skeleton(new):
            old_px = int(px_old.group(1))
            new_px = int(px_new.group(1))

            # Dimensões absurdas não recebem o benefício.
            if 20 <= old_px <= 2000 and 20 <= new_px <= 2000:
                ratio = max(old_px, new_px) / max(1, min(old_px, new_px))
                if ratio <= 2.0:
                    return {
                        "factor": 0.55,
                        "reason": "alteração técnica mínima de dimensão de imagem",
                    }

        # Pequena troca numérica isolada em parâmetro de predefinição.
        # Exige '=' para não reduzir datas/quantidades alteradas em prosa.
        if "=" in old and "=" in new and skeleton(old) == skeleton(new):
            nums_old = re.findall(r"(?<!\w)\d+(?:[.,]\d+)?(?!\w)", old)
            nums_new = re.findall(r"(?<!\w)\d+(?:[.,]\d+)?(?!\w)", new)

            if len(nums_old) == 1 and len(nums_new) == 1:
                try:
                    a = float(nums_old[0].replace(",", "."))
                    b = float(nums_new[0].replace(",", "."))
                    magnitude = max(abs(a), abs(b), 1.0)
                    relative_change = abs(a - b) / magnitude
                except Exception:
                    relative_change = 1.0

                if relative_change <= 0.25:
                    return {
                        "factor": 0.70,
                        "reason": "pequena alteração numérica em parâmetro técnico",
                    }

    return None


def is_discussion_namespace(change):
    """Reconhece espaços de conversa, inclusive páginas de ajuda comunitária.

    Não trata todo o namespace Ajuda como discussão: apenas páginas
    reconhecidas como locais de perguntas e respostas recebem o redutor.
    """
    title = str(change.get("title") or "").replace("_", " ").strip()
    normalized = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode().casefold()
    discussion_help = (
        "ajuda:tire suas duvidas",
        "ajuda:contato/fale com a wikipedia",
    )
    if any(normalized == prefix or normalized.startswith(prefix + "/") for prefix in discussion_help):
        return True
    # Páginas comunitárias de conversa explicitamente identificadas.
    if normalized.startswith(("wikipedia:esplanada/", "wikipedia:pedidos/", "wikipedia:cafe dos novatos")):
        return True
    try:
        namespace = int(change.get("namespace"))
        if namespace > 0 and namespace % 2 == 1:
            return True
    except (TypeError, ValueError):
        pass
    if ":" not in title:
        return False
    prefix = title.split(":", 1)[0].casefold()
    return "discussão" in prefix or "discussao" in prefix or prefix.endswith(" talk")


def looks_like_signed_discussion_comment(added_text):
    """
    Detecta uma assinatura típica já expandida pelo MediaWiki:
    usuário/contribuições + horário/data + UTC.
    """
    value = str(added_text or "")

    timestamp = bool(
        re.search(
            r"\b\d{1,2}h\d{2}min\s+de\s+\d{1,2}\s+de\s+"
            r"[A-Za-zÀ-ÿ]+\s+de\s+\d{4}\s*\(UTC\)",
            value,
            flags=re.I,
        )
        or
        re.search(
            r"\b\d{1,2}:\d{2},\s*\d{1,2}\s+[A-Za-zÀ-ÿ]+\s+\d{4}\s*\(UTC\)",
            value,
            flags=re.I,
        )
    )

    identity_marker = bool(
        re.search(
            r"(Especial:Contribui|Usu[aá]ri[oa](?:\(a\))?:|discuss[aã]o)",
            value,
            flags=re.I,
        )
    )

    raw_signature = "~~~~" in value

    return raw_signature or (timestamp and identity_marker)


def count_external_links(value):
    return len(
        re.findall(
            r"https?://[^\s\]\[<>\"']+",
            str(value or ""),
            flags=re.I,
        )
    )


def discussion_comment_body(added):
    """Retira apenas a assinatura FINAL; não interpreta seu ID/data como prosa."""
    value = str(added or "")
    # Assinatura expandida termina em data UTC. Preserva a prosa anterior.
    timestamp = re.search(
        r"\b\d{1,2}h\d{2}min\s+de\s+\d{1,2}\s+de\s+"
        r"[A-Za-zÀ-ÿ]+\s+de\s+\d{4}\s*\(UTC\)\s*$",
        value, re.I,
    )
    if timestamp:
        prefix = value[:timestamp.start()]
        # Identidade deve aparecer perto do horário; não apaga links arbitrários.
        identity = list(re.finditer(
            r"\[\[(?:Usu[aá]rio(?:\(a\))?|Especial:Contribui[^:]*|"
            r"Usu[aá]rio\s+Discuss[aã]o):", prefix, re.I,
        ))
        if identity and len(prefix) - identity[-1].start() <= 450:
            return prefix[:identity[-1].start()].strip()
    return value.replace("~~~~", "").strip()


def contextual_discussion_adjustment(change, diff, strong_signals):
    """Reduz falsos positivos em respostas assinadas, sem blindar abuso."""
    added = str(diff.get("added", "") or "")
    removed = str(diff.get("removed", "") or "")
    signed = looks_like_signed_discussion_comment(added)
    talk = is_discussion_namespace(change)
    if talk and signed:
        body = discussion_comment_body(added)
        # Apenas acréscimos. Não encobre remoção, insultos, spam ou repetição.
        # URLs da assinatura não contam como spam; URLs da mensagem contam.
        links = count_external_links(body)
        body_signals = max(profanity_score(body), repetition_score(body), nonsense_score(body))
        if (not removed.strip() and strong_signals == 0 and body_signals < 0.75
                and links == 0 and len(body) >= 12):
            return {
                "multiplier": 0.45,
                "additive": 0.0,
                "reason": "comentário assinado inserido em espaço de conversa, sem remoções nem sinais fortes",
                "kind": "talk_signed_append",
            }
        # Não aplica redutor genérico a edições com remoções ou links externos.
        return None
    if not talk and signed:
        return {
            "multiplier": 1.0,
            "additive": 0.10 + min(0.10, 0.05 * count_external_links(added)),
            "reason": "formato de mensagem de discussão inserido fora de página de discussão",
            "kind": "signed_outside_talk",
        }
    return None


def analyze_vandalism(change, diff, revert_risk):
    added = diff.get("added", "")
    removed = diff.get("removed", "")
    # Na discussão, avalia a prosa sem os números/links da assinatura final.
    signal_text = (discussion_comment_body(added)
                   if is_discussion_namespace(change)
                   and looks_like_signed_discussion_comment(added)
                   else added)

    profanity = profanity_score(signal_text)
    repetition = repetition_score(signal_text)
    destructive = destructive_score(
        added,
        removed
    )
    nonsense = nonsense_score(signal_text)

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

    # Regras novas não são cumulativas com redutores já existentes.
    cosmetic_adjustment = None
    if change.get("type") != "new" and max(signals) < 0.75:
        cosmetic_adjustment = (whitespace_only_priority_adjustment(diff)
                               or reference_date_priority_adjustment(diff)
                               or isolated_wikilink_priority_adjustment(diff))
    children_adjustment = children_count_priority_adjustment(change, diff)
    if children_adjustment and children_adjustment.get("factor") and not cosmetic_adjustment and max(signals) < 0.75:
        cosmetic_adjustment = children_adjustment
    if not cosmetic_adjustment and max(signals) < 0.75:
        cosmetic_adjustment = contextual_prose_addition_adjustment(change, diff)
    benign = None if cosmetic_adjustment or children_adjustment else benign_technical_change(diff)

    # O redutor técnico atua apenas em mudanças mínimas reconhecidas.
    if benign:
        score *= float(benign.get("factor", 1.0))
    if cosmetic_adjustment:
        score *= float(cosmetic_adjustment["factor"])

    minimal_adjustment = None
    contextual_calibration = contextual_priority_calibration(change, diff, strong_signals)
    if not benign and not cosmetic_adjustment and not change.get("type") == "new" and max(signals) < 0.75:
        minimal_adjustment = (equivalent_wikimarkup_priority_adjustment(diff)
                              or orthographic_priority_adjustment(diff)
                              or minimal_text_priority_adjustment(diff))
        if contextual_calibration and (not minimal_adjustment or contextual_calibration["factor"] < minimal_adjustment["factor"]):
            minimal_adjustment = contextual_calibration
        if minimal_adjustment:
            score *= float(minimal_adjustment["factor"])

    context_adjustment = contextual_discussion_adjustment(
        change,
        diff,
        strong_signals,
    )

    if cosmetic_adjustment:
        context_adjustment = None  # Não acumular descontos para a mesma edição.
    if context_adjustment and contextual_calibration and context_adjustment.get("kind") == "talk_signed_append":
        context_adjustment = None  # One contextual discount, never multiply 0.70 by 0.45.
    if context_adjustment:
        score *= float(context_adjustment.get("multiplier", 1.0))
        score += float(context_adjustment.get("additive", 0.0))

    promotional_adjustment = new_page_promotional_signals(change, diff)
    if promotional_adjustment["bonus"] > 0:
        score += promotional_adjustment["bonus"]

    reference_removal = reference_removal_priority_adjustment(change, diff)
    if reference_removal:
        score += reference_removal["bonus"]
    if children_adjustment and children_adjustment.get("bonus"):
        score += children_adjustment["bonus"]

    # Aplicar uma única vez após os redutores existentes; Revert Risk original intacto.
    score = min(max(score * GENERAL_PRIORITY_FACTOR, 0.0), 1.0)

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

    if benign:
        reasons.append(
            str(benign.get("reason") or "alteração técnica mínima")
        )
    if cosmetic_adjustment:
        reasons.append(cosmetic_adjustment["reason"])

    if minimal_adjustment:
        reasons.append(minimal_adjustment["reason"])

    if context_adjustment:
        reasons.append(
            str(
                context_adjustment.get("reason")
                or "ajuste contextual por namespace"
            )
        )

    if reference_removal:
        reasons.append(reference_removal["reason"])
    if children_adjustment and children_adjustment.get("bonus"):
        reasons.append(children_adjustment["reason"])

    reasons.extend(promotional_adjustment.get("signals", []))

    if not reasons:
        reasons.append("edição suspeita")

    return {
        "score": score,
        "revert_risk": revert_risk,
        "reason": ", ".join(reasons),
        "benign_reduction": benign,
        "cosmetic_adjustment": cosmetic_adjustment,
        "minimal_adjustment": minimal_adjustment,
        "context_adjustment": context_adjustment,
        "promotional_adjustment": promotional_adjustment,
        "reference_removal_adjustment": reference_removal,
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


def article_link_html(title):
    """Article title linked to the current page; diff remains a separate raw URL."""
    display = str(title or "Sem título")
    url = "https://pt.wikipedia.org/wiki/" + quote(display.replace(" ", "_"), safe="/:()")
    return f'<a href="{html.escape(url, quote=True)}">{html.escape(display)}</a>'


def user_contributions_url(username):
    encoded_username = quote(
        str(username or "").replace("_", " ").strip(),
        safe=""
    )
    return (
        "https://pt.wikipedia.org/w/index.php"
        "?title=Especial%3AContribui%C3%A7%C3%B5es"
        f"&target={encoded_username}"
    )


def user_contributions_link_html(username):
    display_name = str(username or "Desconhecido")
    safe_name = html.escape(display_name)
    safe_url = html.escape(
        user_contributions_url(display_name),
        quote=True
    )
    return f'<a href="{safe_url}">{safe_name}</a>'


def edit_link_html(url):
    safe_url = html.escape(str(url or ""), quote=True)
    return f"🔗 Ver edição — {safe_url}"


def tracked_edit_reply_markup(
    revision_id,
    alert_kind="normal",
    include_resolution_buttons=True
):
    resolution_row = []
    if include_resolution_buttons:
        resolution_row = [
            {
                "text": "✅ Resolver",
                "callback_data": f"resolve:{revision_id}",
            },
        ]

        # "Falso +" só se aplica aos alertas produzidos pelo detector normal.
        # Edições publicadas apenas por observação de conta ou vigilância de
        # página não são classificações positivas do detector.
        if alert_kind == "normal":
            resolution_row.append({
                "text": "⚠️ Falso +",
                "callback_data": f"falsepos:{revision_id}",
            })

    if alert_kind == "observed":
        rows = [
            [{
                "text": "⛔ Desobservar",
                "callback_data": f"unobserve:{revision_id}",
            }],
            [{
                "text": "👁 Vigiar página (6h)",
                "callback_data": f"watch:{revision_id}",
            }],
        ]
    elif alert_kind == "watched":
        rows = [
            [{
                "text": "🔎 Observar conta (6h)",
                "callback_data": f"observe:{revision_id}",
            }],
            [{
                "text": "🙈 Desvigiar",
                "callback_data": f"unwatch:{revision_id}",
            }],
        ]
    else:
        rows = [
            [{
                "text": "🔎 Observar conta (6h)",
                "callback_data": f"observe:{revision_id}",
            }],
            [{
                "text": "👁 Vigiar página (6h)",
                "callback_data": f"watch:{revision_id}",
            }],
        ]

    if resolution_row:
        rows.append(resolution_row)

    return {"inline_keyboard": rows}


def reply_markup_without_resolution_buttons(reply_markup, revision_id):
    """Remove Resolver e Falso +, preservando os dois botões superiores."""
    if not isinstance(reply_markup, dict):
        return tracked_edit_reply_markup(
            revision_id,
            include_resolution_buttons=False
        )

    blocked = {
        f"resolve:{revision_id}",
        f"falsepos:{revision_id}",
    }
    rows = []

    for row in reply_markup.get("inline_keyboard", []):
        if not isinstance(row, list):
            continue

        cleaned = [
            button
            for button in row
            if not (
                isinstance(button, dict)
                and button.get("callback_data") in blocked
            )
        ]
        if cleaned:
            rows.append(cleaned)

    return {"inline_keyboard": rows} if rows else None



def tracked_queue_item(
    change,
    message,
    title,
    stats_payload=None,
    alert_kind="normal"
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
        "alert_kind": alert_kind,
        "parse_mode": "HTML",
        "reply_markup": tracked_edit_reply_markup(
            revision.get("new"),
            alert_kind=alert_kind,
        ),
    }


def format_observed_message(change, observation):
    reason = (observation.get("reason") or "").strip()
    reason_line = f"\n📌 Motivo: {html.escape(reason)}\n" if reason else ""
    mention = observation.get("observer_mention")
    observer_line = f"\n🔔 Observação solicitada por: {html.escape(mention)}" if mention else ""
    return (
        "👁 Edição de conta observada\n\n"
        f"👤 {user_contributions_link_html(change.get('user', 'Desconhecido'))}\n"
        f"📝 {article_link_html(change.get('title', 'Sem título'))}\n"
        f"💬 {html.escape(str(change.get('comment') or 'Sem resumo'))}\n"
        f"{reason_line}\n"
        f"{edit_link_html(build_diff_url(change))}"
        f"{observer_line}"
    )


def format_watched_message(change):
    return (
        "👁 Edição em página vigiada\n\n"
        f"📝 {article_link_html(change.get('title', 'Sem título'))}\n"
        f"👤 {user_contributions_link_html(change.get('user', 'Desconhecido'))}\n"
        f"💬 {html.escape(str(change.get('comment') or 'Sem resumo'))}\n\n"
        f"{edit_link_html(build_diff_url(change))}"
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
        f"📝 {article_link_html(change.get('title', 'Sem título'))}\n"
        f"👤 {user_contributions_link_html(change.get('user', 'Desconhecido'))}\n"
        f"💬 {html.escape(str(change.get('comment') or 'Sem resumo'))}\n\n"
        f"🤖 Risco de reversão: {revert_score}%\n\n"
        f"{edit_link_html(build_diff_url(change))}"
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
                        f"Conta observada: {username}",
                        alert_kind="observed"
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
                # Vigilância explícita prevalece sobre o filtro de administradores.
                # Edições bot já são descartadas antes deste ponto.
                message = format_watched_message(
                    change
                )

                telegram_queue.put(
                    tracked_queue_item(
                        change,
                        message,
                        title,
                        alert_kind="watched"
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

            if result.get("benign_reduction"):
                print(
                    "🧩 Redutor benigno:",
                    result["benign_reduction"].get("reason"),
                    "| fator",
                    result["benign_reduction"].get("factor"),
                    "|",
                    title
                )

            if result.get("context_adjustment"):
                adjustment = result["context_adjustment"]
                print(
                    "💬 Ajuste contextual:",
                    adjustment.get("reason"),
                    "| multiplicador",
                    adjustment.get("multiplier"),
                    "| acréscimo",
                    adjustment.get("additive"),
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
                            "diff_added": diff.get("added", "")[:MAX_DIFF_CHARS],
                            "diff_removed": diff.get("removed", "")[:MAX_DIFF_CHARS],
                            "risk_reasons": result.get("reason", ""),
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
        "📌 Consulta e acompanhamento\n"
        "👤 /conta Usuário — consulta uma conta.\n"
        "🕒 /pendentes — mostra alertas ainda pendentes.\n"
        "🏷 /falsospositivos — lista os falsos positivos aguardando ajuste; não exige ID.\n"
        "🔎 /falsonegativo ID ou LINK — registra uma revisão que o detector deixou passar.\n"
        "🧪 /falsosnegativos — mostra a base de calibração de falsos negativos.\n"
        "📡 /status — mostra o estado do bot.\n"
        "⏸ /pausarwiki — pausa somente a escrita na Wikipédia em português.\n"
        "▶️ /reiniciarwiki — retoma somente a escrita na Wikipédia em português.\n"
        "⏸ /pausarteste — pausa somente a escrita na Test Wikipedia.\n"
        "▶️ /reiniciarteste — retoma somente a escrita na Test Wikipedia.\n\n"
        "👁 Vigilância de páginas\n"
        "👁 /vigiar Página — vigia uma página permanentemente.\n"
        "🙈 /desvigiar Página — encerra a vigilância.\n"
        "📋 /vigiadas — lista páginas vigiadas, inclusive temporárias.\n\n"
        "🔎 Observação de contas\n"
        "🔎 /observar Usuário — observa uma conta por 6 horas.\n"
        "⛔ /desobservar Usuário — encerra a observação.\n"
        "📋 /observadas — lista contas observadas.\n\n"
        "🙈 Exclusão temporária do detector\n"
        "🙈 /ignorar Usuário — ignora a conta por 6 horas no detector normal.\n"
        "👀 /designorar Usuário — volta a considerar a conta.\n"
        "📋 /ignoradas — lista contas temporariamente ignoradas.\n\n"
        "🛡 Filtros de abuso\n"
        "🛡 /vigiarfiltro ID — vigia um filtro.\n"
        "🛑 /desvigiarfiltro ID — encerra a vigilância do filtro.\n"
        "📋 /filtros — lista filtros vigiados.\n\n"
        "🧹 Manutenção\n"
        "🧹 /revisarpendentes — revisa imediatamente os alertas pendentes.\n"
        "✅ /resolverfalso ID ou LINK — marca como concluído o ajuste de um falso positivo.\n"
        "✅ /resolverfalsonegativo ID — marca como concluído o ajuste de um falso negativo.\n\n"
        "ℹ️ /start — apresentação do bot.\n"
        "📖 /comandos — mostra esta lista.\n\n"
        "🔐 Comandos que alteram o estado do bot e /revisarpendentes "
        "devem ser publicados diretamente no canal configurado."
    )



def telegram_person_display_name(user):
    if not isinstance(user, dict):
        return None

    first_name = str(user.get("first_name") or "").strip()
    last_name = str(user.get("last_name") or "").strip()
    full_name = " ".join(part for part in (first_name, last_name) if part).strip()

    if full_name:
        return full_name

    username = str(user.get("username") or "").strip()
    if username:
        return f"@{username}"

    return None


def observation_actor_from_channel_post(message):
    # Em posts assinados de canal, o Telegram pode fornecer author_signature.
    # Em algumas situações também há um objeto `from` identificável.
    actor = telegram_person_display_name(message.get("from") or {})
    if actor:
        return actor

    signature = str(message.get("author_signature") or "").strip()
    if signature:
        return signature

    return None


def parse_revision_reference(value):
    """Accept a revision ID or a pt.wikipedia edit/revision URL."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("informe o ID ou o link da revisão")

    if raw.isdigit():
        return int(raw)

    # Accept only Portuguese Wikipedia links when a URL is supplied.
    try:
        parsed = urlparse(raw)
    except Exception:
        parsed = None

    if parsed and parsed.scheme in ("http", "https"):
        host = (parsed.hostname or "").casefold()
        if host not in ("pt.wikipedia.org", "www.pt.wikipedia.org"):
            raise ValueError("o link deve ser da Wikipédia em português")

        qs = parse_qs(parsed.query)
        for key in ("diff", "oldid"):
            values = qs.get(key) or []
            if values:
                candidate = str(values[0]).strip()
                if candidate.isdigit():
                    return int(candidate)

        # Also accept /wiki/Special:Diff/123 and localized variants that end in /123.
        m = re.search(r"/(?:Special:Diff|Especial:Diff|Especial:Diferenças?)/([0-9]+)(?:/|$)", parsed.path, re.I)
        if m:
            return int(m.group(1))

    raise ValueError("não consegui identificar o ID da revisão; use um número ou um link com oldid=/diff=")


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

    # Barreira central para comandos que alteram estado. As verificações
    # específicas existentes em cada comando permanecem como defesa em
    # profundidade, mas um novo caminho não deve conseguir contorná-las.
    mutating_commands = {
        "/observar",
        "/desobservar",
        "/ignorar",
        "/designorar",
        "/vigiar",
        "/desvigiar",
        "/vigiarfiltro",
        "/desvigiarfiltro",
        "/revisarpendentes",
        "/resolverfalso",
        "/falsonegativo",
        "/resolverfalsonegativo",
        "/pausarwiki",
        "/reiniciarwiki",
        "/pausarteste",
        "/reiniciarteste",
    }

    if command in mutating_commands and (
        not from_channel or not is_target_channel(chat)
    ):
        send_telegram_message(
            "⚠️ Este comando administrativo deve ser publicado diretamente no canal configurado.",
            chat_id=chat_id,
        )
        return

    if command in ("/pausarwiki", "/reiniciarwiki"):
        try:
            pause = command == "/pausarwiki"
            set_wiki_writing_paused(pause)
            send_telegram_message(
                "⏸ Escrita na Wikipédia em português pausada. A fila foi preservada; a Test Wikipedia não foi afetada."
                if pause else
                "▶️ Escrita na Wikipédia em português retomada. Fila e limite de uma tentativa por hora preservados; a Test Wikipedia não foi afetada.",
                chat_id=chat_id,
            )
        except Exception as exc:
            send_telegram_message("❌ Não foi possível alterar escrita wiki: " + safe_exception(exc), chat_id=chat_id)
        return

    if command in ("/pausarteste", "/reiniciarteste"):
        try:
            pause = command == "/pausarteste"
            set_testwiki_writing_paused(pause)
            send_telegram_message(
                "⏸ Escrita na Test Wikipedia pausada. A fila foi preservada; a Wikipédia em português não foi afetada."
                if pause else
                "▶️ Escrita na Test Wikipedia retomada. Fila e intervalo mínimo de 121 segundos preservados; a Wikipédia em português não foi afetada.",
                chat_id=chat_id,
            )
        except Exception as exc:
            send_telegram_message("❌ Não foi possível alterar a escrita na Test Wikipedia: " + safe_exception(exc), chat_id=chat_id)
        return

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

    if command == "/pendentes":
        items = get_pending_posted_edits()
        pending_text, pending_markup = build_pending_page(items, page=0)
        send_telegram_message(
            pending_text,
            chat_id=chat_id,
            parse_mode="HTML",
            reply_markup=pending_markup,
        )
        return

    if command == "/falsonegativo":
        if not argument:
            send_telegram_message("Uso: /falsonegativo ID_OU_LINK_DA_REVISÃO", chat_id=chat_id)
            return
        try:
            rid = parse_revision_reference(argument)
            actor = observation_actor_from_channel_post(message) or "administrador do canal"
            item = register_false_negative(rid, actor)
            rr = item.get("revert_risk")
            rr_text = f"{rr:.0%}" if isinstance(rr, (int, float)) else "indisponível"
            signals = item.get("promotional_signals") or []
            signal_text = "\n".join("• " + html.escape(x) for x in signals) if signals else "• Nenhum novo sinal contextual ativado"
            send_telegram_message("🔎 <b>Falso negativo registrado para calibração</b>\n\n" + f"📝 {html.escape(item['title'])}\n👤 {html.escape(item['username'])}\n🆔 Revisão: {rid}\n🆕 Página nova: {'sim' if item.get('is_new_page') else 'não'}\n🤖 Revert Risk: {rr_text}\n\nSinais atuais:\n{signal_text}\n\nO caso foi salvo para testar ajustes futuros do detector.", chat_id=chat_id, parse_mode="HTML")
        except Exception as e:
            send_telegram_message("❌ Não foi possível registrar o falso negativo: " + html.escape(safe_exception(e)), chat_id=chat_id, parse_mode="HTML")
        return

    if command == "/falsosnegativos":
        with false_negatives_lock:
            pending=sorted((dict(x) for x in false_negatives.values() if not x.get("resolved_at")), key=lambda x: float(x.get("reported_at",0)))
        m=false_negative_metrics()
        lines=["🔎 <b>Base de falsos negativos</b>","",f"Total registrado: {m['total']}",f"Ajustados: {m['resolved']}",f"Aguardando ajuste: {m['unresolved']}"]
        for x in pending[:20]:
            lines += ["", f"• {html.escape(x.get('title') or '')} — revisão {x.get('revision_id')}", f"  /resolverfalsonegativo {x.get('revision_id')}"]
        send_telegram_message("\n".join(lines), chat_id=chat_id, parse_mode="HTML")
        return

    if command == "/resolverfalsonegativo":
        if not argument:
            send_telegram_message("Uso: /resolverfalsonegativo ID_DA_REVISÃO", chat_id=chat_id); return
        try: key=str(int(argument.strip()))
        except Exception:
            send_telegram_message("❌ ID de revisão inválido.", chat_id=chat_id); return
        with false_negatives_lock:
            item=false_negatives.get(key)
            if item and not item.get("resolved_at"):
                actor=observation_actor_from_channel_post(message) or "administrador do canal"
                item["resolved_at"]=time.time(); item["resolved_by"]=actor
            else: actor=None
        if not item:
            send_telegram_message("❌ Falso negativo não encontrado.", chat_id=chat_id); return
        if actor is None:
            send_telegram_message("ℹ️ Este falso negativo já foi marcado como ajustado.", chat_id=chat_id); return
        save_false_negatives()
        send_telegram_message("✅ <b>Falso negativo revisado</b>\n\n" + f"📝 {html.escape(item.get('title') or '')}\n🆔 Revisão: {item.get('revision_id')}\n🛠 Revisão concluída por: {html.escape(actor)}\n\nO caso permanece na base histórica de calibração.", chat_id=chat_id, parse_mode="HTML")
        return

    if command == "/falsospositivos":
        # Consulta simples: NÃO exige ID, página ou qualquer complemento.
        try:
            with false_positives_lock:
                items = [
                    dict(item)
                    for item in false_positives.values()
                    if not item.get("resolved_at")
                ]

            def _fp_time(item):
                try:
                    return float(item.get("marked_at") or 0)
                except (TypeError, ValueError):
                    return 0.0

            items.sort(key=_fp_time)

            if not items:
                response_text = (
                    "🏷 <b>Falsos positivos</b>\n\n"
                    "✅ Nenhum falso positivo aguardando ajuste."
                )
            else:
                lines = [
                    "🏷 <b>Falsos positivos aguardando ajuste</b>",
                    "",
                    f"Total: {len(items)}",
                ]
                for item in items[:20]:
                    revision_id = item.get("revision_id")
                    title = html.escape(str(item.get("title") or "Sem título"))
                    lines.extend([
                        "",
                        f"• <b>{title}</b>",
                        f'  🆔 <a href="https://pt.wikipedia.org/w/index.php?diff={revision_id}">{revision_id}</a>',
                        f"  Após o ajuste: <code>/resolverfalso {revision_id}</code>",
                    ])
                if len(items) > 20:
                    lines.extend(["", f"… e mais {len(items) - 20} caso(s)."])
                response_text = "\n".join(lines)

            sent = send_telegram_message(
                response_text,
                chat_id=chat_id,
                parse_mode="HTML"
            )
            if sent is None:
                # Segunda tentativa sem HTML, para que erro de formatação
                # também não deixe o comando sem resposta.
                send_telegram_message(
                    f"Falsos positivos aguardando ajuste: {len(items)}",
                    chat_id=chat_id
                )
        except Exception as exc:
            safe_log(f"Falha direta em /falsospositivos: {exc}")
            send_telegram_message(
                "⚠️ Falha ao consultar falsos positivos. Verifique o log do Railway.",
                chat_id=chat_id
            )
        return

    if command == "/resolverfalso":
        if not argument:
            send_telegram_message(
                "Uso: /resolverfalso ID_OU_LINK_DA_REVISÃO",
                chat_id=chat_id
            )
            return

        try:
            revision_id = parse_revision_reference(argument)
        except ValueError as exc:
            send_telegram_message(
                f"❌ Referência de revisão inválida: {html.escape(str(exc))}",
                chat_id=chat_id
            )
            return

        actor = (
            observation_actor_from_channel_post(message)
            or "administrador do canal"
        )
        item, result = mark_false_positive_fixed(
            revision_id,
            actor
        )

        if result == "not_found":
            send_telegram_message(
                f"❌ Falso positivo não encontrado: {revision_id}",
                chat_id=chat_id
            )
            return

        if result == "already_resolved":
            send_telegram_message(
                f"ℹ️ O falso positivo {revision_id} já estava marcado como resolvido.",
                chat_id=chat_id
            )
            return

        # Tenta também atualizar o post original. A resolução da fila permanece
        # válida mesmo se o Telegram não permitir editar uma mensagem antiga.
        message_id = item.get("telegram_message_id")
        updated = False
        if message_id:
            updated = bool(
                edit_telegram_message(
                    message_id,
                    false_positive_message(item, fixed=True),
                    parse_mode="HTML",
                    reply_markup=None
                )
            )

        reporter = str(
            item.get("marked_by")
            or "administrador não identificado"
        )

        send_telegram_message(
            (
                "✅ Falso positivo revisado — ajuste concluído\n\n"
                f'🆔 Revisão: <a href="https://pt.wikipedia.org/w/index.php?diff={revision_id}">{revision_id}</a>\n'
                f"🏷 Reportado por: {telegram_actor_mention(item)}\n"
                f"🛠 Revisão concluída por: {html.escape(str(actor))}\n\n"
                "Obrigado pelo reporte. Este caso foi incorporado ao ciclo "
                "de melhoria do detector e saiu da fila de ajustes pendentes."
                + (
                    "\n✏️ O aviso original também foi atualizado."
                    if updated
                    else "\nℹ️ Não foi possível atualizar o aviso original, mas a fila foi corrigida."
                )
            ),
            chat_id=chat_id,
            parse_mode="HTML"
        )
        return

    if command == "/revisarpendentes":
        if not from_channel or not is_target_channel(chat):
            send_telegram_message(
                "⚠️ /revisarpendentes deve ser publicado diretamente no canal.",
                chat_id=chat_id,
            )
            return

        threading.Thread(
            target=manual_pending_reconciliation,
            args=(chat_id,),
            daemon=True,
            name="manual-pending-reconciliation",
        ).start()
        return

    if command == "/status":
        cleanup_expired_observations()
        cleanup_expired_temporary_watches()
        cleanup_expired_ignored_users()
        cleanup_posted_edits()

        with stream_lock:
            connected = stream_connected
            last_stream = last_stream_event_at
            last_ptwiki = last_ptwiki_edit_at

        with watchlist_lock:
            permanent_watch_count = len(watched_pages)
        with temporary_watchlist_lock:
            temporary_watch_count = len(temporary_watched_pages)
        watch_count = permanent_watch_count + temporary_watch_count

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

        false_positive_pending_count = len(
            unresolved_false_positives()
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

        wiki_writing_enabled, wiki_queued_edits = wiki_write_status_snapshot()

        send_telegram_message(
            (
                "🤖 Status do bot\n\n"
                f"📦 Versão: {BOT_VERSION}\n"
                + (f"🔧 Build: {BOT_BUILD}\n" if BOT_BUILD != BOT_VERSION else "")
                + "\n"
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
                f"🏷 Falsos positivos aguardando ajuste: "
                f"{false_positive_pending_count}\n"
                f"📌 Resumo prioritário: a cada 2h "
                f"(top 10, 48h)\n"
                f"🧹 Reconciliação de pendências: a cada 30 min\n"
                f"📊 Registros estatísticos (90d): "
                f"{stats_count}\n"
                f"🕗 Relatório diário: 20:05 (Brasília)\n"
                f"📝 Escrita na wiki: {'habilitada' if wiki_writing_enabled else 'pausada/desabilitada'}\n"
                f"📚 Edições na fila wiki: {wiki_queued_edits}\n"
                f"📄 Páginas registradas para atualização: {len(wiki_pending_pages_snapshot())}\n"
                + ("\n".join("• " + html.escape(t) for t in wiki_pending_pages_snapshot()) + "\n" if wiki_pending_pages_snapshot() else "")
                + f"🔐 Wikimedia: {auth_text}\n"
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

        try:
            account_message, parse_mode = build_account_message(argument)
        except Exception as e:
            print("⚠️ Falha no comando /conta:", safe_exception(e))
            account_message = "⚠️ Erro temporário ao consultar a conta. Tente novamente."
            parse_mode = None

        sent = send_telegram_message(
            account_message,
            chat_id=chat_id,
            parse_mode=parse_mode
        )
        if not sent:
            print("⚠️ /conta: resposta não entregue pelo Telegram; chat_id=", chat_id)
            if parse_mode:
                send_telegram_message(
                    "⚠️ Não foi possível formatar a resposta da conta. Tente novamente.",
                    chat_id=chat_id,
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
                    f"• {user_contributions_link_html(item['username'])}\n"
                    f"  ⏳ "
                    f"{format_remaining(remaining_time)}"
                    + (
                        f"\n  📌 {html.escape(str(item.get('reason')))}"
                        if item.get('reason')
                        else ""
                    )
                )
            )

        send_telegram_message(
            (
                "🔎 Contas observadas:\n\n"
                +
                "\n\n".join(lines)
            ),
            chat_id=chat_id,
            parse_mode="HTML"
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

        observation_actor = observation_actor_from_channel_post(message)
        # Apenas @username verificável permite menção; assinatura textual não é identidade autenticada.
        observer_mention = observation_actor if observation_actor and re.fullmatch(r"@[A-Za-z0-9_]{5,32}", observation_actor) else None
        if observe_user(
            canonical_username,
            reason,
            observer_mention=observer_mention,
        ):
            observation_actor = observation_actor_from_channel_post(message)
            observation_actor_line = (
                f"\n👮 Colocada em observação por {html.escape(observation_actor)}"
                if observation_actor
                else ""
            )

            send_telegram_message(
                (
                    "🔎 Conta colocada em observação\n\n"
                    f'👤 <a href="{html.escape(user_contributions_url(canonical_username), quote=True)}">'
                    f"{html.escape(canonical_username)}</a>\n"
                    f"⏳ Duração: 6 horas"
                    f"{observation_actor_line}\n\n"
                    "Toda edição desta conta será "
                    "publicada no canal durante "
                    "esse período."
                ),
                chat_id=chat_id,
                parse_mode="HTML",
                reply_markup=reversible_action_markup(
                    "unobserve",
                    canonical_username,
                    "⛔ Desobservar",
                ),
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
                f"ℹ️ {user_contributions_link_html(canonical_username)} "
                "não estava em observação."
            )
        else:
            response_text = (
                "⛔ Observação encerrada\n\n"
                f"👤 {user_contributions_link_html(canonical_username)}"
            )

        reply_markup = None
        if success and removed:
            reply_markup = reversible_action_markup(
                "observe",
                canonical_username,
                "🔎 Observar novamente (6h)",
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id,
            parse_mode="HTML",
            reply_markup=reply_markup,
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
                    f"• {user_contributions_link_html(item['username'])} — "
                    f"{format_remaining(remaining_time)} restantes"
                )
            )

        send_telegram_message(
            (
                "🙈 Contas temporariamente ignoradas:\n\n"
                +
                "\n".join(lines)
            ),
            chat_id=chat_id,
            parse_mode="HTML"
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
                    f"👤 {user_contributions_link_html(canonical_username)}\n"
                    "⏳ Duração: 6 horas\n\n"
                    "As edições desta conta não serão "
                    "avaliadas pelo detector normal de "
                    "vandalismo durante esse período.\n\n"
                    "ℹ️ Contas observadas e páginas "
                    "vigiadas continuam tendo prioridade."
                ),
                chat_id=chat_id,
                parse_mode="HTML",
                reply_markup=reversible_action_markup(
                    "unignore",
                    canonical_username,
                    "👀 Deixar de ignorar",
                ),
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
                f"ℹ️ {user_contributions_link_html(canonical_username)} "
                "não estava na lista de ignoradas."
            )
        else:
            response_text = (
                "👀 Conta removida da lista de ignoradas\n\n"
                f"👤 {user_contributions_link_html(canonical_username)}\n\n"
                "As próximas edições voltarão a seguir "
                "o fluxo normal de análise."
            )

        reply_markup = None
        if success and removed:
            reply_markup = reversible_action_markup(
                "ignore",
                canonical_username,
                "🙈 Ignorar novamente (6h)",
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id,
            parse_mode="HTML",
            reply_markup=reply_markup,
        )
        return

    if command == "/vigiadas":
        cleanup_expired_temporary_watches()
        now = time.time()
        with watchlist_lock:
            permanent_pages = sorted(watched_pages, key=str.lower)
        with temporary_watchlist_lock:
            temporary_items = sorted(
                [dict(item) for item in temporary_watched_pages.values()],
                key=lambda x: x.get("title", "").lower(),
            )

        if not permanent_pages and not temporary_items:
            response_text = "👁 Nenhuma página está sendo vigiada."
        else:
            lines = [f"• {page}" for page in permanent_pages]
            for item in temporary_items:
                remaining = item.get("expires_at", 0) - now
                lines.append(
                    f"• {item.get('title')} — temporária, {format_remaining(remaining)} restantes"
                )
            response_text = "👁 Páginas vigiadas:\n\n" + "\n".join(lines)

        send_telegram_message(response_text, chat_id=chat_id)
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
                remove_any_watched_page(title)
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

        reply_markup = None
        if success:
            if command == "/vigiar" and added:
                reply_markup = reversible_action_markup(
                    "unwatch",
                    title,
                    "🙈 Desvigiar",
                )
            elif command == "/desvigiar" and removed:
                reply_markup = reversible_action_markup(
                    "watch_perm",
                    title,
                    "👁 Vigiar novamente",
                )

        send_telegram_message(
            response_text,
            chat_id=chat_id,
            reply_markup=reply_markup,
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

        reply_markup = None
        if success and added:
            reply_markup = reversible_action_markup(
                "unwatch_filter",
                filter_id,
                "🛑 Desvigiar filtro",
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id,
            reply_markup=reply_markup,
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

        reply_markup = None
        if success and removed:
            reply_markup = reversible_action_markup(
                "watch_filter",
                filter_id,
                "🛡 Vigiar filtro novamente",
            )

        send_telegram_message(
            response_text,
            chat_id=chat_id,
            reply_markup=reply_markup,
        )
        return


def answer_callback_query(callback_query_id, text=None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        # Evita falha 400 caso título/nome vindo da Wikipédia torne a
        # confirmação maior que o limite aceito pelo Telegram.
        payload["text"] = safe_log_text(text, max_length=180)
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


def process_edit_action_callback(callback):
    callback_id = callback.get("id")
    data = callback.get("data", "")

    if data.startswith("pend:"):
        callback_message = callback.get("message") or {}
        callback_chat = callback_message.get("chat") or {}
        clicker = callback.get("from") or {}
        clicker_id = clicker.get("id")

        if is_target_channel(callback_chat):
            if not clicker_id or not telegram_user_is_channel_admin(clicker_id):
                answer_callback_query(
                    callback_id,
                    "Apenas administradores do canal podem navegar nesta lista."
                )
                return

        try:
            page = int(data.split(":", 1)[1])
        except Exception:
            page = 0

        items = get_pending_posted_edits()
        pending_text, pending_markup = build_pending_page(items, page=page)
        ok = edit_telegram_message_in_chat(
            callback_chat.get("id"),
            callback_message.get("message_id"),
            pending_text,
            parse_mode="HTML",
            reply_markup=pending_markup,
        )
        answer_callback_query(
            callback_id,
            "Página atualizada." if ok else "Não foi possível atualizar a página."
        )
        return

    if data.startswith("act:"):
        process_reversible_action_callback(
            callback,
            data.split(":", 1)[1]
        )
        return

    if ":" not in data:
        answer_callback_query(callback_id)
        return

    action, revision_text = data.split(":", 1)
    if action not in ("observe", "watch", "unobserve", "unwatch", "resolve", "falsepos", "unfalsepos"):
        answer_callback_query(callback_id)
        return

    callback_message = callback.get("message") or {}
    callback_chat = callback_message.get("chat") or {}
    if not is_target_channel(callback_chat):
        answer_callback_query(callback_id, "Este botão só funciona no canal configurado.")
        return

    clicker = callback.get("from") or {}
    clicker_id = clicker.get("id")
    if not clicker_id or not telegram_user_is_channel_admin(clicker_id):
        answer_callback_query(callback_id, "Apenas administradores do canal podem usar este botão.")
        return

    with posted_edits_lock:
        record = posted_edits.get(str(revision_text))

    if not record:
        answer_callback_query(callback_id, "Não encontrei os dados deste alerta.")
        return

    username = str(record.get("username") or "").strip()
    title = str(record.get("title") or "").strip()
    actor = telegram_person_display_name(clicker)
    actor_html = html.escape(actor) if actor else None

    if action == "unfalsepos":
        revision_id = int(record.get("revision_id") or revision_text)

        # Registros antigos podem ter sido marcados como falso positivo numa
        # versão em que o post era atualizado antes de false_positives.json.
        # Se depois houve reversão, o status terminal substitui "false_positive",
        # mas os metadados false_positive_* permanecem. Aceitar esses metadados
        # como prova da marcação permite corrigir também alertas legados.
        fp = None
        previous_marker = record.get("false_positive_by")
        with false_positives_lock:
            fp = false_positives.get(str(revision_id))

            legacy_marked = bool(
                record.get("false_positive_at")
                or record.get("false_positive_by")
            )

            if fp and fp.get("resolved_at"):
                answer_callback_query(
                    callback_id,
                    "Este falso positivo já foi encerrado e não pode ser desmarcado."
                )
                return

            if not fp and not legacy_marked and record.get("status") != "false_positive":
                answer_callback_query(
                    callback_id,
                    "Este alerta não possui marcação de falso positivo ativa."
                )
                return

            if fp:
                false_positives.pop(str(revision_id), None)

        if fp:
            save_false_positives()

        # Pode haver uma corrida: o alerta é marcado Falso + e, quase ao
        # mesmo tempo, a Wikipédia confirma reversão/patrulhamento/exclusão.
        # Desmarcar o falso positivo não deve apagar esse desfecho real.
        terminal_statuses = {
            "reverted", "self_reverted", "deleted",
            "patrolled", "resolved_no_action"
        }

        with posted_edits_lock:
            live = posted_edits.get(str(revision_id))
            if live:
                current_status = live.get("status")
                live.pop("false_positive_at", None)
                live.pop("false_positive_by", None)
                if current_status == "false_positive":
                    live["status"] = None
                record = dict(live)
            else:
                current_status = record.get("status")

        save_posted_edits()

        # Restaurar a participação nas estatísticas sem perder um resultado
        # terminal que já tenha sido observado.
        try:
            register_detection_stat(
                revision_id,
                record.get("revert_risk"),
                record.get("final_score"),
                record.get("posted_at")
            )
            if current_status == "reverted":
                mark_detection_stat_reverted(
                    revision_id,
                    record.get("reverted_at") or time.time()
                )
            elif current_status == "patrolled":
                mark_detection_stat_patrolled(
                    revision_id,
                    record.get("patrolled_at") or time.time()
                )
            elif current_status == "resolved_no_action":
                mark_detection_stat_resolved_no_action(
                    revision_id,
                    record.get("resolved_at") or time.time()
                )
            elif current_status == "self_reverted":
                remove_detection_stat(revision_id)
        except Exception as exc:
            safe_log(
                f"Falha ao restaurar estatística após desmarcar falso positivo "
                f"{revision_id}: {exc}"
            )

        try:
            if current_status in terminal_statuses:
                restored_text = message_with_status(
                    record,
                    current_status,
                    reverter=record.get("reverted_by")
                    if current_status == "reverted" else None
                )
                restored_markup = tracked_edit_reply_markup(
                    revision_id,
                    record.get("alert_kind", "normal"),
                    include_resolution_buttons=False
                )
            else:
                restored_text = record.get("base_message")
                restored_markup = tracked_edit_reply_markup(
                    revision_id,
                    record.get("alert_kind", "normal"),
                    include_resolution_buttons=True
                )

            restored_ok = edit_telegram_message(
                record.get("message_id"),
                restored_text,
                parse_mode=record.get("parse_mode") or "HTML",
                reply_markup=restored_markup
            )
        except Exception as exc:
            restored_ok = False
            safe_log(
                f"Falha ao restaurar post após desmarcar falso positivo "
                f"{revision_id}: {exc}"
            )

        # O botão fica numa mensagem auxiliar. Sua edição só é confirmada
        # depois que o post original foi restaurado no Telegram.
        if not restored_ok:
            with posted_edits_lock:
                live = posted_edits.get(str(revision_id))
                if live and live.get("status") is None:
                    live["status"] = "false_positive"
                    live["false_positive_at"] = time.time()
                    live["false_positive_by"] = previous_marker or actor or "administrador do canal"
            save_posted_edits()
            answer_callback_query(callback_id, "Não consegui restaurar o post; tente novamente.")
            return
        answer_callback_query(callback_id, "Marcação de falso positivo desfeita.")
        auxiliary_message_id = callback_message.get("message_id")
        if auxiliary_message_id and auxiliary_message_id != record.get("message_id"):
            auxiliary_ok = edit_telegram_message(
                auxiliary_message_id,
                "↩️ Marcação de falso positivo desfeita.",
                parse_mode="HTML",
                reply_markup={"inline_keyboard": []}
            )
            if not auxiliary_ok:
                safe_log(f"Falha ao sincronizar mensagem auxiliar de falso positivo {revision_id}")
        return

    if action == "falsepos":
        revision_id = int(record.get("revision_id") or revision_text)

        if record.get("alert_kind", "normal") != "normal":
            answer_callback_query(
                callback_id,
                "Falso positivo só pode ser marcado em alertas do detector."
            )
            return

        if record.get("status"):
            current_status = record.get("status")

            # Recupera automaticamente registros órfãos de falso positivo
            # que possam ter sido criados antes da gravação na fila.
            if current_status == "false_positive":
                with false_positives_lock:
                    existing_fp = false_positives.get(str(revision_id))

                if not existing_fp:
                    marker_name = record.get("false_positive_by") or actor or "administrador do canal"
                    callback_from = callback.get("from") or {}
                    reporter_user_id = callback_from.get("id")
                    reporter_username = callback_from.get("username")
                    fp_item = register_false_positive(
                        record, marker_name, reporter_user_id, reporter_username
                    )
                    remove_detection_stat(revision_id)

                    edit_telegram_message(
                        record.get("message_id"),
                        false_positive_message(fp_item, fixed=False),
                        parse_mode="HTML",
                        reply_markup=reply_markup_without_resolution_buttons(
                            record.get("reply_markup"), revision_id
                        )
                    )
                    send_telegram_message(
                        (
                            "🏷 <b>Falso positivo encaminhado para verificação.</b>\n"
                            f'🆔 <a href="https://pt.wikipedia.org/w/index.php?diff={revision_id}">{revision_id}</a>\n'
                            f"👤 Marcado por: {html.escape(str(marker_name))}"
                        ),
                        chat_id=TELEGRAM_CHANNEL,
                        parse_mode="HTML",
                        reply_to_message_id=record.get("message_id"),
                        reply_markup={
                            "inline_keyboard": [[{
                                "text": "↩️ Desmarcar falso positivo",
                                "callback_data": f"unfalsepos:{revision_id}"
                            }]]
                        }
                    )
                    answer_callback_query(
                        callback_id,
                        "Falso positivo recuperado e encaminhado para verificação."
                    )
                    return

                answer_callback_query(
                    callback_id,
                    "Este alerta já está marcado como falso positivo."
                )
                return

            try:
                terminal_text = message_with_status(
                    record,
                    current_status,
                    reverter=record.get("reverted_by") if current_status == "reverted" else None
                )
                edit_telegram_message(
                    record.get("message_id"),
                    terminal_text,
                    parse_mode="HTML",
                    reply_markup=tracked_edit_reply_markup(
                        revision_id,
                        record.get("alert_kind", "normal"),
                        include_resolution_buttons=False
                    )
                )
            except Exception as exc:
                safe_log(f"Falha ao sincronizar alerta terminal {revision_id}: {exc}")
            answer_callback_query(
                callback_id,
                "Este alerta já foi resolvido; o post foi sincronizado."
            )
            return

        marker_name = actor or "administrador do canal"
        callback_from = callback.get("from") or {}
        reporter_user_id = callback_from.get("id")
        reporter_username = callback_from.get("username")

        with posted_edits_lock:
            live = posted_edits.get(str(revision_text))
            if not live or live.get("status"):
                answer_callback_query(
                    callback_id,
                    "Este alerta já foi resolvido."
                )
                return

            live["status"] = "false_positive"
            live["false_positive_at"] = time.time()
            live["false_positive_by"] = marker_name
            live["reply_markup"] = reply_markup_without_resolution_buttons(
                live.get("reply_markup"),
                revision_id
            )
            record = dict(live)

        try:
            save_posted_edits()
        except Exception as e:
            print(
                "⚠️ Erro ao persistir falso positivo em posted_edits:",
                safe_exception(e)
            )

        fp_item = register_false_positive(
            record, marker_name, reporter_user_id, reporter_username
        )

        # Falso positivo não entra nas estatísticas de desempenho do detector.
        remove_detection_stat(revision_id)

        success = edit_telegram_message(
            record["message_id"],
            false_positive_message(fp_item, fixed=False),
            parse_mode="HTML",
            reply_markup=record.get("reply_markup")
        )

        answer_callback_query(
            callback_id,
            "Falso positivo registrado. Obrigado — o caso entrou na fila de melhoria do detector."
        )

        send_telegram_message(
                (
                    "🏷 <b>Falso positivo encaminhado para verificação.</b>\n"
                    f"🆔 <a href=\"https://pt.wikipedia.org/w/index.php?diff={revision_id}\">{revision_id}</a>\n"
                    f"👤 Marcado por: {html.escape(actor)}"
                ),
                chat_id=TELEGRAM_CHANNEL,
                parse_mode="HTML",
                reply_to_message_id=record.get("message_id"),
                reply_markup={
                    "inline_keyboard": [[
                        {
                            "text": "↩️ Desmarcar falso positivo",
                            "callback_data": f"unfalsepos:{revision_id}"
                        }
                    ]]
                }
            )

        print(
            "🏷 Falso positivo registrado:",
            revision_id,
            "| por:",
            marker_name,
            "| mensagem atualizada:",
            bool(success)
        )
        return

    if action == "resolve":
        revision_id = int(record.get("revision_id") or revision_text)

        if record.get("status"):
            answer_callback_query(callback_id, "Este alerta já foi resolvido.")
            return

        resolved_at = time.time()
        resolver_name = actor or "administrador do canal"

        with posted_edits_lock:
            live = posted_edits.get(str(revision_text))
            if not live or live.get("status"):
                answer_callback_query(callback_id, "Este alerta já foi resolvido.")
                return

            live["status"] = "resolved_no_action"
            live["resolved_at"] = resolved_at
            live["resolved_by"] = resolver_name
            live["reply_markup"] = reply_markup_without_resolution_buttons(
                live.get("reply_markup"),
                revision_id
            )
            record = dict(live)

        try:
            save_posted_edits()
        except Exception as e:
            print(
                "⚠️ Erro ao persistir resolução manual:",
                safe_exception(e)
            )

        success = edit_telegram_message(
            record["message_id"],
            message_with_status(record, "resolved_no_action"),
            parse_mode="HTML",
            reply_markup=record.get("reply_markup")
        )

        mark_detection_stat_resolved_no_action(
            revision_id,
            resolved_at
        )

        record_community_event(
            "resolved_no_action",
            actor=resolver_name,
            title=record.get("title"),
            timestamp=resolved_at,
            revision_id=revision_id,
            latency=max(
                0,
                resolved_at - float(record.get("posted_at", resolved_at))
            ),
            metadata={
                "telegram_message_updated": bool(success),
                "resolution": "seen_no_action_required",
            },
        )

        answer_callback_query(
            callback_id,
            "Pendência resolvida: nenhuma ação necessária."
        )
        print(
            "✅ Alerta resolvido manualmente sem ação necessária:",
            revision_id,
            "| por:",
            resolver_name
        )
        return

    if action == "observe":
        if not username:
            answer_callback_query(callback_id, "Não encontrei a conta deste alerta.")
            return
        if not observe_user(username):
            answer_callback_query(callback_id, "Não foi possível salvar a observação.")
            return
        answer_callback_query(callback_id, f"{username} em observação por 6 horas.")
        actor_line = f"\n👮 Colocada em observação por {actor_html}" if actor_html else ""
        send_telegram_message(
            "🔎 Conta colocada em observação\n\n"
            f'<a href="{html.escape(user_contributions_url(username), quote=True)}">👤 {html.escape(username)}</a>\n'
            "⏳ Duração: 6 horas"
            f"{actor_line}",
            chat_id=TELEGRAM_CHANNEL,
            parse_mode="HTML",
            reply_markup=reversible_action_markup(
                "unobserve",
                username,
                "⛔ Desobservar",
            ),
        )
        return

    if action == "watch":
        if not title:
            answer_callback_query(callback_id, "Não encontrei a página deste alerta.")
            return
        if not add_temporary_watched_page(title):
            answer_callback_query(callback_id, "Não foi possível salvar a vigilância.")
            return
        answer_callback_query(callback_id, f"{title} vigiada por 6 horas.")
        actor_line = f"\n👮 Colocada em vigilância por {actor_html}" if actor_html else ""
        send_telegram_message(
            "👁 Página colocada em vigilância\n\n"
            f"📝 {html.escape(title)}\n"
            "⏳ Duração: 6 horas"
            f"{actor_line}",
            chat_id=TELEGRAM_CHANNEL,
            parse_mode="HTML",
            reply_markup=reversible_action_markup(
                "unwatch",
                title,
                "🙈 Desvigiar",
            ),
        )
        return

    if action == "unobserve":
        if not username:
            answer_callback_query(callback_id, "Não encontrei a conta deste alerta.")
            return
        success, removed = stop_observing_user(username)
        if not success:
            answer_callback_query(callback_id, "Não foi possível encerrar a observação.")
            return
        if not removed:
            answer_callback_query(callback_id, f"{username} já não estava em observação.")
            return
        answer_callback_query(callback_id, f"Observação de {username} encerrada.")
        actor_line = f"\n👮 Desobservada por {actor_html}" if actor_html else ""
        send_telegram_message(
            "⛔ Observação encerrada\n\n"
            f'<a href="{html.escape(user_contributions_url(username), quote=True)}">👤 {html.escape(username)}</a>'
            f"{actor_line}",
            chat_id=TELEGRAM_CHANNEL,
            parse_mode="HTML",
            reply_markup=reversible_action_markup(
                "observe",
                username,
                "🔎 Observar novamente (6h)",
            ),
        )
        return

    if action == "unwatch":
        if not title:
            answer_callback_query(callback_id, "Não encontrei a página deste alerta.")
            return
        success, removed = remove_any_watched_page(title)
        if not success:
            answer_callback_query(callback_id, "Não foi possível encerrar a vigilância.")
            return
        if not removed:
            answer_callback_query(callback_id, f"{title} já não estava sendo vigiada.")
            return
        answer_callback_query(callback_id, f"Vigilância de {title} encerrada.")
        actor_line = f"\n👮 Retirada da vigilância por {actor_html}" if actor_html else ""
        send_telegram_message(
            "🙈 Vigilância encerrada\n\n"
            f"📝 {html.escape(title)}"
            f"{actor_line}",
            chat_id=TELEGRAM_CHANNEL,
            parse_mode="HTML",
            reply_markup=reversible_action_markup(
                "watch_perm",
                title,
                "👁 Vigiar novamente",
            ),
        )


# =========================================================
# LISTENER TELEGRAM
# =========================================================

_account_command_slots = threading.BoundedSemaphore(3)


def _process_account_command_async(message):
    try:
        process_telegram_command(message, from_channel=False)
    except Exception as exc:
        print("⚠️ Erro inesperado em /conta:", safe_exception(exc))
        send_telegram_message(
            "⚠️ Falha temporária ao consultar a conta.",
            chat_id=(message.get("chat") or {}).get("id"),
        )
    finally:
        _account_command_slots.release()


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
                    safe_log_text(response.text)
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
                    process_edit_action_callback(callback)
                    continue

                message = update.get("message")

                if message:
                    text = (message.get("text") or "").strip()
                    is_account = text.split(maxsplit=1)[0].split("@")[0].lower() == "/conta" if text else False
                    if is_account:
                        print("📨 /conta recebido:", (message.get("chat") or {}).get("type"),
                              "chat_id=", (message.get("chat") or {}).get("id"))
                        if _account_command_slots.acquire(blocking=False):
                            threading.Thread(
                                target=_process_account_command_async,
                                args=(message,), daemon=True,
                                name="telegram-conta",
                            ).start()
                        else:
                            send_telegram_message(
                                "⏳ Consultas de conta ocupadas. Aguarde e tente novamente.",
                                chat_id=(message.get("chat") or {}).get("id"),
                            )
                    else:
                        process_telegram_command(message, from_channel=False)

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

def is_help_tests_page(title):
    """Ignora Ajuda:Página de testes e todos os títulos com esse início."""
    if not isinstance(title, str):
        return False
    normalized = unicodedata.normalize("NFKD", title.replace("_", " ").strip())
    normalized = "".join(c for c in normalized if not unicodedata.combining(c)).casefold()
    return normalized.startswith("ajuda:pagina de testes")


def is_user_tests_page(title):
    """Ignora subpáginas /Testes no namespace de usuário."""
    if not isinstance(title, str):
        return False

    normalized = title.strip()
    if not re.match(
        r"^(?:Usuário|Usuária|Usuário\s*\(a\)|Usuario|Usuaria|Usuario\s*\(a\)|User)\s*:",
        normalized,
        flags=re.IGNORECASE,
    ):
        return False

    return re.search(
        r"/Testes(?:/|$)",
        normalized,
        flags=re.IGNORECASE,
    ) is not None


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
                        elif action == "unblock":
                            handle_unblock_for_observation(change)

                    elif log_type == "protect":
                        # Registra somente proteção e alteração de uma
                        # proteção existente. Desproteções são ignoradas.
                        if action in ("protect", "modify"):
                            handle_protection_event(change)

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

                # Páginas pessoais de testes não entram no pipeline de
                # análise/alertas. Aceita as formas localizadas do
                # namespace de usuário e qualquer subpágina de /Testes.
                if is_help_tests_page(change.get("title", "")):
                    print("🧪 Página de testes de ajuda ignorada:", change.get("title"))
                    continue

                if is_user_tests_page(change.get("title", "")):
                    print(
                        "🧪 Página de testes de usuário ignorada:",
                        change.get("title"),
                    )
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


# =========================================================
# TEST WIKIPEDIA: LISTA DE ALTO RISCO (PTWIKI)
# =========================================================
import hashlib
import calendar

# Publicação de testes independente dos relatórios da ptwiki.
TESTWIKI_API = "https://test.wikipedia.org/w/api.php"
WIKIPEDIA_WRITE_API = TESTWIKI_API
TESTWIKI_BOT_USERNAME = os.environ.get("TESTWIKI_WIKIMEDIA_BOT_USERNAME")
TESTWIKI_BOT_PASSWORD = os.environ.get("TESTWIKI_WIKIMEDIA_BOT_PASSWORD")
WIKI_HIGH_RISK_TITLE = "User:TelesGramBot/Edições de alto risco"
WIKI_HIGH_RISK_ARCHIVE_PREFIX = WIKI_HIGH_RISK_TITLE + "/"
WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE = WIKI_HIGH_RISK_ARCHIVE_PREFIX + "Arquivo"
WIKI_HIGH_RISK_HEADER_TITLE = WIKI_HIGH_RISK_ARCHIVE_PREFIX + "Cabeçalho"
WIKI_HIGH_RISK_THRESHOLD = 0.85
WIKI_HIGH_RISK_RESOLVED_TTL_SECONDS = 30 * 60
HIGH_RISK_ARCHIVE_FILE = "/data/ptwiki_high_risk_archive.json"
TESTWIKI_QUEUE_FILE = "/data/ptwiki_testwiki_queue.json"
TESTWIKI_CONTROL_FILE = "/data/ptwiki_testwiki_control.json"
TESTWIKI_WRITE_INTERVAL_SECONDS = 121
TESTWIKI_LOCK = threading.RLock()
testwiki_session = requests.Session()
testwiki_session.headers.update(HEADERS)
testwiki_auth_lock = threading.Lock()
testwiki_authenticated = False
testwiki_authenticated_user = None
high_risk_archive = {}
high_risk_archive_lock = threading.Lock()

def testwiki_login():
    """Autentica a sessão dedicada exclusivamente à Test Wikipedia."""
    global testwiki_authenticated, testwiki_authenticated_user

    if not TESTWIKI_BOT_USERNAME or not TESTWIKI_BOT_PASSWORD:
        testwiki_authenticated = False
        testwiki_authenticated_user = None
        print("⚠️ Credenciais da Test Wikipedia não configuradas.")
        return False

    with testwiki_auth_lock:
        try:
            token_response = testwiki_session.get(
                WIKIPEDIA_WRITE_API,
                params={
                    "action": "query", "meta": "tokens", "type": "login",
                    "format": "json", "formatversion": 2,
                },
                timeout=25,
            )
            token_response.raise_for_status()
            login_token = (
                token_response.json().get("query", {})
                .get("tokens", {}).get("logintoken")
            )
            if not login_token:
                raise RuntimeError("token de login da Test Wikipedia não retornado")

            login_response = testwiki_session.post(
                WIKIPEDIA_WRITE_API,
                data={
                    "action": "login",
                    "lgname": TESTWIKI_BOT_USERNAME,
                    "lgpassword": TESTWIKI_BOT_PASSWORD,
                    "lgtoken": login_token,
                    "format": "json",
                    "formatversion": 2,
                },
                timeout=25,
            )
            login_response.raise_for_status()
            login_data = login_response.json().get("login", {})
            if login_data.get("result") != "Success":
                raise RuntimeError(
                    "login na Test Wikipedia falhou: "
                    + str(login_data.get("reason") or login_data.get("result"))
                )

            user_response = testwiki_session.get(
                WIKIPEDIA_WRITE_API,
                params={
                    "action": "query", "meta": "userinfo",
                    "format": "json", "formatversion": 2,
                },
                timeout=25,
            )
            user_response.raise_for_status()
            userinfo = user_response.json().get("query", {}).get("userinfo", {})
            if userinfo.get("anon"):
                raise RuntimeError("sessão da Test Wikipedia permaneceu anônima")

            testwiki_authenticated = True
            testwiki_authenticated_user = userinfo.get("name")
            print("✅ Test Wikipedia autenticada como:", testwiki_authenticated_user)
            return True
        except Exception as exc:
            testwiki_authenticated = False
            testwiki_authenticated_user = None
            print("❌ Falha no login da Test Wikipedia:", safe_exception(exc))
            return False


def get_testwiki_csrf_token():
    if not testwiki_authenticated and not testwiki_login():
        raise RuntimeError("sessão da Test Wikipedia não autenticada")

    response = testwiki_session.get(
        WIKIPEDIA_WRITE_API,
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
    token = (
        response.json()
        .get("query", {})
        .get("tokens", {})
        .get("csrftoken")
    )
    if not token:
        raise RuntimeError("token CSRF não retornado")
    return token


def testwiki_page_exists(title):
    response = testwiki_session.get(
        WIKIPEDIA_WRITE_API,
        params={
            "action": "query", "format": "json", "formatversion": 2,
            "titles": title,
        },
        timeout=25,
    )
    response.raise_for_status()
    pages = (response.json().get("query") or {}).get("pages") or []
    return bool(pages and not pages[0].get("missing"))


def get_latest_testwiki_deletion_log(title):
    response = testwiki_session.get(
        WIKIPEDIA_WRITE_API,
        params={
            "action": "query", "format": "json", "formatversion": 2,
            "list": "logevents", "letype": "delete",
            "leaction": "delete/delete", "letitle": title,
            "leprop": "title|user|timestamp|type|details",
            "lelimit": 1, "ledir": "older",
        },
        timeout=25,
    )
    response.raise_for_status()
    events = response.json().get("query", {}).get("logevents", [])
    return events[0] if events else None



def wiki_safe_text(value):
    """Escapa caracteres que poderiam alterar o wikitext da lista."""
    return (
        str(value or "—")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("|", "&#124;")
    )


def format_high_risk_utc(record):
    value = record.get("revision_timestamp")
    try:
        if isinstance(value, (int, float)):
            moment = datetime.fromtimestamp(float(value), timezone.utc)
        elif value:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            moment = moment.astimezone(timezone.utc)
        else:
            moment = datetime.fromtimestamp(
                float(record.get("posted_at") or 0), timezone.utc
            )
    except (TypeError, ValueError, OverflowError):
        return "data desconhecida"
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def high_risk_record_date(record):
    value = record.get("revision_timestamp")
    try:
        if isinstance(value, (int, float)):
            moment = datetime.fromtimestamp(float(value), timezone.utc)
        elif value:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            moment = moment.astimezone(timezone.utc)
        else:
            moment = datetime.fromtimestamp(float(record.get("posted_at") or 0), timezone.utc)
    except (TypeError, ValueError, OverflowError):
        moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%d")


def high_risk_account_link(username):
    username = str(username or "Desconhecido")
    encoded = quote(username.replace(" ", "_"), safe="")
    return (
        f"[https://pt.wikipedia.org/wiki/Usu%C3%A1rio:{encoded} "
        f"{wiki_safe_text(username)}]"
    )


def high_risk_action(record):
    status = record.get("status")
    if status == "reverted":
        return "Revertido", record.get("reverted_by"), record.get("reverted_at")
    if status == "self_reverted":
        return (
            "Autorrevertido",
            record.get("reverted_by") or record.get("username"),
            record.get("reverted_at"),
        )
    if status == "patrolled":
        return "Patrulhado", record.get("patrolled_by"), record.get("patrolled_at")
    if status == "deleted":
        return "Eliminado", record.get("deleted_by"), record.get("deleted_at")
    if status == "resolved_no_action":
        return "Resolvido sem ação necessária", None, record.get("resolved_at")
    if status == "false_positive":
        return "Marcado como falso positivo", None, record.get("false_positive_at")
    return None, None, None


def high_risk_diff_excerpt(record, limit=360):
    """Prévia textual; o modelo Revert Risk não fornece atribuição por palavra."""
    def compact(value):
        return re.sub(r"\s+", " ", str(value or "")).strip()

    old = compact(record.get("diff_removed"))
    new = compact(record.get("diff_added"))
    if not old and not new:
        return "<small>Prévia indisponível; consulte o diferencial completo.</small>"

    # Prioriza o ponto de divergência em vez de cortar sempre o começo do texto.
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    changes = [op for op in matcher.get_opcodes() if op[0] != "equal"]
    if changes:
        _, i1, i2, j1, j2 = max(changes, key=lambda op: max(op[2]-op[1], op[4]-op[3]))
        before = old[max(0, i1-65):min(len(old), i2+65)]
        after = new[max(0, j1-65):min(len(new), j2+65)]
    else:
        before, after = old[:limit//2], new[:limit//2]
    before = before[:limit]
    after = after[:limit]
    old_line = wiki_safe_text(before) if before else "(sem texto anterior)"
    new_line = wiki_safe_text(after) if after else "(texto removido)"
    reasons = compact(record.get("risk_reasons"))
    # Os motivos são heurísticas identificadas, não explicações causais do modelo.
    reasons_line = ("<br><small>Sinais detectados: " + wiki_safe_text(reasons[:240]) + "</small>") if reasons else ""
    return ("<div style=\"margin:0.3em 0; padding:0.35em; border:1px solid #a2a9b1; background:#ffffff\">"
            "<small>Prévia das alterações (trecho aproximado):</small><br>"
            "<small>Antes: <del>" + old_line + "</del></small><br>"
            "<small>Depois: <ins>" + new_line + "</ins></small>"
            + reasons_line + "</div>")


HIGH_RISK_PATTERN_MIN_PER_CLASS = 3
HIGH_RISK_PATTERN_MAX_SAMPLES_PER_CLASS = 300
HIGH_RISK_PATTERN_MIN_MATCH = 0.03
HIGH_RISK_PATTERN_MIN_MARGIN = 0.01

HIGH_RISK_PATTERN_STOPWORDS = frozenset((
    "a", "as", "o", "os", "um", "uma", "uns", "umas", "de", "da",
    "do", "das", "dos", "em", "no", "na", "nos", "nas", "por", "para",
    "com", "sem", "sob", "sobre", "entre", "que", "quem", "qual", "quais",
    "como", "quando", "onde", "mais", "menos", "muito", "muita", "muitos",
    "muitas", "ser", "estar", "foi", "foram", "era", "sao", "seu", "sua",
    "seus", "suas", "ele", "ela", "eles", "elas", "isso", "isto", "aquele",
    "aquela", "the", "and", "for", "with", "from", "that", "this", "was",
    "were", "are", "but", "not", "you", "your", "have", "has", "had",
))


def high_risk_pattern_label(status):
    """Usa somente as categorias de desfecho definidas para a página."""
    if status in ("reverted", "deleted"):
        return "vandalismo"
    if status in ("patrolled", "false_positive"):
        return "sem_vandalismo"
    return None


def high_risk_pattern_features(record):
    """Extrai palavras, pares de palavras e formas simples do diff."""
    added = str(record.get("diff_added") or "")[:MAX_DIFF_CHARS]
    removed = str(record.get("diff_removed") or "")[:MAX_DIFF_CHARS]
    features = set()

    def normalized_words(text):
        normalized = unicodedata.normalize("NFKC", text).casefold()
        words = re.findall(r"[^\W_]{3,}", normalized, flags=re.UNICODE)
        result = []
        for word in words:
            folded = unicodedata.normalize("NFKD", word)
            word = "".join(ch for ch in folded if not unicodedata.combining(ch))
            if len(word) >= 3 and word not in HIGH_RISK_PATTERN_STOPWORDS:
                result.append(word)
        return result[:180]

    for side, text in (("add", added), ("remove", removed)):
        words = normalized_words(text)
        for word in set(words):
            features.add(f"{side}:word:{word}")
        for first, second in zip(words, words[1:]):
            if first != second:
                features.add(f"{side}:pair:{first}_{second}")

        char_count = len(text.strip())
        if char_count:
            size = "short" if char_count < 80 else "medium" if char_count < 500 else "long"
            features.add(f"{side}:size:{size}")
            if re.search(r"https?://|www\.", text, flags=re.IGNORECASE):
                features.add(f"{side}:has_url")
            if re.search(r"<ref\b|\{\{\s*(?:citar|cite)", text, flags=re.IGNORECASE):
                features.add(f"{side}:has_reference")
            if re.search(r"\[\[Categoria:", text, flags=re.IGNORECASE):
                features.add(f"{side}:has_category")

    if len(removed.strip()) > max(300, len(added.strip()) * 3):
        features.add("shape:large_removal")
    if not added.strip() and removed.strip():
        features.add("shape:blanking")
    if added.count("!") >= 4:
        features.add("shape:many_exclamation_marks")
    if re.search(r"(.)\1{5,}", added, flags=re.DOTALL):
        features.add("shape:repeated_character_run")
    return features


def train_high_risk_pattern_model():
    """Aprende apenas de diffs arquivados com um dos quatro rótulos definidos."""
    with high_risk_archive_lock:
        records = [dict(item) for item in high_risk_archive.values()]

    by_label = {"vandalismo": [], "sem_vandalismo": []}
    for record in records:
        label = high_risk_pattern_label(record.get("status"))
        if not label:
            continue
        features = high_risk_pattern_features(record)
        if not features:
            continue
        try:
            timestamp = float(
                record.get("reverted_at")
                or record.get("deleted_at")
                or record.get("patrolled_at")
                or record.get("false_positive_at")
                or record.get("posted_at")
                or 0
            )
        except (TypeError, ValueError):
            timestamp = 0.0
        by_label[label].append((timestamp, features))

    samples = {}
    for label, items in by_label.items():
        items.sort(key=lambda item: item[0], reverse=True)
        samples[label] = [
            features for _, features in items[:HIGH_RISK_PATTERN_MAX_SAMPLES_PER_CLASS]
        ]

    document_frequency = Counter()
    total_documents = sum(len(items) for items in samples.values())
    for items in samples.values():
        for features in items:
            document_frequency.update(features)

    inverse_document_frequency = {
        feature: math.log((total_documents + 1) / (frequency + 1)) + 1.0
        for feature, frequency in document_frequency.items()
    }
    return {
        "samples": samples,
        "counts": {label: len(items) for label, items in samples.items()},
        "idf": inverse_document_frequency,
        "ready": all(
            len(samples[label]) >= HIGH_RISK_PATTERN_MIN_PER_CLASS
            for label in ("vandalismo", "sem_vandalismo")
        ),
    }


def high_risk_pattern_similarity(left, right, idf):
    union = left | right
    if not union:
        return 0.0
    union_weight = sum(idf.get(feature, 1.0) for feature in union)
    if union_weight <= 0:
        return 0.0
    shared_weight = sum(idf.get(feature, 1.0) for feature in left & right)
    return shared_weight / union_weight


def classify_high_risk_pattern(record, model):
    features = high_risk_pattern_features(record)
    counts = model.get("counts", {})
    result = {
        "label": None,
        "vandalismo_similarity": 0.0,
        "sem_vandalismo_similarity": 0.0,
        "counts": counts,
        "ready": bool(model.get("ready")),
    }
    if not model.get("ready") or not features:
        return result

    idf = model.get("idf", {})
    for label in ("vandalismo", "sem_vandalismo"):
        similarities = sorted(
            (
                high_risk_pattern_similarity(features, sample, idf)
                for sample in model.get("samples", {}).get(label, [])
            ),
            reverse=True,
        )
        if similarities:
            # A média dos três exemplos mais próximos limita o peso de um caso único.
            result[label + "_similarity"] = (
                sum(similarities[:3]) / min(3, len(similarities))
            )

    vandalismo = result["vandalismo_similarity"]
    sem_vandalismo = result["sem_vandalismo_similarity"]
    if (
        max(vandalismo, sem_vandalismo) >= HIGH_RISK_PATTERN_MIN_MATCH
        and abs(vandalismo - sem_vandalismo) >= HIGH_RISK_PATTERN_MIN_MARGIN
    ):
        result["label"] = "vandalismo" if vandalismo > sem_vandalismo else "sem_vandalismo"
    return result


def high_risk_pattern_annotation(record, model):
    label = high_risk_pattern_label(record.get("status"))
    if label:
        label_text = "vandalismo" if label == "vandalismo" else "sem vandalismo"
        return (
            "<small>'''Rótulo registrado para aprendizagem:''' "
            + label_text + "</small>"
        )

    if high_risk_action(record)[0] is not None:
        return ""

    result = classify_high_risk_pattern(record, model)
    if not result["ready"]:
        return ""

    vandalismo = result["vandalismo_similarity"]
    sem_vandalismo = result["sem_vandalismo_similarity"]
    if result["label"] == "vandalismo":
        assessment = "mais próximo de padrões rotulados como vandalismo"
    elif result["label"] == "sem_vandalismo":
        assessment = "mais próximo de padrões rotulados sem vandalismo"
    else:
        assessment = "sem correspondência clara entre as classes"
    return (
        "<small>'''Padrão IA (sem alterar o risco):''' "
        + assessment
        + f" · vandalismo {vandalismo:.0%}, sem vandalismo {sem_vandalismo:.0%}</small>"
    )


def high_risk_background(record):
    if high_risk_action(record)[0] is not None:
        return "#cfe2ff"  # Revista: azul tem prioridade.
    return "#f8d7da" if float(record.get("revert_risk") or 0) > 0.95 else "#fff3cd"


def build_high_risk_edit_line(record, pattern_model=None):
    revision_id = int(record["revision_id"])
    username = str(record.get("username") or "Desconhecido")
    title = str(record.get("title") or "Sem título")
    risk = float(record.get("revert_risk") or 0)

    encoded_user = quote(username.replace(" ", "_"), safe="")
    encoded_title = quote(title.replace(" ", "_"), safe="/:()")
    article_link = (
        f"[https://pt.wikipedia.org/wiki/{encoded_title} "
        f"{wiki_safe_text(title)}]"
    )
    diff_url = f"https://pt.wikipedia.org/w/index.php?diff={revision_id}"
    history_url = f"https://pt.wikipedia.org/w/index.php?title={encoded_title}&action=history"
    contributions_url = f"https://pt.wikipedia.org/wiki/Especial:Contribui%C3%A7%C3%B5es/{encoded_user}"
    first_line = (
        f"'''{article_link}''' · [{diff_url} Ver diferenças] · "
        f"[{history_url} Histórico] · [{contributions_url} Contribuições] · "
        f"<span style=\"font-size:115%\">'''{risk:.0%}'''</span>"
    )
    second_line = high_risk_diff_excerpt(record)

    action, actor, _ = high_risk_action(record)
    if action:
        status_text = f"{action} por {high_risk_account_link(actor)}" if actor else action
    else:
        status_text = "Pendente de revisão"
    pattern_line = high_risk_pattern_annotation(record, pattern_model or {})
    background = high_risk_background(record)
    return (
        f'<div style="background:{background}; border:1px solid #a2a9b1; '
        f'padding:0.45em 0.7em; margin:0.35em 0; line-height:1.35">'
        f"{first_line}<br>{second_line}<br>"
        f"<small>'''Estado:''' {status_text}</small>"
        + ("<br>" + pattern_line if pattern_line else "")
        + "</div>"
    )


def select_high_risk_records(records):
    eligible = []
    for record in records:
        try:
            risk = float(record.get("revert_risk"))
            revision_id = int(record.get("revision_id"))
        except (TypeError, ValueError):
            continue
        if risk < WIKI_HIGH_RISK_THRESHOLD:
            continue
        record["revert_risk"] = risk
        record["revision_id"] = revision_id
        eligible.append(record)

    eligible.sort(
        key=lambda item: (
            float(item.get("revert_risk") or 0),
            float(item.get("posted_at") or 0),
        ),
        reverse=True,
    )

    return eligible


def high_risk_header_transclusion():
    return "{{" + WIKI_HIGH_RISK_HEADER_TITLE + "}}"


def build_high_risk_page(records, heading, introduction):
    eligible = select_high_risk_records(records)
    pattern_model = train_high_risk_pattern_model()
    pattern_counts = pattern_model.get("counts", {})
    lines = [
        "__NOINDEX__",
        high_risk_header_transclusion(),
        f"= {heading} =",
        introduction,
        "",
        "Amarelo: pendente (85–95%); vermelho: pendente (acima de 95%); "
        "azul: edição revista.",
        "Treino de padrões: revertida/eliminada = vandalismo; patrulhada/falso positivo = sem vandalismo. "
        "Autorrevertidas e outros estados ficam fora do treino.",
        "A semelhança de padrões é informativa; não altera o risco calculado nem confirma sozinha o caso.",
        "",
    ]
    if pattern_model.get("ready"):
        lines.append(
            "''Base de padrões: "
            f"{pattern_counts.get('vandalismo', 0)} exemplos de vandalismo e "
            f"{pattern_counts.get('sem_vandalismo', 0)} exemplos sem vandalismo.''"
        )
    else:
        lines.append(
            "''Aprendizagem em fase inicial: "
            f"{pattern_counts.get('vandalismo', 0)} exemplos de vandalismo e "
            f"{pattern_counts.get('sem_vandalismo', 0)} sem vandalismo; "
            f"mínimo de {HIGH_RISK_PATTERN_MIN_PER_CLASS} por classe para exibir semelhanças.''"
        )
    lines.append("")
    if eligible:
        lines.extend(
            build_high_risk_edit_line(record, pattern_model)
            for record in eligible
        )
    else:
        lines.append("''Não há edições que atendam ao limiar neste momento.''")
    return "\n".join(lines) + "\n"


def load_high_risk_archive():
    global high_risk_archive
    loaded = load_json(HIGH_RISK_ARCHIVE_FILE, {})
    if not isinstance(loaded, dict):
        loaded = {}
    with high_risk_archive_lock:
        high_risk_archive = {
            str(key): value for key, value in loaded.items() if isinstance(value, dict)
        }


def save_high_risk_archive():
    with high_risk_archive_lock:
        snapshot = dict(high_risk_archive)
    atomic_write_json(HIGH_RISK_ARCHIVE_FILE, snapshot)


def sync_high_risk_archive():
    with posted_edits_lock:
        current = [dict(item) for item in posted_edits.values()]
    changed = False
    with high_risk_archive_lock:
        for record in select_high_risk_records(current):
            revision_id = str(record["revision_id"])
            archived = {
                key: record.get(key)
                for key in (
                    "revision_id", "username", "title", "revert_risk",
                    "revision_timestamp", "posted_at", "status", "edit_comment",
                    "diff_added", "diff_removed", "risk_reasons",
                    "reverted_by", "reverted_at", "patrolled_by", "patrolled_at",
                    "deleted_by", "deleted_at", "resolved_at", "false_positive_at",
                )
            }
            archived["archive_date"] = high_risk_record_date(archived)
            if high_risk_archive.get(revision_id) != archived:
                high_risk_archive[revision_id] = archived
                changed = True
    if changed:
        save_high_risk_archive()
    return changed


def build_high_risk_wikitext(now=None):
    with high_risk_archive_lock:
        records = [dict(item) for item in high_risk_archive.values()]
    visible = [record for record in records if high_risk_action(record)[0] is None]
    return build_high_risk_page(
        visible,
        "Edições com alto risco de vandalismo",
        "Esta lista inclui edições da Wikipédia em português com risco "
        f"igual ou superior a {WIKI_HIGH_RISK_THRESHOLD:.0%}.",
    )


def build_high_risk_daily_wikitext(day, records):
    return build_high_risk_page(
        records,
        f"Edições com alto risco de vandalismo — {day}",
        f"Arquivo permanente das edições detectadas em {day} (UTC).",
    )


HIGH_RISK_MONTH_NAMES = (
    "", "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
)
HIGH_RISK_MONTH_ABBREVIATIONS = (
    "", "jan", "fev", "mar", "abr", "mai", "jun",
    "jul", "ago", "set", "out", "nov", "dez",
)


def high_risk_archive_days(records):
    return sorted({
        str(item.get("archive_date"))
        for item in records
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", str(item.get("archive_date") or ""))
    })


def build_high_risk_header_wikitext(records):
    days = high_risk_archive_days(records)
    months = sorted({day[:7] for day in days})
    years = sorted({day[:4] for day in days}, reverse=True)
    lines = [
        "__NOINDEX__",
        '<div style="border:1px solid #a2a9b1; background:#f8f9fa; padding:0.6em; margin-bottom:0.8em">',
        "'''Navegação:''' "
        f"[[{WIKI_HIGH_RISK_TITLE}|avisos pendentes]] · "
        f"[[{WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE}|arquivo por data]]",
    ]
    for year in years:
        links = []
        for month in range(1, 13):
            key = f"{year}-{month:02d}"
            label = HIGH_RISK_MONTH_ABBREVIATIONS[month]
            links.append(
                f"[[{WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE}#"
                f"{HIGH_RISK_MONTH_NAMES[month].capitalize()}_{year}|{label}]]"
                if key in months else label
            )
        lines.append(f"<small>'''{year}:''' " + " · ".join(links) + "</small>")
    if not years:
        lines.append("<small>''Ainda não há arquivos diários.''</small>")
    lines.append("</div><noinclude>Cabeçalho automático dos avisos e arquivos do TelesGramBot.</noinclude>")
    return "\n".join(lines) + "\n"


def build_high_risk_archive_index_wikitext(records):
    days = high_risk_archive_days(records)
    available = set(days)
    months = sorted({day[:7] for day in days}, reverse=True)
    lines = [
        "__NOINDEX__",
        high_risk_header_transclusion(),
        "= Arquivo de edições de alto risco =",
        "Os dias com arquivo disponível aparecem como links. As semanas começam na segunda-feira.",
    ]
    if not months:
        lines.append("''Ainda não há arquivos diários.''")
        return "\n\n".join(lines) + "\n"

    month_calendar = calendar.Calendar(firstweekday=0)
    for key in months:
        year, month = (int(part) for part in key.split("-"))
        lines.extend([
            f"== {HIGH_RISK_MONTH_NAMES[month].capitalize()} {year} ==",
            '{| class="wikitable" style="text-align:center; width:100%; max-width:42em"',
            "! Seg !! Ter !! Qua !! Qui !! Sex !! Sáb !! Dom",
        ])
        for week in month_calendar.monthdayscalendar(year, month):
            cells = []
            for day_number in week:
                if not day_number:
                    cells.append("")
                    continue
                day = f"{year:04d}-{month:02d}-{day_number:02d}"
                cells.append(
                    f"[[{WIKI_HIGH_RISK_ARCHIVE_PREFIX}{day}|'''{day_number}''']]"
                    if day in available else str(day_number)
                )
            lines.extend(["|-", "| " + " || ".join(cells)])
        lines.append("|}")
    return "\n".join(lines) + "\n"




def testwiki_allowed_title(title):
    if title in (WIKI_HIGH_RISK_TITLE, WIKI_HIGH_RISK_HEADER_TITLE, WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE):
        return True
    if title.startswith(WIKI_HIGH_RISK_ARCHIVE_PREFIX):
        suffix = title[len(WIKI_HIGH_RISK_ARCHIVE_PREFIX):]
        try:
            return datetime.strptime(suffix, "%Y-%m-%d").strftime("%Y-%m-%d") == suffix
        except ValueError:
            return False
    return False


def queue_testwiki_edit(title, text, summary):
    if not testwiki_allowed_title(title):
        raise PermissionError("Título não autorizado na Test Wikipedia")
    with TESTWIKI_LOCK:
        state = load_json(TESTWIKI_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        if not isinstance(state, dict):
            state = {"pending": [], "last_attempt": 0}
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        pending = state.get("pending", [])
        if state.get("published_hashes", {}).get(title) == digest and not any(x.get("title") == title for x in pending):
            return False
        existing = next((x for x in pending if x.get("title") == title), None)
        if existing and existing.get("digest") == digest:
            return False
        item = {"title": title, "text": text, "summary": summary, "digest": digest}
        if existing:
            pending[pending.index(existing)] = item
        else:
            pending.append(item)
        state["pending"] = pending
        atomic_write_json(TESTWIKI_QUEUE_FILE, state)
        return True


def queue_high_risk_wiki_pages():
    sync_high_risk_archive()
    with high_risk_archive_lock:
        archived = [dict(x) for x in high_risk_archive.values()]
    queue_testwiki_edit(WIKI_HIGH_RISK_TITLE, build_high_risk_wikitext(), "Atualizando lista de edições de alto risco")
    queue_testwiki_edit(WIKI_HIGH_RISK_HEADER_TITLE, build_high_risk_header_wikitext(archived), "Atualizando cabeçalho")
    queue_testwiki_edit(WIKI_HIGH_RISK_ARCHIVE_INDEX_TITLE, build_high_risk_archive_index_wikitext(archived), "Atualizando índice do arquivo")
    for day in high_risk_archive_days(archived):
        queue_testwiki_edit(WIKI_HIGH_RISK_ARCHIVE_PREFIX + day, build_high_risk_daily_wikitext(day, [x for x in archived if x.get("archive_date") == day]), "Atualizando arquivo de " + day)


def testwiki_writing_paused():
    """Independent persistent switch; fail closed on invalid state."""
    try:
        with open(TESTWIKI_CONTROL_FILE, "r", encoding="utf-8") as control:
            state = json.load(control)
        return not isinstance(state, dict) or not isinstance(state.get("paused"), bool) or state["paused"]
    except FileNotFoundError:
        return False
    except Exception as exc:
        print("⚠️ Controle da Test Wikipedia indisponível:", safe_exception(exc))
        return True


def set_testwiki_writing_paused(paused):
    with TESTWIKI_LOCK:
        atomic_write_json(TESTWIKI_CONTROL_FILE, {"paused": bool(paused)})


def testwiki_write_once():
    with TESTWIKI_LOCK:
        if testwiki_writing_paused():
            return False
        state = load_json(TESTWIKI_QUEUE_FILE, {"pending": [], "last_attempt": 0})
        pending = state.get("pending", [])
        if not pending or time.time() - float(state.get("last_attempt") or 0) < TESTWIKI_WRITE_INTERVAL_SECONDS:
            return False
        item = pending[0]
        if not testwiki_allowed_title(item["title"]):
            raise PermissionError("Destino de escrita não autorizado")
        state["last_attempt"] = time.time()
        atomic_write_json(TESTWIKI_QUEUE_FILE, state)
        if not testwiki_authenticated and not testwiki_login():
            raise RuntimeError("Falha na autenticação da Test Wikipedia")
        exists = testwiki_page_exists(item["title"])
        if not exists and get_latest_testwiki_deletion_log(item["title"]):
            raise PermissionError("Página eliminada: recriação automática proibida")
        payload = {"action":"edit", "format":"json", "formatversion":2, "title":item["title"], "text":item["text"], "summary":item["summary"], "token":get_testwiki_csrf_token(), "assert":"user", "bot":1}
        payload["nocreate" if exists else "createonly"] = 1
        response = testwiki_session.post(TESTWIKI_API, data=payload, timeout=35)
        response.raise_for_status()
        result = response.json()
        if result.get("error") or result.get("edit", {}).get("result") != "Success":
            raise RuntimeError("Publicação não confirmada: " + safe_log_text(result))
        state = load_json(TESTWIKI_QUEUE_FILE, state)
        if state.get("pending") and state["pending"][0] == item:
            state["pending"].pop(0)
            state.setdefault("published_hashes", {})[item["title"]] = item["digest"]
            atomic_write_json(TESTWIKI_QUEUE_FILE, state)
        return True


def testwiki_high_risk_worker():
    while True:
        try:
            queue_high_risk_wiki_pages()
            testwiki_write_once()
        except Exception as exc:
            print("⚠️ Test Wikipedia:", safe_exception(exc))
        time.sleep(30)

def main():
    print("========================================")
    print("Detector de vandalismo ptwiki")
    print(f"Versão {BOT_VERSION} | Build {BOT_BUILD}")
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
    load_temporary_watchlist()
    load_observed_users()
    load_post_block_observations()
    load_ignored_users()
    load_abuse_filters()
    load_abuse_filter_state()
    load_posted_edits()
    load_high_risk_archive()
    load_detection_stats()
    load_pending_summary_state()
    load_reversible_actions()
    load_community_stats()
    load_false_positives()
    load_false_negatives()

    cleanup_expired_observations()
    activate_due_post_block_observations()
    cleanup_expired_temporary_watches()
    cleanup_expired_ignored_users()
    cleanup_posted_edits()
    cleanup_detection_stats()
    cleanup_community_stats()

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
    print("👁 Vigilância temporária de página: 6 horas")
    print("🙈 Ignorar conta: 6 horas")
    print("🔒 Monitor de bloqueios: ativo")
    print("🔎 Observação automática pós-bloqueio: ativa")
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
        "🕒 Resumo prioritário: a cada 2 horas, "
        "top 10 por risco, janela de 48h"
    )
    print(
        "🧹 Reconciliação de pendências: a cada 30 minutos, "
        "com confirmação de páginas eliminadas"
    )
    print(
        "📝 Relatórios wiki: escrita habilitada com limite de 60 minutos"
    )
    print(
        "🔒 Prefixo permitido para futura escrita:",
        WIKI_ALLOWED_TITLE_PREFIX
    )

    threads = [
        ("telegram-sender", telegram_sender),
        ("analysis-worker", analysis_worker),
        ("block-worker", block_worker),
        ("post-block-observation", post_block_observation_scheduler),
        ("protection-worker", protection_worker),
        ("page-deletion-worker", page_deletion_worker),
        ("eventstream-watchdog", eventstream_watchdog),
        ("telegram-listener", telegram_command_listener),
        ("abuse-filter-monitor", abuse_filter_monitor),
        ("posted-edit-status", posted_edit_status_monitor),
        ("reversal-result-worker", _reversal_result_worker),
        ("patrol-result-worker", _patrol_result_worker),
        ("posted-status-maintenance", _posted_status_maintenance),
        ("posted-edit-patrol", posted_edit_patrol_monitor),
        ("daily-detection-report", daily_detection_report_scheduler),
        ("pending-alerts-summary", pending_alerts_summary_scheduler),
        ("pending-resolution-reconciliation", pending_resolution_reconciliation_scheduler),
        ("testwiki-high-risk", testwiki_high_risk_worker),
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
        target=version_announcement_worker,
        daemon=True,
        name="version-announcement",
    ).start()

    wikimedia_loop()


if __name__ == "__main__":
    threading.Thread(target=wiki_write_queue_worker, daemon=True).start()
    main()
