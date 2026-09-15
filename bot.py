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

BOT_VERSION = "2.24"
BOT_BUILD = "2.24"

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
# ESCRITA NA WIKIPÉDIA — PREPARADA, MAS DESATIVADA
# =========================================================

# Trava deliberadamente hardcoded. Nesta versão não existe variável de
# ambiente capaz de habilitar escrita por acidente.
WIKI_WRITE_ENABLED = False

# Regra de segurança solicitada: mesmo quando a escrita for liberada numa
# versão futura, o bot somente poderá editar títulos iniciados exatamente por:
WIKI_ALLOWED_TITLE_PREFIX = "Usuário:TelesGramBot:"

# Relatórios que serão usados quando a publicação for futuramente ativada.
WIKI_DAILY_REPORT_PREFIX = "Usuário:TelesGramBot:Relatórios/Diário/"
WIKI_MONTHLY_REPORT_PREFIX = "Usuário:TelesGramBot:Relatórios/Mensal/"



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

POSTED_EDIT_CHECK_SECONDS = 10
REVISION_STATUS_INTERVAL_SECONDS = 30
POSTED_EDIT_TRACK_SECONDS = 48 * 60 * 60

# Resumo periódico dos alertas ainda pendentes no canal.
PENDING_SUMMARY_INTERVAL_SECONDS = 2 * 60 * 60
PENDING_SUMMARY_MAX_ITEMS = 10
PENDING_COMMAND_PAGE_SIZE = 5
PENDING_RECONCILE_INTERVAL_SECONDS = 30 * 60
PENDING_PAGE_BATCH_SIZE = 50

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
                    safe_log_text(response.text)
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


def register_false_positive(record, actor):
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
    title = html.escape(str(item.get("title") or "Sem título"))
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
            "✅ Falso positivo revisado — ajuste no bot marcado como concluído\n\n"
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
        "Edição será revista para ajustes no bot.\n\n"
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

    data = load_json(
        COMMUNITY_STATS_FILE,
        {"events": [], "last_preview_date": None},
    )

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
    token = (
        response.json()
        .get("query", {})
        .get("tokens", {})
        .get("csrftoken")
    )
    if not token:
        raise RuntimeError("token CSRF não retornado")
    return token


def wiki_edit_page(title, wikitext, summary):
    """
    Implementação pronta para uso futuro, mas bloqueada por duas barreiras:
    1) WIKI_WRITE_ENABLED precisa ser alterado no código;
    2) o título precisa começar por Usuário:TelesGramBot:

    Nesta versão a primeira barreira é False e nenhuma chamada action=edit
    é enviada.
    """
    if not wiki_title_is_allowed(title):
        raise PermissionError(
            f"título fora do prefixo permitido: {title!r}"
        )

    if not WIKI_WRITE_ENABLED:
        print(
            "🔒 Escrita wiki bloqueada; relatório mantido apenas como prévia:",
            title,
        )
        return False

    token = get_wikimedia_csrf_token()

    response = wikimedia_session.post(
        WIKIPEDIA_API,
        data={
            "action": "edit",
            "format": "json",
            "formatversion": 2,
            "title": title,
            "text": wikitext,
            "summary": summary,
            "token": token,
            "assert": "user",
            "bot": 1,
        },
        timeout=35,
    )
    response.raise_for_status()
    data = response.json()

    if data.get("error"):
        raise RuntimeError(
            f"API edit recusou publicação: {data['error']}"
        )

    return data.get("edit", {}).get("result") == "Success"


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
        "'''Quem ajudou a calibrar o detector'''",
        wikitext_false_positive_reporters(
            false_positive_metrics["reporter_counts"],
            top=5,
        ),
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
        "* Falso positivo: alerta retirado da fila operacional por um administrador por não representar vandalismo e enviado à fila de melhoria do detector.",
        "* Ajuste concluído: confirmação administrativa de que o caso de falso positivo já foi tratado no código/regras do bot; isso não implica retreinamento automático do modelo.",
        "* Faixas de checagem: muito alto ≥85%; alto 70–84%; moderado 50–69%; baixo 30–49%; muito baixo <30%.",
        "* Capacidade observada: folga quando ≥85% e backlog muito pequeno; adequada ≥70%; pressionada 50–69%; sobrecarregada <50%.",
        "* Autorreversões são retiradas da demanda comunitária e não melhoram artificialmente o índice.",
        "* Os dados começam a ser coletados a partir da implantação desta versão; não há reconstrução histórica automática.",
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
        wiki_edit_page(
            daily_title,
            daily_text,
            "Atualizando relatório diário de manutenção e combate a vandalismo",
        )
        wiki_edit_page(
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


def announce_new_version_if_needed():
    announced_build = load_saved_bot_version()

    if announced_build == BOT_BUILD:
        print("ℹ️ Versão já anunciada. Nenhuma mensagem enviada.")
        return

    message = (
        "🤖 <b>TelesGramBot 2.24</b>\n\n"
        "🔗 <b>Links nos falsos positivos</b>\n"
        "• O ID da revisão agora é clicável na confirmação de Falso + e em /falsospositivos.\n"
        "• O link abre diretamente a edição correspondente na Wikipédia."


    )

    sent = send_telegram_message(message)

    if not sent:
        print("⚠️ Não foi possível anunciar a nova versão.")
        return

    try:
        save_bot_version(BOT_VERSION, BOT_BUILD)
        print("✅ Nova versão anunciada e registrada.")
    except Exception as e:
        print(
            "⚠️ Mensagem enviada, mas houve erro ao registrar a versão:",
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


def message_with_status(record, status, reverter=None, deleter=None):
    title = html.escape(str(record.get("title") or "Sem título"))
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
        return (
            "✅ Possível vandalismo patrulhado\n\n"
            f"📝 {title}\n"
            f"👤 {username}\n"
            f"💬 {comment}\n"
            f"{risk_line}\n"
            f"{edit_link}"
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
            if record.get("status") not in ("reverted", "self_reverted", "deleted", "resolved_no_action", "false_positive")
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
                reverter = None

                # Quando a revisão foi revertida, identifica primeiro o autor
                # da reversão para distinguir uma reversão comum de uma
                # autorreversão. A comparação usa a mesma normalização de nomes
                # já empregada pelo bot (espaços/underscores e casefold).
                if new_status == "reverted":
                    reverter = get_reverter_username(
                        record.get("title") or "",
                        revision_id
                    )

                    if (
                        reverter
                        and username_key(reverter)
                        == username_key(record.get("username"))
                    ):
                        new_status = "self_reverted"

                new_text = message_with_status(
                    record,
                    new_status,
                    reverter=reverter if new_status == "reverted" else None
                )

                # Mantém os botões já associados ao tipo original do alerta.
                status_reply_markup = record.get("reply_markup")
                if not status_reply_markup:
                    status_reply_markup = tracked_edit_reply_markup(revision_id)

                success = edit_telegram_message(
                    record["message_id"],
                    new_text,
                    parse_mode="HTML",
                    reply_markup=status_reply_markup
                )

                if success:
                    with posted_edits_lock:
                        live = posted_edits.get(
                            str(revision_id)
                        )

                        if live:
                            live["status"] = new_status
                            if reverter:
                                live["reverted_by"] = reverter
                            if new_status in ("reverted", "self_reverted"):
                                live["reverted_at"] = time.time()

                    changed_any = True

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
                        patroller = get_patroller_username(
                            record.get("title") or "",
                            revision_id,
                        )
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

        # Depois tenta refletir o estado na mensagem original.
        status_reply_markup = record.get("reply_markup")
        if not status_reply_markup:
            status_reply_markup = tracked_edit_reply_markup(revision_id)

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


def normalized_diff_lines(value):
    lines = []
    for raw in str(value or "").splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if line:
            lines.append(line)
    return lines


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
    """
    MediaWiki organiza, em regra, namespaces de discussão nos IDs ímpares
    pareados aos namespaces de conteúdo. Usa o ID quando disponível e cai
    para o prefixo do título como fallback.
    """
    try:
        namespace = int(change.get("namespace"))
        if namespace > 0 and namespace % 2 == 1:
            return True
    except Exception:
        pass

    title = str(change.get("title") or "")
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


def contextual_discussion_adjustment(change, diff, strong_signals):
    """
    Ajuste contextual por namespace.

    Em páginas de discussão, uma mensagem assinada tem contexto legítimo e
    recebe redutor moderado. Links externos ainda elevam o risco, pois podem
    ser spam.

    No domínio principal, uma mensagem com formato de discussão/assinatura
    é contextualizada como inadequada e recebe acréscimo, especialmente se
    trouxer link externo.

    Sinais fortes de vandalismo nunca recebem o redutor de discussão.
    """
    added = str(diff.get("added", "") or "")
    signed = looks_like_signed_discussion_comment(added)
    links = count_external_links(added)
    talk = is_discussion_namespace(change)

    if talk and signed and strong_signals == 0:
        # Comentário assinado é esperado em discussão.
        # Um link mantém parte da suspeita para não mascarar spam.
        return {
            "multiplier": 0.62,
            "additive": min(0.12, 0.06 * links),
            "reason": (
                "comentário assinado em página de discussão"
                + (" com link externo" if links else "")
            ),
            "kind": "talk_signed",
        }

    if not talk and signed:
        # Assinatura de discussão inserida em artigo/conteúdo é anômala.
        return {
            "multiplier": 1.0,
            "additive": 0.10 + min(0.10, 0.05 * links),
            "reason": (
                "formato de mensagem de discussão inserido fora de página de discussão"
            ),
            "kind": "signed_outside_talk",
        }

    return None


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

    benign = benign_technical_change(diff)

    # O redutor técnico atua apenas em mudanças mínimas reconhecidas.
    if benign:
        score *= float(benign.get("factor", 1.0))

    context_adjustment = contextual_discussion_adjustment(
        change,
        diff,
        strong_signals,
    )

    if context_adjustment:
        score *= float(context_adjustment.get("multiplier", 1.0))
        score += float(context_adjustment.get("additive", 0.0))

    promotional_adjustment = new_page_promotional_signals(change, diff)
    if promotional_adjustment["bonus"] > 0:
        score += promotional_adjustment["bonus"]

    score = min(max(score, 0.0), 1.0)

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

    if context_adjustment:
        reasons.append(
            str(
                context_adjustment.get("reason")
                or "ajuste contextual por namespace"
            )
        )

    reasons.extend(promotional_adjustment.get("signals", []))

    if not reasons:
        reasons.append("edição suspeita")

    return {
        "score": score,
        "revert_risk": revert_risk,
        "reason": ", ".join(reasons),
        "benign_reduction": benign,
        "context_adjustment": context_adjustment,
        "promotional_adjustment": promotional_adjustment,
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



def reply_markup_without_resolution_buttons(reply_markup, revision_id):
    if not isinstance(reply_markup, dict):
        return tracked_edit_reply_markup(
            revision_id,
            include_resolve=False
        )

    target = f"resolve:{revision_id}"
    rows = []

    for row in reply_markup.get("inline_keyboard", []):
        if not isinstance(row, list):
            continue
        cleaned = [
            button
            for button in row
            if not (
                isinstance(button, dict)
                and button.get("callback_data") == target
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
    return (
        "👁 Edição de conta observada\n\n"
        f"👤 {user_contributions_link_html(change.get('user', 'Desconhecido'))}\n"
        f"📝 {html.escape(str(change.get('title', 'Sem título')))}\n"
        f"💬 {html.escape(str(change.get('comment') or 'Sem resumo'))}\n"
        f"{reason_line}\n"
        f"{edit_link_html(build_diff_url(change))}"
    )


def format_watched_message(change):
    return (
        "👁 Edição em página vigiada\n\n"
        f"📝 {html.escape(str(change.get('title', 'Sem título')))}\n"
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
        f"📝 {html.escape(str(change.get('title', 'Sem título')))}\n"
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
                if is_wikipedia_admin(username):
                    continue

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
        "📡 /status — mostra o estado do bot.\n\n"
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
        "✅ /resolverfalso ID — marca como concluído o ajuste de um falso positivo.\n"
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
    }

    if command in mutating_commands and (
        not from_channel or not is_target_channel(chat)
    ):
        send_telegram_message(
            "⚠️ Este comando administrativo deve ser publicado diretamente no canal configurado.",
            chat_id=chat_id,
        )
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
        send_telegram_message("✅ <b>Falso negativo revisado</b>\n\n" + f"📝 {html.escape(item.get('title') or '')}\n🆔 Revisão: {item.get('revision_id')}\n🛠 Ajuste concluído por: {html.escape(actor)}\n\nO caso permanece na base histórica de calibração.", chat_id=chat_id, parse_mode="HTML")
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
                "Uso: /resolverfalso ID_DA_REVISÃO",
                chat_id=chat_id
            )
            return

        try:
            revision_id = int(argument.strip())
        except Exception:
            send_telegram_message(
                "❌ ID de revisão inválido.",
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
                f"🆔 Revisão: {revision_id}\n"
                f"🏷 Reportado por: {reporter}\n"
                f"🛠 Ajuste concluído por: {actor}\n\n"
                "Obrigado pelo reporte. Este caso foi incorporado ao ciclo "
                "de melhoria do detector e saiu da fila de ajustes pendentes."
                + (
                    "\n✏️ O aviso original também foi atualizado."
                    if updated
                    else "\nℹ️ Não foi possível atualizar o aviso original, mas a fila foi corrigida."
                )
            ),
            chat_id=chat_id
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

        if observe_user(
            canonical_username,
            reason
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
    if action not in ("observe", "watch", "unobserve", "unwatch", "resolve", "falsepos"):
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

    if action == "falsepos":
        revision_id = int(record.get("revision_id") or revision_text)

        if record.get("alert_kind", "normal") != "normal":
            answer_callback_query(
                callback_id,
                "Falso positivo só pode ser marcado em alertas do detector."
            )
            return

        if record.get("status"):
            answer_callback_query(
                callback_id,
                "Este alerta já foi resolvido."
            )
            return

        marker_name = actor or "administrador do canal"

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

        fp_item = register_false_positive(record, marker_name)

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
                    "🏷 Falso positivo encaminhado para verificação.\n"
                    f'🆔 <a href="https://pt.wikipedia.org/w/index.php?diff={revision_id}">{revision_id}</a>'
                ),
                chat_id=TELEGRAM_CHANNEL,
                parse_mode="HTML"
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
        "📝 Relatórios wiki: coleta ativa, escrita DESATIVADA"
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
        ("daily-detection-report", daily_detection_report_scheduler),
        ("pending-alerts-summary", pending_alerts_summary_scheduler),
        ("pending-resolution-reconciliation", pending_resolution_reconciliation_scheduler),
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
