import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock


# The production dependencies are deliberately replaced before import: these
# tests exercise persistence and decision logic and must never make HTTP calls.
class _NoNetworkSession:
    def __init__(self):
        self.headers = {}

    def request(self, *args, **kwargs):
        raise AssertionError("network access is forbidden in unit tests")

    get = request
    post = request


_requests = types.ModuleType("requests")
_requests.Session = _NoNetworkSession
_requests.sessions = types.SimpleNamespace(Session=_NoNetworkSession)
_requests.exceptions = types.SimpleNamespace(
    HTTPError=type("HTTPError", (Exception,), {}),
    RequestException=type("RequestException", (Exception,), {}),
)
_requests.get = _NoNetworkSession().request
_requests.post = _NoNetworkSession().request
sys.modules.setdefault("requests", _requests)

_sseclient = types.ModuleType("sseclient")
_sseclient.SSEClient = type("SSEClient", (), {})
sys.modules.setdefault("sseclient", _sseclient)

_import_data = tempfile.TemporaryDirectory()
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "unit-test-token")
os.environ["TOOL_DATA_DIR"] = _import_data.name
os.environ["PTWIKI_HIGH_RISK_MODE"] = "shadow"

import bot  # noqa: E402


class HighRiskDelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        bot.HIGH_RISK_CANDIDATES_FILE = os.path.join(self.temp.name, "candidates.json")
        bot.HIGH_RISK_ARCHIVE_FILE = os.path.join(self.temp.name, "archive.json")
        bot.HIGH_RISK_WRITE_CONTROL_FILE = os.path.join(self.temp.name, "control.json")
        bot.WIKI_WRITE_QUEUE_FILE = os.path.join(self.temp.name, "wiki-queue.json")
        bot.WIKI_PENDING_PAGES_FILE = os.path.join(self.temp.name, "pending-pages.json")
        bot.PTWIKI_HIGH_RISK_MODE = "shadow"
        bot.posted_edits = {}
        bot.high_risk_archive = {}

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def change(revision_id=101, timestamp=1_000, old_revision=100):
        return {
            "id": 55,
            "page_id": 77,
            "type": "edit" if old_revision else "new",
            "title": "Artigo de teste",
            "user": "Editor",
            "comment": "ajuste",
            "timestamp": timestamp,
            "revision": {"old": old_revision, "new": revision_id},
            "length": {"old": 10, "new": 20},
        }

    @staticmethod
    def result(risk=0.81):
        return {
            "revert_risk": risk,
            "score": risk,
            "raw_score": risk,
            "reason": "teste",
        }

    def load_candidates(self):
        with open(bot.HIGH_RISK_CANDIDATES_FILE, encoding="utf-8") as handle:
            return json.load(handle)["items"]

    def test_threshold_is_strict_and_deadline_uses_revision_time(self):
        self.assertFalse(
            bot.enqueue_high_risk_candidate(
                self.change(revision_id=101), self.result(0.80), {"added": "x"}
            )
        )
        self.assertTrue(
            bot.enqueue_high_risk_candidate(
                self.change(revision_id=102), self.result(0.81), {"added": "texto relevante"}
            )
        )
        candidate = self.load_candidates()["102"]
        self.assertEqual(candidate["eligible_at"], 1_000 + 2 * 60 * 60)
        self.assertEqual(candidate["state"], "waiting")

    def test_reenqueue_is_idempotent_and_never_moves_deadline(self):
        change = self.change(revision_id=103, timestamp=1_000)
        bot.enqueue_high_risk_candidate(change, self.result(), {"added": "primeiro"})
        change["timestamp"] = 5_000
        bot.enqueue_high_risk_candidate(change, self.result(0.95), {"added": "segundo"})
        candidate = self.load_candidates()["103"]
        self.assertEqual(candidate["eligible_at"], 8_200)
        self.assertEqual(candidate["state"], "waiting")

    def test_shadow_mode_decides_but_does_not_publish_or_archive(self):
        bot.enqueue_high_risk_candidate(self.change(), self.result(), {"added": "texto"})
        with mock.patch.object(
            bot, "evaluate_high_risk_candidate",
            return_value={"decision": "publish", "reason": "still_unreviewed"},
        ):
            counts = bot.process_due_high_risk_candidates(now=9_000)
        self.assertEqual(counts["approved"], 1)
        self.assertEqual(self.load_candidates()["101"]["state"], "shadow_approved")
        self.assertEqual(bot.high_risk_archive, {})

    def test_publish_mode_approves_and_archives_only_after_verification(self):
        bot.PTWIKI_HIGH_RISK_MODE = "publish"
        bot.enqueue_high_risk_candidate(self.change(), self.result(), {"added": "texto"})
        with mock.patch.object(
            bot, "evaluate_high_risk_candidate",
            return_value={"decision": "publish", "reason": "still_unreviewed"},
        ):
            counts = bot.process_due_high_risk_candidates(now=9_000)
        self.assertEqual(counts["approved"], 1)
        self.assertEqual(self.load_candidates()["101"]["state"], "approved")
        self.assertIn("101", bot.high_risk_archive)
        self.assertIs(bot.high_risk_archive["101"]["ptwiki_delay_verified"], True)

    def test_known_resolution_suppresses_candidate(self):
        bot.posted_edits["101"] = {"revision_id": 101, "status": "reverted", "reverted_by": "Revisor"}
        decision = bot._candidate_terminal_resolution({"revision_id": 101})
        self.assertEqual(decision["decision"], "suppress")
        self.assertEqual(decision["reason"], "reverted")

    def test_only_explicit_non_auto_patrol_counts_as_seen(self):
        candidate = {"revision_id": 101, "title": "Artigo de teste", "revision_timestamp": 1_000}

        def reply(auto):
            return mock.Mock(), {
                "query": {"logevents": [{
                    "action": "patrol", "user": "Revisor",
                    "params": {"curid": 101, "auto": auto},
                }]}
            }

        with mock.patch.object(bot, "wikimedia_api_get", return_value=reply(True)):
            event, complete = bot.find_manual_patrol_event(candidate, now=2_000)
        self.assertTrue(complete)
        self.assertIsNone(event)

        with mock.patch.object(bot, "wikimedia_api_get", return_value=reply(False)):
            event, complete = bot.find_manual_patrol_event(candidate, now=2_000)
        self.assertTrue(complete)
        self.assertEqual(event["user"], "Revisor")

    def test_exact_parent_restore_is_obsolete(self):
        relevance, evidence = bot._later_edit_relevance(
            {"revision_id": 101, "is_new_page": False},
            {
                "original": {"revid": 101, "sha1": "bad"},
                "current": {"revid": 102, "sha1": "parent"},
                "parent": {"revid": 100, "sha1": "parent"},
                "parent_id": 100,
            },
        )
        self.assertEqual(relevance, "superseded")
        self.assertTrue(evidence["exact_parent_restore"])

    def test_shadow_mode_cannot_enqueue_a_wiki_write(self):
        with mock.patch.object(bot, "queue_wiki_edit") as queue_edit:
            self.assertFalse(
                bot.queue_high_risk_wiki_edit(
                    bot.WIKI_HIGH_RISK_TITLE, "conteÃºdo", "resumo"
                )
            )
        queue_edit.assert_not_called()

    def test_archive_sync_never_admits_an_unverified_telegram_record(self):
        bot.posted_edits["101"] = {
            "revision_id": 101,
            "revert_risk": 0.99,
            "title": "Artigo de teste",
        }
        self.assertFalse(bot.sync_high_risk_archive())
        self.assertEqual(bot.high_risk_archive, {})

    def test_legacy_testwiki_archive_is_not_publishable_without_new_gate(self):
        bot.high_risk_archive = {
            "100": {"revision_id": 100, "title": "Legado", "revert_risk": 0.99},
            "101": {
                "revision_id": 101,
                "title": "Verificado",
                "revert_risk": 0.99,
                "ptwiki_delay_verified": True,
            },
        }
        records = bot.ptwiki_publishable_high_risk_records()
        self.assertEqual([record["revision_id"] for record in records], [101])

    def test_identical_published_text_is_not_queued_again(self):
        bot.PTWIKI_HIGH_RISK_MODE = "publish"
        self.assertTrue(
            bot.queue_high_risk_wiki_edit(
                bot.WIKI_HIGH_RISK_TITLE, "conteÃºdo estÃ¡vel", "resumo"
            )
        )
        state = bot.load_json(bot.WIKI_WRITE_QUEUE_FILE, {})
        digest = state["pending"][0]["digest"]
        state["pending"] = []
        state["published_hashes"] = {bot.WIKI_HIGH_RISK_TITLE: digest}
        bot.atomic_write_json(bot.WIKI_WRITE_QUEUE_FILE, state)
        self.assertFalse(
            bot.queue_high_risk_wiki_edit(
                bot.WIKI_HIGH_RISK_TITLE, "conteÃºdo estÃ¡vel", "resumo"
            )
        )

    def test_prepublish_suppression_removes_approved_candidate_from_archive(self):
        bot.PTWIKI_HIGH_RISK_MODE = "publish"
        candidate = {
            "revision_id": 101,
            "state": "approved",
            "approval_mode": "publish",
            "queued_at": 1_000,
        }
        bot.atomic_write_json(
            bot.HIGH_RISK_CANDIDATES_FILE,
            {"schema_version": 1, "items": {"101": candidate}},
        )
        bot.high_risk_archive = {"101": dict(candidate)}
        with mock.patch.object(
            bot, "evaluate_high_risk_candidate",
            return_value={"decision": "suppress", "reason": "manually_patrolled"},
        ):
            self.assertEqual(bot.revalidate_approved_high_risk_candidates(now=9_000), [])
        self.assertEqual(self.load_candidates()["101"]["state"], "suppressed")
        self.assertNotIn("101", bot.high_risk_archive)

    def test_first_publication_orders_dependencies_before_main_page(self):
        bot.PTWIKI_HIGH_RISK_MODE = "publish"
        with (
            mock.patch.object(bot, "revalidate_approved_high_risk_candidates", return_value=[]),
            mock.patch.object(bot, "refresh_pending_high_risk_block_states", return_value=False),
            mock.patch.object(bot, "sync_high_risk_archive", return_value=False),
        ):
            self.assertTrue(bot.queue_high_risk_wiki_pages())
        state = bot.load_json(bot.WIKI_WRITE_QUEUE_FILE, {})
        titles = [item["title"] for item in state["pending"]]
        self.assertEqual(
            titles[:3],
            [
                bot.WIKI_HIGH_RISK_ENTRY_TEMPLATE_TITLE,
                bot.WIKI_HIGH_RISK_HEADER_TITLE,
                bot.WIKI_HIGH_RISK_TITLE,
            ],
        )

    def test_write_worker_uses_text_revalidated_at_last_safe_point(self):
        bot.PTWIKI_HIGH_RISK_MODE = "publish"
        queued = {
            "title": bot.WIKI_HIGH_RISK_TITLE,
            "text": "stale",
            "summary": "resumo",
            "write_class": "high_risk",
            "publication_revision_ids": [101],
        }
        bot.atomic_write_json(
            bot.WIKI_WRITE_QUEUE_FILE,
            {"pending": [queued], "last_attempts": {"high_risk": 0}},
        )
        prepared = {**queued, "text": "fresh", "publication_revision_ids": [202]}
        with (
            mock.patch.object(bot, "prepare_high_risk_write_item", return_value=prepared),
            mock.patch.object(bot, "wiki_edit_page", return_value=True) as edit,
            mock.patch.object(bot, "mark_wiki_page_published"),
            mock.patch.object(bot, "mark_high_risk_candidates_published") as mark,
            mock.patch.object(bot, "purge_high_risk_main_page"),
        ):
            self.assertTrue(bot.process_wiki_write_queue_once())
        edit.assert_called_once_with(
            bot.WIKI_HIGH_RISK_TITLE, "fresh", "resumo", write_class="high_risk"
        )
        mark.assert_called_once_with([202], published_at=mock.ANY)

    def test_mediawiki_write_uses_identity_lag_and_edit_conflict_guards(self):
        bot.wikimedia_authenticated = True
        bot.wikimedia_authenticated_user = "TelesGramBot"
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"edit": {"result": "Success"}}
        context = {
            "exists": True,
            "revid": 500,
            "timestamp": "2026-10-07T10:00:00Z",
            "starttimestamp": "2026-10-07T10:00:01Z",
        }
        with (
            mock.patch.object(bot, "wiki_page_write_context", return_value=context),
            mock.patch.object(bot, "get_wikimedia_csrf_token", return_value="csrf"),
            mock.patch.object(bot.wikimedia_session, "post", return_value=response) as post,
        ):
            self.assertTrue(
                bot.wiki_edit_page(
                    bot.WIKI_HIGH_RISK_TITLE,
                    "conteÃºdo",
                    "resumo",
                    write_class="high_risk",
                )
            )
        payload = post.call_args.kwargs["data"]
        self.assertEqual(payload["assert"], "bot")
        self.assertEqual(payload["assertuser"], "TelesGramBot")
        self.assertEqual(payload["maxlag"], 5)
        self.assertEqual(payload["baserevid"], 500)
        self.assertEqual(payload["basetimestamp"], "2026-10-07T10:00:00Z")
        self.assertEqual(payload["starttimestamp"], "2026-10-07T10:00:01Z")
        self.assertEqual(payload["nocreate"], 1)


if __name__ == "__main__":
    unittest.main()
