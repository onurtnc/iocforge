"""IOCForge birim testleri - hicbiri ag erisimi gerektirmez."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iocforge.cache import Cache                                    # noqa: E402
from iocforge.cli import main                                       # noqa: E402
from iocforge.enrich import Enriched, Enricher                      # noqa: E402
from iocforge.extract import defang, extract, guess_type, refang    # noqa: E402
from iocforge.providers.base import Provider, ProviderResult        # noqa: E402
from iocforge.report import to_csv, to_html, to_json, to_markdown   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "olay_raporu.txt")


# --------------------------------------------------------------------------- #
class FakeMalicious(Provider):
    """Ag kullanmayan sahte kaynak - her seyi zararli bulur."""
    name = "FakeMalicious"
    requires_key = False
    supports = ("ipv4", "domain", "url", "md5", "sha256")

    def _query(self, indicator, ioc_type):
        return ProviderResult(self.name, indicator, found=True, malicious=True,
                              score=90, labels=["TestMalware"],
                              detail="test amacli zararli", link="https://example.invalid")


class FakeClean(Provider):
    name = "FakeClean"
    requires_key = False
    supports = ("ipv4", "domain", "url", "md5", "sha256")

    def _query(self, indicator, ioc_type):
        return ProviderResult(self.name, indicator, found=True, malicious=False,
                              score=0, detail="temiz")


class FakeBroken(Provider):
    name = "FakeBroken"
    requires_key = False
    supports = ("ipv4",)

    def _query(self, indicator, ioc_type):
        raise RuntimeError("baglanti hatasi (test)")


class FakeNeedsKey(Provider):
    name = "FakeNeedsKey"
    requires_key = True
    key_env = "FAKE_KEY"
    supports = ("ipv4",)

    def _query(self, indicator, ioc_type):
        return ProviderResult(self.name, indicator, found=True, score=50)


# --------------------------------------------------------------------------- #
class TestRefangDefang(unittest.TestCase):
    def test_refang_variants(self):
        self.assertEqual(refang("hxxp://evil[.]com"), "http://evil.com")
        self.assertEqual(refang("hxxps://a(.)b[.]com"), "https://a.b.com")
        self.assertEqual(refang("user[at]evil[dot]com"), "user@evil.com")

    def test_defang(self):
        self.assertEqual(defang("http://evil.com"), "hxxp://evil[.]com")


class TestExtract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SAMPLE, encoding="utf-8") as fh:
            cls.data = extract(fh.read())

    def test_ips(self):
        self.assertIn("45.155.205.233", self.data["ipv4"])
        self.assertIn("185.244.25.171", self.data["ipv4"])

    def test_defanged_domains_recovered(self):
        self.assertIn("cdn-telemetry.top", self.data["domain"])
        self.assertIn("turkfatura-online.click", self.data["domain"])

    def test_hashes_classified(self):
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", self.data["md5"])
        self.assertIn(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            self.data["sha256"])
        for value in self.data["md5"]:
            self.assertEqual(len(value), 32)

    def test_cve_and_btc(self):
        self.assertEqual(self.data["cve"], ["CVE-2026-21445"])
        self.assertTrue(self.data["btc"])

    def test_filenames_not_domains(self):
        for value in self.data["domain"]:
            self.assertFalse(value.endswith((".docm", ".exe", ".txt", ".php")),
                             f"{value} alan adi olarak alinmamaliydi")

    def test_private_ips_excluded_by_default(self):
        data = extract("10.0.0.5 ve 192.168.1.1 ve 8.8.8.8")
        self.assertEqual(data["ipv4"], ["8.8.8.8"])
        data = extract("10.0.0.5 ve 8.8.8.8", include_private=True)
        self.assertIn("10.0.0.5", data["ipv4"])

    def test_guess_type(self):
        self.assertEqual(guess_type("8.8.8.8"), "ipv4")
        self.assertEqual(guess_type("evil.top"), "domain")
        self.assertEqual(guess_type("hxxp://evil[.]com/a"), "url")
        self.assertEqual(guess_type("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        self.assertEqual(guess_type("a" * 64), "sha256")
        self.assertEqual(guess_type("CVE-2021-44228"), "cve")
        self.assertEqual(guess_type("!!!"), "unknown")


class TestCache(unittest.TestCase):
    def test_put_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Cache(os.path.join(tmp, "c.sqlite"))
            self.assertIsNone(cache.get("p", "i"))
            cache.put("p", "i", {"a": 1})
            self.assertEqual(cache.get("p", "i"), {"a": 1})
            cache.clear()
            self.assertIsNone(cache.get("p", "i"))
            cache.close()

    def test_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Cache(os.path.join(tmp, "c.sqlite"), ttl=0)
            cache.put("p", "i", {"a": 1})
            self.assertIsNone(cache.get("p", "i"))
            cache.close()

    def test_disabled_cache_is_noop(self):
        cache = Cache(enabled=False)
        cache.put("p", "i", {"a": 1})
        self.assertIsNone(cache.get("p", "i"))


class TestScoring(unittest.TestCase):
    def _item(self, *results):
        return Enriched("x", "ipv4", list(results))

    def test_no_results_is_unknown(self):
        item = self._item()
        self.assertEqual(item.score, 0)
        self.assertEqual(item.verdict, "BILGI YOK")

    def test_single_malicious_source(self):
        item = self._item(ProviderResult("VirusTotal", "x", found=True,
                                         malicious=True, score=90))
        self.assertGreaterEqual(item.score, 75)
        self.assertEqual(item.verdict, "ZARARLI")

    def test_multiple_confirmations_raise_score(self):
        one = self._item(ProviderResult("VirusTotal", "x", True, True, 60))
        two = self._item(ProviderResult("VirusTotal", "x", True, True, 60),
                         ProviderResult("ThreatFox", "x", True, True, 60))
        self.assertGreater(two.score, one.score)

    def test_clean_result_is_temiz(self):
        item = self._item(ProviderResult("GreyNoise", "x", found=True,
                                         malicious=False, score=5))
        self.assertEqual(item.verdict, "TEMIZ")

    def test_errors_ignored_in_scoring(self):
        item = self._item(ProviderResult("Broken", "x", error="down"),
                          ProviderResult("VirusTotal", "x", True, True, 90))
        self.assertEqual(item.verdict, "ZARARLI")


class TestEnricher(unittest.TestCase):
    def test_combines_providers(self):
        enricher = Enricher(providers=[FakeMalicious, FakeClean], cache=None, workers=1)
        item = enricher.enrich_one("8.8.8.8", "ipv4")
        self.assertEqual(len(item.results), 2)
        self.assertIn("TestMalware", item.labels)
        self.assertIn("FakeMalicious", item.sources_hit)

    def test_provider_exception_becomes_error(self):
        enricher = Enricher(providers=[FakeBroken], cache=None, workers=1)
        item = enricher.enrich_one("8.8.8.8", "ipv4")
        self.assertTrue(item.results[0].error)
        self.assertEqual(item.verdict, "BILGI YOK")

    def test_missing_key_is_reported_not_crashed(self):
        enricher = Enricher(providers=[FakeNeedsKey], cache=None, workers=1)
        item = enricher.enrich_one("8.8.8.8", "ipv4")
        self.assertEqual(item.results, [])
        self.assertEqual(len(enricher.skipped_providers), 1)
        self.assertTrue(any("FAKE_KEY" in n for n in item.notes))

    def test_private_ip_skipped(self):
        enricher = Enricher(providers=[FakeMalicious], cache=None, workers=1)
        item = enricher.enrich_one("192.168.1.10", "ipv4")
        self.assertEqual(item.results, [])
        self.assertIn("ozel", item.notes[0])

    def test_offline_mode_makes_no_queries(self):
        enricher = Enricher(providers=[FakeMalicious], cache=None,
                            workers=1, offline=True)
        item = enricher.enrich_one("8.8.8.8", "ipv4")
        self.assertEqual(item.results, [])

    def test_cache_is_used_on_second_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Cache(os.path.join(tmp, "c.sqlite"))
            enricher = Enricher(providers=[FakeMalicious], cache=cache, workers=1)
            first = enricher.enrich_one("1.2.3.4", "ipv4")
            second = enricher.enrich_one("1.2.3.4", "ipv4")
            self.assertFalse(first.results[0].cached)
            self.assertTrue(second.results[0].cached)
            self.assertEqual(first.score, second.score)
            cache.close()

    def test_unsupported_type_is_noted(self):
        enricher = Enricher(providers=[FakeBroken], cache=None, workers=1)
        item = enricher.enrich_one("example.org", "domain")
        self.assertTrue(item.notes)


class TestReports(unittest.TestCase):
    def setUp(self):
        enricher = Enricher(providers=[FakeMalicious], cache=None, workers=1)
        self.items = [enricher.enrich_one("8.8.8.8", "ipv4"),
                      enricher.enrich_one("evil.top", "domain")]

    def test_json_structure(self):
        data = json.loads(to_json(self.items))
        self.assertEqual(data["summary"]["total"], 2)
        self.assertEqual(len(data["indicators"]), 2)
        self.assertIn("verdict", data["indicators"][0])

    def test_markdown_and_html_contain_indicator(self):
        self.assertIn("evil[.]top", to_markdown(self.items))
        self.assertIn("evil[.]top", to_html(self.items))

    def test_csv_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.csv")
            to_csv(self.items, path)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
        self.assertIn("evil.top", content)
        self.assertIn("ZARARLI", content)


class TestCli(unittest.TestCase):
    def test_extract_only(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["-f", SAMPLE, "--extract-only"])
        output = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("45.155.205.233", output)
        self.assertIn("cdn-telemetry.top", output)

    def test_list_providers(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--list-providers"])
        self.assertEqual(code, 0)
        self.assertIn("VirusTotal", buffer.getvalue())

    def test_offline_run(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["8.8.8.8", "--offline", "--no-cache", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("8[.]8[.]8[.]8", buffer.getvalue())

    def test_type_filter(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main(["-f", SAMPLE, "--extract-only", "--types", "cve"])
        self.assertEqual(buffer.getvalue().strip(), "cve\tCVE-2026-21445")


if __name__ == "__main__":
    unittest.main(verbosity=2)
