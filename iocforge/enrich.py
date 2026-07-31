"""IOC'leri saglayicilarla zenginlestirir ve nihai skoru hesaplar."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .cache import Cache
from .extract import defang, guess_type, is_private_ip
from .providers import ALL_PROVIDERS, Provider, ProviderResult

# Kaynak guvenilirligi agirliklari
PROVIDER_WEIGHT = {
    "VirusTotal": 1.0, "AbuseIPDB": 0.9, "URLhaus": 1.0,
    "ThreatFox": 1.0, "AlienVault OTX": 0.8, "GreyNoise": 0.7,
}


@dataclass
class Enriched:
    indicator: str
    ioc_type: str
    results: List[ProviderResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    @property
    def score(self) -> int:
        usable = [r for r in self.results if not r.error and r.found]
        if not usable:
            return 0
        weighted = [(r.score * PROVIDER_WEIGHT.get(r.provider, 0.7), r.score)
                    for r in usable]
        top = max(raw for _w, raw in weighted)
        avg = sum(w for w, _raw in weighted) / len(weighted)
        confirmations = sum(1 for r in usable if r.malicious)
        bonus = min(15, max(0, confirmations - 1) * 8)
        return max(0, min(100, int(top * 0.6 + avg * 0.4 + bonus)))

    @property
    def verdict(self) -> str:
        score = self.score
        if score >= 75:
            return "ZARARLI"
        if score >= 45:
            return "SUPHELI"
        if score >= 15:
            return "DUSUK RISK"
        if any(r.found for r in self.results):
            return "TEMIZ"
        return "BILGI YOK"

    @property
    def labels(self) -> List[str]:
        seen: List[str] = []
        for result in self.results:
            for label in result.labels:
                if label and label not in seen:
                    seen.append(label)
        return seen[:8]

    @property
    def sources_hit(self) -> List[str]:
        return [r.provider for r in self.results if r.found and r.malicious]

    @property
    def defanged(self) -> str:
        return defang(self.indicator) if self.ioc_type in (
            "url", "domain", "ipv4", "ipv6", "email") else self.indicator

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "defanged": self.defanged,
            "type": self.ioc_type,
            "score": self.score,
            "verdict": self.verdict,
            "labels": self.labels,
            "sources_hit": self.sources_hit,
            "notes": self.notes,
            "results": [r.to_dict(include_raw) for r in self.results],
        }


class Enricher:
    def __init__(self, keys: Optional[Dict[str, str]] = None,
                 providers: Optional[List[type]] = None,
                 cache: Optional[Cache] = None,
                 workers: int = 4, offline: bool = False):
        keys = keys or {}
        self.offline = offline
        self.cache = cache
        self.workers = max(1, workers)
        self.providers: List[Provider] = []
        for provider_class in (providers or ALL_PROVIDERS):
            instance = provider_class(keys.get(provider_class.key_env, ""))
            self.providers.append(instance)

    # ------------------------------------------------------------------ #
    @property
    def active_providers(self) -> List[Provider]:
        return [p for p in self.providers if p.ready]

    @property
    def skipped_providers(self) -> List[Provider]:
        return [p for p in self.providers if not p.ready]

    def enrich_one(self, indicator: str, ioc_type: str = "") -> Enriched:
        ioc_type = ioc_type or guess_type(indicator)
        item = Enriched(indicator=indicator, ioc_type=ioc_type)

        if ioc_type in ("ipv4", "ipv6") and is_private_ip(indicator):
            item.notes.append("ozel/ic ag IP adresi - harici sorgu yapilmadi")
            return item
        if ioc_type == "unknown":
            item.notes.append("gosterge turu belirlenemedi")
            return item
        if self.offline:
            item.notes.append("cevrimdisi mod - sadece cikarma yapildi")
            return item

        candidates = [p for p in self.active_providers if p.handles(ioc_type)]
        missing = [p for p in self.skipped_providers if p.handles(ioc_type)]
        if missing:
            item.notes.append(
                "anahtar olmadigi icin atlanan kaynak(lar): "
                + ", ".join(f"{p.name} ({p.key_env})" for p in missing))
        if not candidates:
            item.notes.append(f"'{ioc_type}' turunu sorgulayabilecek aktif kaynak yok")
            return item

        def run(provider: Provider) -> Optional[ProviderResult]:
            if self.cache:
                cached = self.cache.get(provider.name, indicator)
                if cached is not None:
                    result = ProviderResult(**cached)
                    result.cached = True
                    return result
            result = provider.lookup(indicator, ioc_type)
            if result and self.cache and not result.error:
                payload = {
                    "provider": result.provider, "indicator": result.indicator,
                    "found": result.found, "malicious": result.malicious,
                    "score": result.score, "labels": result.labels,
                    "detail": result.detail, "link": result.link, "raw": result.raw,
                }
                self.cache.put(provider.name, indicator, payload)
            return result

        if self.workers > 1 and len(candidates) > 1:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                results = list(pool.map(run, candidates))
        else:
            results = [run(p) for p in candidates]
        item.results = [r for r in results if r is not None]
        return item

    def enrich_many(self, indicators: List[tuple]) -> List[Enriched]:
        """indicators: (deger, tur) demetleri."""
        return [self.enrich_one(value, ioc_type) for value, ioc_type in indicators]
