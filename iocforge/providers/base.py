"""Tum saglayicilarin uydugu ortak arayuz."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProviderResult:
    """Bir kaynagin tek bir IOC hakkinda sagladigi normalize edilmis bilgi."""
    provider: str
    indicator: str
    found: bool = False
    malicious: bool = False
    score: int = 0                       # 0-100, kaynagin kotucullik kanaati
    labels: List[str] = field(default_factory=list)   # aile/kampanya/etiket
    detail: str = ""
    link: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    cached: bool = False

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        data = {
            "provider": self.provider, "found": self.found,
            "malicious": self.malicious, "score": self.score,
            "labels": self.labels, "detail": self.detail, "link": self.link,
            "cached": self.cached,
        }
        if self.error:
            data["error"] = self.error
        if include_raw:
            data["raw"] = self.raw
        return data


class Provider:
    """Alt siniflar `name`, `supports` ve `_query` tanimlar."""

    name = "base"
    requires_key = False
    key_env = ""
    site = ""
    supports: tuple = ()
    min_interval = 0.0          # ardisik istekler arasi minimum saniye

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or ""

    # ------------------------------------------------------------------ #
    @property
    def ready(self) -> bool:
        return not self.requires_key or bool(self.api_key)

    def handles(self, ioc_type: str) -> bool:
        return ioc_type in self.supports

    def lookup(self, indicator: str, ioc_type: str) -> Optional[ProviderResult]:
        if not self.handles(ioc_type):
            return None
        if not self.ready:
            return ProviderResult(self.name, indicator,
                                  error=f"{self.key_env} tanimli degil")
        try:
            return self._query(indicator, ioc_type)
        except Exception as exc:                     # ag/parse hatasi akisi bozmasin
            return ProviderResult(self.name, indicator, error=str(exc))

    # ------------------------------------------------------------------ #
    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        raise NotImplementedError
