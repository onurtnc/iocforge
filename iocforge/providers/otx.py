"""AlienVault OTX - pulse (kampanya) uyelikleri."""
from __future__ import annotations

from ..http import get_json
from .base import Provider, ProviderResult

BASE = "https://otx.alienvault.com/api/v1/indicators"


class AlienVaultOTX(Provider):
    name = "AlienVault OTX"
    requires_key = True
    key_env = "OTX_API_KEY"
    site = "https://otx.alienvault.com"
    supports = ("md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url")
    min_interval = 0.5

    def _path(self, indicator: str, ioc_type: str) -> str:
        mapping = {
            "ipv4": f"IPv4/{indicator}/general",
            "ipv6": f"IPv6/{indicator}/general",
            "domain": f"domain/{indicator}/general",
            "url": f"url/{indicator}/general",
        }
        if ioc_type in mapping:
            return mapping[ioc_type]
        return f"file/{indicator}/general"

    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        data = get_json(f"{BASE}/{self._path(indicator, ioc_type)}",
                        headers={"X-OTX-API-KEY": self.api_key},
                        rate_key="otx", min_interval=self.min_interval)
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = int(pulse_info.get("count", len(pulses)))

        labels: list = []
        for pulse in pulses[:5]:
            if pulse.get("name"):
                labels.append(pulse["name"][:60])
        for tag in (pulse_info.get("references") or [])[:0]:
            labels.append(tag)

        score = min(100, count * 12)
        return ProviderResult(
            provider=self.name, indicator=indicator, found=count > 0,
            malicious=count >= 2, score=score, labels=labels,
            detail=(f"{count} pulse'ta gecikyor" if count else "hicbir pulse'ta yok")
                   .replace("gecikyor", "geciyor"),
            link=f"{self.site}/indicator/"
                 f"{'file' if ioc_type in ('md5', 'sha1', 'sha256') else ioc_type}/{indicator}",
            raw={"pulse_count": count,
                 "country": data.get("country_name"),
                 "asn": data.get("asn")},
        )
