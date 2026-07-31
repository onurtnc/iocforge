"""VirusTotal v3 - dosya hash, IP, alan adi ve URL sorgusu."""
from __future__ import annotations

import base64

from ..http import get_json
from .base import Provider, ProviderResult

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(Provider):
    name = "VirusTotal"
    requires_key = True
    key_env = "VT_API_KEY"
    site = "https://www.virustotal.com"
    supports = ("md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url")
    min_interval = 15.0        # ucretsiz anahtar: dakikada 4 istek

    def _endpoint(self, indicator: str, ioc_type: str) -> str:
        if ioc_type in ("md5", "sha1", "sha256"):
            return f"{BASE}/files/{indicator}"
        if ioc_type in ("ipv4", "ipv6"):
            return f"{BASE}/ip_addresses/{indicator}"
        if ioc_type == "domain":
            return f"{BASE}/domains/{indicator}"
        encoded = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        return f"{BASE}/urls/{encoded}"

    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        data = get_json(self._endpoint(indicator, ioc_type),
                        headers={"x-apikey": self.api_key},
                        rate_key="virustotal", min_interval=self.min_interval)
        attributes = (data.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1

        labels = []
        suggested = (attributes.get("popular_threat_classification") or {})
        for item in suggested.get("suggested_threat_label", "") and \
                [suggested["suggested_threat_label"]] or []:
            labels.append(item)
        for entry in (suggested.get("popular_threat_name") or [])[:3]:
            if entry.get("value"):
                labels.append(entry["value"])
        if attributes.get("meaningful_name"):
            labels.append(attributes["meaningful_name"])

        score = min(100, int((malicious + suspicious * 0.5) / total * 140))
        link_type = {"md5": "file", "sha1": "file", "sha256": "file",
                     "ipv4": "ip-address", "ipv6": "ip-address",
                     "domain": "domain", "url": "url"}[ioc_type]
        return ProviderResult(
            provider=self.name, indicator=indicator, found=True,
            malicious=malicious > 0,
            score=score,
            labels=labels[:5],
            detail=f"{malicious}/{total} motor kotucul, {suspicious} supheli",
            link=f"{self.site}/gui/{link_type}/{indicator}",
            raw={"stats": stats, "reputation": attributes.get("reputation")},
        )
