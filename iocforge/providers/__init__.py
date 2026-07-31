"""Tehdit istihbarati kaynaklari."""
from .abuseipdb import AbuseIPDB
from .base import Provider, ProviderResult
from .greynoise import GreyNoise
from .otx import AlienVaultOTX
from .threatfox import ThreatFox
from .urlhaus import URLhaus
from .virustotal import VirusTotal

ALL_PROVIDERS = [VirusTotal, AbuseIPDB, AlienVaultOTX, URLhaus, ThreatFox, GreyNoise]

# Anahtar gerektirmeyen kaynaklar
FREE_PROVIDERS = [URLhaus, ThreatFox, GreyNoise]

__all__ = ["Provider", "ProviderResult", "VirusTotal", "AbuseIPDB",
           "AlienVaultOTX", "URLhaus", "ThreatFox", "GreyNoise",
           "ALL_PROVIDERS", "FREE_PROVIDERS"]
