# IOCForge

**Metinden IOC cikarir, alti tehdit istihbarati kaynagiyla zenginlestirir, tek bir skora indirger.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-31%20passing-success)

Bir olay raporu, e-posta ya da log dosyasi verin; IOCForge icindeki IP, alan adi,
URL, hash, CVE ve cuzdan adreslerini bulsun, VirusTotal / AbuseIPDB / OTX /
URLhaus / ThreatFox / GreyNoise uzerinden sorgulasin ve **ZARARLI / SUPHELI /
TEMIZ** kararini gerekcesiyle versin.

`requests` bile gerektirmez — `urllib` ve `sqlite3` ile yazilmistir.

---

## Neden?

Bir olayda 30 tane IOC cikar ve her birini tek tek uc ayri sitede aramak yarim saat
alir. IOCForge bunu tek komuta indirir; ustelik sonuclari **onbellege alir**, ayni
gostergeyi ikinci kez sorgulayip ucretsiz API kotanizi yakmaz.

## Ozellikler

- **Akilli cikarma** — defang edilmis girdileri anlar (`hxxp://evil[.]com`, `user[at]evil[dot]com`)
- **Tur tespiti** — IPv4/IPv6, alan adi, URL, MD5/SHA1/SHA256, e-posta, CVE, Bitcoin adresi
- **Gurultu filtresi** — `rapor.docm`, `script.php` gibi dosya adlarini alan adi sanmaz; ozel IP'leri disari sormaz
- **Alti kaynak** — ucu anahtarsiz calisir, hicbiri zorunlu degil
- **Agirlikli skorlama** — kaynak guvenilirligi + coklu dogrulama bonusu ile 0-100 skor
- **SQLite onbellek** — varsayilan 24 saat, `--cache-ttl` ile ayarlanir
- **Paralel sorgu** — thread havuzu, kaynak basina ayri hiz siniri
- **Dayaniklilik** — bir kaynak coksede digerleri calismaya devam eder
- **Bes cikti formati** — konsol, JSON, CSV, Markdown (ticket'a yapistirmalik), HTML

## Kaynaklar

| Kaynak | Anahtar | Destekledigi turler | Ucretsiz limit |
|---|---|---|---|
| **URLhaus** (abuse.ch) | gerekmez | url, domain, ip, md5, sha256 | serbest |
| **ThreatFox** (abuse.ch) | gerekmez | url, domain, ip, md5, sha256 | serbest |
| **GreyNoise** Community | gerekmez | ipv4 | gunluk sinirli |
| **VirusTotal** v3 | `VT_API_KEY` | hash, ip, domain, url | 4 istek/dk |
| **AbuseIPDB** | `ABUSEIPDB_API_KEY` | ipv4, ipv6 | 1000 sorgu/gun |
| **AlienVault OTX** | `OTX_API_KEY` | hash, ip, domain, url | comert |

Hicbir anahtar tanimlamadan da calisir — o zaman sadece anahtarsiz uc kaynak sorgulanir.

## Kurulum

```bash
git clone https://github.com/<kullanici>/iocforge.git
cd iocforge
python -m iocforge --list-providers
```

Komut olarak eklemek icin: `pip install -e .`

### API anahtarlari

Uc yoldan biriyle verebilirsiniz (oncelik sirasiyla):

```bash
# 1) Ortam degiskeni
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."

# 2) Proje kokunde .env dosyasi
echo 'VT_API_KEY=...' >> .env

# 3) iocforge.json (ornek: iocforge.example.json)
cp iocforge.example.json iocforge.json
```

> `.gitignore` `iocforge.json`, `.env` ve `*.sqlite` dosyalarini disarida birakir.
> Anahtarlarinizi asla commit etmeyin.

## Kullanim

```bash
# Tek gosterge
python -m iocforge 45.155.205.233

# Bir rapordan cikar + zenginlestir
python -m iocforge -f samples/olay_raporu.txt --html rapor.html

# Sadece IOC listesi (sorgu yok) - SIEM'e beslemek icin
python -m iocforge -f log.txt --extract-only

# stdin'den
cat supheli.eml | python -m iocforge -

# Anahtarsiz kaynaklarla hizli tarama
python -m iocforge -f iocs.txt --free-only

# Belirli kaynaklar / turler
python -m iocforge -f rapor.txt --providers VirusTotal,AbuseIPDB --types ipv4,domain

# Ticket'a yapistirmalik Markdown tablo
python -m iocforge -f rapor.txt --markdown bulgular.md

# CI: 75+ skorlu IOC varsa exit 1
python -m iocforge -f iocs.txt --fail-on 75 --quiet
```

### Ornek cikti

```
==============================================================================
  IOCForge - Tehdit Istihbarati Raporu
==============================================================================
  Toplam 18 gosterge  |  ZARARLI: 5  SUPHELI: 2  TEMIZ: 8  BILGI YOK: 3
------------------------------------------------------------------------------
  [ZARARLI] 45[.]155[.]205[.]233
      tur: ipv4   skor: [#########.] 94/100
      etiket: SSH, Brute-Force, Port Scan
      eslesen kaynaklar: AbuseIPDB, VirusTotal, GreyNoise
      ! AbuseIPDB: guven skoru %100, 4821 rapor, ulke: NL, ISP: Alsycon B.V.
      ! VirusTotal: 12/94 motor kotucul, 1 supheli
      ! GreyNoise: siniflandirma: malicious, son goruldu: 2026-07-29

  [TEMIZ] 8[.]8[.]8[.]8
      tur: ipv4   skor: [..........] 5/100
      + GreyNoise: siniflandirma: benign (onbellek)
```

### PhishTriage / NetSentry ile birlikte

```bash
# Phishing mailden cikan IOC'leri dogrudan zenginlestir
python -m phishtriage supheli.eml --iocs | cut -f2 | python -m iocforge -

# PCAP'ten cikan alan adlarini sorgula
python -m netsentry capture.pcap --dns | awk '{print $4}' | python -m iocforge -
```

## Skorlama nasil calisir?

```
skor = en_yuksek_kaynak_skoru * 0.6
     + agirlikli_ortalama      * 0.4
     + coklu_dogrulama_bonusu  (kaynak basina +8, en fazla +15)
```

Kaynak agirliklari (`enrich.py` icinde, degistirilebilir):
VirusTotal 1.0 · URLhaus 1.0 · ThreatFox 1.0 · AbuseIPDB 0.9 · OTX 0.8 · GreyNoise 0.7

| Skor | Karar |
|---|---|
| 75-100 | **ZARARLI** — blokla |
| 45-74 | **SUPHELI** — analist incelemesi |
| 15-44 | **DUSUK RISK** — izle |
| 1-14 | **TEMIZ** |
| kayit yok | **BILGI YOK** |

## Mimari

```
iocforge/
├── extract.py    Regex tabanli IOC cikarma, refang/defang, gurultu filtresi
├── http.py       urllib sarmalayici: hiz siniri, yeniden deneme, hata yonetimi
├── cache.py      SQLite onbellek (TTL'li)
├── config.py     Anahtar yukleme: env > .env > config.json
├── enrich.py     Paralel sorgu, agirlikli skorlama, karar uretimi
├── report.py     Konsol / JSON / CSV / Markdown / HTML
├── cli.py        argparse arayuzu
└── providers/
    ├── base.py         Ortak arayuz (Provider, ProviderResult)
    ├── virustotal.py   abuseipdb.py   otx.py
    └── urlhaus.py      threatfox.py   greynoise.py
```

### Yeni kaynak eklemek

`Provider` sinifindan turetip `_query` yazmaniz yeterli:

```python
from .base import Provider, ProviderResult
from ..http import get_json

class MyFeed(Provider):
    name = "MyFeed"
    requires_key = True
    key_env = "MYFEED_API_KEY"
    supports = ("ipv4", "domain")
    min_interval = 1.0

    def _query(self, indicator, ioc_type):
        data = get_json(f"https://api.myfeed.io/v1/{indicator}",
                        headers={"Authorization": self.api_key},
                        rate_key="myfeed", min_interval=self.min_interval)
        return ProviderResult(
            provider=self.name, indicator=indicator,
            found=bool(data.get("hits")), malicious=data.get("bad", False),
            score=int(data.get("score", 0)), labels=data.get("tags", []),
            detail=f"{data.get('hits', 0)} kayit",
        )
```

Sonra `providers/__init__.py` icindeki `ALL_PROVIDERS` listesine ekleyin.

## Testler

```bash
python -m unittest discover -s tests -v
```

31 testin **hicbiri ag erisimi gerektirmez** — saglayicilar sahte (fake) siniflarla
degistirilir. Bu sayede CI'da API anahtari olmadan da calisir.

## Yol haritasi

- [ ] MISP ve OpenCTI entegrasyonu
- [ ] STIX 2.1 disa aktarimi
- [ ] Pasif DNS (`passivetotal`, `securitytrails`) kaynaklari
- [ ] Toplu dosya yukleme ile VirusTotal tarama
- [ ] `--watch` modu: bir dizini izleyip yeni IOC'leri otomatik sorgulama

## Sorumluluk reddi

Savunma amaclidir. Ucuncu parti API'lerin kullanim sartlarina uyun; sorguladiginiz
gostergelerin bu servislere gonderildigini unutmayin — gizli/hassas IOC'ler icin
kurum politikanizi kontrol edin.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
