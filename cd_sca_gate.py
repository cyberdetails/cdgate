#!/usr/bin/env python3
"""CyberDetails SCA gate — tarayici raporunu istismar kanitina gore pass/fail'e cevirir.

    trivy fs --scanners vuln --format json --output trivy.json .
    python cd_sca_gate.py trivy.json                 # varsayilan: KEV/aktif somuru engeller
    python cd_sca_gate.py trivy.json --block-at high --json-out triage.json

Trivy (ya da Grype) "su paketin su surumunde su CVE var" der; bu arac her CVE
icin CyberDetails'e sorar: CISA/VulnCheck KEV'de mi, aktif somuruluyor mu,
Metasploit/Nuclei modulu var mi, EPSS ne diyor. Politika engellenmesi
gerekeni secer, gerisi rapor olur.

NE GONDERILIR
Yalnizca CVE kimlikleri. Paket adi, surum, dosya yolu, repo ya da imaj adi
bu makineden CIKMAZ; CVE'ler paketlerle burada, yerelde eslestirilir. CVE'si
olmayan bulgular (GHSA-..., GO-...) gonderilmez, "no_cve" olarak raporlanir.

CIKIS KODLARI — uc ayri durum, karistirilmaz
    0  politika gecti
    1  politika en az bir bulguyu engelledi
    2  arac calisamadi (rapor okunamadi, API erisilemedi/hata verdi)
"API'ye ulasilamadi" ile "temiz" ayni kodu dondurseydi, kopuk bir ag her
build'i yesil gosterirdi. Bilerek gecirmek istiyorsan `|| [ $? -eq 2 ]`.

BUILD KIRILDI, SIMDI NE? (0.2.0)
  * FIX PLAN: tarayicinin duzeltme surumlerinden paket bazinda yukseltme
    listesi — "su 3 paketi yukselt, engellenen her sey kapanir" — ve isletim
    sistemi paketleri icin yapistirilabilir `apt-get` / `apk` satiri. Yerelde
    hesaplanir; paket bilgisi yine makineden cikmaz.
  * Engellenen CVE'nin hazir SIEM sorgulari (Sigma, Splunk, Sentinel, Elastic,
    YARA-L) ve, duzeltme yoksa, modelin yazdigi gecici onlemler ("AI-written,
    verify" etiketiyle).
  * Trivy isletim sisteminin destegi bittiyse (EOSL) bunu soyler: o imaj
    artik duzeltme almaz, yukseltme degil yeniden taban imaj gerekir.

Bagimlilik yok (Python 3.8+ standart kutuphane).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

__version__ = "0.2.0"

VARSAYILAN_API = "https://cyberdetails.org"
UC = "/api/v1/sca/triage"
USER_AGENT = f"CyberDetails-SCA-Gate/{__version__} (+https://cyberdetails.org)"
PARCA = 1000          # sunucunun istek basina CVE tavani (models/sca.py)
ZAMAN_ASIMI = 30
MAX_DENEME = 3
MAX_BEKLEME = 30
MAX_RAPOR_BAYT = 200 * 1024 * 1024

# re.ASCII: Python'da `\d` Unicode rakamlarini da (٢٠٢١) kabul ediyor.
CVE_DESEN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE | re.ASCII)
#: Sunucunun dondurdugu link yalnizca sitenin kendi sayfasina gidebilir
#: (`/cve/CVE-...` kanonik sayfa, `/exploit/<slug>` kayit); baska bir URL
#: CI loguna tiklanabilir link olarak yazilmaz.
SAYFA_YOLU = re.compile(r"^/(cve/CVE-\d{4}-\d{4,7}|exploit/[A-Za-z0-9._-]{1,300}(/pack\.zip)?)$", re.ASCII)

#: Sunucunun bildirebilecegi sorgu bicimleri -> insan adi. Bilinmeyen atlanir.
BICIM_ADLARI = {"sigma": "Sigma", "splunk_spl": "Splunk SPL", "sentinel_kql": "Sentinel KQL",
                "elastic_eql": "Elastic EQL", "google_secops_yaral": "YARA-L"}
#: Isletim sistemi paketi turleri (Grype `artifact.type`). Trivy `Class` ile soyluyor.
OS_TURLERI = {"deb", "apk", "rpm", "alpm", "portage"}
#: Paket turu -> yapistirilabilir yukseltme komutu (yalnizca guvenle bilinenler).
YONETICI = {"debian": "apt", "ubuntu": "apt", "deb": "apt",
            "alpine": "apk", "wolfi": "apk", "chainguard": "apk", "apk": "apk"}
#: Yapistirilabilir komuta girecek paket adi: Debian Policy 5.6.1 (kucuk harf,
#: rakam, + - .; harf/rakamla baslar) ve apk adlari (buyuk harf ve _ da var).
#: Rapor bir PR'in icerigini tarar; uymayan ad komuta HIC girmez (kabuk enjeksiyonu).
KOMUT_ADI = {"apt": re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,127}$", re.ASCII),
             "apk": re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._\-]{0,127}$", re.ASCII)}

CIKIS_GECTI, CIKIS_ENGEL, CIKIS_HATA = 0, 1, 2


class AracHatasi(Exception):
    """Exit 2: araç işini yapamadı."""


# --------------------------------------------------------------------------
# Rapor okuma
# --------------------------------------------------------------------------

def _rapor_metni(v: Any, n: int) -> str:
    """Rapor alani -> CI loguna ve JSON'a yazilabilir metin. Tarayici bir PR'in
    lockfile'ini okur: surum ya da yol alaninda ANSI kacisi / bidi karakteri
    olabilir. Kontrol (Cc), bicim (Cf) ve satir/paragraf ayiricilari (Zl, Zp)
    atilir, sekme ve satir sonu bosluk olur; sonra n karaktere kesilir."""
    t = str(v or "")
    t = "".join(" " if ch in "\t\n\r" else ch for ch in t
                if ch in "\t\n\r" or unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp"))
    return t[:n]


def _bulgu(kimlik: Any, paket: Any, surum: Any, duzeltme: Any, hedef: Any,
           kaynak_onem: Any, cve: Optional[str], tur: Any = None,
           os_paketi: bool = False) -> Dict[str, Any]:
    return {
        "pkg_type": _rapor_metni(tur, 40),
        "os_package": bool(os_paketi),
        "id": _rapor_metni(kimlik, 80),
        "cve": cve,
        "package": _rapor_metni(paket, 200),
        "installed": _rapor_metni(surum, 80),
        "fixed": _rapor_metni(duzeltme, 200),
        "target": _rapor_metni(hedef, 300),
        "scanner_severity": _rapor_metni(kaynak_onem, 20),
    }


def _cve_mi(v: Any) -> Optional[str]:
    s = str(v or "").strip().upper()
    return s if CVE_DESEN.match(s) else None


def trivy_bulgulari(rapor: Dict[str, Any]) -> List[Dict[str, Any]]:
    """`trivy ... --format json` -> bulgular. Results[].Vulnerabilities[]."""
    out: List[Dict[str, Any]] = []
    for sonuc in rapor.get("Results") or []:
        if not isinstance(sonuc, dict):
            continue
        for v in sonuc.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            kimlik = v.get("VulnerabilityID")
            cve = _cve_mi(kimlik)
            if cve is None:
                # Trivy CVE'yi bazen yalnizca referanslarda tasiyor (GHSA kimligi).
                for ek in v.get("VendorIDs") or []:
                    cve = _cve_mi(ek)
                    if cve:
                        break
            out.append(_bulgu(kimlik, v.get("PkgName"), v.get("InstalledVersion"),
                              v.get("FixedVersion"), sonuc.get("Target"), v.get("Severity"), cve,
                              sonuc.get("Type"), sonuc.get("Class") == "os-pkgs"))
    return out


def grype_bulgulari(rapor: Dict[str, Any]) -> List[Dict[str, Any]]:
    """`grype ... -o json` -> bulgular. matches[] (GHSA ise relatedVulnerabilities'ten CVE)."""
    out: List[Dict[str, Any]] = []
    for m in rapor.get("matches") or []:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        kimlik = vuln.get("id")
        cve = _cve_mi(kimlik)
        if cve is None:
            for r in m.get("relatedVulnerabilities") or []:
                cve = _cve_mi((r or {}).get("id"))
                if cve:
                    break
        duzeltme = ", ".join(str(x) for x in ((vuln.get("fix") or {}).get("versions") or [])[:5])
        konum = ""
        for loc in art.get("locations") or []:
            konum = (loc or {}).get("path") or ""
            if konum:
                break
        out.append(_bulgu(kimlik, art.get("name"), art.get("version"), duzeltme, konum,
                          vuln.get("severity"), cve, art.get("type"),
                          str(art.get("type") or "") in OS_TURLERI))
    return out


def rapor_meta(rapor: Dict[str, Any]) -> Dict[str, Any]:
    """Taranan isletim sistemi ve destegi bitmis mi (yalnizca Trivy soyluyor)."""
    os_ = (rapor.get("Metadata") or {}).get("OS") if isinstance(rapor.get("Metadata"), dict) else None
    if isinstance(os_, dict) and os_.get("Family"):
        return {"os": _rapor_metni(f"{os_.get('Family')} {os_.get('Name') or ''}".strip(), 60),
                "eosl": os_.get("EOSL") is True}
    d = rapor.get("distro")
    if isinstance(d, dict) and d.get("name"):
        return {"os": _rapor_metni(f"{d.get('name')} {d.get('version') or ''}".strip(), 60), "eosl": None}
    return {"os": None, "eosl": None}


def rapor_oku(yol: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Dosya ya da '-' (stdin). Bicim kendiliginden: Trivy `Results`, Grype `matches`."""
    arac, bulgular, _ = rapor_oku_tam(yol)
    return arac, bulgular


def rapor_oku_tam(yol: str) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """`rapor_oku` + rapor meta verisi (isletim sistemi, EOSL)."""
    try:
        if yol == "-":
            ham = sys.stdin.buffer.read(MAX_RAPOR_BAYT + 1)
        else:
            with open(yol, "rb") as f:
                ham = f.read(MAX_RAPOR_BAYT + 1)
    except OSError as exc:
        raise AracHatasi(f"cannot read report: {exc}") from None
    if len(ham) > MAX_RAPOR_BAYT:
        raise AracHatasi("report is larger than 200 MB")
    try:
        rapor = json.loads(ham.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AracHatasi(f"report is not valid JSON: {exc}") from None
    if not isinstance(rapor, dict):
        raise AracHatasi("report must be a JSON object (Trivy or Grype JSON output)")
    if "matches" in rapor:
        return "grype", grype_bulgulari(rapor), rapor_meta(rapor)
    if "Results" in rapor or "SchemaVersion" in rapor:
        return "trivy", trivy_bulgulari(rapor), rapor_meta(rapor)
    raise AracHatasi("unrecognised report: expected Trivy JSON (`--format json`) "
                     "or Grype JSON (`-o json`)")


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

def api_dogrula(api: str) -> str:
    """HTTPS zorunlu; yalnizca loopback'e duz HTTP (yerel gelistirme)."""
    p = urlsplit(api)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise AracHatasi("--api must be an http(s) URL")
    if p.scheme == "http":
        host = p.hostname
        try:
            yerel = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            yerel = False
        if not yerel:
            raise AracHatasi("--api must use https (plain http only for localhost)")
    if p.username or p.password:
        raise AracHatasi("--api must not contain credentials")
    return f"{p.scheme}://{p.netloc}{p.path.rstrip('/')}"


def basliklar() -> Dict[str, str]:
    """Istek basliklari. CD_API_KEY (istege bagli, e-postayla ucretsiz) daha
    yuksek saatlik sinir verir; anahtar hicbir ciktiya yazilmaz."""
    h = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT}
    anahtar = os.environ.get("CD_API_KEY", "").strip()
    if anahtar:
        if len(anahtar) > 200 or any(ord(c) < 0x21 or ord(c) > 0x7e for c in anahtar):
            raise AracHatasi("CD_API_KEY is not a valid key (value not shown)")
        h["CD-API-KEY"] = anahtar
    return h


def _gonder(url: str, govde: Dict[str, Any]) -> Dict[str, Any]:
    veri = json.dumps(govde).encode("utf-8")
    h = basliklar()
    for deneme in range(1, MAX_DENEME + 1):
        istek = urllib.request.Request(url, data=veri, method="POST", headers=h)
        try:
            with urllib.request.urlopen(istek, timeout=ZAMAN_ASIMI) as yanit:
                return json.loads(yanit.read(20 * 1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503, 504) and deneme < MAX_DENEME:
                try:
                    bekle = int(exc.headers.get("Retry-After") or 0)
                except ValueError:
                    bekle = 0
                time.sleep(min(max(bekle, 2 ** deneme), MAX_BEKLEME))
                continue
            try:
                detay = json.loads(exc.read(4096).decode("utf-8", "replace")).get("detail")
            except Exception:  # noqa: BLE001 — govde JSON olmayabilir; kod yeter
                detay = None
            raise AracHatasi(f"CyberDetails API returned HTTP {exc.code}"
                             + (f": {str(detay)[:300]}" if detay else "")) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if deneme < MAX_DENEME:
                time.sleep(2 ** deneme)
                continue
            raise AracHatasi(f"cannot reach CyberDetails API: {exc}") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AracHatasi("CyberDetails API returned a non-JSON response") from None
    raise AracHatasi("CyberDetails API did not answer")


def triyaj(api: str, cveler: List[str], block_at: str, block_unknown: bool,
           gonder=_gonder) -> Dict[str, Dict[str, Any]]:
    """CVE -> sunucu satiri. 1000'lik parcalar halinde."""
    url = api + UC
    out: Dict[str, Dict[str, Any]] = {}
    for i in range(0, len(cveler), PARCA):
        yanit = gonder(url, {"cves": cveler[i:i + PARCA], "block_at": block_at,
                             "block_unknown": block_unknown})
        satirlar = yanit.get("items") if isinstance(yanit, dict) else None
        if not isinstance(satirlar, list):
            raise AracHatasi("CyberDetails API response has no items")
        for s in satirlar:
            if isinstance(s, dict) and s.get("cve"):
                out[str(s["cve"]).upper()] = s
    eksik = [c for c in cveler if c not in out]
    if eksik:
        # Sunucu her CVE icin bir satir dondurur; eksik satir sessizce "gecti" olmasin.
        raise AracHatasi(f"CyberDetails API omitted {len(eksik)} CVE(s) from its answer")
    return out


def _duz_metin(v: Any, n: int = 200) -> Optional[str]:
    """Sunucu metni -> CI loguna basilabilir tek satir. Kontrol karakterleri
    (ANSI kacislari) ve bicim karakterleri (bidi yonlendirmeleri) atilir: gecici
    onlemler model metni, kaynagi kazinmis icerik. Sunucu da temizliyor; bu
    ikinci kat."""
    if not isinstance(v, str):
        return None
    t = "".join(" " if ch in "\t\n\r" else ch for ch in v
                if unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp") or ch in "\t\n\r")
    t = " ".join(t.split())
    if not t:
        return None
    return t if len(t) <= n else t[: n - 1].rstrip() + "…"


def _onlem(m: Any, api: str) -> Optional[Dict[str, Any]]:
    """Sunucunun `mitigation` blogu -> dogrulanmis linkler + temiz metin."""
    if not isinstance(m, dict):
        return None
    tespit = None
    det = m.get("detection")
    if isinstance(det, dict):
        yol, paket = det.get("path"), det.get("pack_path")
        bicim = [b for b in (det.get("formats") or []) if b in BICIM_ADLARI]
        if isinstance(yol, str) and SAYFA_YOLU.match(yol) and bicim:
            tespit = {"url": api + yol, "formats": bicim,
                      "pack_url": (api + paket) if isinstance(paket, str)
                      and SAYFA_YOLU.match(paket) else None}
    gecici = [t for t in (_duz_metin(w) for w in (m.get("workarounds") or [])[:3]) if t]
    return {"detection": tespit, "workarounds": gecici, "workarounds_ai_generated": bool(gecici)}


# --------------------------------------------------------------------------
# Surum karsilastirma — duzeltme plani icin
# --------------------------------------------------------------------------
# Karsilastirilamayan iki surum None doner ve plan o paketi "belirsiz" diye
# adaylarla birlikte gosterir: yanlis bir "su surume yukselt" demektense
# "su ikisinden biri, kontrol et" demek.

# dpkg C yerel ayariyla calisir: rakam ve harf yalnizca ASCII, karsilastirma
# bayt bayt (lib/dpkg/version.c `c_isdigit`/`c_isalpha`). `str.isdigit()`
# '²' gibi karakterlere de True diyordu ve `int('²')` istisnaya, istisna da
# cikis 1'e ("engellendi") donusuyordu (2026-11-18, Go portu sirasinda bulundu).
_RAKAM = frozenset(b"0123456789")
_HARF = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _ascii_sayi(s: str) -> bool:
    return bool(s) and all("0" <= ch <= "9" for ch in s)


def _deb_sira(a: bytes, i: int) -> int:
    if i >= len(a) or a[i] in _RAKAM:
        return 0
    c = a[i]
    if c == 0x7E:  # ~
        return -1
    if c in _HARF:
        return c
    return c + 256


def _verrevcmp(sa: str, sb: str) -> int:
    """dpkg'nin `verrevcmp`'i birebir (lib/dpkg/version.c), UTF-8 baytlari uzerinde."""
    a, b = sa.encode("utf-8", "surrogatepass"), sb.encode("utf-8", "surrogatepass")
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and a[i] not in _RAKAM) or (j < len(b) and b[j] not in _RAKAM):
            ac, bc = _deb_sira(a, i), _deb_sira(b, j)
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == 0x30:
            i += 1
        while j < len(b) and b[j] == 0x30:
            j += 1
        fark = 0
        while i < len(a) and a[i] in _RAKAM and j < len(b) and b[j] in _RAKAM:
            if not fark:
                fark = a[i] - b[j]
            i += 1
            j += 1
        if i < len(a) and a[i] in _RAKAM:
            return 1
        if j < len(b) and b[j] in _RAKAM:
            return -1
        if fark:
            return -1 if fark < 0 else 1
    return 0


def _deb_ayir(v: str) -> Tuple[Optional[int], str, str]:
    epoch: Optional[int] = None
    if ":" in v:
        e, v = v.split(":", 1)
        if not _ascii_sayi(e):
            raise ValueError(v)
        epoch = int(e)
    u, r = v.rsplit("-", 1) if "-" in v else (v, "")
    if not u or not ("0" <= u[0] <= "9"):
        raise ValueError(v)
    return epoch, u, r


def os_karsilastir(a: str, b: str) -> Optional[int]:
    """Dagitim paketi surumu (dpkg kurali; rpm ve apk icin de yeterince yakin).
    Epoch yalnizca iki tarafta da yaziliysa karsilastirilir: Trivy Debian'da
    duzeltmeyi KAYNAK paketin surumuyle (epoch'suz) veriyor, ikili paket epoch
    tasiyabiliyor (bsdutils `1:2.36.1-8+deb11u1`, duzeltme `2.36.1-8+deb11u2`)."""
    try:
        ea, ua, ra = _deb_ayir(a.strip())
        eb, ub, rb = _deb_ayir(b.strip())
    except ValueError:
        return None
    if ea is not None and eb is not None and ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def _dil_parcalari(v: str) -> Optional[List[int]]:
    v = v.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    # Maven: RELEASE / Final / GA "son ek yok" demek (5.2.20.RELEASE == 5.2.20).
    v = re.sub(r"(?i)[.\-](release|final|ga)$", "", v)
    parca = re.split(r"[.\-_]", v)
    if not v or not all(_ascii_sayi(p) for p in parca):
        return None
    return [int(p) for p in parca]


def dil_karsilastir(a: str, b: str) -> Optional[int]:
    """Uygulama paketi surumu: yalnizca rakam parcalari (1.2.3, 2.9.10.1).
    Harfli surumler (rc1, .RELEASE, post1) ekosisteme gore farkli siralanir;
    tahmin etmiyoruz."""
    pa, pb = _dil_parcalari(a), _dil_parcalari(b)
    if pa is None or pb is None:
        return None
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def surum_karsilastir(a: str, b: str, os_paketi: bool) -> Optional[int]:
    return os_karsilastir(a, b) if os_paketi else dil_karsilastir(a, b)


def _en_buyuk(surumler: List[str], os_paketi: bool) -> Optional[str]:
    if not surumler:
        return None
    en = surumler[0]
    for s in surumler[1:]:
        c = surum_karsilastir(s, en, os_paketi)
        if c is None:
            return None
        if c > 0:
            en = s
    return en


def aday_sec(kurulu: str, duzeltme: str, os_paketi: bool) -> Tuple[Optional[str], List[str]]:
    """Tarayicinin duzeltme alanindan (virgullu dal listesi olabilir: Maven
    `2.9.10, 2.8.11.5, 2.6.7.3`) kurulu surumden buyuk EN KUCUK aday — ayni
    dalda kalan en kucuk yukseltme. Karsilastirilamazsa (None, adaylar)."""
    # npm danismanliklari `>=4.6.0` yaziyor: "4.6.0'da duzeldi".
    adaylar = [re.sub(r"^(>=|=)\s*", "", x.strip()) for x in duzeltme.split(",") if x.strip()]
    adaylar = [a for a in adaylar if a]
    dil_kurulu = not os_paketi and _dil_parcalari(kurulu) is not None
    buyuk = []
    for a in adaylar:
        c = surum_karsilastir(a, kurulu, os_paketi)
        if c is None:
            if dil_kurulu:
                # Kurulu surum duz rakamli; karsilastirilamayan aday baska bir
                # dalin on surumu (`5.0.0-beta.3`). Beta'ya yukselt demeyiz.
                continue
            return None, adaylar
        if c > 0:
            buyuk.append(a)
    if not buyuk:
        return None, adaylar
    en = buyuk[0]
    for a in buyuk[1:]:
        if (surum_karsilastir(a, en, os_paketi) or 0) < 0:
            en = a
    return en, adaylar


# --------------------------------------------------------------------------
# Duzeltme plani
# --------------------------------------------------------------------------

KADEME_SIRA = {"blocked": 0, "high": 1, "other": 2}


def duzeltme_plani(sonuclar: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Bulgular -> paket bazinda yukseltme listesi.

    Paket = (hedef, ad, kurulu surum, tur). Hedef surum: o paketin engellenen ve
    yuksek sinyalli bulgularini kapatan en kucuk surum (`upgrade_to`); paketin
    listelenen BUTUN duzeltmeleri icin ayrica `upgrade_to_all`. Ayni kaynaktan
    gelen ikili paketler (libc6 + libc-bin: ayni kurulu surum, ayni hedef, ayni
    CVE'ler) tek satirda birlesir."""
    paketler: Dict[Tuple[str, str, str, str, bool], Dict[str, Any]] = {}
    for r in sonuclar:
        anahtar = (r.get("target", ""), r["package"], r["installed"], r.get("pkg_type", ""),
                   bool(r.get("os_package")))
        p = paketler.setdefault(anahtar, {"duzelir": {}, "duzelmez": set()})
        kimlik = r["cve"] or r["id"]
        onemli = r["blocked"] or r["urgency"] in ("known_exploited", "high")
        kademe = "blocked" if r["blocked"] else ("high" if onemli else "other")
        if r["fixed"]:
            secim, adaylar = aday_sec(r["installed"], r["fixed"], bool(r.get("os_package")))
            eski = p["duzelir"].get(kimlik)
            if eski is None or KADEME_SIRA[kademe] < KADEME_SIRA[eski["kademe"]]:
                p["duzelir"][kimlik] = {"kademe": kademe, "secim": secim, "adaylar": adaylar}
        else:
            p["duzelmez"].add(kimlik)

    satirlar: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for (hedef, ad, kurulu, tur, os_), p in paketler.items():
        if not p["duzelir"]:
            continue
        d = p["duzelir"]
        onemli = [k for k, v in d.items() if v["kademe"] != "other"]
        kume = onemli or list(d)

        def hedef_surum(anahtarlar: List[str]) -> Optional[str]:
            secimler = [d[k]["secim"] for k in anahtarlar]
            if any(x is None for x in secimler):
                return None
            return _en_buyuk(secimler, os_)

        yukselt = hedef_surum(kume)
        hepsi = hedef_surum(list(d))
        adaylar = sorted({a for k in kume for a in d[k]["adaylar"]}) if yukselt is None else []
        engel = sorted(k for k, v in d.items() if v["kademe"] == "blocked")
        yuksek = sorted(k for k, v in d.items() if v["kademe"] == "high")
        kademe = "blocked" if engel else ("high" if yuksek else "other")
        anahtar = (hedef, kurulu, tur, os_, yukselt, hepsi, tuple(adaylar),
                   tuple(sorted(d)), tuple(sorted(p["duzelmez"])))
        satir = satirlar.get(anahtar)
        if satir:
            satir["packages"].append(ad)
            continue
        satirlar[anahtar] = {
            "packages": [ad], "pkg_type": tur, "os_package": os_, "target": hedef,
            "installed": kurulu, "upgrade_to": yukselt,
            "upgrade_to_all": hepsi if hepsi != yukselt else None,
            "candidates": adaylar, "tier": kademe,
            "blocked_cves": engel, "high_cves": yuksek,
            "other_fixable": len(d) - len(engel) - len(yuksek),
            "unfixed": len(p["duzelmez"]),
        }
    plan = sorted(satirlar.values(), key=lambda x: (
        KADEME_SIRA[x["tier"]], -len(x["blocked_cves"]), -len(x["high_cves"]),
        -x["other_fixable"], x["packages"][0]))

    # Engellenen CVE'ler: hangileri planla kapaniyor, hangisinin bir paketi
    # icin henuz duzeltme yok.
    engellenen = {r["cve"] or r["id"] for r in sonuclar if r["blocked"]}
    kapanan = {k for x in plan for k in x["blocked_cves"]}
    duzeltmesiz = sorted({r["cve"] or r["id"] for r in sonuclar if r["blocked"] and not r["fixed"]})

    def komut(kademeler: Tuple[str, ...]) -> List[str]:
        gruplar: Dict[str, List[str]] = {}
        for x in plan:
            yon = YONETICI.get(x["pkg_type"]) if x["os_package"] else None
            if yon and x["tier"] in kademeler and x["upgrade_to"]:
                for ad in x["packages"]:
                    if KOMUT_ADI[yon].match(ad) and ad not in gruplar.setdefault(yon, []):
                        gruplar[yon].append(ad)
        out = []
        for yon, adlar in gruplar.items():
            if yon == "apt":
                out.append("apt-get update && apt-get install -y --only-upgrade " + " ".join(adlar))
            elif yon == "apk":
                out.append("apk add --no-cache --upgrade " + " ".join(adlar))
        return out

    return {
        "entries": plan,
        "blocked_cves": len(engellenen),
        "blocked_cves_fixable": len(kapanan),
        "blocked_without_fix": duzeltmesiz,
        "commands": {"blocked": komut(("blocked",)), "blocked_and_high": komut(("blocked", "high"))},
    }


# --------------------------------------------------------------------------
# Birlestirme ve cikti
# --------------------------------------------------------------------------

SIRA = {"known_exploited": 0, "high": 1, "standard": 2, "not_in_database": 3, "no_cve": 4}


def birlestir(bulgular: List[Dict[str, Any]], satirlar: Dict[str, Dict[str, Any]],
              api: str) -> List[Dict[str, Any]]:
    """Yerel bulgu + sunucu karari. CVE'siz bulgu 'no_cve', engellemez."""
    out = []
    for b in bulgular:
        s = satirlar.get(b["cve"]) if b["cve"] else None
        if s is None:
            out.append({**b, "urgency": "no_cve", "blocked": False,
                        "reasons": ["No CVE identifier; not triaged by CyberDetails."],
                        "url": None, "signals": None, "mitigation": None})
            continue
        yol = s.get("path")
        out.append({**b, "urgency": s.get("urgency"), "blocked": bool(s.get("blocked")),
                    "reasons": [t for t in (_duz_metin(x, 300) for x in (s.get("reasons") or [])[:10])
                                if t],
                    "url": (api + yol) if isinstance(yol, str) and SAYFA_YOLU.match(yol) else None,
                    "signals": s.get("signals"),
                    "mitigation": _onlem(s.get("mitigation"), api)})
    out.sort(key=lambda r: (not r["blocked"], SIRA.get(r["urgency"], 9), r["cve"] or r["id"],
                            r["package"]))
    return out


def _kisa(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


ETIKET = {"known_exploited": "known exploited", "high": "high", "standard": "standard",
          "not_in_database": "not in archive", "no_cve": "without CVE"}
#: REVIEW bolumunde gosterilen azami satir; tamami --json-out'ta.
MAX_INCELE = 10


def _cve_gruplari(liste: List[Dict[str, Any]]) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Ayni CVE'nin bulgulari tek grupta. Dagitim imajinda tek kaynak paket
    birden cok ikili paket uretir (libc-bin + libc6, libssl1.1 + openssl);
    paket basina satir ayni CVE'yi tekrar tekrar gosteriyordu."""
    gruplar: Dict[str, List[Dict[str, Any]]] = {}
    for r in liste:
        gruplar.setdefault(r["cve"] or r["id"], []).append(r)
    return list(gruplar.items())


def _grup_satirlari(kimlik: str, grup: List[Dict[str, Any]], onlem: bool = True) -> List[str]:
    r = grup[0]
    neden = r["reasons"][0] if r["reasons"] else ""
    out = [f"  {kimlik:<17} {_kisa(neden, 96)}"]
    surumler: Dict[Tuple[str, str], List[str]] = {}
    for b in grup:
        surumler.setdefault((b["installed"], b["fixed"]), [])
        if b["package"] not in surumler[(b["installed"], b["fixed"])]:
            surumler[(b["installed"], b["fixed"])].append(b["package"])
    for (kurulu, fix), paketler in surumler.items():
        adlar = ", ".join(paketler[:4]) + (f" +{len(paketler) - 4}" if len(paketler) > 4 else "")
        hedef = f"-> {fix}" if fix else "(no fix listed)"
        out.append(f"      {_kisa(adlar, 70)} {_kisa(kurulu, 30)} {_kisa(hedef, 50)}")
    if r["url"]:
        out.append(f"      {r['url']}")
    m = r.get("mitigation") or {}
    det = m.get("detection") if onlem else None
    if det:
        adlar = ", ".join(BICIM_ADLARI[b] for b in det["formats"])
        out.append(f"      detect: SIEM queries ({adlar}) {det['url']}")
    # Gecici onlem yalnizca engellenen ve HICBIR paketi icin duzeltme olmayan
    # CVE'de: duzeltme varken asil cevap yukseltmedir.
    if onlem and r["blocked"] and m.get("workarounds") and not any(b["fixed"] for b in grup):
        out.append("      no fixed version yet; if you cannot patch (AI-written, verify):")
        for w in m["workarounds"]:
            out.append(f"        - {_kisa(w, 110)}")
    return out


#: FIX PLAN'in "sonraki" kademesinde gosterilen azami satir.
MAX_PLAN = 5


def _plan_satiri(x: Dict[str, Any]) -> str:
    adlar = ", ".join(x["packages"][:3]) + (f" +{len(x['packages']) - 3}" if len(x["packages"]) > 3 else "")
    if not x["os_package"] and x["target"]:
        adlar += f" ({x['target']})"
    if x["upgrade_to"]:
        hedef = f"-> {x['upgrade_to']}"
        if x["upgrade_to_all"]:
            hedef += f" (all listed fixes: {x['upgrade_to_all']})"
    else:
        hedef = "-> one of " + ", ".join(x["candidates"][:4]) + " (check)"
    parca = []
    if x["blocked_cves"]:
        parca.append(f"{len(x['blocked_cves'])} blocked")
    if x["high_cves"]:
        parca.append(f"{len(x['high_cves'])} high")
    if x["other_fixable"]:
        parca.append(f"+{x['other_fixable']} other")
    return f"  {_kisa(adlar, 46):<46} {_kisa(x['installed'], 26)} {_kisa(hedef, 60)}   {', '.join(parca)}"


def plan_metni(plan: Dict[str, Any]) -> List[str]:
    satir: List[str] = []
    girdiler = plan["entries"]
    engel = [x for x in girdiler if x["tier"] == "blocked"]
    yuksek = [x for x in girdiler if x["tier"] == "high"]
    diger = [x for x in girdiler if x["tier"] == "other"]
    if engel:
        n, k = plan["blocked_cves"], plan["blocked_cves_fixable"]
        bas = (f"FIX PLAN — {len(engel)} upgrade(s) clear all {n} blocked CVE(s)" if k >= n else
               f"FIX PLAN — {len(engel)} upgrade(s) clear {k} of {n} blocked CVE(s)")
        satir.append(bas)
        satir.extend(_plan_satiri(x) for x in engel)
        for c in plan["commands"]["blocked"]:
            satir.append(f"  run: {c}")
    if plan["blocked_without_fix"]:
        satir.append(f"  {len(plan['blocked_without_fix'])} blocked CVE(s) have a package with no fixed "
                     "version yet: " + ", ".join(plan["blocked_without_fix"][:5])
                     + (" …" if len(plan["blocked_without_fix"]) > 5 else ""))
    if yuksek:
        cve = len({c for x in yuksek for c in x["high_cves"]})
        bas = "NEXT" if engel else "FIX PLAN"
        satir.append(f"{bas} — {len(yuksek)} upgrade(s) fix {cve} high-signal CVE(s)"
                     + (f" (top {MAX_PLAN})" if len(yuksek) > MAX_PLAN else ""))
        satir.extend(_plan_satiri(x) for x in yuksek[:MAX_PLAN])
        for c in plan["commands"]["blocked_and_high"]:
            satir.append(f"  run{' (blocked + high)' if engel else ''}: {c}")
    if diger:
        satir.append(f"  + {len(diger)} more upgrade(s) fix {sum(x['other_fixable'] for x in diger)} "
                     "other finding(s); full plan in --json-out.")
    if satir:
        satir.append("")
    return satir


def tablo(sonuclar: List[Dict[str, Any]], arac: str, block_at: str,
          plan: Optional[Dict[str, Any]] = None, meta: Optional[Dict[str, Any]] = None) -> str:
    """Insan icin ozet. Bir CVE bir kez; tam liste --json-out'ta."""
    if plan is None:
        plan = duzeltme_plani(sonuclar)
    sayac: Dict[str, int] = {}
    onem: Dict[str, int] = {}
    for r in sonuclar:
        sayac[r["urgency"]] = sayac.get(r["urgency"], 0) + 1
        o = (r["scanner_severity"] or "UNKNOWN").upper()
        onem[o] = onem.get(o, 0) + 1
    cve_sayisi = len({r["cve"] for r in sonuclar if r["cve"]})
    engel = [r for r in sonuclar if r["blocked"]]

    satir = [f"CyberDetails SCA gate {__version__} — {arac}: {len(sonuclar)} finding(s), "
             f"{cve_sayisi} distinct CVE(s); block at: {block_at}"]
    if onem:
        sira = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        satir.append("  scanner severity: " + ", ".join(
            f"{onem[k]} {k}" for k in sorted(onem, key=lambda k: sira.index(k) if k in sira else 9)))
    satir.append("  exploitation:     " + ", ".join(
        f"{sayac[k]} {ETIKET.get(k, k)}" for k in sorted(sayac, key=lambda k: SIRA.get(k, 9))))
    if meta and meta.get("os"):
        satir.append(f"  base OS:          {meta['os']}" + (
            " — END OF LIFE: the distribution no longer ships security fixes; "
            "rebuild on a supported base image" if meta.get("eosl") else ""))
    satir.append("")

    if engel:
        gruplar = _cve_gruplari(engel)
        satir.append(f"BLOCKED — {len(gruplar)} CVE(s), {len(engel)} finding(s)")
        for kimlik, grup in gruplar:
            satir.extend(_grup_satirlari(kimlik, grup))
        satir.append("")

    incele = _cve_gruplari([r for r in sonuclar if not r["blocked"]
                            and r["urgency"] in ("known_exploited", "high")])
    if incele:
        satir.append(f"REVIEW — {len(incele)} CVE(s) with strong signals, not blocking at this "
                     f"threshold" + (f" (top {MAX_INCELE})" if len(incele) > MAX_INCELE else ""))
        for kimlik, grup in incele[:MAX_INCELE]:
            satir.extend(_grup_satirlari(kimlik, grup))
        satir.append("")

    satir.extend(plan_metni(plan))

    yok = sayac.get("not_in_database", 0)
    if yok:
        satir.append(f"NOTE — {yok} finding(s) have no CyberDetails record. They are NOT judged safe; "
                     "use --block-unknown to fail on them.")
    if sayac.get("no_cve"):
        satir.append(f"NOTE — {sayac['no_cve']} finding(s) have no CVE identifier (e.g. GHSA-only) "
                     "and were not sent.")
    satir.append("Version matching comes from the scanner; CyberDetails ranks by exploitation evidence.")
    satir.append(f"RESULT: FAIL ({len(engel)} blocked)" if engel else "RESULT: PASS")
    return "\n".join(satir)


def main(argv: Optional[List[str]] = None, gonder=_gonder) -> int:
    ap = argparse.ArgumentParser(
        prog="cd_sca_gate",
        description="Fail a build only on scanner findings that matter: known-exploited "
                    "CVEs (CISA/VulnCheck KEV, active exploitation) by default.")
    ap.add_argument("report", help="Trivy JSON (--format json) or Grype JSON (-o json); '-' for stdin")
    ap.add_argument("--block-at", choices=("cisa_kev", "known_exploited", "high", "never"),
                    default="known_exploited",
                    help="what fails the build: cisa_kev (CISA KEV only), known_exploited "
                         "(default: CISA/VulnCheck KEV or active exploitation), high, never")
    ap.add_argument("--block-unknown", action="store_true",
                    help="also fail on CVEs that are not in the CyberDetails archive")
    ap.add_argument("--api", default=VARSAYILAN_API, help=f"API base URL (default: {VARSAYILAN_API})")
    ap.add_argument("--json-out", metavar="FILE", help="write the merged triage result as JSON")
    ap.add_argument("--quiet", action="store_true", help="print only the result line")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    try:
        api = api_dogrula(a.api)
        arac, bulgular, meta = rapor_oku_tam(a.report)
        cveler = sorted({b["cve"] for b in bulgular if b["cve"]})
        satirlar = triyaj(api, cveler, a.block_at, a.block_unknown, gonder=gonder) if cveler else {}
        sonuclar = birlestir(bulgular, satirlar, api)
        plan = duzeltme_plani(sonuclar)
        if a.json_out:
            try:
                with open(a.json_out, "w", encoding="utf-8") as f:
                    json.dump({"tool": f"cd_sca_gate {__version__}", "scanner": arac,
                               "os": meta,
                               "block_at": a.block_at, "block_unknown": a.block_unknown,
                               "decision": "fail" if any(r["blocked"] for r in sonuclar) else "pass",
                               "fix_plan": plan, "findings": sonuclar}, f, indent=2)
            except OSError as exc:
                raise AracHatasi(f"cannot write --json-out: {exc}") from None
        engel = any(r["blocked"] for r in sonuclar)
        cikti = ("RESULT: FAIL" if engel else "RESULT: PASS") if a.quiet else \
            tablo(sonuclar, arac, a.block_at, plan, meta)
    except AracHatasi as exc:
        return _hata(str(exc))
    except Exception as exc:  # noqa: BLE001 — beklenmeyen hata ASLA cikis 1 ("engellendi") olmasin
        # Python yakalanmamis istisnada 1 doner: CI bunu "acik bulundu" okur.
        # Mesaja yalnizca istisna turu yazilir; metni rapordan gelebilir.
        return _hata(f"internal error ({type(exc).__name__}); please report it")
    if not _yaz(cikti):
        return _hata("cannot write the result to standard output")
    return CIKIS_ENGEL if engel else CIKIS_GECTI


def _yaz(metin: str) -> bool:
    """Sonucu stdout'a yaz; yazilamazsa False (cagiran cikis 2 doner).

    Yakalanmamis bir yazma hatasi Python'u 1 ile cikarir ve CI bunu "engellendi"
    okur: Windows'ta cp1252 konsola rapordan gelen bir paket adi/yolu (CJK, Kiril)
    yazilamaz, kapanmis bir boru BrokenPipeError verir. Kodlanamayan karakter
    `\\uXXXX` olarak yazilir, karar satiri kaybolmaz."""
    try:
        kod = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(metin.encode(kod, "backslashreplace").decode(kod))
        sys.stdout.flush()
        return True
    except (OSError, ValueError, LookupError):
        return False


def _hata(mesaj: str) -> int:
    print(f"cd_sca_gate: error: {mesaj}", file=sys.stderr)
    print("RESULT: ERROR (exit 2) — the gate did not run; this is not a pass.", file=sys.stderr)
    return CIKIS_HATA


if __name__ == "__main__":
    sys.exit(main())
