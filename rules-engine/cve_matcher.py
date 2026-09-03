"""
CVE Eslestirme Modulu
========================
Amac: nmap_parser'in buldugu her servisi (product + version),
NVD (National Vulnerability Database) API'sine sorgulayip bilinen
CVE (Common Vulnerabilities and Exposures) kayitlarini bulmak.

NVD API dokumantasyonu: https://nvd.nist.gov/developers/vulnerabilities
API key gerekmiyor (public), ama rate limit var (key'siz ~5 istek/30sn).
Cok fazla servis taranacaksa, istekler arasina time.sleep() eklenmeli.
"""

import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD'nin key'siz kullanicilar icin onerdigi bekleme suresi (rate limit asmamak icin)
REQUEST_DELAY_SECONDS = 6


def query_cves_for_service(product: str, version: str) -> list[dict]:
    """
    Tek bir servis (product + version) icin NVD'ye sorgu atar.

    Args:
        product: servis adi, ornegin "Apache httpd"
        version: versiyon, ornegin "2.4.49"

    Returns:
        Bulunan CVE kayitlarinin listesi:
        [
            {
                "cve_id": "CVE-2021-41773",
                "description": "...",
                "cvss_score": 7.5,
                "severity": "HIGH",
            },
            ...
        ]
        Hicbir sey bulunamazsa veya product/version bossa, bos liste doner.
    """
    # Product veya version bilgisi yoksa (nmap tespit edememisse) sorgu atmanin anlami yok
    if not product or not version:
        return []
    
    
    # NVD'nin kullandigi isimlendirme bazen nmap'inkinden farkli oluyor
    # (orn. nmap "httpd" der, NVD "HTTP Server" der) -- bilinen birkac
    # farkliligi burada normalize ediyoruz
    product_aliases = {
        "apache httpd": "Apache HTTP Server",
        "openssh": "OpenSSH",
    }
    normalized_product = product_aliases.get(product.lower(), product)
    query = f"{normalized_product} {version}"

    # keywordSearch: NVD'nin CVE aciklamalarinda gecen kelimeleri arayan basit yontem
    # Tam CPE eslestirmesi daha kesin olurdu ama bu proje icin yeterli ve daha basit
    
    params = {
        "keywordSearch": query,
        "resultsPerPage": 10,  # cok fazla sonuc istemiyoruz, en alakali ilk 10 yeterli
    }

    response = requests.get(NVD_API_URL, params=params, timeout=15)
    response.raise_for_status()  # HTTP hatasi varsa (429, 500 vb.) exception firlat

    data = response.json()
    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        # Aciklama genelde birden fazla dilde geliyor, ingilizcesini aliyoruz
        descriptions = cve.get("descriptions", [])
        description_text = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "Aciklama bulunamadi",
        )

        # CVSS skoru "metrics" altinda, versiyon 3.1 -> 3.0 -> 2.0 sirasiyla deneniyor
        # cunku her CVE'de ayni CVSS versiyonu olmayabilir
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss_data = metrics[metric_key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        results.append({
            "cve_id": cve_id,
            "description": description_text,
            "cvss_score": cvss_score,
            "severity": severity,
        })

    return results


def scan_services_for_cves(services: list[dict]) -> list[dict]:
    """
    nmap_parser.parse_nmap_xml()'den gelen servis listesinin tamamini
    tarayip, her biri icin bulunan CVE'leri servisin yanina ekler.

    Args:
        services: nmap_parser'dan gelen servis dict listesi

    Returns:
        Her servise "cves" alani eklenmis hali:
        [
            {
                "host": "192.168.1.10",
                "port": 80,
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.49",
                "cves": [{"cve_id": "CVE-2021-41773", ...}, ...]
            },
            ...
        ]
    """
    results = []

    for i, service in enumerate(services):
        cves = query_cves_for_service(service.get("product", ""), service.get("version", ""))

        # Orijinal servis bilgisine cves alanini ekliyoruz (kopyalayip degistiriyoruz)
        service_with_cves = {**service, "cves": cves}
        results.append(service_with_cves)

        # Rate limit'e takilmamak icin, son servis degilse bekle
        if i < len(services) - 1:
            time.sleep(REQUEST_DELAY_SECONDS)

    return results


if __name__ == "__main__":
    from pathlib import Path
    from nmap_parser import parse_nmap_xml

    sample_path = Path(__file__).parent / "tests" / "sample_nmap_output.xml"
    services = parse_nmap_xml(sample_path)

    print("NVD sorgulaniyor, birkac saniye surebilir...\n")
    results = scan_services_for_cves(services)

    for r in results:
        print(f"{r['host']}:{r['port']} - {r['product']} {r['version']}")
        if r["cves"]:
            for cve in r["cves"]:
                print(f"  -> {cve['cve_id']} (CVSS: {cve['cvss_score']}, {cve['severity']})")
        else:
            print("  -> Bilinen CVE bulunamadi")
        print()