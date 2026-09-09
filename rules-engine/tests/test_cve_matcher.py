import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from cve_matcher import query_cves_for_service, scan_services_for_cves


def test_empty_product_or_version_returns_empty_list():
    """Product veya version bos ise sorgu atilmamali, bos liste donmeli."""
    assert query_cves_for_service("", "1.0") == []
    assert query_cves_for_service("Apache httpd", "") == []


def test_known_vulnerable_service_returns_cves():
    """Bilinen acik iceren bir versiyon (Apache 2.4.49) CVE bulmali.
    NOT: bu test gercek internete baglaniyor, NVD API'sine sorgu atiyor.
    Internet yoksa veya NVD yavassa bu test basarisiz olabilir -- normal."""
    results = query_cves_for_service("Apache httpd", "2.4.49")
    assert len(results) > 0
    assert any(r["cve_id"] == "CVE-2021-41773" for r in results)


def test_scan_services_adds_cves_field():
    """scan_services_for_cves, her servise 'cves' alani eklemeli."""
    services = [{"host": "1.2.3.4", "port": 80, "product": "", "version": ""}]
    results = scan_services_for_cves(services)
    assert "cves" in results[0]
    assert results[0]["cves"] == []  # product/version bos oldugu icin bos donmeli


if __name__ == "__main__":
    test_empty_product_or_version_returns_empty_list()
    print("Test 1 gecti (bos alan kontrolu)")
    test_scan_services_adds_cves_field()
    print("Test 2 gecti (cves alani ekleniyor)")
    test_known_vulnerable_service_returns_cves()
    print("Test 3 gecti (gercek CVE bulundu) -- internet baglantisi gerekli")
    print("\nTum testler gecti!")