"""
Nmap Cikti Parser
====================
Amac: Nmap'in urettigi XML raporunu okuyup, her bulunan servisi
(host, port, servis adi, versiyon) Python listesine cevirmek.

Nmap XML raporu almak icin (Kisi 1'in kurdugu test aginda calistir):
    nmap -sV -oX tarama_sonucu.xml <hedef_ip>

-sV bayragi ONEMLI: bu, sadece port acik mi diye bakmakla kalmiyor,
servisin VERSIYONUNU da tespit etmeye calisiyor (CVE eslestirmesi
icin versiyon sart, sadece "port 80 acik" yetmez).
"""

import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """
    Nmap XML dosyasini okuyup, bulunan her servisi bir dict olarak dondurur.

    Returns:
        [
            {
                "host": "192.168.1.10",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.49",
            },
            ...
        ]
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results = []

    # Nmap XML yapisi: <host> icinde <address> (IP) ve <ports><port> var
    for host_elem in root.findall("host"):
        address_elem = host_elem.find("address")
        if address_elem is None:
            continue
        host_ip = address_elem.get("addr")

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            # Sadece "acik" (open) portlarla ilgileniyoruz
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port_elem.find("service")
            if service_elem is None:
                # Servis bilgisi yoksa (nmap tanimlayamadiysa) atla
                continue

            results.append({
                "host": host_ip,
                "port": int(port_elem.get("portid")),
                "protocol": port_elem.get("protocol"),
                "service": service_elem.get("name", "unknown"),
                # .get() ile cekiyoruz cunku product/version her zaman
                # nmap tarafindan tespit edilemeyebilir (bos gelebilir)
                "product": service_elem.get("product", ""),
                "version": service_elem.get("version", ""),
            })

    return results


if __name__ == "__main__":
    sample_path = Path(__file__).parent / "tests" / "sample_nmap_output.xml"
    services = parse_nmap_xml(sample_path)

    print(f"{len(services)} servis bulundu:\n")
    for s in services:
        print(s)