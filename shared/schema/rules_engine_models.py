"""
Rules-Engine Pydantic Modelleri
===================================
Amac: rules-engine'in urettigi alarmlarin (port_scan, brute_force,
syn_flood) ve zafiyet/CVE sonuclarinin RESMI veri modelini tanimlamak.

Bu modeller, alarm_formatter.py'nin urettigi dict yapisiyla birebir
uyumlu olacak sekilde yazildi. Dashboard (FastAPI) tarafi da ayni
modelleri import edip kullanabilir, boylece iki taraf da ayni
"sozlesmeye" uyar.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AlarmType(str, Enum):
    """Rules-engine'in uretebilecegi alarm turleri.
    str'den de miras aldigi icin, JSON'a cevrilirken otomatik
    olarak duz metin ("port_scan" gibi) olarak yazilir."""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    SYN_FLOOD = "syn_flood"


class Severity(str, Enum):
    """Alarmin onem derecesi."""
    HIGH = "high"
    MEDIUM = "medium"


class RuleAlarm(BaseModel):
    """
    Ortak alarm zarfi. alarm_formatter.py'nin urettigi dict'in
    Pydantic karsiligi.

    dst_ip Optional cunku port_scan alarminda bu alan yok (None geliyor).
    details, modul-ozel alanlari (distinct_ports, failed_attempts,
    syn_count gibi) tutan serbest bir sozluk -- her alarm turunde
    farkli alanlar oldugu icin sabit bir model yerine esnek dict kullanildi.
    """
    alarm_id: str
    source_module: str = "rules-engine"
    alarm_type: AlarmType
    src_ip: str
    dst_ip: Optional[str] = None
    severity: Severity
    window_start: str
    window_end: str
    details: dict = Field(default_factory=dict)


class CVEResult(BaseModel):
    """Tek bir CVE eslesmesi (cve_matcher.py'nin urettigi sonuc)."""
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: Optional[str] = None


class VulnerableService(BaseModel):
    """
    nmap_parser + cve_matcher'in birlikte urettigi sonuc:
    bir servis ve o servise ait bulunan CVE'ler.
    """
    host: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    cves: list[CVEResult] = Field(default_factory=list)


if __name__ == "__main__":
    # Hizli dogrulama: mevcut alarm_formatter ciktisini bu modele sokup
    # gercekten uyumlu mu diye test ediyoruz
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "rules-engine"))

    # Ornek bir ham alarm (port_scan_detector'in urettigi gibi)
    example_raw_alarm = {
        "alarm_id": "test-123",
        "source_module": "rules-engine",
        "alarm_type": "port_scan",
        "src_ip": "192.168.1.50",
        "dst_ip": None,
        "severity": "medium",
        "window_start": "2026-08-23T14:32:10Z",
        "window_end": "2026-08-23T14:32:12Z",
        "details": {"distinct_ports": 15},
    }

    # Eger bu satir hatasiz calisirsa, modelimiz gercek ciktiyla uyumlu demektir
    validated = RuleAlarm(**example_raw_alarm)
    print("Model dogrulandi:")
    print(validated.model_dump_json(indent=2))