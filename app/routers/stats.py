"""
/stats endpoint — Sistem metrikleri ve tespit gecikmesi ozeti.

Dokümanin istedigi "Tespit Gecikmesi (Latency)" metrigini API uzerinden
sunmak icin eklendi. Panel ve degerlendirme raporlari bu endpoint'i kullanabilir.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone

from .. import models
from ..database import get_db

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("")
def get_stats(db: Session = Depends(get_db)):
    """
    Sisteme ait ozet metrikleri dondurur:
    - Toplam event / alarm sayilari
    - Severity dagilimi
    - Ortalama ve maksimum tespit gecikmesi (saniye)
    """
    # --- Sayimlar ---
    total_events = db.query(func.count(models.Event.id)).scalar()
    total_alarms = db.query(func.count(models.Alarm.id)).scalar()
    unprocessed  = db.query(func.count(models.Event.id)).filter(
        models.Event.correlated == "false"
    ).scalar()

    # --- Severity Dagilimi ---
    severity_rows = (
        db.query(models.Alarm.severity, func.count(models.Alarm.id))
        .group_by(models.Alarm.severity)
        .all()
    )
    severity_dist = {str(sev): cnt for sev, cnt in severity_rows}

    # --- Tespit Gecikmesi ---
    # Her alarm icin, ilgili rule event'in timestamp'inden alarm'in
    # timestamp'ine kadar gecen sure (saniye).
    # Sadece rule_event_id olan alarmlar icin hesaplanir.
    latencies = []
    alarms_with_rule = db.query(models.Alarm).filter(
        models.Alarm.rule_event_id.isnot(None)
    ).limit(500).all()

    for alarm in alarms_with_rule:
        rule_ev = db.query(models.Event).filter(
            models.Event.id == alarm.rule_event_id
        ).first()
        if rule_ev and rule_ev.timestamp and alarm.timestamp:
            ev_ts = rule_ev.timestamp
            al_ts = alarm.timestamp
            # timezone-aware karsilastirma
            if ev_ts.tzinfo is None:
                ev_ts = ev_ts.replace(tzinfo=timezone.utc)
            if al_ts.tzinfo is None:
                al_ts = al_ts.replace(tzinfo=timezone.utc)
            diff = (al_ts - ev_ts).total_seconds()
            if diff >= 0:
                latencies.append(diff)

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None
    max_latency = round(max(latencies), 2) if latencies else None
    min_latency = round(min(latencies), 2) if latencies else None

    return {
        "events": {
            "total": total_events,
            "unprocessed": unprocessed,
            "processed": total_events - unprocessed,
        },
        "alarms": {
            "total": total_alarms,
            "severity_distribution": severity_dist,
        },
        "latency_seconds": {
            "average": avg_latency,
            "maximum": max_latency,
            "minimum": min_latency,
            "sample_count": len(latencies),
            "note": "Event olusturulma -> Alarm uretilme suresi (saniye)"
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
