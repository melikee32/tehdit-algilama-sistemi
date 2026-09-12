from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from ..ws_manager import ws_manager
from sqlalchemy.orm import Session

from .. import crud, schemas, models
from ..database import get_db

router = APIRouter(prefix="/alarms", tags=["alarms"])

@router.post("", response_model=schemas.AlarmOut, status_code=201)
async def create_alarm(alarm: schemas.AlarmCreate, db: Session = Depends(get_db)):
    # Eger diger motorlar detection_source gondermediyse otomatik hesapla (Geriye donuk uyumluluk)
    if not alarm.detection_source:
        if alarm.rule_event_id and alarm.ml_event_id:
            ds = "Hybrid"
        elif alarm.rule_event_id:
            ds = "Rule"
        elif alarm.ml_event_id:
            ds = "ML"
        else:
            ds = "-"
        alarm = alarm.model_copy(update={"detection_source": ds})

    db_alarm = crud.create_alarm(db, alarm)

    await ws_manager.broadcast({
        "type": "new_alarm",
        "data": {
            "id": db_alarm.id,
            "attack_type": db_alarm.attack_type,
            "severity": db_alarm.severity,
            "score": db_alarm.score,
            "src_ip": db_alarm.src_ip,
            "dst_ip": db_alarm.dst_ip,
            "detection_source": db_alarm.detection_source,
            "rule_event_id": db_alarm.rule_event_id,
            "ml_event_id": db_alarm.ml_event_id,
            "acknowledged": db_alarm.acknowledged,
            "timestamp": str(db_alarm.timestamp),
        }
    })
    return db_alarm

@router.get("", response_model=List[schemas.AlarmOut])
def get_alarms(severity: Optional[models.Severity] = None, acknowledged: Optional[str] = None, limit: int = 100, offset: int = 0, db: Session = Depends(get_db)):
    return crud.list_alarms(db, severity, acknowledged, limit, offset)

@router.get("/{alarm_id}", response_model=schemas.AlarmOut)
def get_alarm(alarm_id: str, db: Session = Depends(get_db)):
    db_alarm = crud.get_alarm(db, alarm_id)
    if not db_alarm:
        raise HTTPException(status_code=404, detail="Alarm bulunamadı")
    return db_alarm

@router.patch("/{alarm_id}/ack", response_model=schemas.AlarmOut)
async def acknowledge_alarm(alarm_id: str, payload: schemas.AlarmAcknowledge, db: Session = Depends(get_db)):
    db_alarm = crud.acknowledge_alarm(db, alarm_id, payload.acknowledged)
    if not db_alarm:
        raise HTTPException(status_code=404, detail="Alarm bulunamadı")
    await ws_manager.broadcast({"type": "alarm_updated", "data": {"id": db_alarm.id, "acknowledged": db_alarm.acknowledged}})
    return db_alarm
