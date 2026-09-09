"""
Alarms Router.

React panel (Issue #23), gÃ¶sterilecek nihai alarmlarÄ± buradan okur.
Alarm kayÄ±tlarÄ± correlation engine (Issue #22) tarafÄ±ndan POST /alarms
ile oluÅŸturulur (rule-engine ve ML-engine Ã§Ä±ktÄ±larÄ±nÄ±n birleÅŸtirilmiÅŸ hali).

WebSocket entegrasyonu (Issue #21) tamamlandÄ±ÄŸÄ±nda, yeni bir alarm
oluÅŸtuÄŸunda burada `broadcast_alarm()` Ã§aÄŸrÄ±larak panele anlÄ±k push
yapÄ±lacaktÄ±r (bkz. TODO notu aÅŸaÄŸÄ±da).
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from ..ws_manager import ws_manager
from sqlalchemy.orm import Session

from .. import crud, schemas, models
from ..database import get_db

router = APIRouter(prefix="/alarms", tags=["alarms"])


@router.post("", response_model=schemas.AlarmOut, status_code=201)
async def create_alarm(alarm: schemas.AlarmCreate, db: Session = Depends(get_db)):
    """Correlation engine'in Ã¼rettiÄŸi nihai alarmÄ± kaydeder ve WebSocket ile yayÄ±nlar."""
    db_alarm = crud.create_alarm(db, alarm)

    # Issue #21: Yeni alarm tÃ¼m baÄŸlÄ± React istemcilerine anlÄ±k gÃ¶nderilir
    await ws_manager.broadcast({
        "type": "new_alarm",
        "data": {
            "id": db_alarm.id,
            "attack_type": db_alarm.attack_type,
            "severity": db_alarm.severity,
            "score": db_alarm.score,
            "src_ip": db_alarm.src_ip,
            "dst_ip": db_alarm.dst_ip,
            "acknowledged": db_alarm.acknowledged,
            "timestamp": str(db_alarm.timestamp),
        }
    })

    return db_alarm

@router.get("", response_model=List[schemas.AlarmOut])
def get_alarms(
    severity: Optional[models.Severity] = None,
    acknowledged: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """
    Panelin ana listesi bu endpoint'i kullanÄ±r.
    Filtreleme: ?severity=high&acknowledged=false gibi.
    """
    return crud.list_alarms(db, severity, acknowledged, limit, offset)


@router.get("/{alarm_id}", response_model=schemas.AlarmOut)
def get_alarm(alarm_id: str, db: Session = Depends(get_db)):
    db_alarm = crud.get_alarm(db, alarm_id)
    if not db_alarm:
        raise HTTPException(status_code=404, detail="Alarm bulunamadÄ±")
    return db_alarm


@router.patch("/{alarm_id}/ack", response_model=schemas.AlarmOut)
async def acknowledge_alarm(
    alarm_id: str, payload: schemas.AlarmAcknowledge, db: Session = Depends(get_db)
):
    """Analist alarmÄ± panelde gÃ¶rÃ¼p 'okundu/ele alÄ±ndÄ±' iÅŸaretlediÄŸinde Ã§aÄŸrÄ±lÄ±r."""
    db_alarm = crud.acknowledge_alarm(db, alarm_id, payload.acknowledged)
    if not db_alarm:
        raise HTTPException(status_code=404, detail="Alarm bulunamadÄ±")
        await ws_manager.broadcast({"type": "alarm_updated", "data": {"id": db_alarm.id, "acknowledged": db_alarm.acknowledged}})
    return db_alarm




