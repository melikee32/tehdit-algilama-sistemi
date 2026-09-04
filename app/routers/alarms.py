"""
Alarms Router.

React panel (Issue #23), gösterilecek nihai alarmları buradan okur.
Alarm kayıtları correlation engine (Issue #22) tarafından POST /alarms
ile oluşturulur (rule-engine ve ML-engine çıktılarının birleştirilmiş hali).

WebSocket entegrasyonu (Issue #21) tamamlandığında, yeni bir alarm
oluştuğunda burada `broadcast_alarm()` çağrılarak panele anlık push
yapılacaktır (bkz. TODO notu aşağıda).
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from fastapi import APIRouter, Depends, HTTPException
from ..ws_manager import ws_manager
from sqlalchemy.orm import Session

from .. import crud, schemas, models
from ..database import get_db

router = APIRouter(prefix="/alarms", tags=["alarms"])


@router.post("", response_model=schemas.AlarmOut, status_code=201)
async def create_alarm(alarm: schemas.AlarmCreate, db: Session = Depends(get_db)):
    """Correlation engine'in ürettiği nihai alarmı kaydeder ve WebSocket ile yayınlar."""
    db_alarm = crud.create_alarm(db, alarm)

    # Issue #21: Yeni alarm tüm bağlı React istemcilerine anlık gönderilir
    await ws_manager.broadcast({
        "type": "new_alarm",
        "data": {
            "id": db_alarm.id,
            "attack_type": db_alarm.attack_type,
            "severity": db_alarm.severity,
            "score": db_alarm.score,
            "src_ip": db_alarm.src_ip,
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
    Panelin ana listesi bu endpoint'i kullanır.
    Filtreleme: ?severity=high&acknowledged=false gibi.
    """
    return crud.list_alarms(db, severity, acknowledged, limit, offset)


@router.get("/{alarm_id}", response_model=schemas.AlarmOut)
def get_alarm(alarm_id: str, db: Session = Depends(get_db)):
    db_alarm = crud.get_alarm(db, alarm_id)
    if not db_alarm:
        raise HTTPException(status_code=404, detail="Alarm bulunamadı")
    return db_alarm


@router.patch("/{alarm_id}/ack", response_model=schemas.AlarmOut)
def acknowledge_alarm(
    alarm_id: str, payload: schemas.AlarmAcknowledge, db: Session = Depends(get_db)
):
    """Analist alarmı panelde görüp 'okundu/ele alındı' işaretlediğinde çağrılır."""
    db_alarm = crud.acknowledge_alarm(db, alarm_id, payload.acknowledged)
    if not db_alarm:
        raise HTTPException(status_code=404, detail="Alarm bulunamadı")
    return db_alarm
