"""
Events Router.

Kişi 2 (kural motoru) ve Kişi 3 (ML motoru) tespitlerini bu endpoint'ler
üzerinden backend'e gönderir. Bu veriler daha sonra correlation engine
(Issue #22) tarafından okunup birleştirilecek ve Alarm'a dönüştürülecektir.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import crud, schemas, models
from ..database import get_db

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=schemas.EventOut, status_code=201)
def ingest_event(event: schemas.EventCreate, db: Session = Depends(get_db)):
    """
    Kural veya ML motorundan gelen HAM tespiti kaydeder.

    Örnek (kural motorundan): {
      "source_engine": "rule",
      "src_ip": "10.0.0.5",
      "attack_type": "port_scan",
      "confidence": 0.9,
      "description": "60 saniyede 40 farklı porta bağlantı denemesi"
    }
    """
    return crud.create_event(db, event)


@router.get("", response_model=List[schemas.EventOut])
def get_events(
    source_engine: Optional[models.EngineSource] = None,
    correlated: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """
    Ham event listesini döner. Correlation engine, henüz işlenmemiş
    (correlated=false) event'leri buradan çekip işleyebilir.
    """
    return crud.list_events(db, source_engine, correlated, limit, offset)


@router.get("/{event_id}", response_model=schemas.EventOut)
def get_event(event_id: str, db: Session = Depends(get_db)):
    db_event = crud.get_event(db, event_id)
    if not db_event:
        raise HTTPException(status_code=404, detail="Event bulunamadı")
    return db_event


@router.patch("/{event_id}/correlate", response_model=schemas.EventOut)
def mark_correlated(event_id: str, db: Session = Depends(get_db)):
    """Correlation engine bir event'i işledikten sonra bunu çağırarak işaretler."""
    db_event = crud.mark_event_correlated(db, event_id)
    if not db_event:
        raise HTTPException(status_code=404, detail="Event bulunamadı")
    return db_event
