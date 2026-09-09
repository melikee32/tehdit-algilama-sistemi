"""Veritabanı CRUD işlemleri. Router'lar bu fonksiyonları çağırır."""
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from . import models, schemas


# ---------- Events ----------

def create_event(db: Session, event: schemas.EventCreate) -> models.Event:
    db_event = models.Event(**event.model_dump())
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


def list_events(
    db: Session,
    source_engine: Optional[models.EngineSource] = None,
    correlated: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    query = db.query(models.Event)
    if source_engine:
        query = query.filter(models.Event.source_engine == source_engine)
    if correlated is not None:
        query = query.filter(models.Event.correlated == correlated)
    return query.order_by(desc(models.Event.timestamp)).offset(offset).limit(limit).all()


def get_event(db: Session, event_id: str) -> Optional[models.Event]:
    return db.query(models.Event).filter(models.Event.id == event_id).first()


def mark_event_correlated(db: Session, event_id: str) -> Optional[models.Event]:
    db_event = get_event(db, event_id)
    if db_event:
        db_event.correlated = "true"
        db.commit()
        db.refresh(db_event)
    return db_event


# ---------- Alarms ----------

def create_alarm(db: Session, alarm: schemas.AlarmCreate) -> models.Alarm:
    db_alarm = models.Alarm(**alarm.model_dump())
    db.add(db_alarm)
    db.commit()
    db.refresh(db_alarm)
    return db_alarm


def list_alarms(
    db: Session,
    severity: Optional[models.Severity] = None,
    acknowledged: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    query = db.query(models.Alarm)
    if severity:
        query = query.filter(models.Alarm.severity == severity)
    if acknowledged is not None:
        query = query.filter(models.Alarm.acknowledged == acknowledged)
    return query.order_by(desc(models.Alarm.timestamp)).offset(offset).limit(limit).all()


def get_alarm(db: Session, alarm_id: str) -> Optional[models.Alarm]:
    return db.query(models.Alarm).filter(models.Alarm.id == alarm_id).first()


def acknowledge_alarm(db: Session, alarm_id: str, acknowledged: bool) -> Optional[models.Alarm]:
    db_alarm = get_alarm(db, alarm_id)
    if db_alarm:
        db_alarm.acknowledged = "true" if acknowledged else "false"
        db.commit()
        db.refresh(db_alarm)
    return db_alarm
