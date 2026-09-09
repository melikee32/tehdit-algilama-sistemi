"""
Veritabanı bağlantı katmanı.

Geliştirme ortamında SQLite kullanılır. Prodüksiyon/canlı test ortamında
DATABASE_URL çevre değişkeni ile PostgreSQL'e geçiş yapılabilir
(örn: postgresql://user:pass@localhost:5432/tehdit_db).

Bu dosya, ekip içindeki "ortak veri şeması" gereksinimini karşılamak için
tek bir merkezi noktadan yönetilir (bkz. Fizibilite dokümanı - Risk: 4 kişi
arası entegrasyon sorunları).
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tehdit_algilama.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency: her request için bir DB oturumu açar ve kapatır."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
