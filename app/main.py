"""
Siber Saldırı Tespit ve Alarm Paneli — Backend Giriş Noktası

Issue #20: FastAPI backend mimarisinin kurulması
-------------------------------------------------
Bu dosya, verilerin ve alarmların sunulması için REST API altyapısını kurar:
  - /events   : Kural (Kişi 2) ve ML (Kişi 3) motorlarından ham tespit alımı
  - /alarms   : Correlation engine (Issue #22) çıktısı, panelin (Issue #23) okuduğu yer
  - /health   : Servis durumu kontrolü
  - /docs     : Otomatik OpenAPI dokümantasyonu (ekip API sözleşmesi olarak kullanılabilir)

WebSocket canlı yayını Issue #21'de bu app'e eklenecektir.

Çalıştırma:
    pip install -r requirements.txt
    uvicorn app.main:app --reload --port 8000

Sonra tarayıcıda http://localhost:8000/docs adresini açarak
tüm endpoint'leri interaktif olarak test edebilirsiniz.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from .ws_manager import ws_manager
from .database import Base, engine
from .routers import health, events, alarms


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Siber Saldırı Tespit ve Alarm Paneli API",
    description=(
        "Hibrit (kural tabanlı + ML) saldırı tespit sisteminin backend'i. "
        "Kural ve ML motorlarından gelen event'leri toplar, correlation engine "
        "tarafından üretilen nihai alarmları panele sunar."
    ),
    version="0.1.0",
)

# React panelin (Issue #23) farklı bir origin'den (örn. localhost:5173/3000)
# istek atabilmesi için CORS açık. Canlı ortamda origin listesi daraltılmalı.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: prod'da spesifik origin(ler) ile değiştirin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(events.router)
app.include_router(alarms.router)


@app.get("/")
def root():
    return {
        "message": "Siber Saldırı Tespit ve Alarm Paneli API çalışıyor.",
        "docs": "/docs",
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    React paneli bu endpoint'e bağlanarak anlık alarm
    ve log bildirimlerini dinler.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # İstemciden mesaj bekliyoruz (bağlantıyı canlı tutar)
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)