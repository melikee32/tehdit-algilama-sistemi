"""
WebSocket BaÄŸlantÄ± YÃ¶neticisi â€” Issue #21

Birden fazla React istemcisi aynÄ± anda baÄŸlanabilir.
Bu sÄ±nÄ±f aktif baÄŸlantÄ±larÄ± takip eder ve yeni alarm
geldiÄŸinde hepsine aynÄ± anda JSON mesajÄ± gÃ¶nderir.
"""
from fastapi import WebSocket
import json


class ConnectionManager:
    def __init__(self):
        # Aktif WebSocket baÄŸlantÄ±larÄ±nÄ±n listesi
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Yeni bir React istemcisi baÄŸlandÄ±ÄŸÄ±nda Ã§aÄŸrÄ±lÄ±r."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Ä°stemci baÄŸlantÄ±yÄ± kestiÄŸinde listeden Ã§Ä±kar."""
        self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        """Bagli tum istemcilere JSON mesaji gonderir. Kopmus baglantilari tolere eder."""
        message = json.dumps(data)
        # Hata aninda list_iterator patlamamasi icin listenin kopyasi (list()) uzerinde donuyoruz
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                if connection in self.active_connections:
                    self.active_connections.remove(connection)


# TÃ¼m uygulama boyunca tek bir Ã¶rnek kullanÄ±lÄ±r (singleton)
ws_manager = ConnectionManager()
