"""
WebSocket Bağlantı Yöneticisi — Issue #21

Birden fazla React istemcisi aynı anda bağlanabilir.
Bu sınıf aktif bağlantıları takip eder ve yeni alarm
geldiğinde hepsine aynı anda JSON mesajı gönderir.
"""
from fastapi import WebSocket
import json


class ConnectionManager:
    def __init__(self):
        # Aktif WebSocket bağlantılarının listesi
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Yeni bir React istemcisi bağlandığında çağrılır."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """İstemci bağlantıyı kestiğinde listeden çıkar."""
        self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        """Bağlı tüm istemcilere JSON mesajı gönderir."""
        message = json.dumps(data)
        for connection in self.active_connections:
            await connection.send_text(message)


# Tüm uygulama boyunca tek bir örnek kullanılır (singleton)
ws_manager = ConnectionManager()