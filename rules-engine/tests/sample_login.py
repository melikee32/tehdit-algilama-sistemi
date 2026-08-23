import json
from datetime import datetime, timedelta

base = datetime(2026, 8, 23, 15, 0, 0)
events = []

# Normal kullanici - 1 basarili giris, brute-force degil
events.append({
    "src_ip": "192.168.1.30", "dst_ip": "192.168.1.10", "username": "mel",
    "protocol": "SSH", "timestamp": base.isoformat() + "Z",
    "event_type": "login_attempt", "success": True
})

# Saldirgan - "admin" kullanicisina 8 basarisiz deneme, 10 saniye icinde
for i in range(8):
    events.append({
        "src_ip": "192.168.1.60", "dst_ip": "192.168.1.10", "username": "admin",
        "protocol": "SSH",
        "timestamp": (base + timedelta(seconds=1.2 * i)).isoformat() + "Z",
        "event_type": "login_attempt", "success": False
    })

with open("sample_login_events.json", "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2, ensure_ascii=False)

print("done", len(events))