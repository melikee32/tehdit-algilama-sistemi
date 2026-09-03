import json
from datetime import datetime, timedelta

base = datetime(2026, 8, 23, 16, 0, 0)
events = []

# Normal kullanici - 3 SYN, flood degil
for i in range(3):
    events.append({
        "src_ip": "192.168.1.25", "dst_ip": "192.168.1.10", "dst_port": 443,
        "protocol": "TCP", "timestamp": (base + timedelta(milliseconds=300*i)).isoformat() + "Z",
        "event_type": "syn_packet", "flags": "SYN"
    })

# Saldirgan - 2 saniye icinde 60 SYN paketi, hep ayni porta (443)
for i in range(60):
    events.append({
        "src_ip": "192.168.1.70", "dst_ip": "192.168.1.10", "dst_port": 443,
        "protocol": "TCP", "timestamp": (base + timedelta(milliseconds=25*i)).isoformat() + "Z",
        "event_type": "syn_packet", "flags": "SYN"
    })

with open("sample_syn_events.json", "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2, ensure_ascii=False)

print("done", len(events))