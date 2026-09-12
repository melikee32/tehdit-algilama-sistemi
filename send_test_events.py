import httpx, time

API = "http://localhost:8000"

events = [
    # KRiTiK: rule=1.0, ml=0.9 => 1.0*0.6 + 0.9*0.4 = 0.96
    {"source_engine": "rule", "src_ip": "192.168.1.50", "dst_ip": "10.0.0.1", "attack_type": "syn_flood",   "confidence": 1.0, "description": "Yuksek yogunluklu SYN flood"},
    {"source_engine": "ml",   "src_ip": "192.168.1.50", "dst_ip": "10.0.0.1", "attack_type": "anomaly",     "confidence": 0.9},

    # YUKSEK: rule=0.85, ml=0.55 => 0.85*0.6 + 0.55*0.4 = 0.73
    {"source_engine": "rule", "src_ip": "172.16.0.20",  "dst_ip": "10.0.0.2", "attack_type": "brute_force", "confidence": 0.85, "description": "SSH brute force"},
    {"source_engine": "ml",   "src_ip": "172.16.0.20",  "dst_ip": "10.0.0.2", "attack_type": "anomaly",     "confidence": 0.55},

    # ORTA: sadece rule=0.6 => combined=0.6
    {"source_engine": "rule", "src_ip": "10.10.10.5",   "dst_ip": "10.0.0.3", "attack_type": "port_scan",   "confidence": 0.6, "description": "Orta yogunluklu port taramasi"},

    # ORTA (esik): sadece ml=0.5 => combined=0.5
    {"source_engine": "ml",   "src_ip": "10.20.30.40",  "dst_ip": "10.0.0.4", "attack_type": "anomaly",     "confidence": 0.5},
]

print("Event gonderiliyor:")
for e in events:
    r = httpx.post(API + "/events", json=e)
    eng  = e["source_engine"]
    ip   = e["src_ip"]
    atyp = e["attack_type"]
    conf = e["confidence"]
    print(f"  [{eng:4}] {ip:15} | {atyp:12} | conf={conf} => HTTP {r.status_code}")
    time.sleep(0.1)

print("\nTum eventler gonderildi!")
