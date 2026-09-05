"""
Correlation Engine - Issue #22

Kisi 2 (kural motoru) ve Kisi 3 (ML motoru) tarafindan
/events endpoint'ine gonderilen ham tespitleri okur,
agirlikli skorlama ile birlestirip nihai alarmi uretir.

Agirliklar:
    Kural motoru (rule) : 0.6
    ML motoru    (ml)   : 0.4

Alarm esigi: birlesik score >= 0.5

Not: Gruplama sadece src_ip bazlidir. Boylece ML'in
"anomaly" gondermesi kural motorunun "port_scan" gibi
spesifik bir tur gondermesiyle eslesebilir.

Calistirma:
    python -m app.correlation
"""
import httpx
from collections import defaultdict

API         = "http://localhost:8000"
RULE_WEIGHT = 0.6
ML_WEIGHT   = 0.4
THRESHOLD   = 0.5


def severity_from_score(score: float) -> str:
    if score >= 0.85:
        return "critical"
    elif score >= 0.70:
        return "high"
    elif score >= 0.50:
        return "medium"
    return "low"


def run():
    # 1. Henuz islenmemis (correlated=false) ham eventleri cek
    resp = httpx.get(f"{API}/events", params={"correlated": "false", "limit": 200})
    resp.raise_for_status()
    events = resp.json()

    if not events:
        print("[Correlation] Islenecek yeni event yok.")
        return

    # 2. Sadece src_ip bazli grupla
    # attack_type farki olsa bile ayni kaynaktan gelen eventler eslesir
    groups: dict = defaultdict(lambda: {"rule": [], "ml": []})
    for ev in events:
        key = ev.get("src_ip") or "unknown"
        groups[key][ev["source_engine"]].append(ev)

    # 3. Her grup icin agirlikli skor hesapla
    for src_ip, engines in groups.items():
        rule_events = engines["rule"]
        ml_events   = engines["ml"]

        # Kural motoru attack_type'i daha spesifik, varsa onu kullan
        attack_type = (
            rule_events[0]["attack_type"] if rule_events
            else ml_events[0]["attack_type"]
        )

        # Birden fazla event varsa en yuksek confidence'i al
        rule_score = max((e["confidence"] for e in rule_events), default=0.0)
        ml_score   = max((e["confidence"] for e in ml_events),   default=0.0)

        combined = rule_score * RULE_WEIGHT + ml_score * ML_WEIGHT

        # Tek motor yuksek guven durumu: esige yaklasiyorsa hafif bonus
        if combined < THRESHOLD:
            if not rule_events and ml_score >= 0.85:
                combined = ml_score * ML_WEIGHT * 1.5
            elif not ml_events and rule_score >= 0.85:
                combined = rule_score * RULE_WEIGHT * 1.2

        print(
            f"[Correlation] {src_ip} / {attack_type} "
            f"rule={rule_score:.2f} ml={ml_score:.2f} combined={combined:.2f}"
        )

        # 4. Esik gecildiyse alarm olustur
        if combined >= THRESHOLD:
            alarm_payload = {
                "src_ip":        src_ip,
                "dst_ip":        (rule_events or ml_events)[0].get("dst_ip"),
                "attack_type":   attack_type,
                "severity":      severity_from_score(combined),
                "score":         round(combined, 4),
                "rule_event_id": rule_events[0]["id"] if rule_events else None,
                "ml_event_id":   ml_events[0]["id"]   if ml_events   else None,
                "description":   (
                    f"Correlation: rule*{RULE_WEIGHT} + ml*{ML_WEIGHT} | "
                    f"Kural turu: {rule_events[0]['attack_type'] if rule_events else 'yok'} | "
                    f"ML turu: {ml_events[0]['attack_type'] if ml_events else 'yok'}"
                ),
            }
            ar = httpx.post(f"{API}/alarms", json=alarm_payload)
            print(f"  >> Alarm olusturuldu: {ar.json().get('id')} ({alarm_payload['severity']})")

        # 5. Bu gruptaki tum eventleri correlated olarak isaretleyin
        for ev in rule_events + ml_events:
            httpx.patch(f"{API}/events/{ev['id']}/correlate")

    print("[Correlation] Tamamlandi.")


if __name__ == "__main__":
    run()
