"""
Correlation Engine — Issue #22

Kişi 2 (kural motoru) ve Kişi 3 (ML motoru) tarafından
/events endpoint'ine gönderilen ham tespitleri okur,
ağırlıklı skorlama ile birleştirir ve nihai alarmı üretir.

Ağırlıklar:
    Kural motoru (rule) : 0.6
    ML motoru    (ml)   : 0.4

Alarm eşiği: birleşik score >= 0.5

Çalıştırma (ayrı bir terminalde):
    python -m app.correlation
"""
import httpx
from collections import defaultdict

API = "http://localhost:8000"
RULE_WEIGHT = 0.6
ML_WEIGHT   = 0.4
THRESHOLD   = 0.5


def severity_from_score(score: float) -> str:
    """Nihai skoru severity etiketine çevirir."""
    if score >= 0.85:
        return "critical"
    elif score >= 0.70:
        return "high"
    elif score >= 0.50:
        return "medium"
    return "low"


def run():
    # 1. Henüz işlenmemiş (correlated=false) ham event'leri çek
    resp = httpx.get(f"{API}/events", params={"correlated": "false", "limit": 200})
    resp.raise_for_status()
    events = resp.json()

    if not events:
        print("[Correlation] İşlenecek yeni event yok.")
        return

    # 2. Aynı (src_ip, attack_type) çiftini grupla
    groups = defaultdict(lambda: {"rule": [], "ml": []})
    for ev in events:
        key = (ev.get("src_ip") or "unknown", ev["attack_type"])
        groups[key][ev["source_engine"]].append(ev)

    # 3. Her grup için ağırlıklı skor hesapla
    for (src_ip, attack_type), engines in groups.items():
        rule_events = engines["rule"]
        ml_events   = engines["ml"]

        # Motorda birden fazla event varsa en yüksek confidence'ı al
        rule_score = max((e["confidence"] for e in rule_events), default=0.0)
        ml_score   = max((e["confidence"] for e in ml_events),   default=0.0)

        combined = rule_score * RULE_WEIGHT + ml_score * ML_WEIGHT

        print(
            f"[Correlation] {src_ip} / {attack_type} → "
            f"rule={rule_score:.2f} ml={ml_score:.2f} combined={combined:.2f}"
        )

        # 4. Eşik geçildiyse alarm oluştur
        if combined >= THRESHOLD:
            alarm_payload = {
                "src_ip":       src_ip,
                "dst_ip":       (rule_events or ml_events)[0].get("dst_ip"),
                "attack_type":  attack_type,
                "severity":     severity_from_score(combined),
                "score":        round(combined, 4),
                "rule_event_id": rule_events[0]["id"] if rule_events else None,
                "ml_event_id":   ml_events[0]["id"]   if ml_events   else None,
                "description":  f"Correlation: rule×{RULE_WEIGHT} + ml×{ML_WEIGHT}",
            }
            ar = httpx.post(f"{API}/alarms", json=alarm_payload)
            print(f"  ✅ Alarm oluşturuldu → {ar.json().get('id')} (severity={alarm_payload['severity']})")

                # 5. Bu gruptaki tüm event'leri 'correlated' olarak işaretle
        for ev in rule_events + ml_events:
            httpx.patch(f"{API}/events/{ev['id']}/correlate")

    print("[Correlation] Tamamlandi.")


if __name__ == "__main__":
    run()