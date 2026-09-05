"""
Correlation Engine - Issue #22 (v3)

Degisiklikler:
  v2: Gruplama src_ip bazina alindi (ML anomaly eslesmesi icin)
  v3:
    - Ayni IP'den farkli attack_type'lar artik ayri alarm uretiyor
    - Oldu kod kaldirildi (kural bonusu hic calismiiyordu)
    - ML tek basina alarm uretirken weight cezasi kaldirildi:
      combined = ml_score (direkt). Boylece:
        - Olü bolge yok (ml_score >= 0.5 yeterli)
        - Severity tam olarak calisir (critical, high vs. ulasilabilir)
      NOT: Kisi 3 IsolationForest skorunu 0-1 araligina normalize
      ederken bu eigi dikkate alabilir.

Agirliklar (iki motor birlikte):
    Kural motoru (rule) : 0.6
    ML motoru    (ml)   : 0.4
Alarm esigi           : combined >= 0.5
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


def process_group(src_ip: str, rule_events: list, ml_events: list) -> list[dict]:
    """
    Tek bir src_ip grubunu islayip alarm payload listesi dondurur.

    Strateji:
    - Kural olaylari attack_type'a gore alt gruplara bolunur.
      Her alt grup icin ML olaylariyla eslesme yapilir.
      Boylece ayni IP'den port_scan + brute_force gelirse iki ayri alarm olusur.
    - Hic kural olayi yoksa ML tek basina degerlendirilir.
    """
    alarms = []

    if rule_events:
        # Kural olaylarini attack_type'a gore grupla
        rule_by_type: dict[str, list] = defaultdict(list)
        for ev in rule_events:
            rule_by_type[ev["attack_type"]].append(ev)

        for attack_type, typed_rules in rule_by_type.items():
            rule_score = max(e["confidence"] for e in typed_rules)
            ml_score   = max((e["confidence"] for e in ml_events), default=0.0)
            combined   = rule_score * RULE_WEIGHT + ml_score * ML_WEIGHT

            print(
                f"[Correlation] {src_ip} / {attack_type} "
                f"rule={rule_score:.2f} ml={ml_score:.2f} combined={combined:.2f}"
            )

            if combined >= THRESHOLD:
                alarms.append({
                    "payload": {
                        "src_ip":        src_ip,
                        "dst_ip":        typed_rules[0].get("dst_ip"),
                        "attack_type":   attack_type,
                        "severity":      severity_from_score(combined),
                        "score":         round(combined, 4),
                        "rule_event_id": typed_rules[0]["id"],
                        "ml_event_id":   ml_events[0]["id"] if ml_events else None,
                        "description": (
                            f"Correlation v3: rule({attack_type})*{RULE_WEIGHT}"
                            + (f" + ml(anomaly)*{ML_WEIGHT}" if ml_events else "")
                        ),
                    },
                    "events_to_mark": typed_rules + (ml_events if ml_events else []),
                })

    else:
        # Sadece ML olayi var — weight cezasi olmadan direkt ml_score kullan
        if not ml_events:
            return []

        ml_score  = max(e["confidence"] for e in ml_events)
        combined  = ml_score          # Ceza yok: ML tek basina tam skoruyla degerlendirilir

        print(
            f"[Correlation] {src_ip} / anomaly (sadece ML) "
            f"ml={ml_score:.2f} combined={combined:.2f}"
        )

        if combined >= THRESHOLD:
            alarms.append({
                "payload": {
                    "src_ip":        src_ip,
                    "dst_ip":        ml_events[0].get("dst_ip"),
                    "attack_type":   ml_events[0].get("attack_type", "anomaly"),
                    "severity":      severity_from_score(combined),
                    "score":         round(combined, 4),
                    "rule_event_id": None,
                    "ml_event_id":   ml_events[0]["id"],
                    "description":   f"ML tek motor: anomaly skoru={ml_score:.2f}",
                },
                "events_to_mark": ml_events,
            })

    return alarms


def run():
    resp = httpx.get(f"{API}/events", params={"correlated": "false", "limit": 200})
    resp.raise_for_status()
    events = resp.json()

    if not events:
        print("[Correlation] Islenecek yeni event yok.")
        return

    # Sadece src_ip bazli grupla (ML eslesmesi icin)
    groups: dict = defaultdict(lambda: {"rule": [], "ml": []})
    for ev in events:
        key = ev.get("src_ip") or "unknown"
        groups[key][ev["source_engine"]].append(ev)

    total_alarms = 0
    for src_ip, engines in groups.items():
        alarm_items = process_group(src_ip, engines["rule"], engines["ml"])

        for item in alarm_items:
            ar = httpx.post(f"{API}/alarms", json=item["payload"])
            alarm_id = ar.json().get("id", "?")
            severity = item["payload"]["severity"]
            print(f"  >> Alarm olusturuldu: {alarm_id} ({severity})")
            total_alarms += 1

            for ev in item["events_to_mark"]:
                httpx.patch(f"{API}/events/{ev['id']}/correlate")

    print(f"[Correlation] Tamamlandi. Toplam {total_alarms} alarm uretildi.")


if __name__ == "__main__":
    run()
