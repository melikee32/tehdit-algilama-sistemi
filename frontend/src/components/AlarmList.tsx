interface Alarm {
  id: string;
  attack_type: string;
  severity: "low" | "medium" | "high" | "critical";
  score: number;
  src_ip: string;
  timestamp: string;
}

const severityColor: Record<string, string> = {
  low: "#4ade80",
  medium: "#facc15",
  high: "#fb923c",
  critical: "#f87171",
};

interface Props { alarms: Alarm[]; }

export default function AlarmList({ alarms }: Props) {
  return (
    <div style={{ background: "#1e293b", borderRadius: "8px", padding: "1rem" }}>
      <h2 style={{ color: "#94a3b8", marginTop: 0, fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "1px" }}>
        Alarm Listesi <span style={{ color: "#475569" }}>({alarms.length})</span>
      </h2>
      <div style={{ maxHeight: "380px", overflowY: "auto" }}>
        {alarms.length === 0 && <p style={{ color: "#475569", fontSize: "0.9rem" }}>Alarm yok.</p>}
        {alarms.map((alarm) => (
          <div key={alarm.id} style={{ borderLeft: `3px solid ${severityColor[alarm.severity] ?? "#475569"}`, background: "#0f172a", borderRadius: "4px", padding: "0.6rem 0.8rem", marginBottom: "0.4rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "2px" }}>
              <span style={{ color: severityColor[alarm.severity], fontSize: "0.75rem", fontWeight: 700, letterSpacing: "0.5px" }}>
                {alarm.severity.toUpperCase()}
              </span>
              <span style={{ color: "#475569", fontSize: "0.75rem" }}>
                {new Date(alarm.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <div style={{ color: "#cbd5e1", fontSize: "0.9rem" }}>{alarm.attack_type}</div>
            <div style={{ color: "#64748b", fontSize: "0.8rem", marginTop: "2px" }}>
              {alarm.src_ip} — Skor: {(alarm.score * 100).toFixed(0)}%
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
