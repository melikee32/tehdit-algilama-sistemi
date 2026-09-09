interface Alarm { 
  id: string; 
  attack_type: string; 
  severity: "low" | "medium" | "high" | "critical"; 
  score: number; 
  src_ip: string; 
  dst_ip?: string; 
  rule_event_id?: string; 
  ml_event_id?: string; 
  timestamp: string; 
}
const SEV_TR: Record<string, string> = { low: "Düşük", medium: "Orta", high: "Yüksek", critical: "Kritik" };
const SEV_COLOR: Record<string, string> = { low: "#107c10", medium: "#ffb900", high: "#f7630c", critical: "#a4262c" };
const IT_ACRONYMS: Record<string, string> = { sql: "SQL", ddos: "DDoS", xss: "XSS", ip: "IP", ssh: "SSH", ftp: "FTP" };

const formatName = (s: string) => s.split('_').map(w => {
  const lower = w.toLowerCase();
  if (IT_ACRONYMS[lower]) return IT_ACRONYMS[lower];
  return w.charAt(0).toUpperCase() + w.slice(1);
}).join(' ');

export default function AlarmTable({ alarms }: { alarms: Alarm[] }) {
  return (
    <div style={{ overflowY: "auto", height: "250px", paddingRight: "4px" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
        <thead style={{ position: "sticky", top: 0, background: "#ffffff", zIndex: 1 }}>
          <tr>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Risk Seviyesi</th>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Saldırı Tipi</th>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Kaynak IP</th>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Hedef IP</th>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Tespit Kaynağı</th>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Güven Skoru</th>
            <th style={{ padding: "8px 12px", fontWeight: "600", borderBottom: "2px solid #edebe9", textAlign: "left" }}>Tarih / Saat</th>
          </tr>
        </thead>
        <tbody>
          {alarms.map((a) => (
            <tr key={a.id} className="hover-row" style={{ borderBottom: "1px solid #edebe9" }}>
              <td style={{ padding: "10px 12px", fontWeight: "600", color: SEV_COLOR[a.severity] }}>
                <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: SEV_COLOR[a.severity], marginRight: "8px" }}></span>
                {SEV_TR[a.severity]}
              </td>
              <td style={{ padding: "10px 12px", fontWeight: "500" }}>{formatName(a.attack_type)}</td>
              <td style={{ padding: "10px 12px", color: "#0078d4" }}>{a.src_ip || "-"}</td>
              <td style={{ padding: "10px 12px", color: "#0078d4" }}>{a.dst_ip || "-"}</td>
              <td style={{ padding: "10px 12px", fontWeight: "500", color: "#605e5c" }}>
                {(a.rule_event_id && a.ml_event_id) ? "Hibrit (AI + Kural)" : a.ml_event_id ? "Makine Öğrenmesi" : a.rule_event_id ? "Kural Motoru" : "-"}
              </td>
              <td style={{ padding: "10px 12px", textAlign: "left" }}>%{(a.score * 100).toFixed(0)}</td>
              <td style={{ padding: "10px 12px", fontSize: "12px", textAlign: "left" }}>{new Date(a.timestamp).toLocaleString("tr-TR")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
