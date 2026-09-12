import { useEffect, useRef, useState } from "react";
import AlarmTable from "./components/AlarmTable";
import ThreatChart from "./components/ThreatChart";
import LogStream from "./components/LogStream";
import type { Alarm, LogEntry } from "./types";


const WS_URL = "ws://localhost:8000/ws";
const API_URL = "http://localhost:8000";

// YENI RENK PALETI (Yüksek = Turuncu, Kritik = Koyu Bordo)
const SEV_COLOR: Record<string, string> = { low: "#107c10", medium: "#ffb900", high: "#f7630c", critical: "#a4262c" };
const SEV_TR_UPPER: Record<string, string> = { low: "DÜŞÜK", medium: "ORTA", high: "YÜKSEK", critical: "KRİTİK" };
const IT_ACRONYMS: Record<string, string> = { sql: "SQL", ddos: "DDoS", xss: "XSS", ip: "IP" };

function KPIBox({ title, value, color }: { title: string; value: number | string; color: string }) {
  return (
    <div style={{ background: "#ffffff", border: "1px solid #edebe9", borderTop: `4px solid ${color}`, padding: "16px", display: "flex", flexDirection: "column" }}>
      <div style={{ fontSize: "12px", fontWeight: "600", color: "#605e5c", marginBottom: "8px", textTransform: "uppercase" }}>{title}</div>
      <div style={{ fontSize: "28px", fontWeight: "400", color: "#323130", lineHeight: "1" }}>{value}</div>
    </div>
  );
}

export default function App() {
  const [alarms, setAlarms] = useState<Alarm[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const [timeFilter, setTimeFilter] = useState("ALL");
  const wsRef = useRef<WebSocket | null>(null);

  const addLog = (text: string, isAlarm = false) => {
    setLogs(p => [{ id: Date.now() + Math.random(), time: new Date().toLocaleTimeString("tr-TR"), text, isAlarm }, ...p].slice(0, 100));
  };

  useEffect(() => { fetch(`${API_URL}/alarms`).then(r => r.json()).then(setAlarms).catch(console.error); }, []);
  
  useEffect(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    ws.onopen = () => { setConnected(true); addLog("[SİSTEM] Sunucu bağlantısı kuruldu ve dinleniyor."); };
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "new_alarm") {
        const a: Alarm = msg.data;
        setAlarms(p => [a, ...p]);
        const fmtName = a.attack_type.split('_').map(w => IT_ACRONYMS[w.toLowerCase()] || (w.charAt(0).toUpperCase() + w.slice(1))).join(' ');
        addLog(`[ALARM] ${fmtName} tehdidi tespit edildi. Kaynak: ${a.src_ip ?? "Bilinmiyor"}`, true);
      }
    };
    ws.onclose = () => { setConnected(false); addLog("[SİSTEM] Sunucu ile bağlantı kesildi. Tekrar deneniyor..."); };
    return () => ws.close();
  }, []);

  const filteredAlarms = alarms.filter(a => {
    if (timeFilter === "ALL") return true;
    const alarmTime = new Date(a.timestamp).getTime();
    const now = Date.now();
    if (timeFilter === "1H") return (now - alarmTime) <= (60 * 60 * 1000);
    if (timeFilter === "24H") return (now - alarmTime) <= (24 * 60 * 60 * 1000);
    if (timeFilter === "7D") return (now - alarmTime) <= (7 * 24 * 60 * 60 * 1000);
    return true;
  });

  const critCount = filteredAlarms.filter(a => a.severity === "critical").length;
  const highCount = filteredAlarms.filter(a => a.severity === "high").length;
  const medCount = filteredAlarms.filter(a => a.severity === "medium").length;

  return (
    <>
      <div className="no-print" style={{ minHeight: "100vh" }}>
        <div style={{ height: "48px", background: "#001433", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 20px", color: "#ffffff" }}>
          <div style={{ fontSize: "16px", fontWeight: "600", display: "flex", alignItems: "center" }}>
            SİBER SOC <span style={{ fontWeight: "400", margin: "0 12px", opacity: 0.6 }}>|</span> Tehdit Algılama Sistemi
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", fontWeight: "500" }}>
            <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: connected ? "#4ade80" : "#f85149", boxShadow: `0 0 8px ${connected ? "#4ade80" : "#f85149"}` }}></div>
            <span>{connected ? "Sistem Aktif (Canlı)" : "Bağlantı Kesik"}</span>
          </div>
        </div>

        <div style={{ padding: "24px", display: "flex", flexDirection: "column", gap: "20px", maxWidth: "1600px", margin: "0 auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ fontSize: "20px", fontWeight: "400" }}>Güvenlik İzleme ve Olay Yönetimi</div>
            
            <div style={{ display: "flex", gap: "12px" }}>
              <select 
                value={timeFilter} 
                onChange={(e) => setTimeFilter(e.target.value)}
                style={{ padding: "8px 12px", background: "#ffffff", border: "1px solid #edebe9", fontSize: "13px", cursor: "pointer", outline: "none", minWidth: "140px", fontWeight: "500" }}
              >
                <option value="1H">Son 1 Saat</option>
                <option value="24H">Son 24 Saat</option>
                <option value="7D">Son 7 Gün</option>
                <option value="ALL">Tüm Zamanlar</option>
              </select>
              <button onClick={() => window.print()} style={{ padding: "8px 16px", background: "#0078d4", color: "#ffffff", fontSize: "13px", border: "none", cursor: "pointer", display: "flex", alignItems: "center", gap: "8px", fontWeight: "600" }}>
                Rapor İndir
              </button>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px" }}>
            <KPIBox title="Toplam Vaka" value={filteredAlarms.length} color="#0078d4" />
            <KPIBox title="Kritik Riskli" value={critCount} color={SEV_COLOR["critical"]} />
            <KPIBox title="Yüksek Riskli" value={highCount} color={SEV_COLOR["high"]} />
            <KPIBox title="Orta Riskli" value={medCount} color={SEV_COLOR["medium"]} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: "16px" }}>
            <div style={{ background: "#ffffff", border: "1px solid #edebe9", padding: "16px", display: "flex", flexDirection: "column" }}>
              <div style={{ fontSize: "14px", fontWeight: "600", marginBottom: "16px" }}>Risk Seviyesi Dağılımı</div>
              <div style={{ height: "250px", position: "relative" }}><ThreatChart alarms={filteredAlarms} /></div>
            </div>
            <div style={{ background: "#ffffff", border: "1px solid #edebe9", padding: "16px", display: "flex", flexDirection: "column" }}>
              <div style={{ fontSize: "14px", fontWeight: "600", marginBottom: "16px" }}>Son Olaylar</div>
              <div style={{ flex: 1, overflow: "hidden" }}><AlarmTable alarms={filteredAlarms} /></div>
            </div>
          </div>

          <div style={{ background: "#ffffff", border: "1px solid #edebe9", padding: "16px" }}>
            <div style={{ fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>Canlı Sistem Kayıtları</div>
            <LogStream logs={logs} />
          </div>
        </div>
      </div>

      <div className="print-only" style={{ padding: "40px" }}>
        <div style={{ borderBottom: "3px solid #001433", paddingBottom: "20px", marginBottom: "30px", display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: "28px", color: "#001433", letterSpacing: "1px" }}>SİBER SOC Olay Raporu</h1>
            <p style={{ margin: "8px 0 0", color: "#555", fontSize: "14px" }}>Tehdit Algılama Sistemi Resmi Sistem Dökümü</p>
          </div>
          <div style={{ textAlign: "right", fontSize: "12px", color: "#444", lineHeight: "1.6" }}>
            <strong>Oluşturulma Tarihi:</strong> {new Date().toLocaleString("tr-TR")}<br/>
            <strong>Yetkili Analist:</strong> SOC Analisti<br/>
            <strong>Zaman Filtresi:</strong> {timeFilter === "ALL" ? "Tüm Zamanlar" : timeFilter === "24H" ? "Son 24 Saat" : timeFilter === "1H" ? "Son 1 Saat" : "Son 7 Gün"}
          </div>
        </div>
        
        <h2 style={{ fontSize: "18px", borderBottom: "1px solid #ccc", paddingBottom: "8px", color: "#333" }}>Yönetici Özeti</h2>
        <div style={{ display: "flex", gap: "20px", marginBottom: "30px" }}>
          <div style={{ padding: "16px", background: "#f8f9fa", border: "1px solid #e9ecef", flex: 1, borderRadius: "4px" }}>
            <div style={{ fontSize: "12px", color: "#666" }}>TOPLAM İNCELENEN VAKA</div>
            <div style={{ fontSize: "24px", fontWeight: "bold" }}>{filteredAlarms.length}</div>
          </div>
          <div style={{ padding: "16px", background: "#fff5f5", border: `1px solid ${SEV_COLOR["critical"]}40`, flex: 1, borderRadius: "4px" }}>
            <div style={{ fontSize: "12px", color: SEV_COLOR["critical"] }}>KRİTİK RİSKLİ MÜDAHALE</div>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: SEV_COLOR["critical"] }}>{critCount}</div>
          </div>
          <div style={{ padding: "16px", background: "#fff4e6", border: `1px solid ${SEV_COLOR["high"]}40`, flex: 1, borderRadius: "4px" }}>
            <div style={{ fontSize: "12px", color: SEV_COLOR["high"] }}>YÜKSEK RİSKLİ TEHDİT</div>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: SEV_COLOR["high"] }}>{highCount}</div>
          </div>
        </div>

        <h2 style={{ fontSize: "18px", borderBottom: "1px solid #ccc", paddingBottom: "8px", marginBottom: "16px", color: "#333" }}>Detaylı Tehdit Logları (Sınıflandırılmış)</h2>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
          <thead>
            <tr style={{ background: "#f1f3f5", color: "#495057" }}>
              <th style={{ padding: "12px 10px", borderBottom: "2px solid #dee2e6" }}>Tarih / Saat</th>
              <th style={{ padding: "12px 10px", borderBottom: "2px solid #dee2e6" }}>Saldırı Karakteristiği</th>
              <th style={{ padding: "12px 10px", borderBottom: "2px solid #dee2e6" }}>Kaynak IP Adresi</th>
              <th style={{ padding: "12px 10px", borderBottom: "2px solid #dee2e6" }}>Algoritma Skoru</th>
              <th style={{ padding: "12px 10px", borderBottom: "2px solid #dee2e6" }}>Risk Durumu</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlarms.map(a => {
              const fmtName = a.attack_type.split('_').map(w => IT_ACRONYMS[w.toLowerCase()] || (w.charAt(0).toUpperCase() + w.slice(1))).join(' ');
              return (
                <tr key={a.id}>
                  <td style={{ padding: "10px", borderBottom: "1px solid #e9ecef" }}>{new Date(a.timestamp).toLocaleString("tr-TR")}</td>
                  <td style={{ padding: "10px", borderBottom: "1px solid #e9ecef", fontWeight: "bold" }}>{fmtName}</td>
                  <td style={{ padding: "10px", borderBottom: "1px solid #e9ecef", fontFamily: "monospace" }}>{a.src_ip}</td>
                  <td style={{ padding: "10px", borderBottom: "1px solid #e9ecef" }}>%{(a.score * 100).toFixed(0)}</td>
                  <td style={{ padding: "10px", borderBottom: "1px solid #e9ecef", color: SEV_COLOR[a.severity], fontWeight: "bold" }}>{SEV_TR_UPPER[a.severity]}</td>
                </tr>
              )
            })}
            {filteredAlarms.length === 0 && <tr><td colSpan={5} style={{ padding: "30px", textAlign: "center", color: "#888" }}>Belirtilen filtre aralığında veri bulunamadı.</td></tr>}
          </tbody>
        </table>
        
        <div style={{ marginTop: "50px", fontSize: "11px", color: "#888", textAlign: "center", borderTop: "1px solid #eee", paddingTop: "15px" }}>
          Bu rapor, Siber SOC otomasyon sistemi tarafından otomatik oluşturulmuştur ve dijital olarak loglanmıştır. İzinsiz kopyalanamaz.
        </div>
      </div>
    </>
  );
}

