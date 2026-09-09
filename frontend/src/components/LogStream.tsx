export interface LogEntry { id: number; time: string; text: string; isAlarm: boolean; }

export default function LogStream({ logs }: { logs: LogEntry[] }) {
  return (
    <div style={{ height: "140px", overflowY: "auto", fontSize: "13px", fontFamily: "Consolas, monospace" }}>
      {logs.length === 0 && <div style={{ color: "#605e5c" }}>Sistem bekleniyor...</div>}
      {logs.map((log) => (
        <div key={log.id} style={{ padding: "6px 0", borderBottom: "1px solid #f3f2f1", display: "flex", gap: "12px" }}>
          <span style={{ color: "#a19f9d" }}>[{log.time}]</span>
          <span style={{ color: log.isAlarm ? "#d13438" : "#323130", fontWeight: log.isAlarm ? "600" : "400" }}>
            {log.text}
          </span>
        </div>
      ))}
    </div>
  );
}
