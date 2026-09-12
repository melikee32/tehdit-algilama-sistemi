interface Alarm { severity: "low" | "medium" | "high" | "critical"; }
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

// 2. HATA COZUMU: Siralama "Kritik, Yuksek, Orta, Dusuk" olarak duzeltildi
const SEV_TR = ["Kritik", "Yüksek", "Orta", "Düşük"];
const SEV_KEY = ["critical", "high", "medium", "low"];
const SEV_COLOR = ["#a4262c", "#f7630c", "#ffb900", "#107c10"];

export default function ThreatChart({ alarms }: { alarms: Alarm[] }) {
  const counts = alarms.reduce<Record<string, number>>((acc, a) => { acc[a.severity] = (acc[a.severity] ?? 0) + 1; return acc; }, {});
  const data = SEV_KEY.map((k, i) => ({ name: SEV_TR[i], value: counts[k] ?? 0, color: SEV_COLOR[i] })).filter(d => d.value > 0);

  if (data.length === 0) return <div style={{ textAlign: "center", marginTop: "100px" }}>Veri yok</div>;

  return (
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} cx="50%" cy="48%" innerRadius={70} outerRadius={90} paddingAngle={2} dataKey="value" stroke="#ffffff" strokeWidth={2}>
            {data.map((d, i) => ( <Cell key={i} fill={d.color} /> ))}
          </Pie>
          <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #edebe9", borderRadius: "0px" }} />
          <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: "12px" }} />
        </PieChart>
      </ResponsiveContainer>
      
      <div style={{ position: "absolute", top: "43%", left: "50%", paddingLeft: "4px", transform: "translate(-50%, -50%)", textAlign: "center", pointerEvents: "none" }}>
        <div style={{ fontSize: "28px", fontWeight: "600", lineHeight: "1" }}>{alarms.length}</div>
        <div style={{ fontSize: "10px", fontWeight: "600", marginTop: "2px", letterSpacing: "1px" }}>TOPLAM</div>
      </div>
    </div>
  );
}

