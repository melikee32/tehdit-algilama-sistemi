export interface Alarm {
  id: string;
  attack_type: string;
  severity: "low" | "medium" | "high" | "critical";
  score: number;
  src_ip: string;
  timestamp: string;
  acknowledged?: string;
}
