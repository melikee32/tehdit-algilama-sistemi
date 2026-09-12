export interface Alarm {
  id: string;
  attack_type: string;
  severity: "low" | "medium" | "high" | "critical";
  score: number;
  src_ip: string;
  dst_ip?: string;
  detection_source?: string;
  rule_event_id?: string;
  ml_event_id?: string;
  timestamp: string;
  acknowledged?: string;
}

export interface LogEntry {
  id: number;
  time: string;
  text: string;
  isAlarm: boolean;
}
