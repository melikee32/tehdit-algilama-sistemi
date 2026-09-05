/**
 * shared/schema/dashboard.ts - Issue #31
 *
 * shared/schema/dashboard.py icindeki Pydantic modellerinin TypeScript
 * karsiliklari. Backend ve panel ayni sozlesmeyi kullansin diye ikisi
 * birlikte guncellenmelidir.
 *
 * Kullanim: frontend/src/types.ts bu dosyadan re-export edebilir veya
 * icerigi oraya kopyalanabilir (build ayarina gore).
 */

export type SeverityLevel = "low" | "medium" | "high" | "critical";

/** Alarmi hangi motorun urettigi. Panel filtrelemesi icin. */
export type DetectionSource = "rule" | "ml" | "both";

export type WSMessageType = "new_alarm" | "metrics_update" | "connection_ack";

/** Yeni alarm bildirimi (WebSocket) ve alarm listesi ogesi. */
export interface AlarmPayload {
  id: string;
  attack_type: string;
  severity: SeverityLevel;
  score: number;
  src_ip: string | null;
  timestamp: string;

  // Backend broadcast'i guncellenene kadar bunlar gelmeyebilir
  dst_ip?: string | null;
  description?: string | null;
  detection_source?: DetectionSource | null;
  rule_event_id?: string | null;
  ml_event_id?: string | null;
}

/** Panel ustundeki ozet kartlar ve grafikler. */
export interface ThreatMetrics {
  total_alarms: number;
  unacknowledged: number;

  /** ornegin { critical: 3, high: 12, medium: 40 } */
  severity_counts: Record<string, number>;
  /** ornegin { port_scan: 8, anomaly: 31 } */
  attack_type_counts: Record<string, number>;
  /** alarmi ureten motor: { rule: 10, ml: 25, both: 4 } */
  source_counts: Record<string, number>;

  alarms_last_hour: number;
  top_source_ips: Array<{ ip: string; count: number }>;
  generated_at: string;
}

export interface ConnectionAck {
  message: string;
  server_time: string;
  active_clients: number;
}

/** WebSocket mesaj zarfi. type alanina gore ayristirilir. */
export type WSMessage =
  | { type: "new_alarm"; data: AlarmPayload }
  | { type: "metrics_update"; data: ThreatMetrics }
  | { type: "connection_ack"; data: ConnectionAck };

/** GET /events yanitindaki ham tespit (korelasyon oncesi log akisi). */
export interface EventListItem {
  id: string;
  timestamp: string;
  source_engine: "rule" | "ml";
  attack_type: string;
  confidence: number;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: string | null;
  protocol?: string | null;
  description?: string | null;
  correlated: boolean;
}

export interface PaginatedAlarms {
  items: AlarmPayload[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

/**
 * WebSocket mesajlarini tip guvenli sekilde ayristirmak icin ornek:
 *
 *   ws.onmessage = (e) => {
 *     const msg: WSMessage = JSON.parse(e.data);
 *     switch (msg.type) {
 *       case "new_alarm":      addAlarm(msg.data); break;
 *       case "metrics_update": setMetrics(msg.data); break;
 *       case "connection_ack": setConnected(true); break;
 *     }
 *   };
 */