export interface Device {
  ip_address: string
  mac_address: string
  vendor: string | null
  hostname: string | null
  device_type: string | null
  device_name: string | null
  first_seen: string
  last_seen: string
  last_arp_time: string | null
  total_packets: number
  total_bytes: number
  port_count: number
  is_online: boolean
  open_ports?: Port[]
  netbios_info?: NetBIOSInfo
  security_anomalies?: SecurityAnomaly[]
  recent_arp_events?: ARPEvent[]
}

export interface Port {
  port: number
  protocol: string
  state: string
  service: string | null
  version: string | null
}

export interface NetBIOSInfo {
  workgroup: string | null
  server_name: string | null
  domain: string | null
  os_version: string | null
  smb_signing: boolean | null
  smb_version: string | null
}

export interface SecurityAnomaly {
  id: number
  ip_address: string
  anomaly_type: string
  description: string
  severity: string
  first_detected: string
  last_detected: string
  occurrence_count: number
}

export interface ARPEvent {
  timestamp: string
  event_type: string
  details: string
}

export interface TimelineEvent {
  id: number
  timestamp: string
  event_type: string
  ip_address: string | null
  mac_address: string | null
  description: string
  metadata: Record<string, any>
}

export interface SpeedTest {
  id: number
  timestamp: string
  download_speed: number
  upload_speed: number
  ping: number
  jitter: number | null
  packet_loss: number | null
  server_name: string | null
  server_location: string | null
  result_url: string | null
  trigger_type: string
  isp: string | null
  external_ip: string | null
  download_latency_iqm: number | null
  download_latency_low: number | null
  download_latency_high: number | null
  upload_latency_iqm: number | null
  upload_latency_low: number | null
  upload_latency_high: number | null
}

export interface SpeedTestStatistics {
  avg_download: number
  avg_upload: number
  avg_ping: number
  min_download: number
  max_download: number
  min_upload: number
  max_upload: number
  min_ping: number
  max_ping: number
  test_count: number
}

export interface NetworkInfo {
  isp: string | null
  external_ip: string | null
  location: {
    city: string | null
    region: string | null
    country: string | null
    timezone: string | null
  }
}

export interface Statistics {
  total_devices: number
  online_devices: number
  offline_devices: number
  total_packets: number
  total_bytes: number
}
