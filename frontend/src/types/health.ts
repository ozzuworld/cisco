// Cluster Health Status Types

export type HealthStatus = 'healthy' | 'degraded' | 'critical' | 'unknown'
export type HealthCheckType = 'replication' | 'services' | 'ntp' | 'diagnostics' | 'cores'

// Request Types
export interface ClusterHealthRequest {
  publisher_host: string
  port?: number
  username: string
  password: string
  connect_timeout_sec?: number
  command_timeout_sec?: number
  nodes?: string[]
  checks?: HealthCheckType[]
}

// Response Types
export interface ClusterHealthResponse {
  cluster_status: HealthStatus
  publisher_host: string
  checked_at: string
  total_nodes: number
  healthy_nodes: number
  degraded_nodes: number
  critical_nodes: number
  unreachable_nodes: number
  nodes: NodeHealthStatus[]
  checks_performed: HealthCheckType[]
  message: string | null
}

export interface NodeHealthStatus {
  ip: string
  hostname: string | null
  role: 'Publisher' | 'Subscriber' | null
  status: HealthStatus
  reachable: boolean
  error: string | null
  checks: {
    replication?: ReplicationStatus
    services?: ServicesStatus
    ntp?: NTPStatus
    diagnostics?: DiagnosticsStatus
    cores?: CoreFilesStatus
  }
  checked_at: string
}

// Replication Check
export interface ReplicationStatus {
  status: HealthStatus
  checked_at: string
  db_version: string | null
  repl_timeout: number | null
  tables_checked: number | null
  tables_total: number | null
  errors_found: boolean
  mismatches_found: boolean
  nodes: ReplicationNodeStatus[]
  message: string | null
}

export interface ReplicationNodeStatus {
  server_name: string
  ip_address: string
  ping_ms: number | null
  db_mon: string | null
  repl_queue: number | null
  group_id: string | null
  setup_state: number | null
  setup_status: string | null
}

// Services Check
export interface ServicesStatus {
  status: HealthStatus
  checked_at: string
  total_services: number
  running_services: number
  stopped_services: number
  critical_services_down: string[]
  services: ServiceInfo[]
  message: string | null
}

export interface ServiceInfo {
  name: string
  status: 'STARTED' | 'STOPPED' | 'STARTING' | 'STOPPING' | 'NOT ACTIVATED'
  is_running: boolean
}

// NTP Check
export interface NTPStatus {
  status: HealthStatus
  checked_at: string
  synchronized: boolean
  stratum: number | null
  ntp_server: string | null
  offset_ms: number | null
  message: string | null
}

// Diagnostics Check
export interface DiagnosticsStatus {
  status: HealthStatus
  checked_at: string
  total_tests: number
  passed_tests: number
  failed_tests: number
  tests: DiagnosticTest[]
  message: string | null
}

export interface DiagnosticTest {
  name: string
  passed: boolean
  message: string | null
}

// Core Files Check
export interface CoreFilesStatus {
  status: HealthStatus
  checked_at: string
  core_count: number
  core_files: string[]
  message: string | null
}

// ==========================================
// Multi-Device Health Check Types
// ==========================================

export type DeviceType = 'cucm' | 'cube' | 'expressway'

// Check types for each device
export type CUCMHealthCheck = 'replication' | 'services' | 'ntp' | 'diagnostics' | 'cores'
export type CUBEHealthCheck = 'system' | 'environment' | 'interfaces' | 'voice_calls' | 'sip_status' | 'sip_registration' | 'dsp' | 'ntp' | 'redundancy'
export type ExpresswayHealthCheck = 'cluster' | 'licensing' | 'alarms' | 'ntp'

// Request types
export interface DeviceHealthTarget {
  device_type: DeviceType
  host: string
  port?: number
  username?: string
  password?: string
  cucm_checks?: CUCMHealthCheck[]
  cube_checks?: CUBEHealthCheck[]
  expressway_checks?: ExpresswayHealthCheck[]
}

export interface DeviceHealthRequest {
  devices: DeviceHealthTarget[]
  username?: string
  password?: string
  connect_timeout_sec?: number
  command_timeout_sec?: number
}

// Response types
export interface DeviceHealthResponse {
  overall_status: HealthStatus
  checked_at: string
  message: string
  total_devices: number
  healthy_devices: number
  degraded_devices: number
  critical_devices: number
  unknown_devices: number
  devices: DeviceHealthResult[]
}

export interface DeviceHealthResult {
  device_type: DeviceType
  host: string
  status: HealthStatus
  reachable: boolean
  checked_at: string
  message: string
  error?: string
  cucm_checks?: CUCMCheckResults
  cube_checks?: CUBECheckResults
  expressway_checks?: ExpresswayCheckResults
}

// CUCM Check Results (reuse existing types where possible)
export interface CUCMCheckResults {
  replication?: ReplicationStatus
  services?: ServicesStatus
  ntp?: NTPStatus
  diagnostics?: DiagnosticsStatus
  cores?: CoreFilesStatus
}

// CUBE/IOS-XE Check Results
export interface CUBECheckResults {
  system?: CUBESystemStatus
  environment?: CUBEEnvironmentStatus
  interfaces?: CUBEInterfacesStatus
  voice_calls?: CUBEVoiceCallsStatus
  sip_status?: CUBESIPStatus
  sip_registration?: CUBESIPRegistrationStatus
  dsp?: CUBEDSPStatus
  ntp?: CUBENTPStatus
  redundancy?: CUBERedundancyStatus
}

export interface CUBESystemStatus {
  status: HealthStatus
  hostname?: string
  version?: string
  uptime_seconds?: number
  message?: string
}

export interface CUBEEnvironmentStatus {
  status: HealthStatus
  temperature_ok?: boolean
  power_ok?: boolean
  message?: string
}

export interface CUBEInterfacesStatus {
  status: HealthStatus
  total_interfaces?: number
  up_interfaces?: number
  down_interfaces?: number
  interfaces?: Array<{
    name: string
    status: 'up' | 'down' | 'administratively down'
    ip_address?: string
  }>
  message?: string
}

export interface CUBEVoiceCallsStatus {
  status: HealthStatus
  active_calls?: number
  total_calls?: number
  message?: string
}

export interface CUBESIPStatus {
  status: HealthStatus
  active_calls?: number
  total_registrations?: number
  message?: string
}

export interface CUBESIPRegistrationStatus {
  status: HealthStatus
  registered_endpoints?: number
  message?: string
}

export interface CUBEDSPStatus {
  status: HealthStatus
  dsp_utilization?: number
  message?: string
}

export interface CUBENTPStatus {
  status: HealthStatus
  synchronized?: boolean
  stratum?: number
  message?: string
}

export interface CUBERedundancyStatus {
  status: HealthStatus
  ha_enabled?: boolean
  peer_status?: string
  message?: string
}

// Expressway Check Results
export interface ExpresswayCheckResults {
  cluster?: ExpresswayClusterStatus
  licensing?: ExpresswayLicensingStatus
  alarms?: ExpresswayAlarmsStatus
  ntp?: ExpresswayNTPStatus
}

export interface ExpresswayClusterStatus {
  status: HealthStatus
  peer_count?: number
  all_peers_active?: boolean
  peers?: Array<{
    address: string
    status: 'active' | 'inactive' | 'unknown'
  }>
  message?: string
}

export interface ExpresswayLicensingStatus {
  status: HealthStatus
  license_valid?: boolean
  days_remaining?: number
  message?: string
}

export interface ExpresswayAlarmsStatus {
  status: HealthStatus
  alarm_count?: number
  critical_count?: number
  warning_count?: number
  alarms?: Array<{
    severity: 'critical' | 'warning' | 'info'
    description: string
  }>
  message?: string
}

export interface ExpresswayNTPStatus {
  status: HealthStatus
  synchronized?: boolean
  stratum?: number
  message?: string
}

// Default checks for each device type
export const defaultCUCMChecks: CUCMHealthCheck[] = ['services', 'ntp', 'diagnostics']
export const defaultCUBEChecks: CUBEHealthCheck[] = ['system', 'interfaces', 'voice_calls', 'sip_status', 'ntp']
export const defaultExpresswayChecks: ExpresswayHealthCheck[] = ['cluster', 'licensing', 'alarms', 'ntp']
