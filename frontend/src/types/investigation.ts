import type { EnvironmentDeviceType } from './environment'

export type InvestigationStatus =
  | 'created'
  | 'preparing'
  | 'ready'
  | 'recording'
  | 'collecting'
  | 'bundling'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled'

export type InvestigationDeviceStatus =
  | 'pending'
  | 'preparing'
  | 'ready'
  | 'recording'
  | 'collecting'
  | 'completed'
  | 'failed'
  | 'skipped'

export interface InvestigationDevice {
  device_id: string
  name: string
  host: string
  device_type: EnvironmentDeviceType
  port: number
  interface: string
  status: InvestigationDeviceStatus
  current_operation?: string
  error?: string
  message?: string
}

export interface InvestigationPhase {
  name: string
  status: string
  started_at?: string
  completed_at?: string
  message?: string
}

export interface InvestigationEvent {
  timestamp: string
  message: string
  level: string
}

export interface InlineDevice {
  name: string
  device_type: EnvironmentDeviceType
  host: string
  port?: number
  interface?: string
  role?: string
}

export interface CreateInvestigationRequest {
  name: string
  scenario: string
  environment_id?: string
  device_ids?: string[]
  inline_devices?: InlineDevice[]
  operations: string[]
  cucm_profile?: string
  expressway_profile?: string
  trace_level?: string
  capture_mode?: string
  capture_duration_sec?: number
  capture_filter?: {
    host?: string
    src?: string
    dest?: string
    port?: number
    protocol?: string
  }
  health_checks?: string[]
  credentials: Record<string, { username: string; password: string }>
}

export interface CreateInvestigationResponse {
  investigation_id: string
  status: InvestigationStatus
  message: string
  created_at: string
}

export interface InvestigationStatusResponse {
  investigation_id: string
  name: string
  scenario: string
  status: InvestigationStatus
  environment_id: string
  devices: InvestigationDevice[]
  phases: InvestigationPhase[]
  active_phases: string[]
  operations: string[]
  capture_session_id?: string
  job_ids: string[]
  log_collection_ids: string[]
  health_results?: Record<string, unknown>
  capture_duration_sec?: number
  recording_started_at?: string
  created_at: string
  started_at?: string
  completed_at?: string
  bundle_path?: string
  download_available: boolean
  events: InvestigationEvent[]
}

export interface InvestigationSummary {
  investigation_id: string
  name: string
  scenario: string
  status: InvestigationStatus
  device_count: number
  created_at: string
  completed_at?: string
  download_available: boolean
}

export interface InvestigationListResponse {
  investigations: InvestigationSummary[]
  total: number
}

export interface ScenarioTemplate {
  name: string
  display_name: string
  description?: string
  device_types: EnvironmentDeviceType[]
  operations: string[]
  cucm_profile?: string
  expressway_profile?: string
  trace_level?: string
  capture_mode?: string
  capture_duration_sec?: number
  health_checks?: string[]
}

export interface ScenarioListResponse {
  scenarios: ScenarioTemplate[]
}
