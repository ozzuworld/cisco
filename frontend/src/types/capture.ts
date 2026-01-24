// Packet Capture Types

export type CaptureStatus = 'pending' | 'running' | 'stopping' | 'completed' | 'failed' | 'cancelled'

export type CaptureProtocol = 'ip' | 'arp' | 'rarp' | 'all'

export type CaptureDeviceType = 'cucm' | 'cube' | 'csr1000v' | 'expressway'

// Filter for packet capture
export interface CaptureFilter {
  host?: string        // Filter by host IP (bidirectional)
  src?: string         // Filter by source IP (cannot use with host)
  dest?: string        // Filter by destination IP (cannot use with host)
  port?: number        // Filter by port number (1-65535)
  protocol?: CaptureProtocol  // Protocol filter (default: "ip")
}

// Request to start a packet capture
export interface StartCaptureRequest {
  device_type?: CaptureDeviceType // Device type: cucm or csr1000v (default: cucm)
  host: string                    // Device IP/FQDN
  port?: number                   // SSH port (default: 22)
  username: string                // SSH username
  password: string                // SSH password
  duration_sec: number            // Capture duration 10-600 seconds
  interface?: string              // Network interface (cucm: eth0, csr1000v: GigabitEthernet1)
  filename?: string               // Custom filename (auto-generated if not provided)
  filter?: CaptureFilter          // Optional packet filter
  packet_count?: number           // Max packets 100-100000 (default: 100000)
  connect_timeout_sec?: number    // SSH timeout 5-120 (default: 30)
}

// Capture information
export interface CaptureInfo {
  capture_id: string
  device_type?: CaptureDeviceType
  status: CaptureStatus
  host: string
  port: number
  interface: string
  filename: string
  duration_sec: number
  filter?: CaptureFilter
  created_at: string
  started_at?: string
  completed_at?: string
  packets_captured?: number
  file_size_bytes?: number
  error?: string
}

// Response types
export interface StartCaptureResponse {
  capture_id: string
  status: CaptureStatus
  message: string
}

export interface CaptureStatusResponse {
  capture: CaptureInfo
}

export interface CaptureListResponse {
  captures: CaptureInfo[]
  total: number
}

export interface StopCaptureResponse {
  capture_id: string
  status: CaptureStatus
  message: string
}

// ==========================================
// Orchestrated Capture Session Types
// ==========================================

// Session status values
export type CaptureSessionStatus =
  | 'pending'      // Created, not started
  | 'configuring'  // Connecting to devices, configuring CSR EPC
  | 'ready'        // All devices ready (brief moment before capture)
  | 'starting'     // Sending start commands
  | 'capturing'    // Active capture - show countdown timer!
  | 'stopping'     // Stopping captures
  | 'collecting'   // Retrieving files from devices
  | 'completed'    // Done - download available
  | 'partial'      // Some devices succeeded - download available
  | 'failed'       // All devices failed
  | 'cancelled'    // User cancelled

// Per-target status values
export type CaptureTargetStatus =
  | 'pending'
  | 'configuring'  // CSR only: takes ~150 seconds
  | 'ready'
  | 'capturing'
  | 'stopping'
  | 'collecting'
  | 'completed'
  | 'failed'
  | 'cancelled'

// Target request for multi-device capture
export interface CaptureTargetRequest {
  device_type: CaptureDeviceType
  host: string
  port?: number
  interface?: string
  username?: string   // Per-device credentials
  password?: string   // Per-device credentials
}

// Start capture session request
export interface StartCaptureSessionRequest {
  name?: string
  duration_sec: number
  filter?: CaptureFilter
  targets: CaptureTargetRequest[]
  username?: string   // Optional global credentials (fallback)
  password?: string   // Optional global credentials (fallback)
}

// Target info in session response
export interface CaptureTargetInfo {
  device_type: CaptureDeviceType
  host: string
  port: number
  interface: string
  status: CaptureTargetStatus
  error?: string
  message?: string
  config_started_at?: string   // ISO timestamp
  capture_started_at?: string  // ISO timestamp - USE FOR TIMELINE
  capture_stopped_at?: string  // ISO timestamp
  completed_at?: string        // ISO timestamp
  packets_captured?: number
  file_size_bytes?: number
  filename?: string
}

// Session info
export interface CaptureSessionInfo {
  session_id: string
  name?: string
  status: CaptureSessionStatus
  created_at: string
  capture_started_at?: string
  completed_at?: string
  duration_sec: number
  targets: CaptureTargetInfo[]
  bundle_filename?: string
}

// Session responses
export interface StartCaptureSessionResponse {
  session_id: string
  status: CaptureSessionStatus
  message: string
  created_at: string
  targets: CaptureTargetInfo[]
}

export interface CaptureSessionStatusResponse {
  session: CaptureSessionInfo
  download_available: boolean
  elapsed_sec?: number    // Only during 'capturing' status
  remaining_sec?: number  // Only during 'capturing' status
}

export interface CaptureSessionListResponse {
  sessions: CaptureSessionInfo[]
  total: number
}

export interface StopCaptureSessionResponse {
  session_id: string
  status: CaptureSessionStatus
  message: string
}

// Helper functions
export function shouldPollCaptureSession(status: CaptureSessionStatus): boolean {
  return !['completed', 'partial', 'failed', 'cancelled'].includes(status)
}

export function getSessionPollingInterval(status: CaptureSessionStatus): number {
  switch (status) {
    case 'pending':
    case 'configuring':
    case 'ready':
    case 'starting':
      return 1000  // 1 second - config phase
    case 'capturing':
      return 2000  // 2 seconds - show countdown
    case 'stopping':
    case 'collecting':
      return 1000  // 1 second - finishing up
    default:
      return 2000
  }
}

export function canDownloadSession(status: CaptureSessionStatus): boolean {
  return status === 'completed' || status === 'partial'
}

// Default interfaces by device type
export const defaultCaptureInterfaces: Record<CaptureDeviceType, string> = {
  cucm: 'eth0',
  cube: 'GigabitEthernet1',
  csr1000v: 'GigabitEthernet1',
  expressway: 'eth0',
}

// Default ports by device type
export const defaultCapturePorts: Record<CaptureDeviceType, number> = {
  cucm: 22,
  cube: 22,
  csr1000v: 22,
  expressway: 443,
}
