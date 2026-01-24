// Log Collection Types for CUBE/Expressway

export type LogDeviceType = 'cube' | 'expressway'

export type LogCollectionStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

// Device-specific profile (CUBE or Expressway)
export interface DeviceProfile {
  name: string
  description: string
  device_type: LogDeviceType
  method: string
  // CUBE-specific
  commands?: string[]
  include_debug?: boolean
  duration_sec?: number | null
  // Expressway-specific
  tcpdump?: boolean
}

// Response from GET /logs/profiles
export interface DeviceProfilesResponse {
  cube_profiles: DeviceProfile[]
  expressway_profiles: DeviceProfile[]
}

// CUBE/Expressway Log Collection
export interface StartLogCollectionRequest {
  device_type: LogDeviceType
  host: string
  port?: number
  username: string
  password: string
  profile?: string              // Profile name from GET /logs/profiles
  include_debug?: boolean       // Legacy: VoIP trace (false) vs Debug mode (true)
  duration_sec?: number         // For debug mode (5-300)
  connect_timeout_sec?: number
}

export interface LogCollectionInfo {
  collection_id: string
  device_type: LogDeviceType
  status: LogCollectionStatus
  host: string
  port: number
  profile?: string
  method?: string
  include_debug?: boolean
  created_at: string
  started_at?: string
  completed_at?: string
  file_count?: number
  file_size_bytes?: number
  total_size_bytes?: number
  error?: string
  files?: LogFileInfo[]
  download_available?: boolean  // Backend includes this inside collection object
}

export interface LogFileInfo {
  filename: string
  size_bytes: number
  collected_at: string
}

export interface StartLogCollectionResponse {
  collection_id: string
  status: LogCollectionStatus
  host: string
  device_type: LogDeviceType
  message: string
  created_at: string
}

export interface LogCollectionStatusResponse {
  collection: LogCollectionInfo
  download_available: boolean
}

export interface LogCollectionListResponse {
  collections: LogCollectionInfo[]
  total: number
}

// CUCM Cluster Discovery Request (uses existing ClusterNode from api.ts)
export interface DiscoverNodesRequest {
  publisher_host: string
  username: string
  password: string
  port?: number
}

// Re-export for convenience - actual types are in api.ts
// DiscoverResponse and ClusterNode are already defined in api.ts

// CUCM Job time range
export interface TimeRange {
  type: 'relative' | 'absolute'
  relative_minutes?: number   // For relative: last N minutes
  start_time?: string         // For absolute: ISO date string
  end_time?: string           // For absolute: ISO date string
}
