// API Response Types based on CUCM Backend

export interface ClusterNode {
  ip: string
  fqdn: string
  host: string
  role: string
  product?: string
  dbrole?: string
  raw?: string
}

export interface DiscoverResponse {
  nodes: ClusterNode[]
}

export interface LogProfile {
  id: string
  name: string
  description: string
  logTypes: string[]
  isCustom: boolean
}

export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface Job {
  id: string
  clusterId: string
  clusterName: string
  profileId: string
  profileName: string
  status: JobStatus
  createdAt: string
  startedAt?: string
  completedAt?: string
  duration?: number
  nodes: string[]
  progress?: number
  error?: string
}

export interface JobDetails extends Job {
  transcript: string[]
  logs: LogFile[]
}

export interface LogFile {
  filename: string
  size: number
  path: string
  nodeHostname: string
  collectedAt: string
}

export interface ConnectionRequest {
  hostname: string
  username: string
  password: string
  port?: number
}

export interface CreateJobRequest {
  publisher_host: string
  username: string
  password: string
  port?: number
  nodes: string[]
  profile: string
  options?: CollectionOptions
}

export type DebugLevel = 'basic' | 'detailed' | 'verbose'

export interface CollectionOptions {
  time_mode?: 'relative' | 'range'
  reltime_minutes?: number
  start_time?: string
  end_time?: string
  debug_level?: DebugLevel
  compress?: boolean
  recurs?: boolean
  match?: string
}

export interface ApiError {
  message: string
  code: string
  details?: Record<string, unknown>
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
  totalPages: number
}
