import { apiClient } from './api'
import type { DebugLevel } from '@/types'

// Request types
export interface TraceLevelGetRequest {
  hosts: string[]
  username: string
  password: string
  port?: number
  connect_timeout_sec?: number
  services?: string[]
}

export interface TraceLevelSetRequest {
  hosts: string[]
  username: string
  password: string
  level: DebugLevel  // "basic" | "detailed" | "verbose"
  port?: number
  connect_timeout_sec?: number
  services?: string[]
}

// Response types matching backend API
export interface ServiceTraceLevel {
  service_name: string
  current_level: string  // "Debug", "Detailed", "Informational", "Error", "Fatal"
  raw_output?: string
}

export interface TraceLevelNodeResult {
  host: string
  success: boolean
  services: ServiceTraceLevel[]
  error?: string
}

export interface TraceLevelGetResponse {
  results: TraceLevelNodeResult[]
  total_nodes: number
  successful_nodes: number
  failed_nodes: number
  checked_at: string
  message: string
}

export interface TraceLevelSetNodeResult {
  host: string
  success: boolean
  services_updated: string[]
  error?: string
}

export interface TraceLevelSetResponse {
  level: string
  results: TraceLevelSetNodeResult[]
  total_nodes: number
  successful_nodes: number
  failed_nodes: number
  completed_at: string
  message: string
}

export const traceService = {
  /**
   * Get current trace levels from CUCM nodes
   */
  async getTraceLevels(request: TraceLevelGetRequest): Promise<TraceLevelGetResponse> {
    return apiClient.post<TraceLevelGetResponse>('/trace-level/get', {
      hosts: request.hosts,
      username: request.username,
      password: request.password,
      port: request.port ?? 22,
      connect_timeout_sec: request.connect_timeout_sec,
      services: request.services,
    })
  },

  /**
   * Set trace levels on CUCM nodes
   */
  async setTraceLevels(request: TraceLevelSetRequest): Promise<TraceLevelSetResponse> {
    return apiClient.post<TraceLevelSetResponse>('/trace-level/set', {
      hosts: request.hosts,
      username: request.username,
      password: request.password,
      level: request.level,
      port: request.port ?? 22,
      connect_timeout_sec: request.connect_timeout_sec,
      services: request.services,
    })
  },
}
