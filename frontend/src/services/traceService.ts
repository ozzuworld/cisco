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
  session_id?: string
}

export interface TraceLevelSetRequest {
  hosts: string[]
  username: string
  password: string
  level: DebugLevel  // "basic" | "detailed" | "verbose"
  port?: number
  connect_timeout_sec?: number
  services?: string[]
  session_id?: string
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
  raw_output?: string
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
  raw_output?: string
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

// SSH Session types
export interface SSHSessionNode {
  host: string
  connected: boolean
  error?: string
}

export interface SSHSession {
  session_id: string
  status: 'connecting' | 'connected' | 'error' | 'disconnected'
  nodes: SSHSessionNode[]
  created_at: string
  last_used_at: string
  ttl_remaining: number
}

export interface CreateSSHSessionRequest {
  hosts: string[]
  username: string
  password: string
  port?: number
  connect_timeout_sec?: number
}

export interface CreateSSHSessionResponse {
  session_id: string
  status: 'connecting' | 'connected' | 'error' | 'disconnected'
  connected_nodes: string[]
  failed_nodes: SSHSessionNode[]
}

export interface DeleteSSHSessionResponse {
  session_id: string
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
      session_id: request.session_id,
    }, {
      timeout: 300000, // 5 minutes - CUCM CLI is slow
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
      session_id: request.session_id,
    }, {
      timeout: 300000, // 5 minutes - CUCM CLI is slow
    })
  },

  /**
   * Create a persistent SSH session to CUCM nodes
   */
  async createSSHSession(request: CreateSSHSessionRequest): Promise<CreateSSHSessionResponse> {
    return apiClient.post<CreateSSHSessionResponse>('/ssh-sessions', {
      hosts: request.hosts,
      username: request.username,
      password: request.password,
      port: request.port ?? 22,
      connect_timeout_sec: request.connect_timeout_sec,
    }, {
      timeout: 300000,
    })
  },

  /**
   * Get SSH session status
   */
  async getSSHSession(sessionId: string): Promise<SSHSession> {
    return apiClient.get<SSHSession>(`/ssh-sessions/${sessionId}`)
  },

  /**
   * Destroy an SSH session
   */
  async deleteSSHSession(sessionId: string): Promise<DeleteSSHSessionResponse> {
    return apiClient.delete<DeleteSSHSessionResponse>(`/ssh-sessions/${sessionId}`)
  },
}
