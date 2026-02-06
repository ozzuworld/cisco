import { apiClient } from './api'
import type {
  LogFile,
  LogProfile,
  DiscoverResponse,
  StartLogCollectionRequest,
  StartLogCollectionResponse,
  LogCollectionListResponse,
  LogCollectionStatusResponse,
  DeviceProfilesResponse,
  DiscoverNodesRequest,
} from '@/types'

// ==========================================
// CUBE Debug Status Types
// ==========================================

export interface CubeDebugStatusRequest {
  host: string
  port?: number
  username: string
  password: string
  connect_timeout_sec?: number
}

export interface CubeDebugCategory {
  name: string
  enabled: boolean
}

export interface CubeDebugStatusResponse {
  host: string
  success: boolean
  categories: CubeDebugCategory[]
  raw_output?: string
  error?: string
  checked_at: string
}

export interface CubeDebugEnableRequest {
  host: string
  port?: number
  username: string
  password: string
  commands: string[]
  connect_timeout_sec?: number
}

export interface CubeDebugEnableResponse {
  host: string
  success: boolean
  enabled: string[]
  failed: string[]
  raw_output?: string
  error?: string
}

export interface CubeDebugClearRequest {
  host: string
  port?: number
  username: string
  password: string
  connect_timeout_sec?: number
}

export interface CubeDebugClearResponse {
  host: string
  success: boolean
  raw_output?: string
  error?: string
}

export const logService = {
  // ==========================================
  // CUCM Job-based Log Retrieval (existing)
  // ==========================================

  /**
   * Get logs for a specific job
   */
  async getJobLogs(jobId: string): Promise<LogFile[]> {
    return apiClient.get<LogFile[]>(`/jobs/${jobId}/artifacts`)
  },

  /**
   * Download a specific log file
   */
  async downloadLog(jobId: string, filename: string): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL}/jobs/${jobId}/artifacts/${filename}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
        },
      }
    )

    if (!response.ok) {
      throw new Error('Failed to download log file')
    }

    return response.blob()
  },

  /**
   * Download all logs as zip
   */
  async downloadAllLogs(jobId: string): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL}/jobs/${jobId}/artifacts/download-all`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
        },
      }
    )

    if (!response.ok) {
      throw new Error('Failed to download logs')
    }

    return response.blob()
  },

  // ==========================================
  // CUBE/Expressway Log Collection (new)
  // ==========================================

  /**
   * Start a log collection from CUBE or Expressway
   */
  async startCollection(request: StartLogCollectionRequest): Promise<StartLogCollectionResponse> {
    return apiClient.post<StartLogCollectionResponse>('/logs', request)
  },

  /**
   * Get all log collections
   */
  async getCollections(): Promise<LogCollectionListResponse> {
    return apiClient.get<LogCollectionListResponse>('/logs')
  },

  /**
   * Get status of a specific log collection
   */
  async getCollectionStatus(collectionId: string): Promise<LogCollectionStatusResponse> {
    return apiClient.get<LogCollectionStatusResponse>(`/logs/${collectionId}`)
  },

  /**
   * Cancel a running log collection
   */
  async cancelCollection(collectionId: string): Promise<void> {
    return apiClient.post(`/logs/${collectionId}/cancel`)
  },

  /**
   * Stop a running log collection gracefully
   */
  async stopCollection(collectionId: string): Promise<void> {
    return apiClient.post(`/logs/${collectionId}/stop`)
  },

  /**
   * Download collected logs (triggers browser download)
   */
  downloadCollection(collectionId: string, filename: string): void {
    const baseUrl = import.meta.env.VITE_API_BASE_URL ?? ''
    const url = `${baseUrl}/logs/${collectionId}/download`

    const link = document.createElement('a')
    link.href = url
    link.download = filename || `logs_${collectionId}.zip`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  },

  /**
   * Fetch collected logs as blob (for bundling)
   */
  async fetchCollectionBlob(collectionId: string): Promise<Blob> {
    const baseUrl = import.meta.env.VITE_API_BASE_URL ?? ''
    const response = await fetch(`${baseUrl}/logs/${collectionId}/download`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
      },
    })

    if (!response.ok) {
      throw new Error(`Failed to fetch collection ${collectionId}`)
    }

    return response.blob()
  },

  /**
   * Delete a log collection
   */
  async deleteCollection(collectionId: string): Promise<void> {
    return apiClient.delete(`/logs/${collectionId}`)
  },

  // ==========================================
  // CUCM Cluster Discovery
  // ==========================================

  /**
   * Discover nodes in a CUCM cluster
   */
  async discoverNodes(request: DiscoverNodesRequest): Promise<DiscoverResponse> {
    // Discovery can take a while, use extended timeout
    return apiClient.post<DiscoverResponse>('/discover-nodes', request, {
      timeout: 120000, // 2 minutes
    })
  },

  // ==========================================
  // Log Profiles
  // ==========================================

  /**
   * Get available CUCM log collection profiles
   */
  async getProfiles(): Promise<{ profiles: LogProfile[] }> {
    return apiClient.get<{ profiles: LogProfile[] }>('/profiles')
  },

  /**
   * Get available CUBE/Expressway log collection profiles
   */
  async getDeviceProfiles(): Promise<DeviceProfilesResponse> {
    return apiClient.get<DeviceProfilesResponse>('/logs/profiles')
  },

  // ==========================================
  // CUBE Debug Status
  // ==========================================

  async getCubeDebugStatus(request: CubeDebugStatusRequest): Promise<CubeDebugStatusResponse> {
    return apiClient.post<CubeDebugStatusResponse>('/cube-debug/status', request, { timeout: 60000 })
  },

  async enableCubeDebug(request: CubeDebugEnableRequest): Promise<CubeDebugEnableResponse> {
    return apiClient.post<CubeDebugEnableResponse>('/cube-debug/enable', request, { timeout: 60000 })
  },

  async clearCubeDebug(request: CubeDebugClearRequest): Promise<CubeDebugClearResponse> {
    return apiClient.post<CubeDebugClearResponse>('/cube-debug/clear', request, { timeout: 60000 })
  },
}
