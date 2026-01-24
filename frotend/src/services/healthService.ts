import { apiClient } from './api'
import type { ClusterHealthRequest, ClusterHealthResponse, DeviceHealthRequest, DeviceHealthResponse } from '@/types'

export const healthService = {
  /**
   * Check cluster health status (legacy CUCM-only endpoint)
   * Performs health checks on CUCM cluster nodes
   */
  async checkClusterHealth(request: ClusterHealthRequest): Promise<ClusterHealthResponse> {
    // Health check can take up to 3 minutes, use 4 minute timeout
    return apiClient.post<ClusterHealthResponse>('/cluster/health', request, {
      timeout: 240000, // 4 minutes
    })
  },

  /**
   * Check multi-device health status
   * Supports CUCM, CUBE/IOS-XE, and Expressway devices
   */
  async checkDeviceHealth(request: DeviceHealthRequest): Promise<DeviceHealthResponse> {
    // Health check can take up to 3 minutes per device, use 5 minute timeout
    return apiClient.post<DeviceHealthResponse>('/health/device', request, {
      timeout: 300000, // 5 minutes
    })
  },
}
