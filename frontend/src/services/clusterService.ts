import { apiClient } from './api'
import type { ConnectionRequest, DiscoverResponse } from '@/types'

export const clusterService = {
  /**
   * Discover CUCM cluster nodes
   */
  async discover(connection: ConnectionRequest): Promise<DiscoverResponse> {
    // Transform frontend field names to match backend API
    const payload = {
      publisher_host: connection.hostname,
      username: connection.username,
      password: connection.password,
      port: connection.port || 22,
    }

    const response = await apiClient.post<DiscoverResponse>('/discover-nodes', payload)

    return response
  },

  /**
   * Test connection to CUCM
   */
  async testConnection(
    connection: ConnectionRequest
  ): Promise<{ success: boolean; message: string }> {
    const payload = {
      publisher_host: connection.hostname,
      username: connection.username,
      password: connection.password,
      port: connection.port || 22,
    }
    return apiClient.post('/connection/test', payload)
  },
}
