import { apiClient } from './api'
import type {
  Environment,
  EnvironmentCreate,
  EnvironmentUpdate,
  EnvironmentListResponse,
  DeviceEntryCreate,
  DiscoverRequest,
} from '@/types/environment'

export const environmentService = {
  async list(): Promise<EnvironmentListResponse> {
    return apiClient.get<EnvironmentListResponse>('/environments')
  },

  async get(envId: string): Promise<Environment> {
    return apiClient.get<Environment>(`/environments/${envId}`)
  },

  async create(data: EnvironmentCreate): Promise<Environment> {
    return apiClient.post<Environment>('/environments', data)
  },

  async update(envId: string, data: EnvironmentUpdate): Promise<Environment> {
    return apiClient.put<Environment>(`/environments/${envId}`, data)
  },

  async delete(envId: string): Promise<void> {
    return apiClient.delete(`/environments/${envId}`)
  },

  async addDevice(envId: string, device: DeviceEntryCreate): Promise<Environment> {
    return apiClient.post<Environment>(`/environments/${envId}/devices`, device)
  },

  async removeDevice(envId: string, deviceId: string): Promise<Environment> {
    return apiClient.delete<Environment>(`/environments/${envId}/devices/${deviceId}`)
  },

  async discover(envId: string, request: DiscoverRequest): Promise<Environment> {
    return apiClient.post<Environment>(`/environments/${envId}/discover`, request)
  },
}
