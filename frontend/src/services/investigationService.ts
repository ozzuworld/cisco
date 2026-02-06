import { apiClient } from './api'
import type {
  CreateInvestigationRequest,
  CreateInvestigationResponse,
  InvestigationStatusResponse,
  InvestigationListResponse,
  ScenarioListResponse,
} from '@/types/investigation'

export const investigationService = {
  async create(data: CreateInvestigationRequest): Promise<CreateInvestigationResponse> {
    return apiClient.post<CreateInvestigationResponse>('/investigations', data)
  },

  async list(): Promise<InvestigationListResponse> {
    return apiClient.get<InvestigationListResponse>('/investigations')
  },

  async get(invId: string): Promise<InvestigationStatusResponse> {
    return apiClient.get<InvestigationStatusResponse>(`/investigations/${invId}`)
  },

  async prepare(invId: string): Promise<InvestigationStatusResponse> {
    return apiClient.post<InvestigationStatusResponse>(`/investigations/${invId}/prepare`)
  },

  async signalReady(invId: string): Promise<InvestigationStatusResponse> {
    return apiClient.post<InvestigationStatusResponse>(`/investigations/${invId}/ready`)
  },

  async startRecording(invId: string): Promise<InvestigationStatusResponse> {
    return apiClient.post<InvestigationStatusResponse>(`/investigations/${invId}/record`)
  },

  async stopAndCollect(invId: string): Promise<InvestigationStatusResponse> {
    return apiClient.post<InvestigationStatusResponse>(`/investigations/${invId}/collect`)
  },

  async cancel(invId: string): Promise<InvestigationStatusResponse> {
    return apiClient.post<InvestigationStatusResponse>(`/investigations/${invId}/cancel`)
  },

  async delete(invId: string): Promise<void> {
    return apiClient.delete(`/investigations/${invId}`)
  },

  downloadBundle(invId: string): void {
    const baseUrl = import.meta.env.VITE_API_BASE_URL ?? ''
    window.open(`${baseUrl}/investigations/${invId}/download`, '_blank')
  },

  async listScenarios(): Promise<ScenarioListResponse> {
    return apiClient.get<ScenarioListResponse>('/scenarios')
  },
}
