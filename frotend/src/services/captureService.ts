import { apiClient } from './api'
import type {
  StartCaptureRequest,
  StartCaptureResponse,
  CaptureStatusResponse,
  CaptureListResponse,
  StopCaptureResponse,
  CaptureInfo,
  // Orchestrated session types
  StartCaptureSessionRequest,
  StartCaptureSessionResponse,
  CaptureSessionStatusResponse,
  CaptureSessionListResponse,
  StopCaptureSessionResponse,
} from '@/types'

export const captureService = {
  /**
   * Start a new packet capture
   */
  async startCapture(request: StartCaptureRequest): Promise<StartCaptureResponse> {
    return apiClient.post<StartCaptureResponse>('/captures', request)
  },

  /**
   * Get all captures
   */
  async getCaptures(): Promise<CaptureListResponse> {
    return apiClient.get<CaptureListResponse>('/captures')
  },

  /**
   * Get capture status by ID
   */
  async getCaptureStatus(captureId: string): Promise<CaptureInfo> {
    const response = await apiClient.get<CaptureStatusResponse>(`/captures/${captureId}`)
    return response.capture
  },

  /**
   * Stop a running capture
   */
  async stopCapture(captureId: string): Promise<StopCaptureResponse> {
    return apiClient.post<StopCaptureResponse>(`/captures/${captureId}/stop`, {})
  },

  /**
   * Download capture file
   */
  downloadCapture(captureId: string, filename: string): void {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const link = document.createElement('a')
    link.href = `${baseUrl}/captures/${captureId}/download`
    link.download = `${filename}.cap`
    link.click()
  },

  /**
   * Delete a capture
   */
  async deleteCapture(captureId: string): Promise<void> {
    await apiClient.delete(`/captures/${captureId}`)
  },

  // ==========================================
  // Orchestrated Capture Sessions
  // ==========================================

  /**
   * Start a new multi-device capture session
   */
  async startSession(request: StartCaptureSessionRequest): Promise<StartCaptureSessionResponse> {
    return apiClient.post<StartCaptureSessionResponse>('/capture-sessions', request)
  },

  /**
   * Get all capture sessions
   */
  async getSessions(limit = 50): Promise<CaptureSessionListResponse> {
    return apiClient.get<CaptureSessionListResponse>(`/capture-sessions?limit=${limit}`)
  },

  /**
   * Get session status by ID
   */
  async getSessionStatus(sessionId: string): Promise<CaptureSessionStatusResponse> {
    return apiClient.get<CaptureSessionStatusResponse>(`/capture-sessions/${sessionId}`)
  },

  /**
   * Stop a running capture session
   */
  async stopSession(sessionId: string): Promise<StopCaptureSessionResponse> {
    return apiClient.post<StopCaptureSessionResponse>(`/capture-sessions/${sessionId}/stop`, {})
  },

  /**
   * Download session bundle (ZIP with all captures)
   */
  downloadSessionBundle(sessionId: string, filename?: string): void {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const link = document.createElement('a')
    link.href = `${baseUrl}/capture-sessions/${sessionId}/download`
    link.download = filename || `capture_session_${sessionId}.zip`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  },

  /**
   * Fetch session bundle as blob (for custom handling)
   */
  async fetchSessionBlob(sessionId: string): Promise<Blob> {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const response = await fetch(`${baseUrl}/capture-sessions/${sessionId}/download`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
      },
    })

    if (!response.ok) {
      throw new Error(`Failed to fetch session ${sessionId}`)
    }

    return response.blob()
  },

  /**
   * Delete a capture session
   */
  async deleteSession(sessionId: string): Promise<void> {
    await apiClient.delete(`/capture-sessions/${sessionId}`)
  },
}
