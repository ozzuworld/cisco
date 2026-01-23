import { apiClient } from './api'
import type { Job, JobDetails, CreateJobRequest, PaginatedResponse, DebugLevel } from '@/types'

// Backend response types (snake_case)
interface BackendJobSummary {
  job_id: string
  status: string
  profile: string
  created_at: string
  node_count: number
}

interface BackendJobsListResponse {
  jobs: BackendJobSummary[]
  total: number
  page: number
  page_size: number
}

interface BackendCreateJobResponse {
  job_id: string
  status: string
  created_at: string
}

// Backend job status response (detailed)
export interface NodeJobStatus {
  node: string
  status: string
  started_at?: string
  completed_at?: string
  error?: string
  artifacts_count: number
}

export interface JobStatusResponse {
  job_id: string
  status: string  // queued, running, succeeded, partial, failed, cancelled
  created_at: string
  started_at?: string
  completed_at?: string
  profile: string
  debug_level?: DebugLevel  // basic, detailed, verbose
  nodes: NodeJobStatus[]
  total_nodes: number
  completed_nodes: number
  succeeded_nodes: number
  failed_nodes: number
  running_nodes: number
  percent_complete: number
  download_available: boolean  // True when artifacts can be downloaded
}

export interface Artifact {
  node: string
  path: string
  filename: string
  size_bytes: number
  created_at: string
  artifact_id?: string
}

export interface ArtifactsResponse {
  job_id: string
  artifacts: Artifact[]
}


// Transform backend job to frontend format
function transformJob(backendJob: BackendJobSummary): Job {
  return {
    id: backendJob.job_id,
    clusterId: '',
    clusterName: '',
    profileId: backendJob.profile,
    profileName: backendJob.profile,
    status: backendJob.status as Job['status'],
    createdAt: backendJob.created_at,
    nodes: [],
    progress: backendJob.status === 'running' ? 50 : backendJob.status === 'completed' ? 100 : 0,
  }
}

export const jobService = {
  /**
   * Get all jobs with pagination
   */
  async getJobs(page = 1, pageSize = 20): Promise<PaginatedResponse<Job>> {
    const response = await apiClient.get<BackendJobsListResponse>(`/jobs?page=${page}&page_size=${pageSize}`)

    // Transform backend response to frontend format
    return {
      items: (response.jobs || []).map(transformJob),
      total: response.total || 0,
      page: response.page || page,
      pageSize: response.page_size || pageSize,
      totalPages: Math.ceil((response.total || 0) / (response.page_size || pageSize)),
    }
  },

  /**
   * Get job by ID
   */
  async getJob(jobId: string): Promise<JobDetails> {
    return apiClient.get<JobDetails>(`/jobs/${jobId}`)
  },

  /**
   * Create new job
   */
  async createJob(request: CreateJobRequest): Promise<Job> {
    const response = await apiClient.post<BackendCreateJobResponse>('/jobs', request)

    // Transform to frontend Job format
    return {
      id: response.job_id,
      clusterId: '',
      clusterName: '',
      profileId: request.profile,
      profileName: request.profile,
      status: response.status as Job['status'],
      createdAt: response.created_at,
      nodes: request.nodes,
      progress: 0,
    }
  },

  /**
   * Cancel running job
   */
  async cancelJob(jobId: string): Promise<{ success: boolean; message: string }> {
    return apiClient.post(`/jobs/${jobId}/cancel`)
  },

  /**
   * Retry failed nodes in a job
   */
  async retryFailedNodes(jobId: string): Promise<{ success: boolean; message: string }> {
    return apiClient.post(`/jobs/${jobId}/retry-failed`)
  },

  /**
   * Get job status (for polling) - detailed version
   */
  async getJobStatus(jobId: string): Promise<JobStatusResponse> {
    return apiClient.get<JobStatusResponse>(`/jobs/${jobId}`)
  },

  /**
   * Get job artifacts
   */
  async getJobArtifacts(jobId: string): Promise<ArtifactsResponse> {
    return apiClient.get<ArtifactsResponse>(`/jobs/${jobId}/artifacts`)
  },

  /**
   * Download all job artifacts as ZIP (triggers browser download)
   */
  async downloadAllArtifacts(jobId: string): Promise<void> {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const url = `${baseUrl}/jobs/${jobId}/download`

    // Open download in new tab/trigger browser download
    window.open(url, '_blank')
  },

  /**
   * Fetch all job artifacts as blob (for bundling)
   */
  async fetchArtifactsBlob(jobId: string): Promise<Blob> {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const response = await fetch(`${baseUrl}/jobs/${jobId}/download`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
      },
    })

    if (!response.ok) {
      throw new Error(`Failed to fetch job ${jobId} artifacts`)
    }

    return response.blob()
  },

  /**
   * Download single artifact
   */
  async downloadArtifact(jobId: string, artifactId: string): Promise<void> {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const url = `${baseUrl}/jobs/${jobId}/artifacts/${artifactId}/download`

    window.open(url, '_blank')
  },

  /**
   * Download logs for a specific node
   */
  async downloadNodeArtifacts(jobId: string, nodeIp: string): Promise<void> {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
    const url = `${baseUrl}/jobs/${jobId}/nodes/${nodeIp}/download`

    window.open(url, '_blank')
  },

  /**
   * Get job transcript (command output log)
   */
  async getJobTranscript(jobId: string, nodeIp?: string): Promise<string> {
    const url = nodeIp
      ? `/jobs/${jobId}/transcript?node=${nodeIp}`
      : `/jobs/${jobId}/transcript`
    return apiClient.get<string>(url)
  },
}
