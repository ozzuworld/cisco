import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { jobService, JobStatusResponse } from '@/services'
import type { Job, JobDetails, CreateJobRequest, PaginatedResponse } from '@/types'

export function useJobs(page = 1, pageSize = 20) {
  return useQuery<PaginatedResponse<Job>>({
    queryKey: ['jobs', page, pageSize],
    queryFn: () => jobService.getJobs(page, pageSize),
    refetchInterval: 5000, // Poll every 5 seconds for updates
  })
}

export function useJob(jobId: string, enabled = true) {
  return useQuery<JobDetails>({
    queryKey: ['job', jobId],
    queryFn: () => jobService.getJob(jobId),
    enabled,
    refetchInterval: query => {
      // Poll every 3 seconds if job is running
      const job = query.state.data
      return job?.status === 'running' ? 3000 : false
    },
  })
}

export function useCreateJob() {
  const queryClient = useQueryClient()

  return useMutation<Job, Error, CreateJobRequest>({
    mutationFn: (request: CreateJobRequest) => jobService.createJob(request),
    onSuccess: () => {
      // Invalidate jobs list to refetch
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
    },
  })
}

export function useCancelJob() {
  const queryClient = useQueryClient()

  return useMutation<{ success: boolean; message: string }, Error, string>({
    mutationFn: (jobId: string) => jobService.cancelJob(jobId),
    onSuccess: (_, jobId) => {
      // Invalidate the specific job and jobs list
      queryClient.invalidateQueries({ queryKey: ['job', jobId] })
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
    },
  })
}

export function useJobStatus(jobId: string, enabled = true) {
  return useQuery<JobStatusResponse>({
    queryKey: ['jobStatus', jobId],
    queryFn: () => jobService.getJobStatus(jobId),
    enabled,
    refetchInterval: 2000, // Poll every 2 seconds
  })
}
