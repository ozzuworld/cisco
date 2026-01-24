import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { captureService } from '@/services'
import type { StartCaptureRequest, CaptureInfo, CaptureListResponse } from '@/types'

/**
 * Hook to get all captures
 */
export function useCaptures() {
  return useQuery<CaptureListResponse>({
    queryKey: ['captures'],
    queryFn: () => captureService.getCaptures(),
    refetchInterval: 5000, // Poll every 5 seconds for status updates
  })
}

/**
 * Hook to get a specific capture's status
 */
export function useCaptureStatus(captureId: string, enabled = true) {
  return useQuery<CaptureInfo>({
    queryKey: ['capture', captureId],
    queryFn: () => captureService.getCaptureStatus(captureId),
    enabled,
    refetchInterval: (query) => {
      const capture = query.state.data
      // Poll every 2 seconds if running, stop if completed/failed
      if (capture?.status === 'running' || capture?.status === 'pending') {
        return 2000
      }
      return false
    },
  })
}

/**
 * Hook to start a new capture
 */
export function useStartCapture() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: StartCaptureRequest) => captureService.startCapture(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captures'] })
    },
  })
}

/**
 * Hook to stop a running capture
 */
export function useStopCapture() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (captureId: string) => captureService.stopCapture(captureId),
    onSuccess: (_, captureId) => {
      queryClient.invalidateQueries({ queryKey: ['capture', captureId] })
      queryClient.invalidateQueries({ queryKey: ['captures'] })
    },
  })
}

/**
 * Hook to delete a capture
 */
export function useDeleteCapture() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (captureId: string) => captureService.deleteCapture(captureId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captures'] })
    },
  })
}
