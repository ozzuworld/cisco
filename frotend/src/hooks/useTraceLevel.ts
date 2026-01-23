import { useMutation } from '@tanstack/react-query'
import {
  traceService,
  TraceLevelGetRequest,
  TraceLevelGetResponse,
  TraceLevelSetRequest,
  TraceLevelSetResponse,
} from '@/services/traceService'

/**
 * Hook to get current trace levels from CUCM nodes
 */
export function useGetTraceLevels() {
  return useMutation<TraceLevelGetResponse, Error, TraceLevelGetRequest>({
    mutationFn: (request: TraceLevelGetRequest) => traceService.getTraceLevels(request),
  })
}

/**
 * Hook to set trace levels on CUCM nodes
 */
export function useSetTraceLevels() {
  return useMutation<TraceLevelSetResponse, Error, TraceLevelSetRequest>({
    mutationFn: (request: TraceLevelSetRequest) => traceService.setTraceLevels(request),
  })
}
