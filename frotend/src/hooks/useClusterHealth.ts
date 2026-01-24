import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { healthService } from '@/services'
import type { ClusterHealthRequest, ClusterHealthResponse } from '@/types'

/**
 * Hook to trigger a cluster health check
 */
export function useClusterHealthCheck() {
  const queryClient = useQueryClient()

  return useMutation<ClusterHealthResponse, Error, ClusterHealthRequest>({
    mutationFn: (request: ClusterHealthRequest) => healthService.checkClusterHealth(request),
    onSuccess: (data) => {
      // Cache the result for the dashboard widget
      queryClient.setQueryData(['clusterHealth', 'latest'], data)
    },
  })
}

/**
 * Hook to get the last cached health check result
 */
export function useLastHealthCheck() {
  return useQuery<ClusterHealthResponse | null>({
    queryKey: ['clusterHealth', 'latest'],
    queryFn: () => null, // Just returns cached data, no fetch
    staleTime: Infinity, // Never refetch automatically
    enabled: false, // Don't fetch on mount
  })
}
