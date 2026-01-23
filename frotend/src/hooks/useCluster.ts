import { useMutation } from '@tanstack/react-query'
import { clusterService } from '@/services'
import type { ConnectionRequest, DiscoverResponse } from '@/types'

export function useDiscoverCluster() {
  return useMutation<DiscoverResponse, Error, ConnectionRequest>({
    mutationFn: (connection: ConnectionRequest) => clusterService.discover(connection),
  })
}

export function useTestConnection() {
  return useMutation<{ success: boolean; message: string }, Error, ConnectionRequest>({
    mutationFn: (connection: ConnectionRequest) => clusterService.testConnection(connection),
  })
}
