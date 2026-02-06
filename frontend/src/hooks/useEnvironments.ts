import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { environmentService } from '@/services/environmentService'
import type {
  Environment,
  EnvironmentCreate,
  EnvironmentUpdate,
  EnvironmentListResponse,
  DeviceEntryCreate,
  DiscoverRequest,
} from '@/types/environment'

export function useEnvironments() {
  return useQuery<EnvironmentListResponse>({
    queryKey: ['environments'],
    queryFn: () => environmentService.list(),
  })
}

export function useEnvironment(envId: string, enabled = true) {
  return useQuery<Environment>({
    queryKey: ['environment', envId],
    queryFn: () => environmentService.get(envId),
    enabled: enabled && !!envId,
  })
}

export function useCreateEnvironment() {
  const queryClient = useQueryClient()
  return useMutation<Environment, Error, EnvironmentCreate>({
    mutationFn: (data) => environmentService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
  })
}

export function useUpdateEnvironment() {
  const queryClient = useQueryClient()
  return useMutation<Environment, Error, { envId: string; data: EnvironmentUpdate }>({
    mutationFn: ({ envId, data }) => environmentService.update(envId, data),
    onSuccess: (_, { envId }) => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      queryClient.invalidateQueries({ queryKey: ['environment', envId] })
    },
  })
}

export function useDeleteEnvironment() {
  const queryClient = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (envId) => environmentService.delete(envId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
  })
}

export function useAddDevice() {
  const queryClient = useQueryClient()
  return useMutation<Environment, Error, { envId: string; device: DeviceEntryCreate }>({
    mutationFn: ({ envId, device }) => environmentService.addDevice(envId, device),
    onSuccess: (_, { envId }) => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      queryClient.invalidateQueries({ queryKey: ['environment', envId] })
    },
  })
}

export function useRemoveDevice() {
  const queryClient = useQueryClient()
  return useMutation<Environment, Error, { envId: string; deviceId: string }>({
    mutationFn: ({ envId, deviceId }) => environmentService.removeDevice(envId, deviceId),
    onSuccess: (_, { envId }) => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      queryClient.invalidateQueries({ queryKey: ['environment', envId] })
    },
  })
}

export function useDiscoverNodes() {
  const queryClient = useQueryClient()
  return useMutation<Environment, Error, { envId: string; request: DiscoverRequest }>({
    mutationFn: ({ envId, request }) => environmentService.discover(envId, request),
    onSuccess: (_, { envId }) => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      queryClient.invalidateQueries({ queryKey: ['environment', envId] })
    },
  })
}
