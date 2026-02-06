import { useMutation, useQuery } from '@tanstack/react-query'
import {
  traceService,
  TraceLevelGetRequest,
  TraceLevelGetResponse,
  TraceLevelSetRequest,
  TraceLevelSetResponse,
  CreateSSHSessionRequest,
  CreateSSHSessionResponse,
  SSHSession,
  DeleteSSHSessionResponse,
} from '@/services/traceService'
import {
  logService,
  CubeDebugStatusRequest,
  CubeDebugStatusResponse,
  CubeDebugEnableRequest,
  CubeDebugEnableResponse,
  CubeDebugClearRequest,
  CubeDebugClearResponse,
} from '@/services/logService'

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

/**
 * Hook to create a persistent SSH session
 */
export function useCreateSession() {
  return useMutation<CreateSSHSessionResponse, Error, CreateSSHSessionRequest>({
    mutationFn: (request: CreateSSHSessionRequest) => traceService.createSSHSession(request),
  })
}

/**
 * Hook to destroy an SSH session
 */
export function useDeleteSession() {
  return useMutation<DeleteSSHSessionResponse, Error, string>({
    mutationFn: (sessionId: string) => traceService.deleteSSHSession(sessionId),
  })
}

/**
 * Hook to poll SSH session status (every 5s while connecting)
 */
export function useSessionStatus(sessionId: string | null, enabled: boolean = true) {
  return useQuery<SSHSession, Error>({
    queryKey: ['ssh-session', sessionId],
    queryFn: () => traceService.getSSHSession(sessionId!),
    enabled: enabled && !!sessionId,
    refetchInterval: (query) => {
      const data = query.state.data
      if (data?.status === 'connecting') return 5000
      return false
    },
  })
}

// ==========================================
// CUBE Debug Status Hooks
// ==========================================

export function useGetCubeDebugStatus() {
  return useMutation<CubeDebugStatusResponse, Error, CubeDebugStatusRequest>({
    mutationFn: (request: CubeDebugStatusRequest) => logService.getCubeDebugStatus(request),
  })
}

export function useEnableCubeDebug() {
  return useMutation<CubeDebugEnableResponse, Error, CubeDebugEnableRequest>({
    mutationFn: (request: CubeDebugEnableRequest) => logService.enableCubeDebug(request),
  })
}

export function useClearCubeDebug() {
  return useMutation<CubeDebugClearResponse, Error, CubeDebugClearRequest>({
    mutationFn: (request: CubeDebugClearRequest) => logService.clearCubeDebug(request),
  })
}
