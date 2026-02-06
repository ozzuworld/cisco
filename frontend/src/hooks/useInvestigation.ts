import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { investigationService } from '@/services/investigationService'
import type {
  CreateInvestigationRequest,
  CreateInvestigationResponse,
  InvestigationStatusResponse,
  InvestigationListResponse,
  ScenarioListResponse,
} from '@/types/investigation'

export function useInvestigations() {
  return useQuery<InvestigationListResponse>({
    queryKey: ['investigations'],
    queryFn: () => investigationService.list(),
    refetchInterval: 10000,
  })
}

export function useInvestigation(invId: string, enabled = true) {
  return useQuery<InvestigationStatusResponse>({
    queryKey: ['investigation', invId],
    queryFn: () => investigationService.get(invId),
    enabled: enabled && !!invId,
    refetchInterval: (query) => {
      const inv = query.state.data
      if (!inv) return 5000
      const activeStatuses = ['preparing', 'recording', 'collecting', 'bundling']
      return activeStatuses.includes(inv.status) ? 2000 : false
    },
  })
}

export function useCreateInvestigation() {
  const queryClient = useQueryClient()
  return useMutation<CreateInvestigationResponse, Error, CreateInvestigationRequest>({
    mutationFn: (data) => investigationService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

export function usePrepareInvestigation() {
  const queryClient = useQueryClient()
  return useMutation<InvestigationStatusResponse, Error, string>({
    mutationFn: (invId) => investigationService.prepare(invId),
    onSuccess: (_, invId) => {
      queryClient.invalidateQueries({ queryKey: ['investigation', invId] })
    },
  })
}

export function useSignalReady() {
  const queryClient = useQueryClient()
  return useMutation<InvestigationStatusResponse, Error, string>({
    mutationFn: (invId) => investigationService.signalReady(invId),
    onSuccess: (_, invId) => {
      queryClient.invalidateQueries({ queryKey: ['investigation', invId] })
    },
  })
}

export function useStartRecording() {
  const queryClient = useQueryClient()
  return useMutation<InvestigationStatusResponse, Error, string>({
    mutationFn: (invId) => investigationService.startRecording(invId),
    onSuccess: (_, invId) => {
      queryClient.invalidateQueries({ queryKey: ['investigation', invId] })
    },
  })
}

export function useStopAndCollect() {
  const queryClient = useQueryClient()
  return useMutation<InvestigationStatusResponse, Error, string>({
    mutationFn: (invId) => investigationService.stopAndCollect(invId),
    onSuccess: (_, invId) => {
      queryClient.invalidateQueries({ queryKey: ['investigation', invId] })
    },
  })
}

export function useCancelInvestigation() {
  const queryClient = useQueryClient()
  return useMutation<InvestigationStatusResponse, Error, string>({
    mutationFn: (invId) => investigationService.cancel(invId),
    onSuccess: (_, invId) => {
      queryClient.invalidateQueries({ queryKey: ['investigation', invId] })
      queryClient.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

export function useDeleteInvestigation() {
  const queryClient = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (invId) => investigationService.delete(invId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

export function useScenarios() {
  return useQuery<ScenarioListResponse>({
    queryKey: ['scenarios'],
    queryFn: () => investigationService.listScenarios(),
    staleTime: 30 * 60 * 1000, // 30 min - scenarios rarely change
  })
}
