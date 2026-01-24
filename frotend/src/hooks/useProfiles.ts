import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { profileService } from '@/services'
import type { LogProfile } from '@/types'

export function useProfiles() {
  return useQuery<LogProfile[]>({
    queryKey: ['profiles'],
    queryFn: () => profileService.getProfiles(),
    staleTime: 10 * 60 * 1000, // Profiles don't change often, cache for 10 minutes
  })
}

export function useProfile(profileId: string, enabled = true) {
  return useQuery<LogProfile>({
    queryKey: ['profile', profileId],
    queryFn: () => profileService.getProfile(profileId),
    enabled,
    staleTime: 10 * 60 * 1000,
  })
}

export function useCreateProfile() {
  const queryClient = useQueryClient()

  return useMutation<LogProfile, Error, Omit<LogProfile, 'id' | 'isCustom'>>({
    mutationFn: profile => profileService.createProfile(profile),
    onSuccess: () => {
      // Invalidate profiles list to refetch
      queryClient.invalidateQueries({ queryKey: ['profiles'] })
    },
  })
}

export function useDeleteProfile() {
  const queryClient = useQueryClient()

  return useMutation<{ success: boolean }, Error, string>({
    mutationFn: (profileId: string) => profileService.deleteProfile(profileId),
    onSuccess: () => {
      // Invalidate profiles list to refetch
      queryClient.invalidateQueries({ queryKey: ['profiles'] })
    },
  })
}
