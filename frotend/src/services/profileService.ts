import { apiClient } from './api'
import type { LogProfile } from '@/types'

export const profileService = {
  /**
   * Get all available log profiles
   */
  async getProfiles(): Promise<LogProfile[]> {
    const response = await apiClient.get<any>('/profiles')

    // Handle different response formats from backend
    // Backend might return: { profiles: [...] } or just [...]
    if (Array.isArray(response)) {
      // Transform to ensure id field exists and map backend fields to frontend
      return response.map((profile: any, index: number) => ({
        ...profile,
        id: profile.id || profile.name || `profile-${index}`,
        logTypes: profile.logTypes || profile.log_types || profile.paths || [],
        isCustom: profile.isCustom ?? profile.is_custom ?? false,
      }))
    }

    if (response && typeof response === 'object' && Array.isArray(response.profiles)) {
      // Transform to ensure id field exists and map backend fields to frontend
      return response.profiles.map((profile: any, index: number) => ({
        ...profile,
        id: profile.id || profile.name || `profile-${index}`,
        logTypes: profile.logTypes || profile.log_types || profile.paths || [],
        isCustom: profile.isCustom ?? profile.is_custom ?? false,
      }))
    }

    if (response && typeof response === 'object') {
      // Try to extract profiles from object keys
      const profilesArray = Object.values(response)
      if (profilesArray.length > 0 && profilesArray.every(p => typeof p === 'object')) {
        // Transform to ensure id field exists and map backend fields to frontend
        return profilesArray.map((profile: any, index: number) => ({
          ...profile,
          id: profile.id || profile.name || `profile-${index}`,
          logTypes: profile.logTypes || profile.log_types || profile.paths || [],
          isCustom: profile.isCustom ?? profile.is_custom ?? false,
        }))
      }
    }

    // Fallback to empty array if format is unexpected
    return []
  },

  /**
   * Get profile by ID
   */
  async getProfile(profileId: string): Promise<LogProfile> {
    return apiClient.get<LogProfile>(`/profiles/${profileId}`)
  },

  /**
   * Create custom profile
   */
  async createProfile(profile: Omit<LogProfile, 'id' | 'isCustom'>): Promise<LogProfile> {
    return apiClient.post<LogProfile>('/profiles', profile)
  },

  /**
   * Delete custom profile
   */
  async deleteProfile(profileId: string): Promise<{ success: boolean }> {
    return apiClient.delete(`/profiles/${profileId}`)
  },
}
