import { useState } from 'react'
import { Box, Typography, Button, Alert } from '@mui/material'
import ProfileSelector from '../ProfileSelector'
import { useProfiles } from '@/hooks'
import LoadingSpinner from '../LoadingSpinner'
import type { LogProfile } from '@/types'

interface ProfileSelectionStepProps {
  selectedProfile: LogProfile | null
  onNext: (profile: LogProfile) => void
  onBack: () => void
}

export function ProfileSelectionStep({
  selectedProfile: initialProfile,
  onNext,
  onBack,
}: ProfileSelectionStepProps) {
  const [selectedProfileId, setSelectedProfileId] = useState<string | undefined>(initialProfile?.id)
  const { data: profiles, isLoading, error } = useProfiles()

  // Ensure profiles is always an array
  const profilesArray = Array.isArray(profiles) ? profiles : []

  const handleNext = () => {
    const profile = profilesArray.find(p => p.id === selectedProfileId)
    if (profile) {
      onNext(profile)
    }
  }

  const handleSelectProfile = (profileId: string) => {
    setSelectedProfileId(profileId)
  }

  if (isLoading) {
    return <LoadingSpinner message="Loading profiles..." />
  }

  if (error) {
    return (
      <Box>
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load profiles: {error.message}
        </Alert>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
          <Button onClick={onBack}>Back</Button>
        </Box>
      </Box>
    )
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Choose Log Collection Profile
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Select a profile that defines which logs to collect from the selected nodes.
      </Typography>

      <ProfileSelector
        profiles={profilesArray}
        selectedProfileId={selectedProfileId}
        onSelect={handleSelectProfile}
      />

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
        <Button onClick={onBack}>Back</Button>
        <Button variant="contained" onClick={handleNext} disabled={!selectedProfileId}>
          Next
        </Button>
      </Box>
    </Box>
  )
}
