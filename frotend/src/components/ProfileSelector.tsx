import { useState } from 'react'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Grid,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  List,
  ListItem,
  ListItemText,
  Alert,
} from '@mui/material'
import {
  CheckCircle,
  Info as InfoIcon,
  Star as StarIcon,
  Build as BuildIcon,
} from '@mui/icons-material'
import type { LogProfile } from '@/types'

interface ProfileSelectorProps {
  profiles: LogProfile[]
  selectedProfileId?: string
  onSelect: (profileId: string) => void
  isLoading?: boolean
}

export default function ProfileSelector({
  profiles,
  selectedProfileId,
  onSelect,
  isLoading = false,
}: ProfileSelectorProps) {
  const [detailsOpen, setDetailsOpen] = useState(false)
  const [selectedProfile, setSelectedProfile] = useState<LogProfile | null>(null)

  const handleProfileClick = (profile: LogProfile) => {
    onSelect(profile.id)
  }

  const handleViewDetails = (profile: LogProfile, event: React.MouseEvent) => {
    event.stopPropagation()
    setSelectedProfile(profile)
    setDetailsOpen(true)
  }

  const handleCloseDetails = () => {
    setDetailsOpen(false)
    setSelectedProfile(null)
  }

  const predefinedProfiles = profiles.filter(p => !p.isCustom)
  const customProfiles = profiles.filter(p => p.isCustom)

  return (
    <Box>
      {predefinedProfiles.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <StarIcon sx={{ mr: 1 }} color="primary" />
            Predefined Profiles
          </Typography>
          <Grid container spacing={2}>
            {predefinedProfiles.map(profile => (
              <Grid item xs={12} sm={6} md={4} key={profile.id}>
                <Card
                  elevation={selectedProfileId === profile.id ? 4 : 1}
                  sx={{
                    border: selectedProfileId === profile.id ? 2 : 0,
                    borderColor: 'primary.main',
                    position: 'relative',
                    cursor: isLoading ? 'default' : 'pointer',
                  }}
                  onClick={() => !isLoading && handleProfileClick(profile)}
                >
                  <CardContent>
                    {selectedProfileId === profile.id && (
                      <CheckCircle
                        color="primary"
                        sx={{ position: 'absolute', top: 8, right: 8 }}
                      />
                    )}
                    <Typography variant="h6" gutterBottom>
                      {profile.name}
                    </Typography>
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ mb: 2, minHeight: 40 }}
                    >
                      {profile.description}
                    </Typography>
                    <Chip
                      label={`${profile.logTypes?.length || 0} log types`}
                      size="small"
                      color="primary"
                      variant="outlined"
                      sx={{ mr: 1 }}
                    />
                    <Button
                      size="small"
                      startIcon={<InfoIcon />}
                      onClick={e => handleViewDetails(profile, e)}
                    >
                      Details
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {customProfiles.length > 0 && (
        <Box>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <BuildIcon sx={{ mr: 1 }} color="secondary" />
            Custom Profiles
          </Typography>
          <Grid container spacing={2}>
            {customProfiles.map(profile => (
              <Grid item xs={12} sm={6} md={4} key={profile.id}>
                <Card
                  elevation={selectedProfileId === profile.id ? 4 : 1}
                  sx={{
                    border: selectedProfileId === profile.id ? 2 : 0,
                    borderColor: 'primary.main',
                    position: 'relative',
                    cursor: isLoading ? 'default' : 'pointer',
                  }}
                  onClick={() => !isLoading && handleProfileClick(profile)}
                >
                  <CardContent>
                    {selectedProfileId === profile.id && (
                      <CheckCircle
                        color="primary"
                        sx={{ position: 'absolute', top: 8, right: 8 }}
                      />
                    )}
                    <Typography variant="h6" gutterBottom>
                      {profile.name}
                    </Typography>
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ mb: 2, minHeight: 40 }}
                    >
                      {profile.description}
                    </Typography>
                    <Chip
                      label={`${profile.logTypes?.length || 0} log types`}
                      size="small"
                      color="secondary"
                      variant="outlined"
                      sx={{ mr: 1 }}
                    />
                    <Chip label="Custom" size="small" color="secondary" sx={{ mr: 1 }} />
                    <Button
                      size="small"
                      startIcon={<InfoIcon />}
                      onClick={e => handleViewDetails(profile, e)}
                    >
                      Details
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {profiles.length === 0 && (
        <Alert severity="info">
          No profiles available. Create a custom profile to get started.
        </Alert>
      )}

      {/* Profile Details Dialog */}
      <Dialog open={detailsOpen} onClose={handleCloseDetails} maxWidth="sm" fullWidth>
        <DialogTitle>{selectedProfile?.name}</DialogTitle>
        <DialogContent>
          <Typography variant="body1" paragraph>
            {selectedProfile?.description}
          </Typography>
          <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
            Included Log Types:
          </Typography>
          <List dense>
            {selectedProfile?.logTypes?.map((logType, index) => (
              <ListItem key={index}>
                <ListItemText primary={logType} />
              </ListItem>
            ))}
          </List>
          {selectedProfile?.isCustom && (
            <Chip label="Custom Profile" color="secondary" size="small" sx={{ mt: 2 }} />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDetails}>Close</Button>
          {selectedProfile && (
            <Button
              variant="contained"
              onClick={() => {
                onSelect(selectedProfile.id)
                handleCloseDetails()
              }}
            >
              Select Profile
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  )
}
