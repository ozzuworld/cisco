import { useEffect, useState } from 'react'
import {
  Box,
  Typography,
  Button,
  LinearProgress,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  CircularProgress,
  Divider,
} from '@mui/material'
import {
  CheckCircle,
  Error as ErrorIcon,
  HourglassEmpty,
  Download,
  Folder,
  Computer,
} from '@mui/icons-material'
import { jobService, JobStatusResponse, Artifact } from '@/services/jobService'

interface JobProgressStepProps {
  jobId: string
  onClose: () => void
}

const statusColors: Record<string, 'default' | 'info' | 'success' | 'error' | 'warning'> = {
  queued: 'default',
  pending: 'default',
  accepted: 'info',
  running: 'info',
  succeeded: 'success',
  completed: 'success',
  failed: 'error',
  partial: 'warning',
  cancelled: 'warning',
}

const statusIcons: Record<string, React.ReactElement> = {
  queued: <HourglassEmpty />,
  pending: <HourglassEmpty />,
  accepted: <HourglassEmpty />,
  running: <HourglassEmpty />,
  succeeded: <CheckCircle color="success" />,
  completed: <CheckCircle color="success" />,
  failed: <ErrorIcon color="error" />,
  partial: <ErrorIcon color="warning" />,
  cancelled: <ErrorIcon color="warning" />,
}

export function JobProgressStep({ jobId, onClose }: JobProgressStepProps) {
  const [jobStatus, setJobStatus] = useState<JobStatusResponse | null>(null)
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Poll for job status
  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval> | null = null

    const fetchStatus = async () => {
      try {
        const status = await jobService.getJobStatus(jobId)
        setJobStatus(status)
        setError(null)

        // If job is complete, fetch artifacts
        if (['succeeded', 'completed', 'failed', 'partial'].includes(status.status)) {
          try {
            const artifactsResponse = await jobService.getJobArtifacts(jobId)
            setArtifacts(artifactsResponse.artifacts || [])
          } catch {
            // Artifacts might not be available yet
          }

          // Stop polling when job is done
          if (intervalId) {
            clearInterval(intervalId)
          }
        }

        setIsLoading(false)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch job status')
        setIsLoading(false)
      }
    }

    // Initial fetch
    fetchStatus()

    // Poll every 2 seconds
    intervalId = setInterval(fetchStatus, 2000)

    return () => {
      if (intervalId) {
        clearInterval(intervalId)
      }
    }
  }, [jobId])

  const handleDownloadAll = () => {
    jobService.downloadAllArtifacts(jobId)
  }

  const isJobComplete = jobStatus && ['succeeded', 'completed', 'failed', 'partial', 'cancelled'].includes(jobStatus.status)
  const isJobSuccessful = jobStatus && ['succeeded', 'completed'].includes(jobStatus.status)
  const hasArtifacts = artifacts.length > 0

  // Format file size
  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  // Calculate total size
  const totalSize = artifacts.reduce((sum, a) => sum + a.size_bytes, 0)

  if (isLoading && !jobStatus) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4 }}>
        <CircularProgress size={60} />
        <Typography sx={{ mt: 2 }}>Starting job...</Typography>
      </Box>
    )
  }

  if (error) {
    return (
      <Box>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        <Button onClick={onClose}>Close</Button>
      </Box>
    )
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Log Collection Progress
      </Typography>

      {/* Job Status Header */}
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box>
            <Typography variant="body2" color="text.secondary">
              Job ID: {jobId}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Profile: {jobStatus?.profile}
            </Typography>
          </Box>
          <Chip
            icon={statusIcons[jobStatus?.status || 'pending'] || <HourglassEmpty />}
            label={jobStatus?.status?.toUpperCase() || 'PENDING'}
            color={statusColors[jobStatus?.status || 'pending'] || 'default'}
          />
        </Box>

        {/* Progress Bar */}
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body2">
              {jobStatus?.completed_nodes || 0} of {jobStatus?.total_nodes || 0} nodes completed
            </Typography>
            <Typography variant="body2" fontWeight="medium">
              {jobStatus?.percent_complete || 0}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={jobStatus?.percent_complete || 0}
            color={isJobSuccessful ? 'success' : isJobComplete ? 'warning' : 'primary'}
            sx={{ height: 10, borderRadius: 5 }}
          />
        </Box>

        {/* Node Status Summary */}
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          {jobStatus?.running_nodes ? (
            <Chip size="small" icon={<HourglassEmpty />} label={`${jobStatus.running_nodes} Running`} color="info" />
          ) : null}
          {jobStatus?.succeeded_nodes ? (
            <Chip size="small" icon={<CheckCircle />} label={`${jobStatus.succeeded_nodes} Succeeded`} color="success" />
          ) : null}
          {jobStatus?.failed_nodes ? (
            <Chip size="small" icon={<ErrorIcon />} label={`${jobStatus.failed_nodes} Failed`} color="error" />
          ) : null}
        </Box>
      </Paper>

      {/* Node Details */}
      {jobStatus?.nodes && jobStatus.nodes.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Computer /> Node Status
          </Typography>
          <Divider sx={{ my: 1 }} />
          <List dense>
            {jobStatus.nodes.map((node) => (
              <ListItem key={node.node}>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  {node.status === 'succeeded' || node.status === 'completed' ? (
                    <CheckCircle color="success" fontSize="small" />
                  ) : node.status === 'failed' ? (
                    <ErrorIcon color="error" fontSize="small" />
                  ) : (
                    <HourglassEmpty color="info" fontSize="small" />
                  )}
                </ListItemIcon>
                <ListItemText
                  primary={node.node}
                  secondary={
                    node.error
                      ? `Error: ${node.error}`
                      : node.artifacts_count
                        ? `${node.artifacts_count} files collected`
                        : node.status
                  }
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Artifacts Section - Only show when job is complete */}
      {isJobComplete && (
        <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Folder /> Collected Artifacts
          </Typography>
          <Divider sx={{ my: 1 }} />

          {hasArtifacts ? (
            <>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  {artifacts.length} files ({formatSize(totalSize)})
                </Typography>
                <Button
                  variant="contained"
                  startIcon={<Download />}
                  onClick={handleDownloadAll}
                  color="primary"
                >
                  Download All (ZIP)
                </Button>
              </Box>

              <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
                {artifacts.slice(0, 20).map((artifact, index) => (
                  <ListItem key={artifact.artifact_id || index}>
                    <ListItemText
                      primary={artifact.filename}
                      secondary={`${artifact.node} - ${formatSize(artifact.size_bytes)}`}
                      primaryTypographyProps={{ variant: 'body2' }}
                      secondaryTypographyProps={{ variant: 'caption' }}
                    />
                  </ListItem>
                ))}
                {artifacts.length > 20 && (
                  <ListItem>
                    <ListItemText
                      primary={`... and ${artifacts.length - 20} more files`}
                      primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
                    />
                  </ListItem>
                )}
              </List>
            </>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {isJobSuccessful ? 'No artifacts collected' : 'Job did not complete successfully'}
            </Typography>
          )}
        </Paper>
      )}

      {/* Completion Message */}
      {isJobComplete && (
        <Alert severity={isJobSuccessful ? 'success' : 'warning'} sx={{ mb: 2 }}>
          {isJobSuccessful
            ? `Job completed successfully! ${artifacts.length} log files collected.`
            : `Job completed with status: ${jobStatus?.status}. Some nodes may have failed.`}
        </Alert>
      )}

      {/* Actions */}
      <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
        {!isJobComplete && (
          <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
            <CircularProgress size={16} sx={{ mr: 1 }} />
            Collecting logs...
          </Typography>
        )}
        <Button onClick={onClose} variant={isJobComplete ? 'contained' : 'outlined'}>
          {isJobComplete ? 'Done' : 'Close'}
        </Button>
      </Box>
    </Box>
  )
}
