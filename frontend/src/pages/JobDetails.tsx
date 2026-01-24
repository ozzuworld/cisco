import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Button,
  Paper,
  Grid,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Alert,
  CircularProgress,
  IconButton,
  Tooltip,
} from '@mui/material'
import {
  ArrowBack,
  CheckCircle,
  Error as ErrorIcon,
  HourglassEmpty,
  Download,
  Folder,
  Computer,
  Refresh,
  Cancel,
  AccessTime,
  Schedule,
  BugReport,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { jobService, JobStatusResponse, Artifact } from '@/services/jobService'
import { useCancelJob } from '@/hooks'

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

export default function JobDetails() {
  const { jobId } = useParams<{ jobId: string }>()
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()
  const cancelMutation = useCancelJob()

  const [jobStatus, setJobStatus] = useState<JobStatusResponse | null>(null)
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Fetch job status
  const fetchJobData = async () => {
    if (!jobId) return

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
          // Artifacts might not be available
        }
      }

      setIsLoading(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch job details')
      setIsLoading(false)
    }
  }

  // Poll for job status
  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval> | null = null

    fetchJobData()

    // Poll every 3 seconds if job is still running
    intervalId = setInterval(() => {
      if (jobStatus && !['succeeded', 'completed', 'failed', 'partial', 'cancelled'].includes(jobStatus.status)) {
        fetchJobData()
      }
    }, 3000)

    return () => {
      if (intervalId) {
        clearInterval(intervalId)
      }
    }
  }, [jobId])

  // Stop polling when job completes
  useEffect(() => {
    if (jobStatus && ['succeeded', 'completed', 'failed', 'partial', 'cancelled'].includes(jobStatus.status)) {
      fetchJobData() // Final fetch to get artifacts
    }
  }, [jobStatus?.status])

  const handleDownloadAll = () => {
    if (jobId) {
      jobService.downloadAllArtifacts(jobId)
      enqueueSnackbar('Download started', { variant: 'success' })
    }
  }

  const handleCancel = async () => {
    if (!jobId) return
    try {
      await cancelMutation.mutateAsync(jobId)
      enqueueSnackbar('Job cancelled', { variant: 'success' })
      fetchJobData()
    } catch (err) {
      enqueueSnackbar(err instanceof Error ? err.message : 'Failed to cancel job', { variant: 'error' })
    }
  }

  const isJobComplete = jobStatus && ['succeeded', 'completed', 'failed', 'partial', 'cancelled'].includes(jobStatus.status)
  const isJobSuccessful = jobStatus && ['succeeded', 'completed'].includes(jobStatus.status)
  const isJobRunning = jobStatus && ['running', 'accepted', 'pending', 'queued'].includes(jobStatus.status)
  const hasArtifacts = artifacts.length > 0

  // Format file size
  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  // Format date
  const formatDate = (dateStr?: string): string => {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString()
  }

  // Calculate duration
  const getDuration = (): string => {
    if (!jobStatus?.started_at) return '-'
    const start = new Date(jobStatus.started_at).getTime()
    const end = jobStatus.completed_at ? new Date(jobStatus.completed_at).getTime() : Date.now()
    const seconds = Math.floor((end - start) / 1000)
    if (seconds < 60) return `${seconds}s`
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}m ${remainingSeconds}s`
  }

  // Calculate total size
  const totalSize = artifacts.reduce((sum, a) => sum + a.size_bytes, 0)

  // Format debug level for display
  const formatDebugLevel = (level?: string): string => {
    switch (level) {
      case 'basic': return 'Basic'
      case 'detailed': return 'Detailed'
      case 'verbose': return 'Verbose'
      default: return 'Basic'
    }
  }

  const getDebugLevelColor = (level?: string): 'default' | 'info' | 'warning' => {
    switch (level) {
      case 'detailed': return 'info'
      case 'verbose': return 'warning'
      default: return 'default'
    }
  }

  if (isLoading && !jobStatus) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 8 }}>
        <CircularProgress size={60} />
        <Typography sx={{ mt: 2 }}>Loading job details...</Typography>
      </Box>
    )
  }

  if (error) {
    return (
      <Box>
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/jobs')} sx={{ mb: 2 }}>
          Back to Jobs
        </Button>
        <Alert severity="error">{error}</Alert>
      </Box>
    )
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
        <Box>
          <Button startIcon={<ArrowBack />} onClick={() => navigate('/jobs')} sx={{ mb: 1 }}>
            Back to Jobs
          </Button>
          <Typography variant="h4" gutterBottom>
            Job Details
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
            {jobId}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchJobData}>
              <Refresh />
            </IconButton>
          </Tooltip>
          {isJobRunning && (
            <Button
              variant="outlined"
              color="error"
              startIcon={<Cancel />}
              onClick={handleCancel}
              disabled={cancelMutation.isPending}
            >
              Cancel Job
            </Button>
          )}
          {isJobComplete && hasArtifacts && (
            <Button variant="contained" startIcon={<Download />} onClick={handleDownloadAll}>
              Download All
            </Button>
          )}
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Job Metadata */}
        <Grid item xs={12} md={8}>
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="h6">Status</Typography>
              <Chip
                icon={statusIcons[jobStatus?.status || 'pending'] || <HourglassEmpty />}
                label={jobStatus?.status?.toUpperCase() || 'PENDING'}
                color={statusColors[jobStatus?.status || 'pending'] || 'default'}
                size="medium"
              />
            </Box>

            {/* Progress Bar */}
            {isJobRunning && (
              <Box sx={{ mb: 3 }}>
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
                  sx={{ height: 10, borderRadius: 5 }}
                />
              </Box>
            )}

            {/* Completion Status */}
            {isJobComplete && (
              <Alert severity={isJobSuccessful ? 'success' : 'warning'} sx={{ mb: 3 }}>
                {isJobSuccessful
                  ? `Job completed successfully! ${artifacts.length} files collected.`
                  : `Job finished with status: ${jobStatus?.status}`}
              </Alert>
            )}

            {/* Metadata Grid */}
            <Grid container spacing={2}>
              <Grid item xs={6} sm={4}>
                <Typography variant="caption" color="text.secondary">Profile</Typography>
                <Typography variant="body1">{jobStatus?.profile || '-'}</Typography>
              </Grid>
              <Grid item xs={6} sm={4}>
                <Typography variant="caption" color="text.secondary">Total Nodes</Typography>
                <Typography variant="body1">{jobStatus?.total_nodes || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={4}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <BugReport fontSize="small" color="action" />
                  <Typography variant="caption" color="text.secondary">Debug Level</Typography>
                </Box>
                <Chip
                  size="small"
                  label={formatDebugLevel(jobStatus?.debug_level)}
                  color={getDebugLevelColor(jobStatus?.debug_level)}
                  sx={{ mt: 0.5 }}
                />
              </Grid>
              <Grid item xs={6} sm={4}>
                <Typography variant="caption" color="text.secondary">Duration</Typography>
                <Typography variant="body1">{getDuration()}</Typography>
              </Grid>
              <Grid item xs={6} sm={4}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Schedule fontSize="small" color="action" />
                  <Typography variant="caption" color="text.secondary">Created</Typography>
                </Box>
                <Typography variant="body2">{formatDate(jobStatus?.created_at)}</Typography>
              </Grid>
              <Grid item xs={6} sm={4}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <AccessTime fontSize="small" color="action" />
                  <Typography variant="caption" color="text.secondary">Started</Typography>
                </Box>
                <Typography variant="body2">{formatDate(jobStatus?.started_at)}</Typography>
              </Grid>
              <Grid item xs={6} sm={4}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <CheckCircle fontSize="small" color="action" />
                  <Typography variant="caption" color="text.secondary">Completed</Typography>
                </Box>
                <Typography variant="body2">{formatDate(jobStatus?.completed_at)}</Typography>
              </Grid>
            </Grid>

            {/* Node Status Summary */}
            <Divider sx={{ my: 2 }} />
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
            <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Computer /> Node Status
              </Typography>
              <Divider sx={{ my: 2 }} />
              <List>
                {jobStatus.nodes.map((node) => (
                  <ListItem key={node.node} sx={{ py: 1.5 }}>
                    <ListItemIcon>
                      {node.status === 'succeeded' || node.status === 'completed' ? (
                        <CheckCircle color="success" />
                      ) : node.status === 'failed' ? (
                        <ErrorIcon color="error" />
                      ) : (
                        <HourglassEmpty color="info" />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={node.node}
                      secondary={
                        <Box component="span">
                          {node.error ? (
                            <Typography component="span" variant="body2" color="error">
                              Error: {node.error}
                            </Typography>
                          ) : (
                            <>
                              <Chip
                                size="small"
                                label={node.status}
                                color={statusColors[node.status] || 'default'}
                                sx={{ mr: 1 }}
                              />
                              {node.artifacts_count > 0 && (
                                <Typography component="span" variant="body2" color="text.secondary">
                                  {node.artifacts_count} files collected
                                </Typography>
                              )}
                            </>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Grid>

        {/* Artifacts Sidebar */}
        <Grid item xs={12} md={4}>
          <Paper variant="outlined" sx={{ p: 3, position: 'sticky', top: 24 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Folder /> Collected Logs
            </Typography>
            <Divider sx={{ my: 2 }} />

            {!isJobComplete ? (
              <Box sx={{ textAlign: 'center', py: 3 }}>
                <CircularProgress size={40} sx={{ mb: 2 }} />
                <Typography color="text.secondary">
                  Collecting logs...
                </Typography>
              </Box>
            ) : hasArtifacts ? (
              <>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    {artifacts.length} files ({formatSize(totalSize)})
                  </Typography>
                </Box>

                <Button
                  variant="contained"
                  fullWidth
                  startIcon={<Download />}
                  onClick={handleDownloadAll}
                  sx={{ mb: 2 }}
                >
                  Download All (ZIP)
                </Button>

                <List dense sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {artifacts.map((artifact, index) => (
                    <ListItem key={artifact.artifact_id || index} sx={{ px: 0 }}>
                      <ListItemText
                        primary={artifact.filename}
                        secondary={`${artifact.node} • ${formatSize(artifact.size_bytes)}`}
                        primaryTypographyProps={{ variant: 'body2', noWrap: true }}
                        secondaryTypographyProps={{ variant: 'caption' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </>
            ) : (
              <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 3 }}>
                {isJobSuccessful ? 'No logs collected' : 'Job did not complete successfully'}
              </Typography>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  )
}
