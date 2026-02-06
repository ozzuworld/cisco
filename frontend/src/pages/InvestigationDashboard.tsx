import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Alert,
  IconButton,
  Tooltip,
  Collapse,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material'
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Download as DownloadIcon,
  Cancel as CancelIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Schedule as ScheduleIcon,
  FiberManualRecord as DotIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { LoadingSpinner } from '@/components'
import {
  useInvestigation,
  usePrepareInvestigation,
  useStartRecording,
  useStopAndCollect,
  useCancelInvestigation,
} from '@/hooks/useInvestigation'
import { investigationService } from '@/services/investigationService'
import type { InvestigationStatus, InvestigationDeviceStatus, InvestigationPhase } from '@/types/investigation'

const STATUS_COLORS: Record<InvestigationStatus, string> = {
  created: '#64748b',
  preparing: '#f59e0b',
  ready: '#3b82f6',
  recording: '#ef4444',
  collecting: '#8b5cf6',
  bundling: '#6366f1',
  completed: '#10b981',
  partial: '#f59e0b',
  failed: '#ef4444',
  cancelled: '#6b7280',
}

const STATUS_LABELS: Record<InvestigationStatus, string> = {
  created: 'Created',
  preparing: 'Preparing...',
  ready: 'Ready',
  recording: 'Recording',
  collecting: 'Collecting...',
  bundling: 'Bundling...',
  completed: 'Completed',
  partial: 'Partial',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

const DEVICE_STATUS_ICONS: Record<InvestigationDeviceStatus, JSX.Element> = {
  pending: <ScheduleIcon sx={{ color: '#64748b', fontSize: 18 }} />,
  preparing: <DotIcon sx={{ color: '#f59e0b', fontSize: 18 }} />,
  ready: <CheckIcon sx={{ color: '#3b82f6', fontSize: 18 }} />,
  recording: <DotIcon sx={{ color: '#ef4444', fontSize: 18, animation: 'pulse 1s infinite' }} />,
  collecting: <DotIcon sx={{ color: '#8b5cf6', fontSize: 18 }} />,
  completed: <CheckIcon sx={{ color: '#10b981', fontSize: 18 }} />,
  failed: <ErrorIcon sx={{ color: '#ef4444', fontSize: 18 }} />,
  skipped: <DotIcon sx={{ color: '#9ca3af', fontSize: 18 }} />,
}

function PhaseProgressBar({ phases, activePhases }: { phases: InvestigationPhase[]; activePhases: string[] }) {
  const visiblePhases = phases.filter(p => activePhases.includes(p.name))

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
      {visiblePhases.map((phase, index) => {
        const isActive = phase.status === 'in_progress'
        const isComplete = phase.status === 'completed'
        const isFailed = phase.status === 'failed'

        let bgcolor = '#e2e8f0'
        if (isComplete) bgcolor = '#10b981'
        else if (isActive) bgcolor = '#3b82f6'
        else if (isFailed) bgcolor = '#ef4444'

        return (
          <Box key={phase.name} sx={{ display: 'flex', alignItems: 'center', flex: 1 }}>
            <Box sx={{ flex: 1 }}>
              <Typography variant="caption" fontWeight={600} sx={{ textTransform: 'capitalize', mb: 0.5, display: 'block' }}>
                {phase.name}
              </Typography>
              <Box sx={{ height: 8, borderRadius: 4, bgcolor, transition: 'all 0.3s' }}>
                {isActive && (
                  <LinearProgress
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      '& .MuiLinearProgress-bar': { bgcolor: '#3b82f6' },
                    }}
                  />
                )}
              </Box>
            </Box>
            {index < visiblePhases.length - 1 && (
              <Box sx={{ width: 20, height: 2, bgcolor: '#e2e8f0', mx: 0.5 }} />
            )}
          </Box>
        )
      })}
    </Box>
  )
}

function ElapsedTimer({ startedAt }: { startedAt?: string }) {
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!startedAt) return
    const start = new Date(startedAt).getTime()
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000))
    }, 1000)
    return () => clearInterval(interval)
  }, [startedAt])

  if (!startedAt) return null

  const mins = Math.floor(elapsed / 60)
  const secs = elapsed % 60
  return (
    <Chip
      icon={<ScheduleIcon />}
      label={`${mins}:${secs.toString().padStart(2, '0')}`}
      size="small"
      variant="outlined"
    />
  )
}

function RecordingPanel({ inv, onStopAndCollect }: {
  inv: import('@/types/investigation').InvestigationStatusResponse
  onStopAndCollect: () => void
}) {
  const [remaining, setRemaining] = useState<number | null>(null)

  useEffect(() => {
    if (!inv.recording_started_at || !inv.capture_duration_sec) return

    const startTime = new Date(inv.recording_started_at).getTime()
    const duration = inv.capture_duration_sec * 1000

    const interval = setInterval(() => {
      const left = Math.max(0, Math.floor((startTime + duration - Date.now()) / 1000))
      setRemaining(left)
    }, 1000)
    return () => clearInterval(interval)
  }, [inv.recording_started_at, inv.capture_duration_sec])

  const hasDuration = inv.capture_duration_sec && inv.capture_duration_sec > 0
  const mins = remaining !== null ? Math.floor(remaining / 60) : null
  const secs = remaining !== null ? remaining % 60 : null

  return (
    <Box sx={{ textAlign: 'center', py: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1, mb: 2 }}>
        <DotIcon sx={{ color: '#ef4444', animation: 'pulse 1s infinite' }} />
        <Typography variant="h6">Recording in progress</Typography>
      </Box>
      {hasDuration && remaining !== null && remaining > 0 ? (
        <>
          <Typography variant="h4" fontWeight={700} sx={{ mb: 1, fontFamily: 'monospace' }}>
            {mins}:{secs!.toString().padStart(2, '0')}
          </Typography>
          <LinearProgress
            variant="determinate"
            value={Math.max(0, 100 - (remaining / inv.capture_duration_sec!) * 100)}
            sx={{ mb: 2, mx: 'auto', maxWidth: 400, height: 8, borderRadius: 4 }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Reproduce the issue now. Collection starts automatically when the timer reaches zero.
          </Typography>
        </>
      ) : hasDuration && remaining === 0 ? (
        <>
          <LinearProgress sx={{ mb: 2, mx: 'auto', maxWidth: 400 }} />
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Capture duration reached. Waiting for all devices to finish file retrieval...
          </Typography>
        </>
      ) : (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Reproduce the issue now. Click "Stop & Collect Early" when done.
        </Typography>
      )}
      <Button
        variant="outlined"
        size="large"
        color="warning"
        startIcon={<StopIcon />}
        onClick={onStopAndCollect}
        disabled={remaining === 0}
      >
        Stop & Collect Early
      </Button>
    </Box>
  )
}

export default function InvestigationDashboard() {
  const { invId } = useParams<{ invId: string }>()
  const { enqueueSnackbar } = useSnackbar()
  const { data: inv, isLoading, refetch } = useInvestigation(invId || '', !!invId)

  const prepare = usePrepareInvestigation()
  const startRecording = useStartRecording()
  const stopAndCollect = useStopAndCollect()
  const cancelInv = useCancelInvestigation()

  const [showTimeline, setShowTimeline] = useState(true)

  if (isLoading || !inv) return <LoadingSpinner message="Loading investigation..." />

  const isTerminal = ['completed', 'partial', 'failed', 'cancelled'].includes(inv.status)

  const handlePrepare = () => {
    if (invId) {
      prepare.mutate(invId, {
        onSuccess: () => enqueueSnackbar('Preparation started', { variant: 'info' }),
        onError: () => enqueueSnackbar('Failed to start preparation', { variant: 'error' }),
      })
    }
  }

  const handleStartRecording = () => {
    if (invId) {
      startRecording.mutate(invId, {
        onSuccess: () => enqueueSnackbar('Recording started', { variant: 'info' }),
        onError: () => enqueueSnackbar('Failed to start recording', { variant: 'error' }),
      })
    }
  }

  const handleStopAndCollect = () => {
    if (invId) {
      stopAndCollect.mutate(invId, {
        onSuccess: () => enqueueSnackbar('Collecting artifacts...', { variant: 'info' }),
        onError: () => enqueueSnackbar('Failed to stop and collect', { variant: 'error' }),
      })
    }
  }

  const handleCancel = () => {
    if (invId) {
      cancelInv.mutate(invId, {
        onSuccess: () => enqueueSnackbar('Investigation cancelled', { variant: 'warning' }),
      })
    }
  }

  const handleDownload = () => {
    if (invId) investigationService.downloadBundle(invId)
  }

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 0.5 }}>
            <Typography variant="h4" fontWeight={700}>{inv.name}</Typography>
            <Chip
              label={STATUS_LABELS[inv.status]}
              sx={{
                bgcolor: `${STATUS_COLORS[inv.status]}20`,
                color: STATUS_COLORS[inv.status],
                fontWeight: 600,
              }}
            />
            <ElapsedTimer startedAt={inv.started_at} />
          </Box>
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            <Chip label={inv.scenario} size="small" variant="outlined" />
            <Typography variant="body2" color="text.secondary">
              {inv.devices.length} device{inv.devices.length !== 1 ? 's' : ''} | {inv.operations.join(', ')}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={() => refetch()}><RefreshIcon /></IconButton>
          </Tooltip>
          {!isTerminal && (
            <Button
              variant="outlined"
              color="error"
              startIcon={<CancelIcon />}
              onClick={handleCancel}
              disabled={cancelInv.isPending}
            >
              Cancel
            </Button>
          )}
        </Box>
      </Box>

      {/* Phase Progress */}
      <PhaseProgressBar phases={inv.phases} activePhases={inv.active_phases} />

      {/* Action Buttons based on status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          {inv.status === 'created' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>Investigation created. Ready to begin?</Typography>
              {inv.active_phases.includes('prepare') ? (
                <Button variant="contained" size="large" startIcon={<PlayIcon />} onClick={handlePrepare}>
                  Start Preparation
                </Button>
              ) : inv.active_phases.includes('record') ? (
                <Button variant="contained" size="large" startIcon={<PlayIcon />} onClick={handleStartRecording}>
                  Start Recording
                </Button>
              ) : (
                <Button variant="contained" size="large" startIcon={<PlayIcon />} onClick={handleStopAndCollect}>
                  Start Collection
                </Button>
              )}
            </Box>
          )}

          {inv.status === 'preparing' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <LinearProgress sx={{ mb: 2 }} />
              <Typography>Setting trace levels and running health checks...</Typography>
            </Box>
          )}

          {inv.status === 'ready' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <Alert severity="success" sx={{ mb: 2 }}>Preparation complete. All devices are ready.</Alert>
              {inv.active_phases.includes('record') ? (
                <Button variant="contained" size="large" color="error" startIcon={<PlayIcon />} onClick={handleStartRecording}>
                  Start Recording
                </Button>
              ) : (
                <Button variant="contained" size="large" startIcon={<PlayIcon />} onClick={handleStopAndCollect}>
                  Collect Artifacts
                </Button>
              )}
            </Box>
          )}

          {inv.status === 'recording' && (
            <RecordingPanel inv={inv} onStopAndCollect={handleStopAndCollect} />
          )}

          {inv.status === 'collecting' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <LinearProgress sx={{ mb: 2 }} />
              <Typography>Collecting logs and artifacts from devices...</Typography>
            </Box>
          )}

          {inv.status === 'bundling' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <LinearProgress sx={{ mb: 2 }} />
              <Typography>Creating artifact bundle...</Typography>
            </Box>
          )}

          {inv.status === 'completed' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <CheckIcon sx={{ fontSize: 48, color: '#10b981', mb: 1 }} />
              <Typography variant="h6" sx={{ mb: 2 }}>Investigation Complete</Typography>
              {inv.download_available && (
                <Button variant="contained" size="large" startIcon={<DownloadIcon />} onClick={handleDownload}>
                  Download Bundle
                </Button>
              )}
            </Box>
          )}

          {inv.status === 'partial' && (
            <Box sx={{ textAlign: 'center', py: 2 }}>
              <WarningIcon sx={{ fontSize: 48, color: '#f59e0b', mb: 1 }} />
              <Typography variant="h6" sx={{ mb: 2 }}>Partially Complete</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Some devices encountered errors. Artifacts from successful devices are available.
              </Typography>
              {inv.download_available && (
                <Button variant="contained" startIcon={<DownloadIcon />} onClick={handleDownload}>
                  Download Available Artifacts
                </Button>
              )}
            </Box>
          )}

          {inv.status === 'failed' && (
            <Alert severity="error">
              Investigation failed. Check the device table and timeline for details.
            </Alert>
          )}

          {inv.status === 'cancelled' && (
            <Alert severity="warning">Investigation was cancelled.</Alert>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={3}>
        {/* Device Table */}
        <Grid item xs={12} md={7}>
          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>Devices</Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Status</TableCell>
                      <TableCell>Name</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Host</TableCell>
                      <TableCell>Operation</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {inv.devices.map((device) => (
                      <TableRow key={device.device_id}>
                        <TableCell>
                          <Tooltip title={device.status}>
                            {DEVICE_STATUS_ICONS[device.status] || <DotIcon />}
                          </Tooltip>
                        </TableCell>
                        <TableCell>{device.name}</TableCell>
                        <TableCell>
                          <Chip label={device.device_type.toUpperCase()} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{device.host}</TableCell>
                        <TableCell>
                          {device.error ? (
                            <Typography variant="body2" color="error" sx={{ fontSize: '0.8rem' }}>
                              {device.error}
                            </Typography>
                          ) : (
                            <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.8rem' }}>
                              {device.current_operation || '-'}
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Timeline */}
        <Grid item xs={12} md={5}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="h6" fontWeight={600}>Timeline</Typography>
                <IconButton size="small" onClick={() => setShowTimeline(!showTimeline)}>
                  {showTimeline ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                </IconButton>
              </Box>
              <Collapse in={showTimeline}>
                <List dense sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {[...inv.events].reverse().map((event, i) => (
                    <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        {event.level === 'error' ? (
                          <ErrorIcon sx={{ fontSize: 16, color: '#ef4444' }} />
                        ) : event.level === 'warning' ? (
                          <WarningIcon sx={{ fontSize: 16, color: '#f59e0b' }} />
                        ) : (
                          <InfoIcon sx={{ fontSize: 16, color: '#3b82f6' }} />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={event.message}
                        secondary={new Date(event.timestamp).toLocaleTimeString()}
                        primaryTypographyProps={{ variant: 'body2', fontSize: '0.8rem' }}
                        secondaryTypographyProps={{ variant: 'caption' }}
                      />
                    </ListItem>
                  ))}
                  {inv.events.length === 0 && (
                    <Typography variant="body2" color="text.secondary" sx={{ py: 2, textAlign: 'center' }}>
                      No events yet
                    </Typography>
                  )}
                </List>
              </Collapse>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  )
}
