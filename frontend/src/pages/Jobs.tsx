import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Grid,
  TextField,
  InputAdornment,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Pagination,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material'
import {
  Search as SearchIcon,
  Add as AddIcon,
  ArrowUpward,
  ArrowDownward,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { JobStatusCard, EmptyState, LoadingSpinner, JobWizard } from '@/components'
import { useJobs, useCancelJob, useDownloadAllLogs } from '@/hooks'
import type { JobStatus, Job } from '@/types'

type SortField = 'createdAt' | 'status'
type SortOrder = 'asc' | 'desc'

export default function Jobs() {
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<JobStatus | 'all'>('all')
  const [showWizard, setShowWizard] = useState(false)
  const [page, setPage] = useState(1)
  const [sortField, setSortField] = useState<SortField>('createdAt')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()

  const pageSize = 12

  // Fetch jobs from API
  const { data: jobsData, isLoading } = useJobs(1, 100)
  const cancelMutation = useCancelJob()
  const downloadAllLogs = useDownloadAllLogs()

  const handleJobCreated = (jobId: string) => {
    enqueueSnackbar(`Job ${jobId} created successfully`, { variant: 'success' })
  }

  const handleViewJob = (jobId: string) => {
    navigate(`/jobs/${jobId}`)
  }

  const handleCancelJob = async (jobId: string) => {
    try {
      await cancelMutation.mutateAsync(jobId)
      enqueueSnackbar('Job cancelled successfully', { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(error instanceof Error ? error.message : 'Failed to cancel job', {
        variant: 'error',
      })
    }
  }

  const handleDownloadLogs = async (jobId: string) => {
    try {
      await downloadAllLogs(jobId)
      enqueueSnackbar('Logs download started', { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(error instanceof Error ? error.message : 'Failed to download logs', {
        variant: 'error',
      })
    }
  }

  // Status priority for sorting
  const statusPriority: Record<string, number> = {
    running: 1,
    pending: 2,
    completed: 3,
    failed: 4,
    cancelled: 5,
  }

  const filteredAndSortedJobs = useMemo(() => {
    if (!jobsData?.items) return []

    // Filter
    const filtered = jobsData.items.filter(job => {
      const matchesSearch =
        job.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        job.clusterName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        job.profileName.toLowerCase().includes(searchQuery.toLowerCase())
      const matchesStatus = statusFilter === 'all' || job.status === statusFilter
      return matchesSearch && matchesStatus
    })

    // Sort
    const sorted = [...filtered].sort((a: Job, b: Job) => {
      let comparison = 0
      if (sortField === 'createdAt') {
        comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
      } else if (sortField === 'status') {
        comparison = (statusPriority[a.status] || 99) - (statusPriority[b.status] || 99)
      }
      return sortOrder === 'asc' ? comparison : -comparison
    })

    return sorted
  }, [jobsData, searchQuery, statusFilter, sortField, sortOrder])

  // Pagination
  const totalPages = Math.ceil(filteredAndSortedJobs.length / pageSize)
  const paginatedJobs = filteredAndSortedJobs.slice((page - 1) * pageSize, page * pageSize)

  const handlePageChange = (_: React.ChangeEvent<unknown>, value: number) => {
    setPage(value)
  }

  const toggleSortOrder = () => {
    setSortOrder(prev => (prev === 'asc' ? 'desc' : 'asc'))
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Log Collection Jobs
          </Typography>
          <Typography color="text.secondary">
            View and manage all your log collection jobs
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setShowWizard(true)}>
          New Job
        </Button>
      </Box>

      <JobWizard open={showWizard} onClose={() => setShowWizard(false)} onSuccess={handleJobCreated} />

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3, mt: 3, flexWrap: 'wrap' }}>
        <TextField
          placeholder="Search jobs..."
          value={searchQuery}
          onChange={e => { setSearchQuery(e.target.value); setPage(1) }}
          sx={{ flexGrow: 1, minWidth: 200 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
        />
        <FormControl sx={{ minWidth: 150 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={statusFilter}
            label="Status"
            onChange={e => { setStatusFilter(e.target.value as JobStatus | 'all'); setPage(1) }}
          >
            <MenuItem value="all">All Statuses</MenuItem>
            <MenuItem value="running">Running</MenuItem>
            <MenuItem value="completed">Completed</MenuItem>
            <MenuItem value="failed">Failed</MenuItem>
            <MenuItem value="cancelled">Cancelled</MenuItem>
            <MenuItem value="pending">Pending</MenuItem>
          </Select>
        </FormControl>
        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Sort By</InputLabel>
          <Select
            value={sortField}
            label="Sort By"
            onChange={e => setSortField(e.target.value as SortField)}
          >
            <MenuItem value="createdAt">Date</MenuItem>
            <MenuItem value="status">Status</MenuItem>
          </Select>
        </FormControl>
        <ToggleButtonGroup
          value={sortOrder}
          exclusive
          onChange={toggleSortOrder}
          size="small"
          sx={{ height: 40, alignSelf: 'center' }}
        >
          <ToggleButton value="desc" aria-label="descending">
            <ArrowDownward fontSize="small" />
          </ToggleButton>
          <ToggleButton value="asc" aria-label="ascending">
            <ArrowUpward fontSize="small" />
          </ToggleButton>
        </ToggleButtonGroup>
      </Box>

      {/* Jobs Grid */}
      {isLoading ? (
        <LoadingSpinner message="Loading jobs..." />
      ) : paginatedJobs.length > 0 ? (
        <>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, filteredAndSortedJobs.length)} of {filteredAndSortedJobs.length} jobs
          </Typography>
          <Grid container spacing={2}>
            {paginatedJobs.map(job => (
              <Grid item xs={12} md={6} lg={4} key={job.id}>
                <JobStatusCard
                  job={job}
                  onView={handleViewJob}
                  onCancel={handleCancelJob}
                  onDownload={handleDownloadLogs}
                />
              </Grid>
            ))}
          </Grid>
          {totalPages > 1 && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
              <Pagination
                count={totalPages}
                page={page}
                onChange={handlePageChange}
                color="primary"
                showFirstButton
                showLastButton
              />
            </Box>
          )}
        </>
      ) : (
        <EmptyState
          title="No jobs found"
          description={
            jobsData?.total === 0
              ? 'No jobs yet. Click "New Job" to get started.'
              : 'No jobs match your search criteria. Try adjusting your filters.'
          }
        />
      )}
    </Box>
  )
}
