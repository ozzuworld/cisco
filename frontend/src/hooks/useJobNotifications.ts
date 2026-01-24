import { useEffect, useRef } from 'react'
import { useSnackbar } from 'notistack'
import { useJobs } from './useJobs'
import type { Job } from '@/types'

/**
 * Hook that monitors job status changes and shows toast notifications
 * when jobs complete or fail
 */
export function useJobNotifications() {
  const { enqueueSnackbar } = useSnackbar()
  const { data: jobsData } = useJobs(1, 20)
  const previousJobsRef = useRef<Map<string, Job['status']>>(new Map())

  useEffect(() => {
    if (!jobsData?.items) return

    const currentJobs = jobsData.items
    const previousJobs = previousJobsRef.current

    // Check for status changes
    currentJobs.forEach(job => {
      const previousStatus = previousJobs.get(job.id)

      // Only notify if we've seen this job before (not on initial load)
      if (previousStatus && previousStatus !== job.status) {
        // Job completed
        if (job.status === 'completed' && previousStatus === 'running') {
          enqueueSnackbar(`Job ${job.id.slice(0, 8)}... completed successfully!`, {
            variant: 'success',
            autoHideDuration: 5000,
          })
        }
        // Job failed
        else if (job.status === 'failed' && previousStatus === 'running') {
          enqueueSnackbar(`Job ${job.id.slice(0, 8)}... failed`, {
            variant: 'error',
            autoHideDuration: 6000,
          })
        }
        // Job cancelled
        else if (job.status === 'cancelled') {
          enqueueSnackbar(`Job ${job.id.slice(0, 8)}... was cancelled`, {
            variant: 'warning',
            autoHideDuration: 4000,
          })
        }
      }
    })

    // Update the previous jobs map
    const newMap = new Map<string, Job['status']>()
    currentJobs.forEach(job => {
      newMap.set(job.id, job.status)
    })
    previousJobsRef.current = newMap
  }, [jobsData, enqueueSnackbar])
}
