import { useQuery } from '@tanstack/react-query'
import { logService } from '@/services'
import type { LogFile } from '@/types'

export function useJobLogs(jobId: string, enabled = true) {
  return useQuery<LogFile[]>({
    queryKey: ['jobLogs', jobId],
    queryFn: () => logService.getJobLogs(jobId),
    enabled,
  })
}

export function useDownloadLog() {
  return async (jobId: string, filename: string) => {
    const blob = await logService.downloadLog(jobId, filename)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  }
}

export function useDownloadAllLogs() {
  return async (jobId: string, zipFilename = `job-${jobId}-logs.zip`) => {
    const blob = await logService.downloadAllLogs(jobId)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = zipFilename
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  }
}
