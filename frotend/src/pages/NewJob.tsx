import { useNavigate } from 'react-router-dom'
import { Box } from '@mui/material'
import { useSnackbar } from 'notistack'
import { JobWizard } from '@/components'

export default function NewJob() {
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()

  const handleClose = () => {
    navigate('/')
  }

  const handleSuccess = (jobId: string) => {
    enqueueSnackbar(`Job ${jobId} created successfully`, { variant: 'success' })
    navigate(`/jobs/${jobId}`)
  }

  return (
    <Box>
      <JobWizard
        open={true}
        onClose={handleClose}
        onSuccess={handleSuccess}
      />
    </Box>
  )
}
