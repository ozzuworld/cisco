import { useState } from 'react'
import {
  Box,
  Stepper,
  Step,
  StepLabel,
  Button,
  Paper,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
} from '@mui/material'
import { useSnackbar } from 'notistack'
import ConnectionForm from './ConnectionForm'
import { NodeSelectionStep } from './wizard/NodeSelectionStep'
import { ProfileSelectionStep } from './wizard/ProfileSelectionStep'
import { ReviewStep } from './wizard/ReviewStep'
import { JobProgressStep } from './wizard/JobProgressStep'
import { useDiscoverCluster, useCreateJob } from '@/hooks'
import type { ConnectionRequest, ClusterNode, LogProfile, DebugLevel } from '@/types'

interface JobWizardProps {
  open: boolean
  onClose: () => void
  onSuccess?: (jobId: string) => void
}

interface WizardData {
  connection: ConnectionRequest | null
  discoveredNodes: ClusterNode[]
  selectedNodes: string[]
  profile: LogProfile | null
  debugLevel: DebugLevel
  createdJobId: string | null
}

const steps = ['Connect to CUCM', 'Select Nodes', 'Choose Profile', 'Review & Submit', 'Collecting Logs']

export function JobWizard({ open, onClose, onSuccess }: JobWizardProps) {
  const [activeStep, setActiveStep] = useState(0)
  const [wizardData, setWizardData] = useState<WizardData>({
    connection: null,
    discoveredNodes: [],
    selectedNodes: [],
    profile: null,
    debugLevel: 'basic',
    createdJobId: null,
  })

  const { enqueueSnackbar } = useSnackbar()
  const discoverMutation = useDiscoverCluster()
  const createJobMutation = useCreateJob()

  const handleNext = () => {
    setActiveStep(prev => prev + 1)
  }

  const handleBack = () => {
    setActiveStep(prev => prev - 1)
  }

  const handleReset = () => {
    setActiveStep(0)
    setWizardData({
      connection: null,
      discoveredNodes: [],
      selectedNodes: [],
      profile: null,
      debugLevel: 'basic',
      createdJobId: null,
    })
  }

  const handleCloseDialog = () => {
    handleReset()
    onClose()
  }

  // Step 1: Connection
  const handleConnect = async (data: ConnectionRequest) => {
    try {
      const result = await discoverMutation.mutateAsync(data)
      setWizardData(prev => ({
        ...prev,
        connection: data,
        discoveredNodes: result.nodes,
        selectedNodes: result.nodes.map(n => n.ip), // Select all by default
      }))
      enqueueSnackbar(
        `Successfully discovered ${result.nodes.length} nodes`,
        { variant: 'success' }
      )
      handleNext()
    } catch (error) {
      enqueueSnackbar(error instanceof Error ? error.message : 'Failed to connect to CUCM', {
        variant: 'error',
      })
    }
  }

  // Step 2: Node Selection
  const handleNodeSelection = (selectedNodeIds: string[]) => {
    if (selectedNodeIds.length === 0) {
      enqueueSnackbar('Please select at least one node', { variant: 'warning' })
      return
    }
    setWizardData(prev => ({ ...prev, selectedNodes: selectedNodeIds }))
    handleNext()
  }

  // Step 3: Profile Selection
  const handleProfileSelection = (profile: LogProfile) => {
    setWizardData(prev => ({ ...prev, profile }))
    handleNext()
  }

  // Handle debug level change from review step
  const handleDebugLevelChange = (debugLevel: DebugLevel) => {
    setWizardData(prev => ({ ...prev, debugLevel }))
  }

  // Step 4: Submit Job
  const handleSubmit = async () => {
    if (!wizardData.connection || !wizardData.profile) {
      enqueueSnackbar('Missing required data', { variant: 'error' })
      return
    }

    try {
      const job = await createJobMutation.mutateAsync({
        publisher_host: wizardData.connection.hostname,
        username: wizardData.connection.username,
        password: wizardData.connection.password,
        port: wizardData.connection.port || 22,
        nodes: wizardData.selectedNodes,
        profile: wizardData.profile.name,
        options: {
          debug_level: wizardData.debugLevel,
        },
      })

      enqueueSnackbar(`Job ${job.id} created - collecting logs...`, { variant: 'success' })

      // Store job ID and move to progress step
      setWizardData(prev => ({ ...prev, createdJobId: job.id }))
      handleNext()
      onSuccess?.(job.id)
    } catch (error) {
      enqueueSnackbar(error instanceof Error ? error.message : 'Failed to create job', {
        variant: 'error',
      })
    }
  }

  // Handle completion from progress step
  const handleProgressComplete = () => {
    handleCloseDialog()
  }

  const renderStepContent = (step: number) => {
    switch (step) {
      case 0:
        return (
          <ConnectionForm
            onSubmit={handleConnect}
            isLoading={discoverMutation.isPending}
            error={discoverMutation.error?.message}
            defaultValues={wizardData.connection || undefined}
          />
        )
      case 1:
        return (
          <NodeSelectionStep
            nodes={wizardData.discoveredNodes}
            selectedNodes={wizardData.selectedNodes}
            onNext={handleNodeSelection}
            onBack={handleBack}
          />
        )
      case 2:
        return (
          <ProfileSelectionStep
            selectedProfile={wizardData.profile}
            onNext={handleProfileSelection}
            onBack={handleBack}
          />
        )
      case 3:
        return (
          <ReviewStep
            data={wizardData}
            onSubmit={handleSubmit}
            onBack={handleBack}
            onDebugLevelChange={handleDebugLevelChange}
            isLoading={createJobMutation.isPending}
          />
        )
      case 4:
        return wizardData.createdJobId ? (
          <JobProgressStep
            jobId={wizardData.createdJobId}
            onClose={handleProgressComplete}
          />
        ) : null
      default:
        return null
    }
  }

  return (
    <Dialog open={open} onClose={handleCloseDialog} maxWidth="md" fullWidth>
      <DialogTitle>
        <Typography variant="h5">Create New Log Collection Job</Typography>
      </DialogTitle>
      <DialogContent>
        <Box sx={{ pt: 2 }}>
          <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
            {steps.map(label => (
              <Step key={label}>
                <StepLabel>{label}</StepLabel>
              </Step>
            ))}
          </Stepper>

          <Paper sx={{ p: 3, minHeight: 400 }}>{renderStepContent(activeStep)}</Paper>

          {activeStep === 0 && (
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
              <Button onClick={handleCloseDialog}>Cancel</Button>
            </Box>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  )
}
