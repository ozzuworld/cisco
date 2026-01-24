import { Box, Card, CardActionArea, Grid } from '@mui/material'
import Lottie from 'lottie-react'
import { useNavigate } from 'react-router-dom'

import callAnimation from '@/assets/call.json'
import voiceAnimation from '@/assets/voice.json'
import healthAnimation from '@/assets/health.json'

interface FeatureCardProps {
  animation: object
  title: string
  onClick: () => void
}

function FeatureCard({ animation, title, onClick }: FeatureCardProps) {
  return (
    <Card
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        border: '1px solid',
        borderColor: 'divider',
        boxShadow: 1,
        borderRadius: 3,
        overflow: 'hidden',
      }}
    >
      <CardActionArea
        onClick={onClick}
        sx={{
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          p: 3,
        }}
      >
        <Box
          sx={{
            width: 120,
            height: 120,
            mb: 2,
          }}
        >
          <Lottie animationData={animation} loop={true} />
        </Box>
        <Box
          component="span"
          sx={{
            fontSize: '1.1rem',
            fontWeight: 600,
            color: 'text.primary',
          }}
        >
          {title}
        </Box>
      </CardActionArea>
    </Card>
  )
}

export default function Home() {
  const navigate = useNavigate()

  return (
    <Box sx={{ p: 2 }}>
      <Grid container spacing={3} justifyContent="center">
        <Grid item xs={12} sm={6} md={4}>
          <FeatureCard
            animation={callAnimation}
            title="Call Routing"
            onClick={() => navigate('/jobs')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={4}>
          <FeatureCard
            animation={voiceAnimation}
            title="Voice Quality"
            onClick={() => navigate('/captures')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={4}>
          <FeatureCard
            animation={healthAnimation}
            title="Health Check"
            onClick={() => navigate('/health')}
          />
        </Grid>
      </Grid>
    </Box>
  )
}
