import { useNavigate } from 'react-router-dom'
import { Box, Grid, Card, CardActionArea, Typography, alpha } from '@mui/material'
import Lottie from 'lottie-react'
import { Description, GraphicEq, HealthAndSafety } from '@mui/icons-material'

import callAnimation from '@/assets/call.json'
import voiceAnimation from '@/assets/voice.json'
import healthAnimation from '@/assets/health.json'

interface FeatureCardProps {
  animation: object
  title: string
  subtitle: string
  icon: React.ReactElement
  accentColor: string
  onClick: () => void
}

function FeatureCard({ animation, title, subtitle, icon, accentColor, onClick }: FeatureCardProps) {
  return (
    <Card
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        border: 'none',
        boxShadow: `0 4px 20px ${alpha(accentColor, 0.15)}`,
        borderRadius: 4,
        overflow: 'hidden',
        transition: 'all 0.3s ease',
        background: theme => theme.palette.mode === 'dark'
          ? `linear-gradient(180deg, ${alpha(accentColor, 0.08)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 40%)`
          : `linear-gradient(180deg, ${alpha(accentColor, 0.06)} 0%, ${theme.palette.background.paper} 40%)`,
        '&:hover': {
          transform: 'translateY(-8px)',
          boxShadow: `0 12px 40px ${alpha(accentColor, 0.3)}`,
        },
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
          p: 4,
          position: 'relative',
        }}
      >
        {/* Accent bar at top */}
        <Box
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: 4,
            background: `linear-gradient(90deg, ${accentColor} 0%, ${alpha(accentColor, 0.5)} 100%)`,
          }}
        />

        {/* Floating icon badge */}
        <Box
          sx={{
            position: 'absolute',
            top: 16,
            right: 16,
            width: 40,
            height: 40,
            borderRadius: 2,
            bgcolor: alpha(accentColor, 0.1),
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${alpha(accentColor, 0.2)}`,
          }}
        >
          {icon}
        </Box>

        {/* Animation container with glow */}
        <Box
          sx={{
            width: 160,
            height: 160,
            mb: 3,
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: theme => theme.palette.mode === 'dark'
              ? `radial-gradient(circle, ${alpha(accentColor, 0.15)} 0%, transparent 70%)`
              : `radial-gradient(circle, ${alpha(accentColor, 0.1)} 0%, transparent 70%)`,
            p: 1,
          }}
        >
          <Lottie animationData={animation} loop={true} style={{ width: '100%', height: '100%' }} />
        </Box>

        {/* Title */}
        <Typography
          variant="h5"
          fontWeight={700}
          sx={{
            color: 'text.primary',
            mb: 0.5,
          }}
        >
          {title}
        </Typography>

        {/* Subtitle */}
        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            textAlign: 'center',
          }}
        >
          {subtitle}
        </Typography>

        {/* Bottom accent */}
        <Box
          sx={{
            mt: 3,
            px: 3,
            py: 0.75,
            borderRadius: 2,
            bgcolor: alpha(accentColor, 0.1),
            border: `1px solid ${alpha(accentColor, 0.2)}`,
          }}
        >
          <Typography
            variant="caption"
            fontWeight={600}
            sx={{ color: accentColor, textTransform: 'uppercase', letterSpacing: 1 }}
          >
            Get Started
          </Typography>
        </Box>
      </CardActionArea>
    </Card>
  )
}

// Feature accent colors
const FEATURE_COLORS = {
  callRouting: '#1976d2',   // blue
  voiceQuality: '#0d9488',  // teal
  healthCheck: '#10b981',   // emerald
}

export default function Landing() {
  const navigate = useNavigate()

  return (
    <Box
      sx={{
        minHeight: 'calc(100vh - 120px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 3,
      }}
    >
      <Grid container spacing={4} sx={{ maxWidth: 1200, justifyContent: 'center' }}>
        <Grid item xs={12} sm={6} md={4}>
          <FeatureCard
            animation={callAnimation}
            title="Call Routing"
            subtitle="Collect logs from CUCM, CUBE & Expressway devices"
            icon={<Description sx={{ fontSize: 22, color: FEATURE_COLORS.callRouting }} />}
            accentColor={FEATURE_COLORS.callRouting}
            onClick={() => navigate('/logs/new')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={4}>
          <FeatureCard
            animation={voiceAnimation}
            title="Voice Quality"
            subtitle="Capture packets across multiple network devices"
            icon={<GraphicEq sx={{ fontSize: 22, color: FEATURE_COLORS.voiceQuality }} />}
            accentColor={FEATURE_COLORS.voiceQuality}
            onClick={() => navigate('/captures')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={4}>
          <FeatureCard
            animation={healthAnimation}
            title="Health Check"
            subtitle="Monitor system health and performance metrics"
            icon={<HealthAndSafety sx={{ fontSize: 22, color: FEATURE_COLORS.healthCheck }} />}
            accentColor={FEATURE_COLORS.healthCheck}
            onClick={() => navigate('/health')}
          />
        </Grid>
      </Grid>
    </Box>
  )
}
