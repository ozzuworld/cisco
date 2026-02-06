import { useNavigate } from 'react-router-dom'
import { Box, Grid, Card, CardActionArea, Typography, alpha, Button, Chip, Divider } from '@mui/material'
import Lottie from 'lottie-react'
import {
  Description,
  GraphicEq,
  HealthAndSafety,
  BugReport,
  Troubleshoot as TroubleshootIcon,
  Add as AddIcon,
  ArrowForward as ArrowIcon,
} from '@mui/icons-material'

import callAnimation from '@/assets/call.json'
import voiceAnimation from '@/assets/voice.json'
import healthAnimation from '@/assets/health.json'
import { useInvestigations } from '@/hooks/useInvestigation'

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
  traceLevel: '#ed6c02',    // orange
}

const STATUS_COLORS: Record<string, string> = {
  created: '#64748b',
  preparing: '#f59e0b',
  ready: '#3b82f6',
  recording: '#ef4444',
  collecting: '#8b5cf6',
  completed: '#10b981',
  partial: '#f59e0b',
  failed: '#ef4444',
  cancelled: '#6b7280',
}

export default function Landing() {
  const navigate = useNavigate()
  const { data: invData } = useInvestigations()

  const recentInvestigations = (invData?.investigations || []).slice(0, 5)

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      {/* Hero Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 5,
          mb: 4,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1, mb: 2 }}>
          <TroubleshootIcon sx={{ fontSize: 40, color: 'primary.main' }} />
          <Typography variant="h3" fontWeight={800}>
            CUCM Collector
          </Typography>
        </Box>
        <Typography variant="h6" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
          Orchestrate troubleshooting across CUCM, CUBE, and Expressway devices
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<AddIcon />}
          onClick={() => navigate('/investigations/new')}
          sx={{
            px: 4,
            py: 1.5,
            fontSize: '1.1rem',
            fontWeight: 700,
            borderRadius: 3,
          }}
        >
          Start New Investigation
        </Button>
      </Box>

      {/* Recent Investigations */}
      {recentInvestigations.length > 0 && (
        <Box sx={{ mb: 5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6" fontWeight={600}>Recent Investigations</Typography>
            <Button size="small" endIcon={<ArrowIcon />} onClick={() => navigate('/investigations')}>
              View All
            </Button>
          </Box>
          <Grid container spacing={2}>
            {recentInvestigations.map((inv) => (
              <Grid item xs={12} sm={6} md={4} key={inv.investigation_id}>
                <Card
                  sx={{
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 },
                  }}
                  onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                >
                  <Box sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="subtitle2" fontWeight={600} noWrap sx={{ flex: 1 }}>
                        {inv.name}
                      </Typography>
                      <Chip
                        label={inv.status}
                        size="small"
                        sx={{
                          bgcolor: `${STATUS_COLORS[inv.status] || '#64748b'}20`,
                          color: STATUS_COLORS[inv.status] || '#64748b',
                          fontWeight: 600,
                          fontSize: '0.7rem',
                        }}
                      />
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      {inv.scenario} | {inv.device_count} devices | {new Date(inv.created_at).toLocaleDateString()}
                    </Typography>
                  </Box>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Individual Tools Section */}
      <Box sx={{ mb: 2 }}>
        <Divider sx={{ mb: 3 }} />
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
          Individual Tools
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Use individual tools for quick one-off operations without creating a full investigation.
        </Typography>
      </Box>

      <Grid container spacing={4} sx={{ justifyContent: 'center' }}>
        <Grid item xs={12} sm={6} md={3}>
          <FeatureCard
            animation={callAnimation}
            title="Call Routing"
            subtitle="Collect logs from CUCM, CUBE & Expressway devices"
            icon={<Description sx={{ fontSize: 22, color: FEATURE_COLORS.callRouting }} />}
            accentColor={FEATURE_COLORS.callRouting}
            onClick={() => navigate('/logs/new')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <FeatureCard
            animation={voiceAnimation}
            title="Voice Quality"
            subtitle="Capture packets across multiple network devices"
            icon={<GraphicEq sx={{ fontSize: 22, color: FEATURE_COLORS.voiceQuality }} />}
            accentColor={FEATURE_COLORS.voiceQuality}
            onClick={() => navigate('/captures')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <FeatureCard
            animation={healthAnimation}
            title="Health Check"
            subtitle="Monitor system health and performance metrics"
            icon={<HealthAndSafety sx={{ fontSize: 22, color: FEATURE_COLORS.healthCheck }} />}
            accentColor={FEATURE_COLORS.healthCheck}
            onClick={() => navigate('/health')}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <FeatureCard
            animation={callAnimation}
            title="Trace Level"
            subtitle="Check and configure CUCM trace levels for debugging"
            icon={<BugReport sx={{ fontSize: 22, color: FEATURE_COLORS.traceLevel }} />}
            accentColor={FEATURE_COLORS.traceLevel}
            onClick={() => navigate('/trace-levels')}
          />
        </Grid>
      </Grid>
    </Box>
  )
}
