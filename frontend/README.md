# CUCM Log Collector - React Frontend

A modern React-based frontend for the CUCM (Cisco Unified Communications Manager) log collection system. This application provides an intuitive interface for managing log collection jobs, monitoring cluster status, and downloading collected logs.

## Features

- **Cluster Discovery**: Connect to CUCM and automatically discover all cluster nodes
- **Job Management**: Create, monitor, and manage log collection jobs
- **Profile Selection**: Choose from predefined or custom log collection profiles
- **Real-time Updates**: Monitor job status with real-time updates
- **Log Downloads**: Download individual logs or bulk download as zip
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices

## Tech Stack

- **React 18** - Modern React with hooks
- **TypeScript** - Type-safe development
- **Vite** - Fast build tool and dev server
- **Material-UI (MUI)** - Professional component library
- **React Router** - Client-side routing
- **TanStack Query** - Data fetching and caching1
- **Axios** - HTTP client
- **React Hook Form** - Form management
- **Zod** - Schema validation

## Project Structure

```
src/
├── components/     # Reusable UI components
├── pages/          # Page components (Dashboard, Jobs, Profiles, Settings)
├── layouts/        # Layout components (MainLayout with navigation)
├── services/       # API services (cluster, jobs, profiles, logs)
├── hooks/          # Custom React hooks
├── types/          # TypeScript type definitions
├── utils/          # Utility functions
├── theme/          # MUI theme configuration
├── App.tsx         # Main app component with routing
└── main.tsx        # Application entry point
```

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- CUCM Log Collector Backend running (https://github.com/ozzuworld/cisco)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/ozzuworld/cisco-js.git
cd cisco-js
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
```bash
cp .env.example .env
```

Edit `.env` and set your backend API URL:
```
VITE_API_BASE_URL=http://localhost:8000
```

### Development

Start the development server:
```bash
npm run dev
```

The application will be available at `http://localhost:3000`

### Build

Build for production:
```bash
npm run build
```

Preview production build:
```bash
npm run preview
```

### Code Quality

Format code with Prettier:
```bash
npm run format
```

Lint code with ESLint:
```bash
npm run lint
```

## Development Sprints

This project is organized into 5 sprints following Jira-style methodology. See [SPRINT_PLAN.md](./SPRINT_PLAN.md) for detailed sprint breakdown.

### Sprint Status

- **Sprint 1**: Project Setup & Infrastructure ✅ COMPLETED
- **Sprint 2**: Core UI Components & Design System ✅ COMPLETED
- **Sprint 3**: Backend Integration & API Layer ✅ COMPLETED
- **Sprint 4**: Dashboard & Job Management - NEXT
- **Sprint 5**: Testing, Polish & Documentation - PENDING

## API Integration

The frontend connects to the FastAPI backend via the following services:

- **clusterService**: Cluster discovery and connection testing
- **jobService**: Job creation, listing, and management
- **profileService**: Log profile management
- **logService**: Log file downloads

All API calls are typed with TypeScript interfaces for type safety.

## Features Roadmap

### Sprint 2: Core Components
- Connection form component
- Profile selector
- Job status cards
- Node list/table

### Sprint 3: Backend Integration
- Cluster discovery integration
- Job management (create, list, cancel)
- Profile fetching
- Log downloads

### Sprint 4: Main Features
- Dashboard with statistics
- Job creation wizard
- Jobs list with filtering
- Job details with transcript viewer

### Sprint 5: Polish
- Error handling & notifications
- Responsive design optimization
- Unit & integration tests
- Documentation

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_BASE_URL` | Backend API base URL | `http://localhost:8000` |
| `VITE_API_VERSION` | API version | `v1` |

## Contributing

1. Create a feature branch
2. Make your changes
3. Run linting and formatting
4. Submit a pull request

## License

MIT

## Related Projects

- [CUCM Log Collector Backend](https://github.com/ozzuworld/cisco) - Python FastAPI backend

## Support

For issues and questions, please use the GitHub issue tracker.
