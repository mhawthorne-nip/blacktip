# Blacktip Web Frontend - Modern React UI

This is the redesigned modern web frontend for Blacktip, built with React, TypeScript, Tailwind CSS, and shadcn/ui components.

## Features

### Modern Tech Stack
- **React 18** with TypeScript for type safety
- **Vite** for fast development and optimized builds
- **Tailwind CSS** for utility-first styling
- **shadcn/ui** for beautiful, accessible UI components
- **React Router** for client-side routing
- **Radix UI** primitives for accessibility

### UI Improvements
- 🎨 Clean, modern design with consistent styling
- 🌙 Dark mode support with theme toggle
- 📱 Fully responsive layout for mobile and desktop
- ⚡ Smooth animations and transitions
- 🎯 Better UX with loading states and error handling
- 🔍 Enhanced search and filtering capabilities
- 📊 Improved data tables with sorting
- 🎭 Beautiful cards and badges
- ♿ Accessible components following WAI-ARIA standards

### Key Features Retained
- **Device Dashboard**: View all network devices with online/offline status
- **Device Details**: Click any device to see detailed information
- **Timeline View**: Track network events with filtering
- **Speed Test**: Run and view internet speed test results

## Development

### Install Dependencies
```bash
npm install
```

### Development Server
```bash
npm run dev
```

Runs on http://localhost:5173 with API proxy to Flask backend at http://localhost:5000

### Build for Production
```bash
npm run build
```

Built files go to `dist/` directory, served automatically by Flask.

## Project Structure

```
client/
├── src/
│   ├── components/        # Reusable UI components
│   ├── pages/            # Page components
│   ├── hooks/            # Custom React hooks
│   ├── services/         # API service layer
│   ├── types/            # TypeScript types
│   └── lib/              # Utilities
├── public/               # Static assets
└── dist/                 # Production build output
```

See the full documentation for more details.
