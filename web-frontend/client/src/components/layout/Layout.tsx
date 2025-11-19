import { NavLink, Outlet } from 'react-router-dom'
import { Monitor, Activity, Wifi, Menu, Moon, Sun } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useStatistics } from '@/hooks/useStatistics'
import { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'

export function Layout() {
  const { statistics } = useStatistics()
  const [darkMode, setDarkMode] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  useEffect(() => {
    const isDark = document.documentElement.classList.contains('dark')
    setDarkMode(isDark)
  }, [])

  const toggleDarkMode = () => {
    const newMode = !darkMode
    setDarkMode(newMode)
    if (newMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Sidebar */}
      <aside
        className={cn(
          'flex flex-col border-r bg-card transition-all duration-300',
          sidebarOpen ? 'w-64' : 'w-16'
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <div className={cn('flex items-center gap-2', !sidebarOpen && 'hidden')}>
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <Monitor className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="text-lg font-bold">Blacktip</span>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className={cn(!sidebarOpen && 'mx-auto')}
          >
            <Menu className="w-5 h-5" />
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1">
          <NavLink
            to="/"
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-md transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-accent hover:text-accent-foreground'
              )
            }
          >
            <Monitor className="w-5 h-5" />
            {sidebarOpen && <span className="font-medium">Devices</span>}
          </NavLink>

          <NavLink
            to="/timeline"
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-md transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-accent hover:text-accent-foreground'
              )
            }
          >
            <Activity className="w-5 h-5" />
            {sidebarOpen && <span className="font-medium">Timeline</span>}
          </NavLink>

          <NavLink
            to="/speedtest"
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-md transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-accent hover:text-accent-foreground'
              )
            }
          >
            <Wifi className="w-5 h-5" />
            {sidebarOpen && <span className="font-medium">Speed Test</span>}
          </NavLink>
        </nav>

        {/* Footer with stats and theme toggle */}
        <div className="p-3 border-t space-y-3">
          {sidebarOpen && statistics && (
            <div className="space-y-2 px-3 py-2 rounded-md bg-secondary/50">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Total</span>
                <span className="font-semibold">{statistics.total_devices}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Online</span>
                <span className="font-semibold text-green-600">
                  {statistics.online_devices}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Offline</span>
                <span className="font-semibold text-gray-500">
                  {statistics.offline_devices}
                </span>
              </div>
            </div>
          )}
          <Button
            variant="ghost"
            size={sidebarOpen ? 'default' : 'icon'}
            onClick={toggleDarkMode}
            className={cn('w-full', !sidebarOpen && 'mx-auto')}
          >
            {darkMode ? (
              <>
                <Sun className="w-5 h-5" />
                {sidebarOpen && <span className="ml-2">Light Mode</span>}
              </>
            ) : (
              <>
                <Moon className="w-5 h-5" />
                {sidebarOpen && <span className="ml-2">Dark Mode</span>}
              </>
            )}
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
