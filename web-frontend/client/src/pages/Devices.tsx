import { useState, useMemo } from 'react'
import { useDevices } from '@/hooks/useDevices'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Search, RefreshCw, ArrowUpDown } from 'lucide-react'
import { DeviceDetailsDialog } from '@/components/DeviceDetailsDialog'
import { timeAgo } from '@/lib/utils'
import type { Device } from '@/types'

type SortField = 'ip_address' | 'mac_address' | 'vendor' | 'last_seen' | 'port_count'
type SortOrder = 'asc' | 'desc'
type FilterStatus = 'all' | 'online' | 'offline'

export function Devices() {
  const { devices, loading, error, refetch } = useDevices()
  const [searchQuery, setSearchQuery] = useState('')
  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all')
  const [sortField, setSortField] = useState<SortField>('last_seen')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)

  const filteredAndSortedDevices = useMemo(() => {
    let result = [...devices]

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      result = result.filter(
        (device) =>
          device.ip_address.toLowerCase().includes(query) ||
          device.mac_address.toLowerCase().includes(query) ||
          device.vendor?.toLowerCase().includes(query) ||
          device.hostname?.toLowerCase().includes(query) ||
          device.device_name?.toLowerCase().includes(query)
      )
    }

    // Filter by status
    if (filterStatus !== 'all') {
      result = result.filter((device) =>
        filterStatus === 'online' ? device.is_online : !device.is_online
      )
    }

    // Sort
    result.sort((a, b) => {
      let aVal: any = a[sortField]
      let bVal: any = b[sortField]

      // Handle null values
      if (aVal === null || aVal === undefined) return 1
      if (bVal === null || bVal === undefined) return -1

      // For dates, convert to timestamps
      if (sortField === 'last_seen') {
        aVal = new Date(aVal).getTime()
        bVal = new Date(bVal).getTime()
      }

      if (typeof aVal === 'string') {
        return sortOrder === 'asc'
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal)
      }

      return sortOrder === 'asc' ? aVal - bVal : bVal - aVal
    })

    return result
  }, [devices, searchQuery, filterStatus, sortField, sortOrder])

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('asc')
    }
  }

  if (error) {
    return (
      <div className="p-8">
        <Card className="border-destructive">
          <CardContent className="pt-6">
            <p className="text-destructive">Error: {error}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Network Devices</h1>
          <p className="text-muted-foreground mt-1">
            Monitor and manage devices on your network
          </p>
        </div>
        <Button onClick={refetch} disabled={loading} variant="outline">
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search by IP, MAC, vendor, or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            <div className="flex gap-2">
              <Button
                variant={filterStatus === 'all' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterStatus('all')}
              >
                All ({devices.length})
              </Button>
              <Button
                variant={filterStatus === 'online' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterStatus('online')}
              >
                Online ({devices.filter((d) => d.is_online).length})
              </Button>
              <Button
                variant={filterStatus === 'offline' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterStatus('offline')}
              >
                Offline ({devices.filter((d) => !d.is_online).length})
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading && devices.length === 0 ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : filteredAndSortedDevices.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground">No devices found</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead
                    className="cursor-pointer hover:text-foreground"
                    onClick={() => handleSort('ip_address')}
                  >
                    <div className="flex items-center gap-1">
                      IP Address
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </TableHead>
                  <TableHead
                    className="cursor-pointer hover:text-foreground"
                    onClick={() => handleSort('mac_address')}
                  >
                    <div className="flex items-center gap-1">
                      MAC Address
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </TableHead>
                  <TableHead
                    className="cursor-pointer hover:text-foreground"
                    onClick={() => handleSort('vendor')}
                  >
                    <div className="flex items-center gap-1">
                      Vendor
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </TableHead>
                  <TableHead>Name/Hostname</TableHead>
                  <TableHead
                    className="cursor-pointer hover:text-foreground"
                    onClick={() => handleSort('last_seen')}
                  >
                    <div className="flex items-center gap-1">
                      Last Seen
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </TableHead>
                  <TableHead
                    className="cursor-pointer hover:text-foreground text-right"
                    onClick={() => handleSort('port_count')}
                  >
                    <div className="flex items-center gap-1 justify-end">
                      Open Ports
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAndSortedDevices.map((device) => (
                  <TableRow
                    key={device.ip_address}
                    className="cursor-pointer"
                    onClick={() => setSelectedDevice(device)}
                  >
                    <TableCell>
                      <Badge
                        variant={device.is_online ? 'success' : 'secondary'}
                        className="font-mono text-xs"
                      >
                        {device.is_online ? 'Online' : 'Offline'}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {device.ip_address}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {device.mac_address}
                    </TableCell>
                    <TableCell>
                      {device.vendor || (
                        <span className="text-muted-foreground">Unknown</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {device.device_name || device.hostname || (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {timeAgo(device.last_seen)}
                    </TableCell>
                    <TableCell className="text-right">
                      {device.port_count > 0 ? (
                        <Badge variant="outline">{device.port_count}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {selectedDevice && (
        <DeviceDetailsDialog
          device={selectedDevice}
          open={!!selectedDevice}
          onClose={() => setSelectedDevice(null)}
        />
      )}
    </div>
  )
}
