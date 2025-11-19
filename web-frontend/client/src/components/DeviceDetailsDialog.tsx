import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Save, AlertTriangle } from 'lucide-react'
import { api } from '@/services/api'
import { formatBytes, timeAgo } from '@/lib/utils'
import type { Device } from '@/types'

interface DeviceDetailsDialogProps {
  device: Device
  open: boolean
  onClose: () => void
}

export function DeviceDetailsDialog({
  device,
  open,
  onClose,
}: DeviceDetailsDialogProps) {
  const [deviceName, setDeviceName] = useState(device.device_name || '')
  const [saving, setSaving] = useState(false)

  const handleSaveName = async () => {
    setSaving(true)
    try {
      await api.updateDeviceName(device.ip_address, deviceName)
      // Optionally show a success message
    } catch (error) {
      console.error('Failed to update device name:', error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-2xl">Device Details</DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="info" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="info">Info</TabsTrigger>
            <TabsTrigger value="ports">
              Ports {device.port_count > 0 && `(${device.port_count})`}
            </TabsTrigger>
            <TabsTrigger value="netbios">NetBIOS/SMB</TabsTrigger>
            <TabsTrigger value="anomalies">
              Anomalies
              {device.security_anomalies && device.security_anomalies.length > 0 && (
                <Badge variant="destructive" className="ml-2">
                  {device.security_anomalies.length}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="info" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Basic Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Status
                    </label>
                    <div className="mt-1">
                      <Badge
                        variant={device.is_online ? 'success' : 'secondary'}
                        className="font-mono"
                      >
                        {device.is_online ? 'Online' : 'Offline'}
                      </Badge>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      IP Address
                    </label>
                    <p className="mt-1 font-mono text-sm">{device.ip_address}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      MAC Address
                    </label>
                    <p className="mt-1 font-mono text-sm">{device.mac_address}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Vendor
                    </label>
                    <p className="mt-1 text-sm">
                      {device.vendor || (
                        <span className="text-muted-foreground">Unknown</span>
                      )}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Hostname
                    </label>
                    <p className="mt-1 text-sm">
                      {device.hostname || (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Device Type
                    </label>
                    <p className="mt-1 text-sm">
                      {device.device_type || (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </p>
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Custom Name
                  </label>
                  <div className="flex gap-2 mt-1">
                    <Input
                      value={deviceName}
                      onChange={(e) => setDeviceName(e.target.value)}
                      placeholder="Enter a custom name for this device"
                    />
                    <Button onClick={handleSaveName} disabled={saving}>
                      <Save className="w-4 h-4 mr-2" />
                      Save
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4 pt-4 border-t">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      First Seen
                    </label>
                    <p className="mt-1 text-sm">
                      {new Date(device.first_seen).toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Last Seen
                    </label>
                    <p className="mt-1 text-sm">
                      {new Date(device.last_seen).toLocaleString()}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {timeAgo(device.last_seen)}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Last ARP
                    </label>
                    <p className="mt-1 text-sm">
                      {device.last_arp_time ? (
                        <>
                          {new Date(device.last_arp_time).toLocaleString()}
                          <p className="text-xs text-muted-foreground">
                            {timeAgo(device.last_arp_time)}
                          </p>
                        </>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Total Packets
                    </label>
                    <p className="mt-1 text-sm font-semibold">
                      {device.total_packets.toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Total Data
                    </label>
                    <p className="mt-1 text-sm font-semibold">
                      {formatBytes(device.total_bytes)}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="ports">
            {device.open_ports && device.open_ports.length > 0 ? (
              <Card>
                <CardContent className="pt-6">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Port</TableHead>
                        <TableHead>Protocol</TableHead>
                        <TableHead>State</TableHead>
                        <TableHead>Service</TableHead>
                        <TableHead>Version</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {device.open_ports.map((port, idx) => (
                        <TableRow key={idx}>
                          <TableCell className="font-mono">{port.port}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{port.protocol}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={port.state === 'open' ? 'success' : 'secondary'}>
                              {port.state}
                            </Badge>
                          </TableCell>
                          <TableCell>{port.service || '—'}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {port.version || '—'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="pt-6">
                  <p className="text-center text-muted-foreground">
                    No open ports detected
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="netbios">
            {device.netbios_info ? (
              <Card>
                <CardContent className="pt-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">
                        Server Name
                      </label>
                      <p className="mt-1 text-sm">
                        {device.netbios_info.server_name || '—'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">
                        Workgroup
                      </label>
                      <p className="mt-1 text-sm">
                        {device.netbios_info.workgroup || '—'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">
                        Domain
                      </label>
                      <p className="mt-1 text-sm">
                        {device.netbios_info.domain || '—'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">
                        OS Version
                      </label>
                      <p className="mt-1 text-sm">
                        {device.netbios_info.os_version || '—'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">
                        SMB Version
                      </label>
                      <p className="mt-1 text-sm">
                        {device.netbios_info.smb_version || '—'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">
                        SMB Signing
                      </label>
                      <p className="mt-1 text-sm">
                        {device.netbios_info.smb_signing !== null
                          ? device.netbios_info.smb_signing
                            ? 'Enabled'
                            : 'Disabled'
                          : '—'}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="pt-6">
                  <p className="text-center text-muted-foreground">
                    No NetBIOS/SMB information available
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="anomalies">
            {device.security_anomalies && device.security_anomalies.length > 0 ? (
              <div className="space-y-4">
                {device.security_anomalies.map((anomaly) => (
                  <Card
                    key={anomaly.id}
                    className={
                      anomaly.severity === 'high'
                        ? 'border-destructive'
                        : anomaly.severity === 'medium'
                        ? 'border-warning'
                        : ''
                    }
                  >
                    <CardContent className="pt-6">
                      <div className="flex items-start gap-3">
                        <AlertTriangle
                          className={`w-5 h-5 mt-0.5 ${
                            anomaly.severity === 'high'
                              ? 'text-destructive'
                              : anomaly.severity === 'medium'
                              ? 'text-yellow-600'
                              : 'text-muted-foreground'
                          }`}
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge
                              variant={
                                anomaly.severity === 'high'
                                  ? 'destructive'
                                  : anomaly.severity === 'medium'
                                  ? 'warning'
                                  : 'secondary'
                              }
                            >
                              {anomaly.severity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline">{anomaly.anomaly_type}</Badge>
                          </div>
                          <p className="text-sm mb-2">{anomaly.description}</p>
                          <div className="flex gap-4 text-xs text-muted-foreground">
                            <span>First: {timeAgo(anomaly.first_detected)}</span>
                            <span>Last: {timeAgo(anomaly.last_detected)}</span>
                            <span>Count: {anomaly.occurrence_count}</span>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <Card>
                <CardContent className="pt-6">
                  <p className="text-center text-muted-foreground">
                    No security anomalies detected
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
