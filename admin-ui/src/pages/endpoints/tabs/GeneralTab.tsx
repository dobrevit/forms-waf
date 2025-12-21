import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Globe, Server } from 'lucide-react'
import type { Endpoint } from '@/api/types'
import type { GeneralTabProps } from './types'

export function GeneralTab({ formData, setFormData, isEdit, vhosts }: GeneralTabProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>General Settings</CardTitle>
        <CardDescription>Basic endpoint configuration</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="id">ID</Label>
            <Input
              id="id"
              value={formData.id || ''}
              onChange={(e) => setFormData({ ...formData, id: e.target.value })}
              disabled={isEdit}
              placeholder="my-endpoint"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              value={formData.name || ''}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="My Endpoint"
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="description">Description</Label>
          <Input
            id="description"
            value={formData.description || ''}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            placeholder="Description of this endpoint"
          />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="mode">Mode</Label>
            <Select
              value={formData.mode || 'monitoring'}
              onValueChange={(value) =>
                setFormData({ ...formData, mode: value as Endpoint['mode'] })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="monitoring">Monitoring</SelectItem>
                <SelectItem value="blocking">Blocking</SelectItem>
                <SelectItem value="passthrough">Passthrough</SelectItem>
                <SelectItem value="strict">Strict</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="priority">Priority</Label>
            <Input
              id="priority"
              type="number"
              value={formData.priority || 100}
              onChange={(e) =>
                setFormData({ ...formData, priority: parseInt(e.target.value) })
              }
            />
            <p className="text-xs text-muted-foreground">Lower = higher priority</p>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vhost">Virtual Host Scope</Label>
          <Select
            value={formData.vhost_id || '_global'}
            onValueChange={(value) =>
              setFormData({ ...formData, vhost_id: value === '_global' ? null : value })
            }
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_global">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-green-500" />
                  Global (all vhosts)
                </div>
              </SelectItem>
              {vhosts.map((vhost) => (
                <SelectItem key={vhost.id} value={vhost.id}>
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-blue-500" />
                    {vhost.name || vhost.id}
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            Global endpoints apply to all vhosts. Vhost-specific endpoints take priority.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <Switch
            id="enabled"
            checked={formData.enabled}
            onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
          />
          <Label htmlFor="enabled">Enabled</Label>
        </div>
      </CardContent>
    </Card>
  )
}
