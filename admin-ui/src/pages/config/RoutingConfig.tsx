import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { configApi } from '@/api/client'
import { GlobalRouting } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { useToast } from '@/components/ui/use-toast'
import { Save, Info, Network, Lock } from 'lucide-react'

export function RoutingConfig() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [values, setValues] = useState<GlobalRouting>({
    haproxy_upstream: 'haproxy:8080',
    haproxy_ssl: false,
    upstream_ssl: false,
    haproxy_timeout: 30,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['config', 'routing'],
    queryFn: configApi.getRouting,
  })

  useEffect(() => {
    if (data?.routing) {
      setValues({
        haproxy_upstream: data.routing.haproxy_upstream || data.defaults?.haproxy_upstream || 'haproxy:8080',
        haproxy_ssl: data.routing.haproxy_ssl ?? false,
        upstream_ssl: data.routing.upstream_ssl ?? false,
        haproxy_timeout: data.routing.haproxy_timeout ?? data.defaults?.haproxy_timeout ?? 30,
      })
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: (config: GlobalRouting) => configApi.updateRouting(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config', 'routing'] })
      toast({ title: 'Routing configuration saved' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to save routing config',
        variant: 'destructive',
      })
    },
  })

  const handleSave = () => {
    saveMutation.mutate(values)
  }

  if (isLoading) {
    return <div>Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Routing Configuration</h2>
        <p className="text-muted-foreground">
          Configure global upstream routing defaults
        </p>
      </div>

      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="flex items-center gap-4 py-4">
          <Info className="h-5 w-5 text-blue-500" />
          <div>
            <p className="font-medium text-blue-800">Global Defaults</p>
            <p className="text-sm text-blue-600">
              These settings apply globally but can be overridden per virtual host.
              Environment variables (HAPROXY_UPSTREAM, HAPROXY_UPSTREAM_SSL, UPSTREAM_SSL)
              provide initial defaults.
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Network className="h-5 w-5" />
              HAProxy Upstream
            </CardTitle>
            <CardDescription>
              Default HAProxy upstream for vhosts using HAProxy routing
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="haproxy_upstream">Upstream Address</Label>
              <Input
                id="haproxy_upstream"
                type="text"
                placeholder="haproxy:8080"
                value={values.haproxy_upstream}
                onChange={(e) =>
                  setValues({ ...values, haproxy_upstream: e.target.value })
                }
              />
              <p className="text-xs text-muted-foreground">
                Default: haproxy:8080. Can use FQDN for Kubernetes (e.g., haproxy.namespace.svc.cluster.local:8080)
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="haproxy_timeout">Connection Timeout (seconds)</Label>
              <Input
                id="haproxy_timeout"
                type="number"
                value={values.haproxy_timeout}
                onChange={(e) =>
                  setValues({ ...values, haproxy_timeout: parseInt(e.target.value) || 30 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Timeout for HAProxy upstream connections
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Lock className="h-5 w-5" />
              SSL/TLS Settings
            </CardTitle>
            <CardDescription>
              Configure HTTPS for upstream connections
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label htmlFor="haproxy_ssl">HAProxy SSL</Label>
                <p className="text-xs text-muted-foreground">
                  Use HTTPS when connecting to HAProxy upstream
                </p>
              </div>
              <Switch
                id="haproxy_ssl"
                checked={values.haproxy_ssl}
                onCheckedChange={(checked) =>
                  setValues({ ...values, haproxy_ssl: checked })
                }
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label htmlFor="upstream_ssl">Direct Upstream SSL</Label>
                <p className="text-xs text-muted-foreground">
                  Use HTTPS when connecting to direct upstream servers (non-HAProxy)
                </p>
              </div>
              <Switch
                id="upstream_ssl"
                checked={values.upstream_ssl}
                onCheckedChange={(checked) =>
                  setValues({ ...values, upstream_ssl: checked })
                }
              />
            </div>
            {(values.haproxy_ssl || values.upstream_ssl) && (
              <div className="rounded-lg border border-amber-200 bg-amber-50 p-3">
                <p className="text-sm text-amber-700">
                  <strong>Note:</strong> Ensure your upstream servers have valid SSL certificates
                  or configure certificate verification appropriately.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-gray-200">
        <CardHeader>
          <CardTitle className="text-lg">Configuration Hierarchy</CardTitle>
          <CardDescription>
            How routing settings are resolved
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2">
              <span className="font-mono bg-gray-100 px-2 py-1 rounded">Environment Variables</span>
              <span className="text-muted-foreground">→ Initial defaults from deployment</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono bg-gray-100 px-2 py-1 rounded">Global Config</span>
              <span className="text-muted-foreground">→ These settings (override env vars)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono bg-gray-100 px-2 py-1 rounded">Vhost Config</span>
              <span className="text-muted-foreground">→ Per-vhost overrides (highest priority)</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saveMutation.isPending}>
          <Save className="mr-2 h-4 w-4" />
          {saveMutation.isPending ? 'Saving...' : 'Save Configuration'}
        </Button>
      </div>
    </div>
  )
}
