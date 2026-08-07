import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { suppressionsApi, vhostsApi, endpointsApi } from '@/api/client'
import type { Suppression, SuppressionScope } from '@/api/client'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { BellOff, Trash2, Info, Plus } from 'lucide-react'

function formatWhen(ts?: number): string {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString()
}

function scopeLabel(s: Suppression): string {
  if (s.scope_type === 'global') return 'Everywhere'
  return `${s.scope_type}: ${s.scope_id}`
}

export default function Suppressions() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  // Arriving from Shadow Mode's "suppress" action, with the detection and the
  // vhost it fired on already chosen. Landing on an empty form and being asked
  // to retype a flag you were just looking at is how a good idea gets abandoned.
  const [searchParams] = useSearchParams()
  const [flag, setFlag] = useState(searchParams.get('flag') ?? '')
  // Validated rather than cast: a stale or hand-edited link carrying
  // ?scope_type=foo would put the form into a state no Select option matches,
  // leaving a control that looks set and submits something else.
  const [scopeType, setScopeType] = useState<SuppressionScope>(() => {
    const fromUrl = searchParams.get('scope_type')
    return fromUrl === 'global' || fromUrl === 'vhost' || fromUrl === 'endpoint'
      ? fromUrl
      : 'vhost'
  })
  const [scopeId, setScopeId] = useState(searchParams.get('scope_id') ?? '')
  const [reason, setReason] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['suppressions'],
    queryFn: suppressionsApi.list,
  })

  const { data: vhostsData } = useQuery({ queryKey: ['vhosts'], queryFn: vhostsApi.list })
  const { data: endpointsData } = useQuery({
    queryKey: ['endpoints'],
    queryFn: () => endpointsApi.list(),
  })

  // Both list endpoints wrap their array, and the items come back untyped.
  // Only id and name are needed to populate the scope picker.
  type ScopeOption = { id: string; name?: string }
  const rawVhosts = (vhostsData as { vhosts?: ScopeOption[] } | undefined)?.vhosts
  const vhosts = Array.isArray(rawVhosts) ? rawVhosts : []
  const rawEndpoints = (endpointsData as { endpoints?: ScopeOption[] } | undefined)?.endpoints
  const endpoints = Array.isArray(rawEndpoints) ? rawEndpoints : []

  const createMutation = useMutation({
    mutationFn: suppressionsApi.create,
    onSuccess: (res) => {
      toast({
        title: res.created ? 'Suppression added' : 'Already suppressed',
        description: `${res.suppression.flag} no longer counts for ${scopeLabel(res.suppression)}.`,
      })
      setFlag('')
      setReason('')
      queryClient.invalidateQueries({ queryKey: ['suppressions'] })
    },
    onError: (err: Error) =>
      toast({ title: 'Could not add suppression', description: err.message, variant: 'destructive' }),
  })

  const removeMutation = useMutation({
    mutationFn: suppressionsApi.remove,
    onSuccess: () => {
      toast({ title: 'Suppression removed', description: 'That detection counts again.' })
      queryClient.invalidateQueries({ queryKey: ['suppressions'] })
    },
    onError: (err: Error) =>
      toast({ title: 'Could not remove', description: err.message, variant: 'destructive' }),
  })

  const scopeOptions = scopeType === 'vhost' ? vhosts : endpoints
  const needsScopeId = scopeType !== 'global'
  const canSubmit = flag.trim().length > 0 && (!needsScopeId || scopeId.length > 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <BellOff className="h-6 w-6" />
          Rule Suppressions
        </h1>
        <p className="text-muted-foreground">
          Stop a detection counting where it is wrong, without turning the endpoint off.
        </p>
      </div>

      <Alert>
        <Info className="h-4 w-4" />
        <AlertDescription>
          A suppression removes one detection from the result. A request that also triggered
          something you did not suppress is still blocked — so suppressing{' '}
          <code className="text-xs">kw:viagra</code> will not let spam through that also
          matched <code className="text-xs">kw:casino</code>. Use a trailing{' '}
          <code className="text-xs">*</code> to cover a family, e.g.{' '}
          <code className="text-xs">kw:*</code>.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Add a suppression</CardTitle>
          <CardDescription>
            The flag is the detection name shown in Shadow Mode, e.g.{' '}
            <code className="text-xs">kw:viagra</code> or{' '}
            <code className="text-xs">fp_flag:suspicious-bot</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="space-y-2">
              <Label htmlFor="flag">Detection flag</Label>
              <Input
                id="flag"
                value={flag}
                onChange={(e) => setFlag(e.target.value)}
                placeholder="kw:viagra"
              />
            </div>
            <div className="space-y-2">
              <Label>Scope</Label>
              <Select
                value={scopeType}
                onValueChange={(v) => {
                  setScopeType(v as SuppressionScope)
                  setScopeId('')
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="vhost">Virtual host</SelectItem>
                  <SelectItem value="endpoint">Endpoint</SelectItem>
                  <SelectItem value="global">Everywhere</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{scopeType === 'endpoint' ? 'Endpoint' : 'Virtual host'}</Label>
              <Select value={scopeId} onValueChange={setScopeId} disabled={!needsScopeId}>
                <SelectTrigger>
                  <SelectValue placeholder={needsScopeId ? 'Select...' : 'Not applicable'} />
                </SelectTrigger>
                <SelectContent>
                  {scopeOptions.map((o) => (
                    <SelectItem key={o.id} value={o.id}>
                      {o.name || o.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="reason">Why (optional)</Label>
              <Input
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Pharmacy client, legitimate term"
              />
            </div>
          </div>
          <div className="mt-4">
            <Button
              onClick={() =>
                createMutation.mutate({
                  flag: flag.trim(),
                  scope_type: scopeType,
                  scope_id: needsScopeId ? scopeId : undefined,
                  reason: reason.trim() || undefined,
                })
              }
              disabled={!canSubmit || createMutation.isPending}
            >
              <Plus className="mr-2 h-4 w-4" />
              Add suppression
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            In force{' '}
            {data?.count !== undefined && (
              <span className="text-muted-foreground">
                ({data.count}
                {data.max ? ` of ${data.max}` : ''})
              </span>
            )}
          </CardTitle>
          <CardDescription>
            Every one of these is a detection that no longer contributes to a block.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : data?.suppressions?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Detection</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Added</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.suppressions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <code className="text-xs font-medium">{s.flag}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant={s.scope_type === 'global' ? 'destructive' : 'secondary'}>
                        {scopeLabel(s)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {s.reason || '-'}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                      {formatWhen(s.created_at)}
                      {s.created_by ? ` by ${s.created_by}` : ''}
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeMutation.mutate(s.id)}
                        disabled={removeMutation.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">
              Nothing suppressed. Every detection counts.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
