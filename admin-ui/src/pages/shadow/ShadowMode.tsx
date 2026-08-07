import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { shadowApi } from '@/api/client'
import type { ShadowCount, ShadowImpact, ShadowScope } from '@/api/client'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import {
  EyeOff,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Trash2,
  ArrowUpCircle,
  Fingerprint,
} from 'lucide-react'

function formatWhen(ts: number): string {
  if (!ts) return '-'
  const secs = Math.floor(Date.now() / 1000 - ts)
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

/**
 * A count bar. The relative width is what makes a list of flags readable at a
 * glance -- "which rule is responsible for most of this" is the whole question.
 */
function CountBars({ items, empty }: { items: ShadowCount[]; empty: string }) {
  if (!items?.length) {
    return <p className="text-sm text-muted-foreground">{empty}</p>
  }
  const max = Math.max(...items.map((i) => i.count))
  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item.name} className="space-y-1">
          <div className="flex items-baseline justify-between gap-4">
            <code className="text-xs font-medium break-all">{item.name}</code>
            <span className="text-sm tabular-nums text-muted-foreground">{item.count}</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-muted">
            <div
              className="h-1.5 rounded-full bg-primary"
              style={{ width: `${max ? (item.count / max) * 100 : 0}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

export default function ShadowMode() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [pending, setPending] = useState<ShadowImpact | null>(null)

  const { data: summary, isLoading, refetch } = useQuery({
    queryKey: ['shadow', 'summary'],
    queryFn: shadowApi.summary,
    refetchInterval: 15000,
  })

  const { data: recent } = useQuery({
    queryKey: ['shadow', 'decisions'],
    queryFn: () => shadowApi.decisions({ limit: 25 }),
    refetchInterval: 15000,
  })

  // Promotion is the one destructive-ish action here: it starts rejecting live
  // traffic. So the impact is fetched first and shown for confirmation rather
  // than promoting straight from the table.
  const impactMutation = useMutation({
    mutationFn: (scope: ShadowScope) => shadowApi.impact(scope.vhost_id),
    onSuccess: (impact) => setPending(impact),
    onError: (err: Error) =>
      toast({ title: 'Could not load impact', description: err.message, variant: 'destructive' }),
  })

  const promoteMutation = useMutation({
    mutationFn: (vhostId: string) => shadowApi.promote(vhostId),
    onSuccess: (res) => {
      setPending(null)
      toast({
        title: res.promoted ? `${res.vhost_id} is now blocking` : 'No change',
        description: res.promoted
          ? `Was ${res.previous_mode}. This vhost now rejects matching traffic.`
          : res.message,
      })
      queryClient.invalidateQueries({ queryKey: ['shadow'] })
      queryClient.invalidateQueries({ queryKey: ['vhosts'] })
    },
    onError: (err: Error) =>
      toast({ title: 'Promote failed', description: err.message, variant: 'destructive' }),
  })

  const clearMutation = useMutation({
    mutationFn: shadowApi.clear,
    onSuccess: () => {
      toast({ title: 'Sample discarded' })
      queryClient.invalidateQueries({ queryKey: ['shadow'] })
    },
    onError: (err: Error) =>
      toast({ title: 'Could not clear', description: err.message, variant: 'destructive' }),
  })

  if (isLoading) {
    return <div className="p-6 text-muted-foreground">Loading shadow decisions...</div>
  }

  const incomplete = (summary?.dropped_total ?? 0) > 0

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <EyeOff className="h-6 w-6" />
            Shadow Mode
          </h1>
          <p className="text-muted-foreground">
            What monitoring mode would have blocked. Review the sample, then promote a
            vhost to blocking once it looks right.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => clearMutation.mutate()}
            disabled={clearMutation.isPending}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Discard sample
          </Button>
        </div>
      </div>

      {incomplete && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>This sample is incomplete</AlertTitle>
          <AlertDescription>
            {summary?.dropped_total} decision(s) were dropped because the recorder's buffer
            filled up. Every count below understates the real impact — treat them as a floor,
            not a total.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Would have blocked</CardDescription>
            <CardTitle className="text-3xl tabular-nums">
              {summary?.would_block_total ?? 0}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              requests allowed through that a blocking vhost would have rejected
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Decisions retained</CardDescription>
            <CardTitle className="text-3xl tabular-nums">
              {summary?.retained_decisions ?? 0}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">individually inspectable below</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Scopes affected</CardDescription>
            <CardTitle className="text-3xl tabular-nums">{summary?.scopes?.length ?? 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">vhost / endpoint combinations</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Fingerprint className="h-4 w-4" />
              Top detections
            </CardTitle>
            <CardDescription>
              The specific signal that fired. This is what identifies a rule to keep or
              suppress — the profile name alone does not.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <CountBars
              items={summary?.top_flags ?? []}
              empty="Nothing recorded yet. Put a vhost in monitoring mode and send traffic."
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top rules</CardTitle>
            <CardDescription>The profile or mechanism that produced the decision.</CardDescription>
          </CardHeader>
          <CardContent>
            <CountBars items={summary?.top_rules ?? []} empty="Nothing recorded yet." />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Affected scopes</CardTitle>
          <CardDescription>
            Promote a vhost once its sample looks right. You will see the impact before
            anything changes.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {summary?.scopes?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vhost</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead className="text-right">Would block</TableHead>
                  <TableHead className="w-32" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {summary.scopes.map((scope) => (
                  <TableRow key={`${scope.vhost_id}|${scope.endpoint_id}`}>
                    <TableCell className="font-medium">{scope.vhost_id}</TableCell>
                    <TableCell>
                      <code className="text-xs">{scope.endpoint_id || '-'}</code>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {scope.would_block_count}
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => impactMutation.mutate(scope)}
                        disabled={impactMutation.isPending}
                      >
                        <ArrowUpCircle className="mr-2 h-4 w-4" />
                        Promote
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">
              No shadow decisions recorded. A vhost in monitoring mode records what it would
              have blocked; a vhost already in blocking mode records nothing here.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent decisions</CardTitle>
          <CardDescription>Newest first.</CardDescription>
        </CardHeader>
        <CardContent>
          {recent?.decisions?.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>When</TableHead>
                    <TableHead>Client</TableHead>
                    <TableHead>Request</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead>Detections</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recent.decisions.map((d, i) => (
                    <TableRow key={`${d.ts}-${i}`}>
                      <TableCell className="whitespace-nowrap text-muted-foreground">
                        {formatWhen(d.ts)}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        <code className="text-xs">{d.client_ip || '-'}</code>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs break-all">
                          {d.method} {d.path}
                        </code>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{d.score}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(d.flags ?? []).slice(0, 4).map((f) => (
                            <Badge key={f} variant="secondary" className="text-xs font-normal">
                              {f}
                            </Badge>
                          ))}
                          {(d.flags?.length ?? 0) > 4 && (
                            <Badge variant="outline" className="text-xs font-normal">
                              +{(d.flags?.length ?? 0) - 4}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No decisions recorded.</p>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <AlertDialogContent className="max-w-2xl">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              Promote {pending?.vhost_id} to blocking?
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-4 pt-2">
                <p>
                  This vhost will start rejecting traffic immediately. Based on the recorded
                  sample, it would have blocked:
                </p>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <div className="text-2xl font-semibold tabular-nums">
                      {pending?.would_block_count ?? 0}
                    </div>
                    <div className="text-xs text-muted-foreground">requests</div>
                  </div>
                  <div>
                    <div className="text-2xl font-semibold tabular-nums">
                      {pending?.unique_client_ips ?? 0}
                    </div>
                    <div className="text-xs text-muted-foreground">distinct clients</div>
                  </div>
                  <div>
                    <div className="text-2xl font-semibold tabular-nums">
                      {pending?.average_score ?? 0}
                    </div>
                    <div className="text-xs text-muted-foreground">average score</div>
                  </div>
                </div>
                {pending?.sample_incomplete && (
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      Records were dropped, so the real impact is larger than these figures.
                    </AlertDescription>
                  </Alert>
                )}
                {!!pending?.top_flags?.length && (
                  <div>
                    <p className="mb-2 text-sm font-medium">Mostly from</p>
                    <CountBars items={pending.top_flags.slice(0, 5)} empty="" />
                  </div>
                )}
                {!!pending?.affected_endpoints?.length && (
                  <div>
                    <p className="mb-2 text-sm font-medium">Affected endpoints</p>
                    <div className="flex flex-wrap gap-1">
                      {pending.affected_endpoints.map((e) => (
                        <Badge key={e.name} variant="secondary" className="font-normal">
                          {e.name} ({e.count})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                if (pending) promoteMutation.mutate(pending.vhost_id)
              }}
              disabled={promoteMutation.isPending}
            >
              {promoteMutation.isPending ? 'Promoting...' : 'Promote to blocking'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
