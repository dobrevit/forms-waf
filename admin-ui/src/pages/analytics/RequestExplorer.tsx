import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { decisionsApi } from '@/api/client'
import type { Decision, DecisionTraceEntry } from '@/api/client'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { Search, AlertTriangle, RefreshCw, Trash2, Info, BellOff } from 'lucide-react'

const ACTIONS = ['blocked', 'would_block', 'challenged', 'tarpit', 'allowed'] as const

function actionVariant(action: string): 'destructive' | 'warning' | 'secondary' | 'success' {
  if (action === 'blocked') return 'destructive'
  if (action === 'would_block' || action === 'tarpit' || action === 'challenged') return 'warning'
  if (action === 'allowed') return 'success'
  return 'secondary'
}

function formatWhen(ts: number): string {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString()
}

/**
 * The breakdown. Rendered as a running tally rather than a flat list because the
 * question is "where did 113 come from", and a column of numbers that adds up is
 * the answer to that in a way a set of badges is not.
 */
function TraceTable({ decision }: { decision: Decision }) {
  const trace = decision.trace ?? []
  if (!trace.length) {
    return (
      <p className="text-sm text-muted-foreground">
        No mechanism breakdown recorded for this decision.
      </p>
    )
  }

  let running = 0
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Mechanism</TableHead>
            <TableHead className="text-right">Contributed</TableHead>
            <TableHead className="text-right">Running</TableHead>
            <TableHead>Detections</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {trace.map((entry: DecisionTraceEntry, i) => {
            running += entry.score ?? 0
            return (
              <TableRow key={`${entry.node ?? entry.defense}-${i}`}>
                <TableCell>
                  <code className="text-xs font-medium">{entry.defense || entry.node}</code>
                  {entry.blocked && (
                    <Badge variant="destructive" className="ml-2 text-xs font-normal">
                      blocked
                    </Badge>
                  )}
                  {entry.profile && (
                    <div className="text-xs text-muted-foreground">profile: {entry.profile}</div>
                  )}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {entry.score ? `+${entry.score}` : '—'}
                </TableCell>
                <TableCell className="text-right tabular-nums text-muted-foreground">
                  {running}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {(entry.flags ?? []).map((f) => (
                      <Badge key={f} variant="secondary" className="text-xs font-normal">
                        {f}
                      </Badge>
                    ))}
                    {(entry.suppressed ?? []).map((f) => (
                      <Badge
                        key={`s-${f}`}
                        variant="outline"
                        className="text-xs font-normal line-through opacity-70"
                        title="Raised by this mechanism, then removed by a suppression"
                      >
                        {f}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

export default function RequestExplorer() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [action, setAction] = useState('any')
  const [clientIp, setClientIp] = useState('')
  const [path, setPath] = useState('')
  const [flag, setFlag] = useState('')
  const [minScore, setMinScore] = useState('')
  const [applied, setApplied] = useState<Record<string, string | number>>({})
  const [selected, setSelected] = useState<Decision | null>(null)

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['decisions', applied],
    queryFn: () => decisionsApi.search({ ...applied, limit: 100 }),
  })

  const clearMutation = useMutation({
    mutationFn: decisionsApi.clear,
    onSuccess: () => {
      toast({ title: 'Decision log discarded' })
      queryClient.invalidateQueries({ queryKey: ['decisions'] })
    },
    onError: (err: Error) =>
      toast({ title: 'Could not clear', description: err.message, variant: 'destructive' }),
  })

  const applyFilters = () => {
    const next: Record<string, string | number> = {}
    if (action !== 'any') next.action = action
    if (clientIp.trim()) next.client_ip = clientIp.trim()
    if (path.trim()) next.path = path.trim()
    if (flag.trim()) next.flag = flag.trim()
    if (minScore.trim() && !Number.isNaN(Number(minScore))) next.min_score = Number(minScore)
    setApplied(next)
  }

  const retention = data?.retention
  const incomplete = (data?.dropped_total ?? 0) > 0

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Search className="h-6 w-6" />
            Request Explorer
          </h1>
          <p className="text-muted-foreground">
            Why a request was blocked — or why it was not — down to the mechanism.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
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
            Discard log
          </Button>
        </div>
      </div>

      {retention?.enabled === false && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>The decision log is turned off</AlertTitle>
          <AlertDescription>
            Nothing new is being recorded. Set <code className="text-xs">
              WAF_DECISION_LOG_ENABLED=true
            </code>{' '}
            to start.
          </AlertDescription>
        </Alert>
      )}

      {incomplete && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>This log has holes</AlertTitle>
          <AlertDescription>
            {data?.dropped_total} decision(s) were dropped because the recorder's buffer filled
            up. A request you are looking for may be missing rather than never having happened.
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Filters</CardTitle>
          <CardDescription>
            {retention
              ? `Keeping up to ${retention.max_records} decisions for ${Math.round(
                  (retention.ttl_seconds ?? 0) / 86400
                )} days. Allowed requests scoring under ${retention.min_score} are not recorded.`
              : 'Search the recorded decisions.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-5">
            <div className="space-y-2">
              <Label>Outcome</Label>
              <Select value={action} onValueChange={setAction}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Any</SelectItem>
                  {ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="ip">Client IP</Label>
              <Input id="ip" value={clientIp} onChange={(e) => setClientIp(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="path">Path contains</Label>
              <Input id="path" value={path} onChange={(e) => setPath(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="flag">Detection</Label>
              <Input
                id="flag"
                value={flag}
                onChange={(e) => setFlag(e.target.value)}
                placeholder="kw:viagra"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="score">Min score</Label>
              <Input
                id="score"
                inputMode="numeric"
                value={minScore}
                onChange={(e) => setMinScore(e.target.value)}
              />
            </div>
          </div>
          <div className="mt-4">
            <Button onClick={applyFilters}>
              <Search className="mr-2 h-4 w-4" />
              Search
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Decisions{' '}
            <span className="text-muted-foreground">
              ({data?.count ?? 0}
              {data?.scanned ? ` of ${data.scanned} scanned` : ''})
            </span>
          </CardTitle>
          <CardDescription>Newest first. Select a row to see why.</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : data?.decisions?.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>When</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>Request</TableHead>
                    <TableHead>Client</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead>Detections</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.decisions.map((d, i) => (
                    <TableRow
                      key={`${d.request_id ?? d.ts}-${i}`}
                      className="cursor-pointer"
                      onClick={() => setSelected(d)}
                    >
                      <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                        {formatWhen(d.ts)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={actionVariant(d.action)}>{d.action}</Badge>
                        {d.status ? (
                          <span className="ml-2 text-xs text-muted-foreground">{d.status}</span>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <code className="text-xs break-all">
                          {d.method} {d.path}
                        </code>
                        <div className="text-xs text-muted-foreground">
                          {d.vhost_id} / {d.endpoint_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs">{d.client_ip || '-'}</code>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{d.score}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(d.flags ?? []).slice(0, 3).map((f) => (
                            <Badge key={f} variant="secondary" className="text-xs font-normal">
                              {f}
                            </Badge>
                          ))}
                          {(d.flags?.length ?? 0) > 3 && (
                            <Badge variant="outline" className="text-xs font-normal">
                              +{(d.flags?.length ?? 0) - 3}
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
            <p className="text-sm text-muted-foreground">
              No decisions match. Clean allowed requests are not recorded, so an empty result
              can simply mean nothing was flagged.
            </p>
          )}
        </CardContent>
      </Card>

      <Dialog open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Badge variant={actionVariant(selected?.action ?? '')}>{selected?.action}</Badge>
              <code className="text-sm">
                {selected?.method} {selected?.path}
              </code>
            </DialogTitle>
            <DialogDescription>
              {selected?.request_id ? (
                <>
                  Request <code className="text-xs">{selected.request_id}</code> —{' '}
                </>
              ) : null}
              {selected ? formatWhen(selected.ts) : ''}
            </DialogDescription>
          </DialogHeader>

          {selected && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
                <div>
                  <div className="text-xs text-muted-foreground">Score</div>
                  <div className="text-lg font-semibold tabular-nums">{selected.score}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Status</div>
                  <div className="text-lg font-semibold tabular-nums">
                    {selected.status ?? '-'}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Mode</div>
                  <div className="text-lg font-semibold">{selected.mode ?? '-'}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Client</div>
                  <div className="font-mono text-sm">{selected.client_ip ?? '-'}</div>
                </div>
              </div>

              {selected.action === 'would_block' && (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    This vhost is in monitoring mode, so the request was allowed through despite
                    the verdict. Shadow Mode shows what promoting it would change.
                  </AlertDescription>
                </Alert>
              )}

              {!!selected.unattributed_score && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Breakdown is incomplete</AlertTitle>
                  <AlertDescription>
                    {selected.unattributed_score} of {selected.score} points are not accounted
                    for by the mechanisms below, so some scoring path is not reporting itself.
                    Treat this explanation as partial.
                  </AlertDescription>
                </Alert>
              )}

              <div>
                <p className="mb-2 text-sm font-medium">Why</p>
                <TraceTable decision={selected} />
              </div>

              {!!selected.trace?.some((t) => t.suppressed?.length) && (
                <p className="flex items-center gap-2 text-xs text-muted-foreground">
                  <BellOff className="h-3 w-3" />
                  Struck-through detections were raised and then removed by a suppression.
                </p>
              )}

              {selected.user_agent && (
                <div>
                  <div className="text-xs text-muted-foreground">User agent</div>
                  <code className="text-xs break-all">{selected.user_agent}</code>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
