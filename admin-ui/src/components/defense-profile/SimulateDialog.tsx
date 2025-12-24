import { useState, useCallback } from 'react'
import { useMutation } from '@tanstack/react-query'
import { defenseProfilesApi } from '@/api/client'
import type { DefenseProfileSimulationResult } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Loader2, Plus, Trash2, CheckCircle2, XCircle, AlertCircle, Clock } from 'lucide-react'

interface SimulateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  profileId: string
  profileName?: string
}

interface KeyValuePair {
  key: string
  value: string
}

const DEFAULT_FORM_FIELDS: KeyValuePair[] = [
  { key: 'name', value: 'John Doe' },
  { key: 'email', value: 'john@example.com' },
  { key: 'message', value: 'Hello, this is a test message.' },
]

const DEFAULT_HEADERS: KeyValuePair[] = [
  { key: 'Content-Type', value: 'application/x-www-form-urlencoded' },
]

export function SimulateDialog({ open, onOpenChange, profileId, profileName }: SimulateDialogProps) {
  const { toast } = useToast()
  const [simulationResult, setSimulationResult] = useState<DefenseProfileSimulationResult | null>(null)
  const [simulationInput, setSimulationInput] = useState({
    client_ip: '192.168.1.100',
    host: 'example.com',
    path: '/contact',
    method: 'POST',
    formFields: [...DEFAULT_FORM_FIELDS],
    headers: [...DEFAULT_HEADERS],
  })

  // Reset state when dialog opens
  const handleOpenChange = useCallback((newOpen: boolean) => {
    if (newOpen) {
      setSimulationResult(null)
    }
    onOpenChange(newOpen)
  }, [onOpenChange])

  // Simulate request mutation
  const simulateMutation = useMutation({
    mutationFn: (requestData: Parameters<typeof defenseProfilesApi.simulate>[1]) =>
      defenseProfilesApi.simulate(profileId, requestData),
    onSuccess: (response) => {
      if (response.simulation) {
        setSimulationResult(response.simulation)
      } else if (response.errors) {
        toast({
          title: 'Simulation Error',
          description: response.errors.join(', '),
          variant: 'destructive',
        })
      }
    },
    onError: (error: Error) => {
      toast({
        title: 'Simulation Failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  const handleSimulate = useCallback(() => {
    // Convert form fields and headers to objects
    const formData: Record<string, unknown> = {}
    for (const field of simulationInput.formFields) {
      if (field.key) {
        formData[field.key] = field.value
      }
    }

    const headers: Record<string, string> = {}
    for (const header of simulationInput.headers) {
      if (header.key) {
        headers[header.key] = header.value
      }
    }

    setSimulationResult(null)
    simulateMutation.mutate({
      form_data: formData,
      client_ip: simulationInput.client_ip,
      host: simulationInput.host,
      path: simulationInput.path,
      method: simulationInput.method,
      headers,
    })
  }, [simulationInput, simulateMutation])

  const addFormField = useCallback(() => {
    setSimulationInput((prev) => ({
      ...prev,
      formFields: [...prev.formFields, { key: '', value: '' }],
    }))
  }, [])

  const removeFormField = useCallback((index: number) => {
    setSimulationInput((prev) => ({
      ...prev,
      formFields: prev.formFields.filter((_, i) => i !== index),
    }))
  }, [])

  const updateFormField = useCallback((index: number, field: 'key' | 'value', value: string) => {
    setSimulationInput((prev) => ({
      ...prev,
      formFields: prev.formFields.map((f, i) => (i === index ? { ...f, [field]: value } : f)),
    }))
  }, [])

  const addHeader = useCallback(() => {
    setSimulationInput((prev) => ({
      ...prev,
      headers: [...prev.headers, { key: '', value: '' }],
    }))
  }, [])

  const removeHeader = useCallback((index: number) => {
    setSimulationInput((prev) => ({
      ...prev,
      headers: prev.headers.filter((_, i) => i !== index),
    }))
  }, [])

  const updateHeader = useCallback((index: number, field: 'key' | 'value', value: string) => {
    setSimulationInput((prev) => ({
      ...prev,
      headers: prev.headers.map((h, i) => (i === index ? { ...h, [field]: value } : h)),
    }))
  }, [])

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'allow':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'block':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'captcha':
        return <AlertCircle className="h-5 w-5 text-yellow-500" />
      case 'tarpit':
        return <Clock className="h-5 w-5 text-orange-500" />
      case 'flag':
        return <AlertCircle className="h-5 w-5 text-blue-500" />
      case 'monitor':
        return <AlertCircle className="h-5 w-5 text-gray-500" />
      default:
        return <AlertCircle className="h-5 w-5" />
    }
  }

  const getActionBadgeVariant = (action: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
    switch (action) {
      case 'allow':
        return 'default'
      case 'block':
        return 'destructive'
      default:
        return 'secondary'
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Simulate Request</DialogTitle>
          <DialogDescription>
            Test how {profileName ? `"${profileName}"` : 'this profile'} handles a simulated request.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-6 py-4">
          {/* Request Settings */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Client IP</Label>
              <Input
                value={simulationInput.client_ip}
                onChange={(e) =>
                  setSimulationInput((prev) => ({ ...prev, client_ip: e.target.value }))
                }
                placeholder="192.168.1.100"
              />
            </div>
            <div className="space-y-2">
              <Label>Host</Label>
              <Input
                value={simulationInput.host}
                onChange={(e) =>
                  setSimulationInput((prev) => ({ ...prev, host: e.target.value }))
                }
                placeholder="example.com"
              />
            </div>
            <div className="space-y-2">
              <Label>Path</Label>
              <Input
                value={simulationInput.path}
                onChange={(e) =>
                  setSimulationInput((prev) => ({ ...prev, path: e.target.value }))
                }
                placeholder="/contact"
              />
            </div>
            <div className="space-y-2">
              <Label>Method</Label>
              <Select
                value={simulationInput.method}
                onValueChange={(value) =>
                  setSimulationInput((prev) => ({ ...prev, method: value }))
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="PATCH">PATCH</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Separator />

          {/* Form Fields */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Form Fields</Label>
              <Button variant="outline" size="sm" onClick={addFormField}>
                <Plus className="h-3 w-3 mr-1" />
                Add Field
              </Button>
            </div>
            <div className="space-y-2">
              {simulationInput.formFields.map((field, index) => (
                <div key={index} className="flex gap-2 items-center">
                  <Input
                    value={field.key}
                    onChange={(e) => updateFormField(index, 'key', e.target.value)}
                    placeholder="Field name"
                    className="w-1/3"
                  />
                  <Input
                    value={field.value}
                    onChange={(e) => updateFormField(index, 'value', e.target.value)}
                    placeholder="Value"
                    className="flex-1"
                  />
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeFormField(index)}
                    className="shrink-0"
                  >
                    <Trash2 className="h-4 w-4 text-muted-foreground" />
                  </Button>
                </div>
              ))}
              {simulationInput.formFields.length === 0 && (
                <p className="text-sm text-muted-foreground">No form fields. Click "Add Field" to add one.</p>
              )}
            </div>
          </div>

          <Separator />

          {/* Headers */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Headers</Label>
              <Button variant="outline" size="sm" onClick={addHeader}>
                <Plus className="h-3 w-3 mr-1" />
                Add Header
              </Button>
            </div>
            <div className="space-y-2">
              {simulationInput.headers.map((header, index) => (
                <div key={index} className="flex gap-2 items-center">
                  <Input
                    value={header.key}
                    onChange={(e) => updateHeader(index, 'key', e.target.value)}
                    placeholder="Header name"
                    className="w-1/3"
                  />
                  <Input
                    value={header.value}
                    onChange={(e) => updateHeader(index, 'value', e.target.value)}
                    placeholder="Value"
                    className="flex-1"
                  />
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeHeader(index)}
                    className="shrink-0"
                  >
                    <Trash2 className="h-4 w-4 text-muted-foreground" />
                  </Button>
                </div>
              ))}
              {simulationInput.headers.length === 0 && (
                <p className="text-sm text-muted-foreground">No headers. Click "Add Header" to add one.</p>
              )}
            </div>
          </div>

          {/* Results Section */}
          {simulationResult && (
            <>
              <Separator />
              <div className="space-y-4">
                <Label className="text-base font-semibold">Simulation Results</Label>

                {/* Action and Score */}
                <div className="flex items-center gap-4 p-4 rounded-lg bg-muted/50">
                  <div className="flex items-center gap-2">
                    {getActionIcon(simulationResult.action)}
                    <span className="font-medium capitalize">{simulationResult.action}</span>
                  </div>
                  <Badge variant={getActionBadgeVariant(simulationResult.action)}>
                    Score: {simulationResult.score}
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    {simulationResult.execution_time_ms}ms | {simulationResult.nodes_executed} nodes
                  </span>
                </div>

                {/* Block/Allow Reason */}
                {simulationResult.block_reason && (
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <span className="text-sm font-medium text-red-600">Block Reason: </span>
                    <span className="text-sm">{simulationResult.block_reason}</span>
                  </div>
                )}
                {simulationResult.allow_reason && (
                  <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                    <span className="text-sm font-medium text-green-600">Allow Reason: </span>
                    <span className="text-sm">{simulationResult.allow_reason}</span>
                  </div>
                )}

                {/* Tarpit Delay */}
                {simulationResult.tarpit_delay && (
                  <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                    <span className="text-sm font-medium text-orange-600">Tarpit Delay: </span>
                    <span className="text-sm">{simulationResult.tarpit_delay} seconds</span>
                  </div>
                )}

                {/* Flags */}
                {simulationResult.flags.length > 0 && (
                  <div className="space-y-2">
                    <Label className="text-sm">Flags ({simulationResult.flags.length})</Label>
                    <div className="flex flex-wrap gap-1">
                      {simulationResult.flags.map((flag, index) => (
                        <Badge key={index} variant="outline">
                          {flag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Details */}
                {Object.keys(simulationResult.details).length > 0 && (
                  <div className="space-y-2">
                    <Label className="text-sm">Details</Label>
                    <pre className="p-3 rounded-lg bg-muted text-xs overflow-auto max-h-48">
                      {JSON.stringify(simulationResult.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)}>
            Close
          </Button>
          <Button onClick={handleSimulate} disabled={simulateMutation.isPending}>
            {simulateMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Simulating...
              </>
            ) : (
              'Run Simulation'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
