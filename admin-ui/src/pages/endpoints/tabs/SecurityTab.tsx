import { useState } from 'react'
import { Button } from '@/components/ui/button'
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
import { Info, Plus, X, Bug, Mail, ShieldAlert } from 'lucide-react'
import type { EndpointTabProps } from './types'

export function SecurityTab({ formData, setFormData }: EndpointTabProps) {
  const [newHoneypotField, setNewHoneypotField] = useState('')

  const honeypotFields = Array.isArray(formData.fields?.honeypot) ? formData.fields.honeypot : []

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bug className="h-5 w-5" />
            Honeypot Fields
          </CardTitle>
          <CardDescription>
            Hidden fields that only bots fill out. If any honeypot field contains data, the submission is flagged or blocked.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-blue-500 mt-0.5" />
              <div>
                <p className="font-medium text-blue-800">How Honeypots Work</p>
                <p className="text-sm text-blue-700 mt-1">
                  Add hidden form fields (via CSS display:none) to your forms. Legitimate users won't see or fill them,
                  but automated bots often fill all fields. When a honeypot contains data, it's a strong indicator of automation.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <Label>Honeypot Field Names</Label>
            <div className="flex gap-2">
              <Input
                value={newHoneypotField}
                onChange={(e) => setNewHoneypotField(e.target.value)}
                placeholder="Field name (e.g., website, hp_email)"
                className="flex-1"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && newHoneypotField) {
                    e.preventDefault()
                    if (!honeypotFields.includes(newHoneypotField)) {
                      setFormData({
                        ...formData,
                        fields: {
                          ...formData.fields,
                          honeypot: [...honeypotFields, newHoneypotField],
                        },
                      })
                    }
                    setNewHoneypotField('')
                  }
                }}
              />
              <Button
                type="button"
                onClick={() => {
                  if (newHoneypotField) {
                    if (!honeypotFields.includes(newHoneypotField)) {
                      setFormData({
                        ...formData,
                        fields: {
                          ...formData.fields,
                          honeypot: [...honeypotFields, newHoneypotField],
                        },
                      })
                    }
                    setNewHoneypotField('')
                  }
                }}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {honeypotFields.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {honeypotFields.map((field: string) => (
                  <div
                    key={field}
                    className="flex items-center gap-1 rounded-md bg-yellow-100 px-2 py-1 text-sm text-yellow-800"
                  >
                    <Bug className="h-3 w-3" />
                    <code>{field}</code>
                    <button
                      type="button"
                      onClick={() =>
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            honeypot: honeypotFields.filter((f: string) => f !== field),
                          },
                        })
                      }
                      className="ml-1 hover:text-red-600"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground italic">
                No honeypot fields configured
              </p>
            )}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Action on Honeypot Trigger</Label>
              <Select
                value={(formData as any).security?.honeypot_action || 'block'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    security: {
                      ...(formData as any).security,
                      honeypot_action: value,
                    },
                  } as any)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="block">Block immediately</SelectItem>
                  <SelectItem value="flag">Flag (add to spam score)</SelectItem>
                  <SelectItem value="ignore">Ignore</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {(formData as any).security?.honeypot_action === 'flag' && (
              <div className="space-y-2">
                <Label>Honeypot Score Penalty</Label>
                <Input
                  type="number"
                  min="1"
                  max="100"
                  value={(formData as any).security?.honeypot_score || 50}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      security: {
                        ...(formData as any).security,
                        honeypot_score: parseInt(e.target.value) || 50,
                      },
                    } as any)
                  }
                />
                <p className="text-xs text-muted-foreground">
                  Points added to spam score when honeypot is filled
                </p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Disposable Email Detection
          </CardTitle>
          <CardDescription>
            Detect and handle submissions from temporary/disposable email addresses
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center space-x-2">
            <Switch
              id="check_disposable"
              checked={(formData as any).security?.check_disposable_email === true}
              onCheckedChange={(checked) =>
                setFormData({
                  ...formData,
                  security: {
                    ...(formData as any).security,
                    check_disposable_email: checked,
                  },
                } as any)
              }
            />
            <Label htmlFor="check_disposable">Enable Disposable Email Detection</Label>
          </div>

          {(formData as any).security?.check_disposable_email && (
            <div className="space-y-4 pl-6 border-l-2 border-orange-200">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Action</Label>
                  <Select
                    value={(formData as any).security?.disposable_email_action || 'flag'}
                    onValueChange={(value) =>
                      setFormData({
                        ...formData,
                        security: {
                          ...(formData as any).security,
                          disposable_email_action: value,
                        },
                      } as any)
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="block">Block submission</SelectItem>
                      <SelectItem value="flag">Flag (add to spam score)</SelectItem>
                      <SelectItem value="ignore">Ignore</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {(formData as any).security?.disposable_email_action === 'flag' && (
                  <div className="space-y-2">
                    <Label>Score Penalty</Label>
                    <Input
                      type="number"
                      min="1"
                      max="100"
                      value={(formData as any).security?.disposable_email_score || 20}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          security: {
                            ...(formData as any).security,
                            disposable_email_score: parseInt(e.target.value) || 20,
                          },
                        } as any)
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      Points added per disposable email found
                    </p>
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-orange-200 bg-orange-50 p-4">
                <div className="flex items-start gap-3">
                  <Info className="h-5 w-5 text-orange-500 mt-0.5" />
                  <div>
                    <p className="font-medium text-orange-800">Built-in Domain List</p>
                    <p className="text-sm text-orange-700 mt-1">
                      The WAF includes a list of ~250 known disposable email domains (mailinator.com,
                      guerrillamail.com, 10minutemail.com, etc.). This list is checked against email
                      fields and any text containing email-like patterns.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            Behavioral Anomaly Detection
          </CardTitle>
          <CardDescription>
            Detect suspicious patterns that indicate automated submissions
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center space-x-2">
            <Switch
              id="check_anomalies"
              checked={(formData as any).security?.check_field_anomalies !== false}
              onCheckedChange={(checked) =>
                setFormData({
                  ...formData,
                  security: {
                    ...(formData as any).security,
                    check_field_anomalies: checked,
                  },
                } as any)
              }
            />
            <Label htmlFor="check_anomalies">Enable Field Anomaly Detection</Label>
          </div>

          <div className="rounded-lg border border-purple-200 bg-purple-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-purple-500 mt-0.5" />
              <div>
                <p className="font-medium text-purple-800">Detected Anomalies</p>
                <ul className="text-sm text-purple-700 mt-2 space-y-1">
                  <li><strong>Same Length Fields (+15):</strong> Multiple fields with identical character counts</li>
                  <li><strong>Sequential Data (+10):</strong> Incremental or repeating patterns (abc123, 111-222-333)</li>
                  <li><strong>All Caps (+10):</strong> Multiple fields in ALL UPPERCASE</li>
                  <li><strong>Test Data (+20):</strong> Common test values (test, asdf, lorem ipsum, foo bar)</li>
                </ul>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-blue-500 mt-0.5" />
              <div>
                <p className="font-medium text-blue-800">Client Fingerprinting</p>
                <p className="text-sm text-blue-700 mt-1">
                  Each submission generates a client fingerprint based on browser characteristics
                  (User-Agent, Accept-Language, Accept-Encoding) and form field names—<strong>not</strong> the
                  actual values submitted. This identifies the <em>client</em>, not the content.
                </p>
                <p className="text-sm text-blue-700 mt-2">
                  <strong>Bot detection:</strong> A single client (same fingerprint) submitting many different
                  form hashes indicates automated behavior—legitimate users typically submit the same form
                  with similar content, while bots vary their payloads.
                </p>
                <p className="text-sm text-blue-700 mt-2">
                  High-frequency fingerprints (20+/minute) trigger rate limiting at the HAProxy layer.
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
