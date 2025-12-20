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
import { Info, Plus, X, ShieldCheck } from 'lucide-react'
import type { EndpointTabProps } from './types'

const COMMON_IGNORE_FIELDS = [
  '_csrf',
  '_token',
  'csrf_token',
  'authenticity_token',
  'captcha',
  'g-recaptcha-response',
  'h-captcha-response',
]

export function FieldsTab({ formData, setFormData }: EndpointTabProps) {
  const [newRequiredField, setNewRequiredField] = useState('')
  const [newMaxLengthField, setNewMaxLengthField] = useState('')
  const [newMaxLengthValue, setNewMaxLengthValue] = useState('')
  const [customIgnoreField, setCustomIgnoreField] = useState('')
  const [newHashField, setNewHashField] = useState('')
  const [newExpectedField, setNewExpectedField] = useState('')

  const required = Array.isArray(formData.fields?.required) ? formData.fields.required : []
  const maxLength = typeof formData.fields?.max_length === 'object' ? formData.fields.max_length : {}
  const ignoreFields = Array.isArray(formData.fields?.ignore) ? formData.fields.ignore : []
  const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
  const hashFields = Array.isArray(formData.fields?.hash?.fields) ? formData.fields.hash.fields : []
  const hasFieldRestrictions = expectedFields.length > 0 || required.length > 0

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Field Validation</CardTitle>
          <CardDescription>Configure form field requirements and constraints</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Required Fields */}
          <div className="space-y-4">
            <Label>Required Fields</Label>
            <p className="text-sm text-muted-foreground">
              Form submissions must include these fields
            </p>
            <div className="flex gap-2">
              <Input
                value={newRequiredField}
                onChange={(e) => setNewRequiredField(e.target.value)}
                placeholder="Field name (e.g., email)"
                className="flex-1"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && newRequiredField) {
                    e.preventDefault()
                    if (!required.includes(newRequiredField)) {
                      setFormData({
                        ...formData,
                        fields: {
                          ...formData.fields,
                          required: [...required, newRequiredField],
                        },
                      })
                    }
                    setNewRequiredField('')
                  }
                }}
              />
              <Button
                type="button"
                onClick={() => {
                  if (newRequiredField && !required.includes(newRequiredField)) {
                    setFormData({
                      ...formData,
                      fields: {
                        ...formData.fields,
                        required: [...required, newRequiredField],
                      },
                    })
                    setNewRequiredField('')
                  }
                }}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {required.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {required.map((field) => (
                  <div
                    key={field}
                    className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                  >
                    <code>{field}</code>
                    <button
                      type="button"
                      onClick={() =>
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            required: required.filter((f) => f !== field),
                          },
                        })
                      }
                      className="ml-1 hover:text-destructive"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground italic">
                No required fields configured
              </p>
            )}
          </div>

          {/* Max Field Lengths */}
          <div className="space-y-4">
            <Label>Max Field Lengths</Label>
            <p className="text-sm text-muted-foreground">
              Maximum character length for specific fields
            </p>
            <div className="flex gap-2">
              <Input
                value={newMaxLengthField}
                onChange={(e) => setNewMaxLengthField(e.target.value)}
                placeholder="Field name"
                className="flex-1"
              />
              <Input
                type="number"
                value={newMaxLengthValue}
                onChange={(e) => setNewMaxLengthValue(e.target.value)}
                placeholder="Max length"
                className="w-32"
              />
              <Button
                type="button"
                onClick={() => {
                  if (newMaxLengthField && newMaxLengthValue) {
                    setFormData({
                      ...formData,
                      fields: {
                        ...formData.fields,
                        max_length: {
                          ...maxLength,
                          [newMaxLengthField]: parseInt(newMaxLengthValue),
                        },
                      },
                    })
                    setNewMaxLengthField('')
                    setNewMaxLengthValue('')
                  }
                }}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {Object.entries(maxLength).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(maxLength).map(([field, length]) => (
                  <div
                    key={field}
                    className="flex items-center justify-between rounded-md bg-secondary px-3 py-2 text-sm"
                  >
                    <div>
                      <code>{field}</code>
                      <span className="text-muted-foreground mx-2">max</span>
                      <span className="font-medium">{length}</span>
                      <span className="text-muted-foreground ml-1">chars</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        const { [field]: _, ...rest } = maxLength
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            max_length: rest,
                          },
                        })
                      }}
                      className="hover:text-destructive"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground italic">
                No max length constraints configured
              </p>
            )}
          </div>

          {/* Ignored Fields */}
          <div className="space-y-4">
            <Label>Ignored Fields</Label>
            <p className="text-sm text-muted-foreground">
              Fields to exclude from WAF inspection (CSRF tokens, captchas, etc.)
            </p>
            <div className="space-y-2">
              <Select
                onValueChange={(value) => {
                  if (value && !ignoreFields.includes(value)) {
                    setFormData({
                      ...formData,
                      fields: {
                        ...formData.fields,
                        ignore: [...ignoreFields, value],
                      },
                    })
                  }
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select common field..." />
                </SelectTrigger>
                <SelectContent>
                  {COMMON_IGNORE_FIELDS.filter(
                    (f) => !ignoreFields.includes(f)
                  ).map((field) => (
                    <SelectItem key={field} value={field}>
                      {field}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <div className="flex gap-2">
                <Input
                  value={customIgnoreField}
                  onChange={(e) => setCustomIgnoreField(e.target.value)}
                  placeholder="Or enter custom field name..."
                  className="flex-1"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && customIgnoreField.trim()) {
                      e.preventDefault()
                      const trimmed = customIgnoreField.trim()
                      if (!ignoreFields.includes(trimmed)) {
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            ignore: [...ignoreFields, trimmed],
                          },
                        })
                      }
                      setCustomIgnoreField('')
                    }
                  }}
                />
                <Button
                  type="button"
                  onClick={() => {
                    const trimmed = customIgnoreField.trim()
                    if (trimmed && !ignoreFields.includes(trimmed)) {
                      setFormData({
                        ...formData,
                        fields: {
                          ...formData.fields,
                          ignore: [...ignoreFields, trimmed],
                        },
                      })
                      setCustomIgnoreField('')
                    }
                  }}
                >
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {ignoreFields.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {ignoreFields.map((field) => (
                  <div
                    key={field}
                    className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                  >
                    <code>{field}</code>
                    <button
                      type="button"
                      onClick={() =>
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            ignore: ignoreFields.filter((f) => f !== field),
                          },
                        })
                      }
                      className="ml-1 hover:text-destructive"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground italic">
                No fields excluded from inspection
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Expected Fields Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            Optional Expected Fields (Anti-Stuffing)
          </CardTitle>
          <CardDescription>
            Define optional fields that are allowed in addition to required fields. Any other fields trigger the configured action.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-amber-500 mt-0.5" />
              <div>
                <p className="font-medium text-amber-800">Prevent Form Stuffing Attacks</p>
                <p className="text-sm text-amber-700 mt-1">
                  Bots often add extra fields to forms to confuse spam detection or inject malicious data.
                  <strong> Required fields are automatically expected.</strong> Use this section to add optional
                  fields that are allowed but not required. Any field not in required, expected, or ignored lists
                  will trigger the action below.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <Label>Optional Expected Fields</Label>
            <p className="text-sm text-muted-foreground">
              Optional fields allowed in addition to required fields (ignored fields are always allowed)
            </p>
            <div className="flex gap-2">
              <Input
                value={newExpectedField}
                onChange={(e) => setNewExpectedField(e.target.value)}
                placeholder="Field name (e.g., email, message)"
                className="flex-1"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && newExpectedField) {
                    e.preventDefault()
                    if (!expectedFields.includes(newExpectedField)) {
                      setFormData({
                        ...formData,
                        fields: {
                          ...formData.fields,
                          expected: [...expectedFields, newExpectedField],
                        },
                      })
                    }
                    setNewExpectedField('')
                  }
                }}
              />
              <Button
                type="button"
                onClick={() => {
                  if (newExpectedField && !expectedFields.includes(newExpectedField)) {
                    setFormData({
                      ...formData,
                      fields: {
                        ...formData.fields,
                        expected: [...expectedFields, newExpectedField],
                      },
                    })
                    setNewExpectedField('')
                  }
                }}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {expectedFields.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {expectedFields.map((field) => (
                  <div
                    key={field}
                    className="flex items-center gap-1 rounded-md bg-amber-100 px-2 py-1 text-sm text-amber-800"
                  >
                    <code>{field}</code>
                    <button
                      type="button"
                      onClick={() =>
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            expected: expectedFields.filter((f) => f !== field),
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
                No optional expected fields defined. If required fields are set, only those (plus ignored) will be allowed.
              </p>
            )}
          </div>

          {hasFieldRestrictions && (
            <div className="space-y-2">
              <Label htmlFor="unexpected_action">Action for Unexpected Fields</Label>
              <Select
                value={formData.fields?.unexpected_action || 'flag'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    fields: {
                      ...formData.fields,
                      unexpected_action: value as 'flag' | 'block' | 'ignore' | 'filter',
                    },
                  })
                }
              >
                <SelectTrigger className="w-64">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="flag">
                    Flag (+5 score per field)
                  </SelectItem>
                  <SelectItem value="block">
                    Block immediately
                  </SelectItem>
                  <SelectItem value="filter">
                    Filter (remove from request)
                  </SelectItem>
                  <SelectItem value="ignore">
                    Ignore (allow anyway)
                  </SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                What to do when a form contains fields not in required, expected, or ignored lists
              </p>
              {formData.fields?.unexpected_action === 'filter' && (
                <div className="rounded-lg border border-red-200 bg-red-50 p-3 mt-2">
                  <p className="text-sm text-red-700">
                    <strong>Warning:</strong> Filtering modifies the request body, which may break form
                    signing/CSRF protections that hash all fields. Use only if you understand the implications.
                  </p>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Content Hashing Card */}
      <Card>
        <CardHeader>
          <CardTitle>Content Hashing</CardTitle>
          <CardDescription>
            Hash specific form fields for duplicate detection via HAProxy stick-tables
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center space-x-2">
            <Switch
              id="hash_enabled"
              checked={formData.fields?.hash?.enabled === true}
              onCheckedChange={(checked) =>
                setFormData({
                  ...formData,
                  fields: { ...formData.fields, hash: { ...formData.fields?.hash, enabled: checked } },
                })
              }
            />
            <Label htmlFor="hash_enabled">Enable Content Hashing</Label>
          </div>

          {formData.fields?.hash?.enabled && (
            <div className="space-y-4">
              <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
                <div className="flex items-start gap-3">
                  <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                  <div>
                    <p className="font-medium text-blue-800">How Content Hashing Works</p>
                    <p className="text-sm text-blue-700 mt-1">
                      Only the specified fields will be hashed (SHA256) and sent to HAProxy via the X-Form-Hash header.
                      HAProxy uses this to detect duplicate submissions and coordinate rate limiting across replicas.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Fields to Hash</Label>
                <p className="text-sm text-muted-foreground">
                  Specify which form fields should be included in the content hash
                </p>
                <div className="flex gap-2">
                  <Input
                    value={newHashField}
                    onChange={(e) => setNewHashField(e.target.value)}
                    placeholder="Field name (e.g., email, message)"
                    className="flex-1"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && newHashField) {
                        e.preventDefault()
                        if (!hashFields.includes(newHashField)) {
                          setFormData({
                            ...formData,
                            fields: {
                              ...formData.fields,
                              hash: { ...formData.fields?.hash, enabled: true, fields: [...hashFields, newHashField] },
                            },
                          })
                        }
                        setNewHashField('')
                      }
                    }}
                  />
                  <Button
                    type="button"
                    onClick={() => {
                      if (newHashField && !hashFields.includes(newHashField)) {
                        setFormData({
                          ...formData,
                          fields: {
                            ...formData.fields,
                            hash: { ...formData.fields?.hash, enabled: true, fields: [...hashFields, newHashField] },
                          },
                        })
                        setNewHashField('')
                      }
                    }}
                  >
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>

                {hashFields.length > 0 ? (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {hashFields.map((field) => (
                      <div
                        key={field}
                        className="flex items-center gap-1 rounded-md bg-green-100 px-2 py-1 text-sm text-green-800"
                      >
                        <code>{field}</code>
                        <button
                          type="button"
                          onClick={() =>
                            setFormData({
                              ...formData,
                              fields: {
                                ...formData.fields,
                                hash: { ...formData.fields?.hash, enabled: true, fields: hashFields.filter((f) => f !== field) },
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
                  <p className="text-sm text-yellow-600 italic mt-2">
                    No fields specified - content hashing will be skipped
                  </p>
                )}
              </div>
            </div>
          )}

          {!formData.fields?.hash?.enabled && (
            <p className="text-sm text-muted-foreground">
              Content hashing is disabled. Enable it to detect duplicate form submissions.
            </p>
          )}
        </CardContent>
      </Card>
    </>
  )
}
