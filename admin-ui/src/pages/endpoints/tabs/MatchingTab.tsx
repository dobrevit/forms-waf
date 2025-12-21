import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Plus, X } from 'lucide-react'
import type { EndpointTabProps } from './types'

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const COMMON_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain',
  'text/html',
  'application/xml',
]

export function MatchingTab({ formData, setFormData }: EndpointTabProps) {
  const [newPath, setNewPath] = useState('')
  const [pathType, setPathType] = useState<'exact' | 'prefix' | 'regex'>('exact')
  const [newContentType, setNewContentType] = useState('')

  const addPath = () => {
    if (!newPath) return

    if (pathType === 'exact') {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          paths: [...(formData.matching?.paths || []), newPath],
        },
      })
    } else if (pathType === 'prefix') {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          path_prefix: newPath,
        },
      })
    } else {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          path_regex: newPath,
        },
      })
    }
    setNewPath('')
  }

  const removePath = (path: string) => {
    setFormData({
      ...formData,
      matching: {
        ...formData.matching,
        paths: formData.matching?.paths?.filter((p) => p !== path),
      },
    })
  }

  const toggleMethod = (method: string) => {
    const methods = Array.isArray(formData.matching?.methods) ? formData.matching.methods : []
    if (methods.includes(method)) {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          methods: methods.filter((m) => m !== method),
        },
      })
    } else {
      setFormData({
        ...formData,
        matching: {
          ...formData.matching,
          methods: [...methods, method],
        },
      })
    }
  }

  const paths = Array.isArray(formData.matching?.paths) ? formData.matching.paths : []
  const contentTypes = Array.isArray(formData.matching?.content_types) ? formData.matching.content_types : []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Request Matching</CardTitle>
        <CardDescription>Define which requests this endpoint handles</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-4">
          <Label>Paths</Label>
          <div className="flex gap-2">
            <Select value={pathType} onValueChange={(v) => setPathType(v as typeof pathType)}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="exact">Exact</SelectItem>
                <SelectItem value="prefix">Prefix</SelectItem>
                <SelectItem value="regex">Regex</SelectItem>
              </SelectContent>
            </Select>
            <Input
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              placeholder={
                pathType === 'exact'
                  ? '/api/contact'
                  : pathType === 'prefix'
                  ? '/api/v2/'
                  : '^/api/.*$'
              }
              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addPath())}
              className="flex-1"
            />
            <Button type="button" onClick={addPath}>
              <Plus className="h-4 w-4" />
            </Button>
          </div>

          {/* Exact paths */}
          {paths.length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium">Exact paths:</p>
              <div className="flex flex-wrap gap-2">
                {paths.map((path) => (
                  <div
                    key={path}
                    className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                  >
                    <code>{path}</code>
                    <button
                      type="button"
                      onClick={() => removePath(path)}
                      className="ml-1 hover:text-destructive"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {formData.matching?.path_prefix && (
            <div className="space-y-2">
              <p className="text-sm font-medium">Path prefix:</p>
              <div className="flex items-center gap-2">
                <code className="rounded-md bg-secondary px-2 py-1 text-sm">
                  {formData.matching.path_prefix}*
                </code>
                <button
                  type="button"
                  onClick={() =>
                    setFormData({
                      ...formData,
                      matching: { ...formData.matching, path_prefix: undefined },
                    })
                  }
                  className="hover:text-destructive"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            </div>
          )}

          {formData.matching?.path_regex && (
            <div className="space-y-2">
              <p className="text-sm font-medium">Path regex:</p>
              <div className="flex items-center gap-2">
                <code className="rounded-md bg-secondary px-2 py-1 text-sm">
                  /{formData.matching.path_regex}/
                </code>
                <button
                  type="button"
                  onClick={() =>
                    setFormData({
                      ...formData,
                      matching: { ...formData.matching, path_regex: undefined },
                    })
                  }
                  className="hover:text-destructive"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="space-y-2">
          <Label>HTTP Methods</Label>
          <div className="flex flex-wrap gap-2">
            {HTTP_METHODS.map((method) => {
              const methods = Array.isArray(formData.matching?.methods) ? formData.matching.methods : []
              return (
                <Button
                  key={method}
                  type="button"
                  variant={methods.includes(method) ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => toggleMethod(method)}
                >
                  {method}
                </Button>
              )
            })}
          </div>
        </div>

        <div className="space-y-4">
          <Label>Content Types</Label>
          <div className="flex gap-2">
            <Select
              value={newContentType}
              onValueChange={(value) => {
                if (value && !contentTypes.includes(value)) {
                  setFormData({
                    ...formData,
                    matching: {
                      ...formData.matching,
                      content_types: [...contentTypes, value],
                    },
                  })
                }
                setNewContentType('')
              }}
            >
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Add content type..." />
              </SelectTrigger>
              <SelectContent>
                {COMMON_CONTENT_TYPES.filter(
                  (ct) => !contentTypes.includes(ct)
                ).map((ct) => (
                  <SelectItem key={ct} value={ct}>
                    {ct}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              value={newContentType}
              onChange={(e) => setNewContentType(e.target.value)}
              placeholder="Or enter custom..."
              className="flex-1"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && newContentType) {
                  e.preventDefault()
                  if (!contentTypes.includes(newContentType)) {
                    setFormData({
                      ...formData,
                      matching: {
                        ...formData.matching,
                        content_types: [...contentTypes, newContentType],
                      },
                    })
                  }
                  setNewContentType('')
                }
              }}
            />
          </div>

          {contentTypes.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {contentTypes.map((ct) => (
                <div
                  key={ct}
                  className="flex items-center gap-1 rounded-md bg-secondary px-2 py-1 text-sm"
                >
                  <code>{ct}</code>
                  <button
                    type="button"
                    onClick={() =>
                      setFormData({
                        ...formData,
                        matching: {
                          ...formData.matching,
                          content_types: contentTypes.filter((c) => c !== ct),
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
            <p className="text-sm text-muted-foreground">
              No content type restrictions (matches all)
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
