import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Info, BookOpen, Trash2, CheckCircle, Hash, EyeOff, ShieldCheck, Bug } from 'lucide-react'
import type { LearnedFieldsTabProps } from './types'

export function LearnedFieldsTab({
  formData,
  learnedFields,
  learnedFieldsLoading,
  learningStats,
  onClearLearning,
  clearLearningPending,
  addToRequiredFields,
  addToHashFields,
  addToIgnoreFields,
  addToExpectedFields,
  addToHoneypotFields,
}: LearnedFieldsTabProps) {
  const required = Array.isArray(formData.fields?.required) ? formData.fields.required : []
  const hashFields = Array.isArray(formData.fields?.hash?.fields) ? formData.fields.hash.fields : []
  const ignoreFields = Array.isArray(formData.fields?.ignore) ? formData.fields.ignore : []
  const expectedFields = Array.isArray(formData.fields?.expected) ? formData.fields.expected : []
  const honeypotFields = Array.isArray(formData.fields?.honeypot) ? formData.fields.honeypot : []

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <BookOpen className="h-5 w-5" />
              Learned Fields
            </CardTitle>
            <CardDescription>
              Form fields automatically discovered from traffic. Use these to configure field requirements.
            </CardDescription>
          </div>
          {learnedFields.length > 0 && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                if (confirm('Clear all learning data for this endpoint? This cannot be undone.')) {
                  onClearLearning()
                }
              }}
              disabled={clearLearningPending}
              className="text-red-600 hover:text-red-700 hover:bg-red-50"
            >
              <Trash2 className="h-4 w-4 mr-1" />
              Clear Data
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {learnedFieldsLoading ? (
          <div className="text-center py-8 text-muted-foreground">
            Loading learned fields...
          </div>
        ) : learnedFields.length === 0 ? (
          <div className="text-center py-8 space-y-2">
            <BookOpen className="h-12 w-12 mx-auto text-muted-foreground/50" />
            <p className="text-muted-foreground">No fields learned yet</p>
            <p className="text-sm text-muted-foreground">
              Field names will be automatically discovered as requests flow through this endpoint.
              Learning uses 10% sampling to minimize performance impact.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Learning stats */}
            {learningStats && (
              <div className="rounded-lg border border-blue-200 bg-blue-50 p-3">
                <div className="flex items-center gap-4 text-sm text-blue-700">
                  <span>
                    <strong>{learnedFields.length}</strong> unique fields discovered
                  </span>
                  <span className="text-blue-300">|</span>
                  <span>
                    <strong>{learningStats.batch_count || 0}</strong> batches processed
                  </span>
                  {learningStats.cache_available && (
                    <>
                      <span className="text-blue-300">|</span>
                      <span className="text-green-600">Cache active</span>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Fields table */}
            <div className="rounded-md border">
              <table className="w-full">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm font-medium">Field Name</th>
                    <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                    <th className="px-4 py-3 text-left text-sm font-medium">Count</th>
                    <th className="px-4 py-3 text-left text-sm font-medium">Last Seen</th>
                    <th className="px-4 py-3 text-right text-sm font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {learnedFields.map((field) => {
                    const isRequired = required.includes(field.name)
                    const isHashed = hashFields.includes(field.name)
                    const isIgnored = ignoreFields.includes(field.name)
                    const isExpected = expectedFields.includes(field.name)
                    const isHoneypot = honeypotFields.includes(field.name)

                    return (
                      <tr key={field.name} className="hover:bg-muted/30">
                        <td className="px-4 py-3">
                          <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{field.name}</code>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {isRequired && (
                              <span className="text-xs bg-green-100 text-green-700 px-1.5 py-0.5 rounded">Required</span>
                            )}
                            {isHashed && (
                              <span className="text-xs bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">Hashed</span>
                            )}
                            {isExpected && (
                              <span className="text-xs bg-amber-100 text-amber-700 px-1.5 py-0.5 rounded">Expected</span>
                            )}
                            {isHoneypot && (
                              <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">Honeypot</span>
                            )}
                            {isIgnored && (
                              <span className="text-xs bg-gray-100 text-gray-700 px-1.5 py-0.5 rounded">Ignored</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-muted-foreground">
                          {field.type || 'text'}
                        </td>
                        <td className="px-4 py-3 text-sm">
                          {field.count.toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-sm text-muted-foreground">
                          {field.last_seen
                            ? new Date(field.last_seen * 1000).toLocaleDateString()
                            : '—'}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => addToRequiredFields(field.name)}
                              disabled={isRequired}
                              title="Add to Required Fields"
                              className={isRequired ? 'text-green-600' : ''}
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => addToHashFields(field.name)}
                              disabled={isHashed}
                              title="Add to Hash Fields"
                              className={isHashed ? 'text-purple-600' : ''}
                            >
                              <Hash className="h-4 w-4" />
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => addToExpectedFields(field.name)}
                              disabled={isExpected}
                              title="Add to Expected Fields"
                              className={isExpected ? 'text-amber-600' : ''}
                            >
                              <ShieldCheck className="h-4 w-4" />
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => addToHoneypotFields(field.name)}
                              disabled={isHoneypot}
                              title="Add to Honeypot Fields"
                              className={isHoneypot ? 'text-red-600' : ''}
                            >
                              <Bug className="h-4 w-4" />
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => addToIgnoreFields(field.name)}
                              disabled={isIgnored}
                              title="Add to Ignored Fields"
                              className={isIgnored ? 'text-gray-600' : ''}
                            >
                              <EyeOff className="h-4 w-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Bulk actions */}
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  learnedFields.forEach(f => addToRequiredFields(f.name))
                }}
              >
                <CheckCircle className="h-4 w-4 mr-1" />
                Add All to Required
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  learnedFields.forEach(f => addToHashFields(f.name))
                }}
              >
                <Hash className="h-4 w-4 mr-1" />
                Add All to Hash
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  learnedFields.forEach(f => addToExpectedFields(f.name))
                }}
              >
                <ShieldCheck className="h-4 w-4 mr-1" />
                Add All to Expected
              </Button>
            </div>

            {/* Info note */}
            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
              <div className="flex items-start gap-3">
                <Info className="h-5 w-5 text-yellow-600 mt-0.5" />
                <div>
                  <p className="font-medium text-yellow-800">About Field Learning</p>
                  <p className="text-sm text-yellow-700 mt-1">
                    Field names are automatically discovered using 10% probabilistic sampling to minimize
                    performance impact. Types are inferred from field names only (no values stored for compliance).
                    Data is retained for 30 days of inactivity. Use the action buttons to configure fields:
                  </p>
                  <ul className="text-sm text-yellow-700 mt-2 space-y-1 list-disc list-inside">
                    <li><strong>Required</strong> - Field must be present in submissions</li>
                    <li><strong>Hash</strong> - Include field in content hash for duplicate detection</li>
                    <li><strong>Expected</strong> - Validate that only expected fields are submitted</li>
                    <li><strong>Honeypot</strong> - Mark as trap field (should be empty, bots fill it)</li>
                    <li><strong>Ignored</strong> - Exclude from spam analysis</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
