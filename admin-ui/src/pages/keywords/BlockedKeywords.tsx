import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { keywordsApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useToast } from '@/components/ui/use-toast'
import { Plus, Search, Trash2, Ban, AlertTriangle, Pencil } from 'lucide-react'

export function BlockedKeywords() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [newKeyword, setNewKeyword] = useState('')
  const [deleteKeyword, setDeleteKeyword] = useState<string | null>(null)
  const [editKeyword, setEditKeyword] = useState<string | null>(null)
  const [editValue, setEditValue] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['keywords', 'blocked'],
    queryFn: keywordsApi.getBlocked,
  })

  const addMutation = useMutation({
    mutationFn: keywordsApi.addBlocked,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keywords', 'blocked'] })
      toast({ title: 'Keyword added' })
      setNewKeyword('')
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to add keyword',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: keywordsApi.removeBlocked,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keywords', 'blocked'] })
      toast({ title: 'Keyword removed' })
      setDeleteKeyword(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to remove keyword',
        variant: 'destructive',
      })
    },
  })

  const editMutation = useMutation({
    mutationFn: ({ oldKeyword, newKeyword }: { oldKeyword: string; newKeyword: string }) =>
      keywordsApi.editBlocked(oldKeyword, newKeyword),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keywords', 'blocked'] })
      toast({ title: 'Keyword updated' })
      setEditKeyword(null)
      setEditValue('')
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update keyword',
        variant: 'destructive',
      })
    },
  })

  // Ensure arrays (Lua cjson may encode empty arrays as objects)
  const rawKeywords = (data as { keywords: string[] } | undefined)?.keywords
  const keywords = Array.isArray(rawKeywords) ? rawKeywords : []
  const filteredKeywords = keywords.filter((k) =>
    k.toLowerCase().includes(search.toLowerCase())
  )

  const handleAdd = () => {
    if (newKeyword.trim()) {
      addMutation.mutate(newKeyword.trim().toLowerCase())
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Blocked Keywords</h2>
        <p className="text-muted-foreground">
          Keywords that will cause immediate rejection of form submissions
        </p>
      </div>

      <Card className="border-red-200 bg-red-50">
        <CardContent className="flex items-center gap-4 py-4">
          <AlertTriangle className="h-5 w-5 text-red-500" />
          <div>
            <p className="font-medium text-red-800">Immediate Blocking</p>
            <p className="text-sm text-red-600">
              Submissions containing these keywords are rejected without score calculation
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Add New Keyword */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Ban className="h-5 w-5" />
            Add Blocked Keyword
          </CardTitle>
          <CardDescription>
            Add a new keyword that will cause immediate rejection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter keyword (e.g., spam-word)"
              value={newKeyword}
              onChange={(e) => setNewKeyword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
              className="max-w-md"
            />
            <Button onClick={handleAdd} disabled={!newKeyword.trim() || addMutation.isPending}>
              <Plus className="mr-2 h-4 w-4" />
              Add
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Search */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search keywords..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <p className="text-sm text-muted-foreground">
          {filteredKeywords.length} of {keywords.length} keywords
        </p>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Keyword</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={2} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredKeywords.length === 0 ? (
              <TableRow>
                <TableCell colSpan={2} className="text-center">
                  No keywords found
                </TableCell>
              </TableRow>
            ) : (
              filteredKeywords.map((keyword) => (
                <TableRow key={keyword}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Ban className="h-4 w-4 text-red-500" />
                      <code className="bg-red-100 px-2 py-0.5 rounded text-red-800">
                        {keyword}
                      </code>
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => {
                        setEditKeyword(keyword)
                        setEditValue(keyword)
                      }}
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setDeleteKeyword(keyword)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteKeyword} onOpenChange={() => setDeleteKeyword(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Blocked Keyword</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove "{deleteKeyword}" from the blocked list?
              Submissions containing this keyword will no longer be automatically rejected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteKeyword && deleteMutation.mutate(deleteKeyword)}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Edit Dialog */}
      <Dialog open={!!editKeyword} onOpenChange={() => { setEditKeyword(null); setEditValue(''); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Blocked Keyword</DialogTitle>
            <DialogDescription>
              Change the keyword text. The updated keyword will continue to cause immediate rejection.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={editValue}
              onChange={(e) => setEditValue(e.target.value)}
              placeholder="Enter new keyword"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && editKeyword && editValue.trim() && editValue.trim().toLowerCase() !== editKeyword) {
                  editMutation.mutate({ oldKeyword: editKeyword, newKeyword: editValue.trim().toLowerCase() })
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setEditKeyword(null); setEditValue(''); }}>
              Cancel
            </Button>
            <Button
              onClick={() => editKeyword && editMutation.mutate({ oldKeyword: editKeyword, newKeyword: editValue.trim().toLowerCase() })}
              disabled={!editValue.trim() || editValue.trim().toLowerCase() === editKeyword || editMutation.isPending}
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
