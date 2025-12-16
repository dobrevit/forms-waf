import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { keywordsApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
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
import { Plus, Search, Trash2, Flag, Info, Pencil } from 'lucide-react'

export function FlaggedKeywords() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [newKeyword, setNewKeyword] = useState('')
  const [newScore, setNewScore] = useState('10')
  const [deleteKeyword, setDeleteKeyword] = useState<string | null>(null)
  const [editItem, setEditItem] = useState<{ keyword: string; score: number } | null>(null)
  const [editKeywordValue, setEditKeywordValue] = useState('')
  const [editScoreValue, setEditScoreValue] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['keywords', 'flagged'],
    queryFn: keywordsApi.getFlagged,
  })

  const addMutation = useMutation({
    mutationFn: ({ keyword, score }: { keyword: string; score: number }) =>
      keywordsApi.addFlagged(keyword, score),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keywords', 'flagged'] })
      toast({ title: 'Keyword added' })
      setNewKeyword('')
      setNewScore('10')
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
    mutationFn: keywordsApi.removeFlagged,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keywords', 'flagged'] })
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
    mutationFn: ({ oldKeyword, newKeyword, newScore }: { oldKeyword: string; newKeyword?: string; newScore?: number }) =>
      keywordsApi.editFlagged(oldKeyword, newKeyword, newScore),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keywords', 'flagged'] })
      toast({ title: 'Keyword updated' })
      setEditItem(null)
      setEditKeywordValue('')
      setEditScoreValue('')
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

  // Parse keyword:score format
  const parsedKeywords = keywords.map((k) => {
    const [keyword, scoreStr] = k.split(':')
    return {
      raw: k,
      keyword: keyword,
      score: parseInt(scoreStr) || 10,
    }
  })

  const filteredKeywords = parsedKeywords.filter((k) =>
    k.keyword.toLowerCase().includes(search.toLowerCase())
  )

  const handleAdd = () => {
    if (newKeyword.trim()) {
      addMutation.mutate({
        keyword: newKeyword.trim().toLowerCase(),
        score: parseInt(newScore) || 10,
      })
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 15) return 'destructive'
    if (score >= 10) return 'warning'
    return 'secondary'
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Flagged Keywords</h2>
        <p className="text-muted-foreground">
          Keywords that add to the spam score without immediate blocking
        </p>
      </div>

      <Card className="border-yellow-200 bg-yellow-50">
        <CardContent className="flex items-center gap-4 py-4">
          <Info className="h-5 w-5 text-yellow-600" />
          <div>
            <p className="font-medium text-yellow-800">Score-Based Filtering</p>
            <p className="text-sm text-yellow-700">
              Each keyword adds its score to the total. Submissions are blocked when score exceeds threshold.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Add New Keyword */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Flag className="h-5 w-5" />
            Add Flagged Keyword
          </CardTitle>
          <CardDescription>
            Add a keyword with a score that contributes to spam detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter keyword (e.g., free)"
              value={newKeyword}
              onChange={(e) => setNewKeyword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
              className="max-w-md"
            />
            <Input
              type="number"
              placeholder="Score"
              value={newScore}
              onChange={(e) => setNewScore(e.target.value)}
              className="w-24"
              min={1}
              max={100}
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
          {filteredKeywords.length} of {parsedKeywords.length} keywords
        </p>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Keyword</TableHead>
              <TableHead>Score</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={3} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredKeywords.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="text-center">
                  No keywords found
                </TableCell>
              </TableRow>
            ) : (
              filteredKeywords.map((item) => (
                <TableRow key={item.raw}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Flag className="h-4 w-4 text-yellow-500" />
                      <code className="bg-yellow-100 px-2 py-0.5 rounded text-yellow-800">
                        {item.keyword}
                      </code>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={getScoreColor(item.score)}>+{item.score}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => {
                        setEditItem({ keyword: item.keyword, score: item.score })
                        setEditKeywordValue(item.keyword)
                        setEditScoreValue(String(item.score))
                      }}
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setDeleteKeyword(item.keyword)}
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
            <AlertDialogTitle>Remove Flagged Keyword</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove "{deleteKeyword}" from the flagged list?
              This keyword will no longer contribute to spam scores.
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
      <Dialog open={!!editItem} onOpenChange={() => { setEditItem(null); setEditKeywordValue(''); setEditScoreValue(''); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Flagged Keyword</DialogTitle>
            <DialogDescription>
              Change the keyword text or adjust its score contribution.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="edit-keyword">Keyword</Label>
              <Input
                id="edit-keyword"
                value={editKeywordValue}
                onChange={(e) => setEditKeywordValue(e.target.value)}
                placeholder="Enter keyword"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-score">Score</Label>
              <Input
                id="edit-score"
                type="number"
                value={editScoreValue}
                onChange={(e) => setEditScoreValue(e.target.value)}
                placeholder="Score"
                min={1}
                max={100}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setEditItem(null); setEditKeywordValue(''); setEditScoreValue(''); }}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!editItem) return
                const newKeyword = editKeywordValue.trim().toLowerCase()
                const newScore = parseInt(editScoreValue) || editItem.score
                const keywordChanged = newKeyword !== editItem.keyword
                const scoreChanged = newScore !== editItem.score
                if (keywordChanged || scoreChanged) {
                  editMutation.mutate({
                    oldKeyword: editItem.keyword,
                    newKeyword: keywordChanged ? newKeyword : undefined,
                    newScore: scoreChanged ? newScore : undefined,
                  })
                }
              }}
              disabled={
                !editKeywordValue.trim() ||
                editMutation.isPending ||
                (editKeywordValue.trim().toLowerCase() === editItem?.keyword && parseInt(editScoreValue) === editItem?.score)
              }
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
