import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { usersApi } from '@/api/client'
import { usePermissions } from '@/hooks/usePermissions'
import { useAuth } from '@/context/AuthContext'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Plus, Search, Pencil, Trash2, User, KeyRound, Shield, Copy, Eye, EyeOff } from 'lucide-react'
import type { User as UserType, UserRole } from '@/api/types'

interface UserFormData {
  username: string
  password: string
  role: UserRole
  vhost_scope: string[]
  display_name: string
  email: string
}

const emptyFormData: UserFormData = {
  username: '',
  password: '',
  role: 'viewer',
  vhost_scope: ['*'],
  display_name: '',
  email: '',
}

export function Users() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { canManageUsers, canViewUsers } = usePermissions()
  const { user: currentUser } = useAuth()
  const [search, setSearch] = useState('')
  const [deleteUsername, setDeleteUsername] = useState<string | null>(null)
  const [resetUsername, setResetUsername] = useState<string | null>(null)
  const [tempPassword, setTempPassword] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [editingUser, setEditingUser] = useState<UserType | null>(null)
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [formData, setFormData] = useState<UserFormData>(emptyFormData)

  const { data, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: usersApi.list,
    enabled: canViewUsers,
  })

  const createMutation = useMutation({
    mutationFn: usersApi.create,
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setIsCreateOpen(false)
      setFormData(emptyFormData)
      if (response.temporary_password) {
        setTempPassword(response.temporary_password)
      } else {
        toast({ title: 'User created successfully' })
      }
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create user',
        variant: 'destructive',
      })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ username, data }: { username: string; data: Partial<UserFormData> }) =>
      usersApi.update(username, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({ title: 'User updated' })
      setEditingUser(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to update user',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: usersApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({ title: 'User deleted' })
      setDeleteUsername(null)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete user',
        variant: 'destructive',
      })
    },
  })

  const resetPasswordMutation = useMutation({
    mutationFn: (username: string) => usersApi.resetPassword(username, ''),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setResetUsername(null)
      if (response.temporary_password) {
        setTempPassword(response.temporary_password)
      }
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to reset password',
        variant: 'destructive',
      })
    },
  })

  const users = data?.users || []
  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      return (
        u.username.toLowerCase().includes(search.toLowerCase()) ||
        u.display_name?.toLowerCase().includes(search.toLowerCase()) ||
        u.email?.toLowerCase().includes(search.toLowerCase())
      )
    })
  }, [users, search])

  const getRoleBadgeVariant = (role: UserRole) => {
    switch (role) {
      case 'admin':
        return 'destructive'
      case 'operator':
        return 'default'
      case 'viewer':
        return 'secondary'
      default:
        return 'outline'
    }
  }

  const handleCreate = () => {
    createMutation.mutate({
      username: formData.username,
      password: formData.password || undefined!,
      role: formData.role,
      vhost_scope: formData.vhost_scope,
      display_name: formData.display_name || undefined,
      email: formData.email || undefined,
    })
  }

  const handleUpdate = () => {
    if (!editingUser) return
    updateMutation.mutate({
      username: editingUser.username,
      data: {
        role: formData.role,
        vhost_scope: formData.vhost_scope,
        display_name: formData.display_name || undefined,
        email: formData.email || undefined,
      },
    })
  }

  const openEditDialog = (user: UserType) => {
    setEditingUser(user)
    setFormData({
      username: user.username,
      password: '',
      role: user.role,
      vhost_scope: user.vhost_scope || ['*'],
      display_name: user.display_name || '',
      email: user.email || '',
    })
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({ title: 'Copied to clipboard' })
  }

  if (!canViewUsers) {
    return (
      <div className="flex items-center justify-center h-96">
        <p className="text-muted-foreground">You don't have permission to view users.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">User Management</h2>
          <p className="text-muted-foreground">
            Manage admin users and their access permissions
          </p>
        </div>
        {canManageUsers && (
          <Button onClick={() => setIsCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Add User
          </Button>
        )}
      </div>

      {/* Search */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search users..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Vhost Scope</TableHead>
              <TableHead>Auth Provider</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredUsers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center">
                  No users found
                </TableCell>
              </TableRow>
            ) : (
              filteredUsers.map((user) => (
                <TableRow key={user.username}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{user.display_name || user.username}</p>
                        <p className="text-xs text-muted-foreground">{user.username}</p>
                        {user.email && (
                          <p className="text-xs text-muted-foreground">{user.email}</p>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={getRoleBadgeVariant(user.role)}>
                      <Shield className="h-3 w-3 mr-1" />
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {user.vhost_scope?.includes('*') ? (
                        <Badge variant="outline" className="text-xs">All Vhosts</Badge>
                      ) : (
                        user.vhost_scope?.slice(0, 3).map((vhost) => (
                          <Badge key={vhost} variant="outline" className="text-xs">
                            {vhost}
                          </Badge>
                        ))
                      )}
                      {user.vhost_scope && user.vhost_scope.length > 3 && !user.vhost_scope.includes('*') && (
                        <Badge variant="outline" className="text-xs">
                          +{user.vhost_scope.length - 3}
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">{user.auth_provider || 'local'}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <Badge variant={user.enabled !== false ? 'default' : 'secondary'}>
                        {user.enabled !== false ? 'Active' : 'Disabled'}
                      </Badge>
                      {user.must_change_password && (
                        <Badge variant="warning" className="text-xs">
                          Password change required
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      {canManageUsers && (
                        <>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditDialog(user)}
                            title="Edit user"
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          {user.auth_provider === 'local' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setResetUsername(user.username)}
                              title="Reset password"
                            >
                              <KeyRound className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setDeleteUsername(user.username)}
                            disabled={user.username === currentUser?.username}
                            title="Delete user"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Create User Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Create New User</DialogTitle>
            <DialogDescription>
              Add a new admin user. Leave password empty to auto-generate a temporary one.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                placeholder="e.g., johndoe"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="password">Password (optional)</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  placeholder="Leave empty to auto-generate"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-0 top-0 h-full"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="role">Role</Label>
              <Select
                value={formData.role}
                onValueChange={(value: UserRole) => setFormData({ ...formData, role: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Admin - Full access</SelectItem>
                  <SelectItem value="operator">Operator - Manage endpoints and keywords</SelectItem>
                  <SelectItem value="viewer">Viewer - Read-only access</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="vhost_scope">Vhost Scope</Label>
              <Input
                id="vhost_scope"
                value={formData.vhost_scope.join(', ')}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    vhost_scope: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                  })
                }
                placeholder="* for all, or comma-separated vhost IDs"
              />
              <p className="text-xs text-muted-foreground">
                Use * for access to all vhosts, or specify comma-separated vhost IDs
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="display_name">Display Name (optional)</Label>
              <Input
                id="display_name"
                value={formData.display_name}
                onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
                placeholder="e.g., John Doe"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="email">Email (optional)</Label>
              <Input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="e.g., john@example.com"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={!formData.username || createMutation.isPending}>
              {createMutation.isPending ? 'Creating...' : 'Create User'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={!!editingUser} onOpenChange={() => setEditingUser(null)}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>
              Update user settings for {editingUser?.username}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="edit-role">Role</Label>
              <Select
                value={formData.role}
                onValueChange={(value: UserRole) => setFormData({ ...formData, role: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Admin - Full access</SelectItem>
                  <SelectItem value="operator">Operator - Manage endpoints and keywords</SelectItem>
                  <SelectItem value="viewer">Viewer - Read-only access</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit-vhost_scope">Vhost Scope</Label>
              <Input
                id="edit-vhost_scope"
                value={formData.vhost_scope.join(', ')}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    vhost_scope: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                  })
                }
                placeholder="* for all, or comma-separated vhost IDs"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit-display_name">Display Name</Label>
              <Input
                id="edit-display_name"
                value={formData.display_name}
                onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="edit-email">Email</Label>
              <Input
                id="edit-email"
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingUser(null)}>
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteUsername} onOpenChange={() => setDeleteUsername(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete the user "{deleteUsername}"? This action cannot be undone.
              All active sessions for this user will also be terminated.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteUsername && deleteMutation.mutate(deleteUsername)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Reset Password Confirmation */}
      <AlertDialog open={!!resetUsername} onOpenChange={() => setResetUsername(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Reset Password</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to reset the password for user "{resetUsername}"?
              A new temporary password will be generated and the user will be required to change it on next login.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => resetUsername && resetPasswordMutation.mutate(resetUsername)}
            >
              Reset Password
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Temporary Password Display */}
      <Dialog open={!!tempPassword} onOpenChange={() => setTempPassword(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Temporary Password</DialogTitle>
            <DialogDescription>
              Please save this password securely. It will only be shown once.
              The user will be required to change it on first login.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between gap-2">
                  <code className="text-lg font-mono bg-muted px-3 py-2 rounded flex-1">
                    {tempPassword}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => tempPassword && copyToClipboard(tempPassword)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
          <DialogFooter>
            <Button onClick={() => setTempPassword(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export default Users
