import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authApi } from '@/api/client'

interface User {
  username: string
  must_change_password: boolean
}

interface AuthContextType {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const verifySession = useCallback(async () => {
    try {
      const response = await authApi.verify()
      if (response.data?.user) {
        setUser(response.data.user)
      }
    } catch {
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    verifySession()
  }, [verifySession])

  const login = async (username: string, password: string) => {
    const response = await authApi.login(username, password)
    if (response.data?.user) {
      setUser(response.data.user)
    }
  }

  const logout = async () => {
    await authApi.logout()
    setUser(null)
  }

  const changePassword = async (currentPassword: string, newPassword: string) => {
    await authApi.changePassword(currentPassword, newPassword)
    if (user) {
      setUser({ ...user, must_change_password: false })
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        changePassword,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
