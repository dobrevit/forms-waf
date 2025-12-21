import type { Endpoint, Vhost, Thresholds, CaptchaProvider, FingerprintProfile, LearnedField } from '@/api/types'

export interface EndpointTabProps {
  formData: Partial<Endpoint>
  setFormData: React.Dispatch<React.SetStateAction<Partial<Endpoint>>>
  isEdit: boolean
}

export interface GeneralTabProps extends EndpointTabProps {
  vhosts: Vhost[]
}

export interface WafSettingsTabProps extends EndpointTabProps {
  globalThresholds: Thresholds
}

export interface RateLimitingTabProps extends EndpointTabProps {}

export interface CaptchaTabProps extends EndpointTabProps {
  captchaProviders: CaptchaProvider[]
  globalCaptchaConfig?: {
    enabled: boolean
    default_provider?: string
    trust_duration?: number
  }
}

export interface FingerprintingTabProps extends EndpointTabProps {
  availableProfiles: FingerprintProfile[]
}

export interface LearnedFieldsTabProps extends EndpointTabProps {
  learnedFields: LearnedField[]
  learnedFieldsLoading: boolean
  learningStats?: {
    batch_count?: number
    cache_available?: boolean
  }
  onClearLearning: () => void
  clearLearningPending: boolean
  addToRequiredFields: (fieldName: string) => void
  addToHashFields: (fieldName: string) => void
  addToIgnoreFields: (fieldName: string) => void
  addToExpectedFields: (fieldName: string) => void
  addToHoneypotFields: (fieldName: string) => void
}
