import type { Endpoint, Vhost, Thresholds, CaptchaProvider, CaptchaGlobalConfig, FingerprintProfile, DefenseProfile, AttackSignature } from '@/api/types'
import type { LearnedField } from '@/api/client'

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
  globalCaptchaConfig?: CaptchaGlobalConfig
}

export interface FingerprintingTabProps extends EndpointTabProps {
  availableProfiles: FingerprintProfile[]
}

export interface DefenseProfilesTabProps extends EndpointTabProps {
  availableProfiles: DefenseProfile[]
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

export interface DefenseLinesTabProps extends EndpointTabProps {
  availableProfiles: DefenseProfile[]
  availableSignatures: AttackSignature[]
}
