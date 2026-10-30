import type { UnitProfile } from '@/core/detect/native'

/** Network profile of the fictional demo unit ("Satuan Contoh"). Change for a real deployment. */
export const DEFAULT_UNIT_PROFILE: UnitProfile = {
  engineeringHosts: ['10.40.7.10'],
  otSubnets: ['10.40.7.0/24'],
  uploadThresholdBytes: 500 * 1024 ** 2,
}
