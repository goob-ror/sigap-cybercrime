import type { UnitProfile } from '@/core/model'

/**
 * Network profile of the fictional demo unit ("Satuan Contoh"). Change for a real deployment.
 * Workstations are not listed: SIGAP learns their addresses from the logs (Sysmon network
 * events, remote logons).
 */
export const DEFAULT_UNIT_PROFILE: UnitProfile = {
  name: 'Satuan Contoh (fiktif)',
  engineeringHosts: ['10.40.7.10'],
  otSubnets: ['10.40.7.0/24'],
  uploadThresholdBytes: 500 * 1024 ** 2,
  assets: [
    { name: 'SRV-SATUAN-01', ip: '10.20.1.5', kind: 'it', role: 'Server berkas & aplikasi satuan' },
    { name: 'HMI-GENSET-01', ip: '10.40.7.10', kind: 'ot', role: 'HMI pengendali genset' },
    { name: 'PLC-GENSET-01', ip: '10.40.7.22', kind: 'ot', role: 'PLC genset pangkalan' },
  ],
}
