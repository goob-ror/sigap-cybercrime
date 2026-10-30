import { Cpu, Database, Globe2, Mail, Monitor, Router, UserRound } from 'lucide-react'

export type Severity = 'Kritis' | 'Tinggi' | 'Sedang' | 'Rendah'
export type Source = 'Email Gateway' | 'Endpoint' | 'Jaringan' | 'OT Simulator'
export type Event = {
  id: string; time: string; date: string; title: string; detail: string; source: Source
  user: string; host: string; ip: string; severity: Severity; mitre?: string
  finding: string; evidence: string[]; rule: string; unknown: string; related: string[]
}

export const events: Event[] = [
  { id: 'EVT-2401', time: '08:42:13.219', date: '18 Jun 2025', title: 'Lampiran phishing terkirim', detail: 'Dokumen invoice dengan macro diterima dari domain baru.', source: 'Email Gateway', user: 'n.rahma', host: 'WS-FIN-014', ip: '185.220.101.42', severity: 'Tinggi', mitre: 'T1566.001', finding: 'Initial access melalui spearphishing attachment', evidence: ['SHA256 lampiran: 7f3a…91bd', 'Domain pengirim berusia 2 hari', 'DMARC gagal; nama tampil meniru vendor'], rule: 'Lampiran executable/macro + domain baru + autentikasi email gagal', unknown: 'Belum diketahui apakah pengguna membuka dokumen.', related: ['EVT-2402'] },
  { id: 'EVT-2402', time: '08:45:37.904', date: '18 Jun 2025', title: 'Proses Office memanggil PowerShell', detail: 'WINWORD.EXE membuat proses PowerShell dengan argumen terenkripsi.', source: 'Endpoint', user: 'n.rahma', host: 'WS-FIN-014', ip: '10.20.4.18', severity: 'Kritis', mitre: 'T1059.001', finding: 'Eksekusi payload dan pencurian kredensial', evidence: ['Parent: WINWORD.EXE → powershell.exe', 'Command line memuat -EncodedCommand', 'Koneksi ke 185.220.101.42'], rule: 'Office child process + encoded command + IOC jaringan cocok', unknown: 'Kredensial spesifik yang terekspos masih diverifikasi.', related: ['EVT-2401', 'EVT-2403'] },
  { id: 'EVT-2403', time: '09:17:04.112', date: '18 Jun 2025', title: 'Login dari lokasi dan perangkat baru', detail: 'Autentikasi berhasil dari ASN yang belum pernah digunakan akun ini.', source: 'Jaringan', user: 'n.rahma', host: 'VPN-GW-01', ip: '103.156.92.17', severity: 'Tinggi', mitre: 'T1078', finding: 'Penyalahgunaan akun valid', evidence: ['Device fingerprint baru', 'Impossible travel: Jakarta → Sofia (34 menit)', 'MFA push disetujui satu kali'], rule: 'Perubahan ASN + impossible travel + korelasi akun korban', unknown: 'Belum ada konfirmasi apakah MFA disetujui pengguna.', related: ['EVT-2402', 'EVT-2404'] },
  { id: 'EVT-2404', time: '09:23:51.477', date: '18 Jun 2025', title: 'Pergerakan lateral melalui SMB', detail: 'Akun mengakses share administratif di server engineering.', source: 'Jaringan', user: 'n.rahma', host: 'ENG-SRV-02', ip: '10.20.4.18', severity: 'Kritis', mitre: 'T1021.002', finding: 'Lateral movement ke zona engineering', evidence: ['ADMIN$ diakses dari WS-FIN-014', 'Akun finansial tidak punya pola akses engineering', 'Session ID sama dengan logon anomali'], rule: 'Akses admin share lintas zona + baseline role mismatch', unknown: 'Artefak yang dipindahkan lewat share belum ditemukan.', related: ['EVT-2403', 'EVT-2405'] },
  { id: 'EVT-2405', time: '09:31:28.660', date: '18 Jun 2025', title: 'Perubahan setpoint PLC simulasi', detail: 'Setpoint tekanan dinaikkan 18% di luar change window.', source: 'OT Simulator', user: 'svc_engr', host: 'PLC-SIM-07', ip: '10.40.7.22', severity: 'Kritis', mitre: 'T0836', finding: 'Manipulasi proses OT simulasi', evidence: ['Setpoint 72 → 85 PSI', 'Tidak ada work order aktif', 'Sesi berasal dari ENG-SRV-02'], rule: 'Perubahan parameter safety-sensitive + tanpa change ticket', unknown: 'Dampak fisik tidak ada karena aset bersifat simulasi.', related: ['EVT-2404', 'EVT-2406'] },
  { id: 'EVT-2406', time: '09:44:09.031', date: '18 Jun 2025', title: 'Transfer data keluar berukuran besar', detail: 'Arsip terenkripsi 1,8 GB dikirim ke penyimpanan anonim.', source: 'Jaringan', user: 'n.rahma', host: 'ENG-SRV-02', ip: '45.153.160.2', severity: 'Kritis', mitre: 'T1041', finding: 'Eksfiltrasi data terindikasi kuat', evidence: ['Outbound 1,8 GB ke host tanpa reputasi', 'Arsip dibuat 3 menit sebelum transfer', 'Korelasi host dengan SMB lateral'], rule: 'Lonjakan outbound + arsip baru + tujuan anonim', unknown: 'Isi arsip masih menunggu hasil forensik.', related: ['EVT-2404', 'EVT-2405'] },
]

export const graphNodes = [
  { id:'user', label:'n.rahma', type:'User', x:12, y:48, icon:UserRound, events:['EVT-2401','EVT-2402','EVT-2403','EVT-2404'] },
  { id:'mail', label:'invoice_0618.docm', type:'Email', x:31, y:18, icon:Mail, events:['EVT-2401','EVT-2402'] },
  { id:'ws', label:'WS-FIN-014', type:'Endpoint', x:36, y:55, icon:Monitor, events:['EVT-2401','EVT-2402','EVT-2404'] },
  { id:'c2', label:'185.220.101.42', type:'IP eksternal', x:52, y:18, icon:Globe2, events:['EVT-2401','EVT-2402'] },
  { id:'vpn', label:'VPN-GW-01', type:'Gateway', x:53, y:80, icon:Router, events:['EVT-2403'] },
  { id:'eng', label:'ENG-SRV-02', type:'Server', x:65, y:48, icon:Database, events:['EVT-2404','EVT-2405','EVT-2406'] },
  { id:'plc', label:'PLC-SIM-07', type:'OT simulasi', x:86, y:24, icon:Cpu, events:['EVT-2405'] },
  { id:'exfil', label:'45.153.160.2', type:'IP eksternal', x:87, y:74, icon:Globe2, events:['EVT-2406'] },
]
export const graphEdges = [
  ['user','mail','penerima'], ['mail','ws','dibuka pada'], ['mail','c2','IOC cocok'], ['user','vpn','login akun'],
  ['ws','eng','SMB ADMIN$'], ['vpn','eng','sesi sama'], ['eng','plc','sesi engineering'], ['eng','exfil','transfer 1,8 GB'],
]
