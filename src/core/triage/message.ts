import type { Level } from '@/core/model'
import { analyzeUrl, type UrlReport } from '@/core/triage/url'

/**
 * Local reading of a pasted message, such as a suspicious WhatsApp forward. Works offline and sends
 * nothing. It looks for what scam messages usually do, so it can flag a message and can never clear one.
 */

export type MessageSignal = { id: string; label: string; level: Level }
export type MessageReport = { signals: MessageSignal[]; links: UrlReport[] }

const CHECKS: { id: string; re: RegExp; label: string; level: Level }[] = [
  { id: 'rahasia', re: /\b(otp|kode (?:verifikasi|rahasia|keamanan)|kata ?sandi|password|sandi|pin|cvv|nomor kartu|m-?pin)\b/i, label: 'Meminta kode rahasia atau kata sandi. Pihak resmi tidak pernah memintanya lewat pesan.', level: 'high' },
  { id: 'apk', re: /\.apk\b|\b(undangan pernikahan|surat tilang|cek resi|lihat foto|kurir)\b.*\b(buka|klik|pasang|instal|unduh)\b|\b(buka|klik|pasang|instal|unduh)\b.*\b(undangan pernikahan|surat tilang|cek resi|lihat foto)\b/i, label: 'Mengajak memasang atau membuka berkas. Aplikasi APK dari pesan adalah cara umum mencuri data ponsel.', level: 'high' },
  { id: 'desak', re: /\b(segera|sekarang juga|secepatnya|hari ini juga|batas (?:waktu|akhir)|dalam \d+ (?:jam|menit)|akan (?:diblokir|ditutup|dinonaktifkan|hangus|dihapus)|terakhir)\b/i, label: 'Mendesak agar cepat bertindak, supaya penerima tidak sempat memeriksa.', level: 'medium' },
  { id: 'uang', re: /\b(transfer|rekening|hadiah|undian|menang|bonus|biaya admin|tukin|pencairan|gaji|pinjaman)\b/i, label: 'Membahas uang, hadiah, atau pencairan dana.', level: 'medium' },
  { id: 'atasan', re: /\b(komandan|dan(?:yon|ramil|rem|dim)|kasad|panglima|atasan|bank|polisi|kejaksaan|bea cukai|admin)\b/i, label: 'Membawa nama atasan atau lembaga. Pastikan lewat jalur resmi, bukan dengan membalas pesan ini.', level: 'low' },
]

const LINK_RE = /\b(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s"'<>]+|\b(?:[a-z0-9-]+\.)+(?:com|net|org|id|top|xyz|click|link|info|site|online|shop|me|ly|gd|co)\b(?:\/[^\s"'<>]*)?/gi

export function findLinks(text: string): string[] {
  const found = new Set<string>()
  for (const match of text.match(LINK_RE) ?? []) found.add(match.replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.').replace(/[.,;:!?)\]]+$/, ''))
  return [...found]
}

export function analyzeMessage(text: string): MessageReport {
  const signals: MessageSignal[] = CHECKS.filter((c) => c.re.test(text)).map(({ id, label, level }) => ({ id, label, level }))
  const links = findLinks(text).slice(0, 10).map((link) => analyzeUrl(link)).filter((r) => r.valid)
  if (links.length) signals.unshift({ id: 'tautan', label: `Memuat ${links.length} tautan. Jangan dibuka; periksa alamatnya lebih dulu.`, level: 'medium' })
  return { signals, links }
}
