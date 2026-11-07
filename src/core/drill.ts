import type { RuleMeta } from '@/core/detect/sigma'
import type { Detection, Incident } from '@/core/model'
import { cutOptions, type OtAnalysis } from '@/core/ot/analysis'
import { LEVEL_RANK } from '@/core/labels'
import { recommendPlaybooks } from '@/data/playbooks'

/**
 * Questions per response phase, worked out from an incident's own data, with no network. So a unit can
 * drill in the offline kit, and a demo does not depend on the venue's connection. The answer key comes
 * from the findings themselves, so it cannot be wrong about them.
 */

export type DrillPhase = 'Deteksi' | 'Analisis' | 'Containment' | 'Recovery'
export type DrillQuestion = { phase: DrillPhase; question: string; options: string[]; answer: number; explanation: string; refs: string[] }

/** Common first-response mistakes, used as wrong answers. */
const BAD_FIRST_MOVES = ['Matikan komputer itu sekarang agar serangan berhenti', 'Hapus log agar jejak penyerang tidak menyebar', 'Tunggu laporan dari pengguna lain sebelum bertindak', 'Instal ulang komputer sekarang, sebelum bukti diamankan']
const BAD_RECOVERY = ['Nyalakan kembali layanan seperti semula tanpa mengganti kata sandi', 'Tutup kasus karena alert sudah berhenti muncul', 'Hapus semua log lama agar disk kembali lega', 'Hubungi penyerang untuk meminta keterangan']
const DECOY_ASSETS = ['WS-TAMU-09', 'SRV-ARSIP-02', 'LAPTOP-GUDANG-1']

function hash32(text: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 0x01000193)
  return h >>> 0
}

/** The same incident always gives the same order, without the right answer sitting in a fixed place. */
function arrange(correct: string, wrong: string[], seed: string): { options: string[]; answer: number } {
  const options = [correct, ...wrong.filter((w) => w !== correct).slice(0, 3)]
  const ranked = options.map((o) => ({ o, k: hash32(`${seed}|${o}`) })).sort((a, b) => a.k - b.k).map((x) => x.o)
  return { options: ranked, answer: ranked.indexOf(correct) }
}

const PHASE_ORDER: DrillPhase[] = ['Deteksi', 'Analisis', 'Containment', 'Recovery']

/** Questions only the link between IT and OT can ask, with answers worked out from the traffic. */
function otQuestions(ot: OtAnalysis, seed: string): DrillQuestion[] {
  const questions: DrillQuestion[] = []
  const evidence = ot.moments.find((m) => m.detectionId && ot.nodes.some((n) => n.zone === 'plc' && m.nodes.includes(n.key)))?.detectionId
  if (!evidence) return questions
  const refs = [evidence]
  const series = ot.series.find((s) => s.kind !== 'terukur' && s.episodes.length)
  const unit = series?.unit ? ` ${series.unit}` : ''

  const restart = ot.runs[0]?.spans.find((span, i) => i > 0 && span.running)
  const episode = series?.episodes.find((ep) => restart && ep.from <= restart.from && (ep.open || ep.to > restart.from))
  if (series && restart && episode) {
    const { options, answer } = arrange(`Belum. ${series.label} masih ${episode.peak}${unit}, di luar batas`, ['Sudah. Peralatan menyala berarti kembali normal', 'Sudah. Alert tidak muncul lagi setelah itu', 'Tidak dapat diketahui dari log'], `${seed}|ot-restart`)
    questions.push({ phase: 'Analisis', question: `${ot.runs[0].deviceName} kembali menyala setelah dihentikan penyerang. Apakah masalahnya sudah selesai?`, options, answer, explanation: 'Menyalakan peralatan dari panel tidak mengubah nilai yang ditulis penyerang. Pembacaan HMI menunjukkan nilainya masih salah, jadi peralatan berjalan di luar batas aman.', refs })
  }

  const best = cutOptions(ot).filter((o) => o.result.protectsOt).sort((a, b) => Number(b.kind === 'jalur') - Number(a.kind === 'jalur'))[0]
  if (best) {
    const device = ot.nodes.find((n) => n.zone === 'plc')?.label ?? 'pengendali'
    const { options, answer } = arrange(best.label, [`Matikan ${device} agar tidak dapat diperintah`, 'Blokir alamat internet penyerang saja', 'Hapus log Modbus agar penyerang tidak melihatnya'], `${seed}|ot-cut`)
    questions.push({ phase: 'Containment', question: 'Tindakan mana yang memutus jalur yang tercatat ke perangkat OT tanpa mengganggu operasinya?', options, answer, explanation: 'Jalur di log masuk ke perangkat OT lewat satu titik. Memutus titik itu menghentikan perintah penyerang, sedangkan HMI tetap dapat mengendalikan peralatan.', refs })
  }

  if (series?.lastGood && series.band) {
    const peak = series.episodes[0].peak
    const { options, answer } = arrange(`${series.lastGood.value}${unit}`, [`${peak}${unit}`, `${series.band.max + 20}${unit}`, `0${unit}`], `${seed}|ot-value`)
    questions.push({ phase: 'Recovery', question: `Penyerang mengubah ${series.label} menjadi ${peak}${unit}. Berapa nilai yang harus dikembalikan?`, options, answer, explanation: `${series.lastGood.value}${unit} adalah nilai normal terakhir yang dilaporkan pengendali sebelum perubahan, dan berada di dalam batas ${series.band.min}–${series.band.max}${unit}.`, refs })
  }
  return questions
}

export function localDrill(incident: Incident, detectionsById: Map<string, Detection>, rules: Map<string, RuleMeta>, ot?: OtAnalysis | null): DrillQuestion[] {
  const detections = incident.detectionIds.map((id) => detectionsById.get(id)).filter((d): d is Detection => !!d).sort((a, b) => a.ts - b.ts)
  if (!detections.length) return []
  const questions: DrillQuestion[] = []
  const seed = incident.id

  const titles = [...new Set(detections.map((d) => d.title))]
  if (titles.length >= 3) {
    const { options, answer } = arrange(titles[0], titles.slice(1).reverse(), `${seed}|deteksi`)
    questions.push({ phase: 'Deteksi', question: 'Temuan mana yang paling awal muncul pada insiden ini?', options, answer, explanation: `Urutan waktu menunjukkan "${titles[0]}" sebagai temuan pertama. Titik awal menentukan ke mana pemeriksaan dimulai.`, refs: [detections[0].id] })
  }

  const assets = incident.entities.filter((e) => e.type === 'host' || e.type === 'device')
  const first = incident.path.length ? incident.entities.find((e) => e.key === incident.path[0]) : assets[0]
  if (first) {
    const others = assets.filter((a) => a.key !== first.key).map((a) => a.value)
    const { options, answer } = arrange(first.value, [...others, ...DECOY_ASSETS], `${seed}|analisis`)
    questions.push({ phase: 'Analisis', question: 'Aset mana yang pertama kali terlihat dalam rangkaian ini?', options, answer, explanation: `${first.value} adalah aset pertama pada rangkaian menurut waktu temuan, sehingga pemeriksaan dimulai dari sana.`, refs: [first.detectionIds[0]] })
  }

  const worst = [...detections].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts).find((d) => (rules.get(d.ruleId)?.respons.length ?? 0) > 0)
  const firstMove = worst && rules.get(worst.ruleId)?.respons[0]
  if (worst && firstMove) {
    const { options, answer } = arrange(firstMove, BAD_FIRST_MOVES, `${seed}|containment`)
    questions.push({ phase: 'Containment', question: `Temuan terberat adalah "${worst.title}". Apa langkah pertama yang tepat?`, options, answer, explanation: 'Mematikan komputer atau menghapus log memusnahkan bukti. Langkah yang benar menahan serangan sambil menjaga bukti.', refs: [worst.id] })
  }

  const playbook = recommendPlaybooks(incident)[0]
  const recover = playbook?.phases[1]?.steps[0]
  if (playbook && recover) {
    const { options, answer } = arrange(recover, BAD_RECOVERY, `${seed}|recovery`)
    questions.push({ phase: 'Recovery', question: `Menurut panduan "${playbook.title}", apa yang dilakukan pada tahap pemulihan?`, options, answer, explanation: 'Pemulihan menutup jalan masuk yang dipakai penyerang. Alert yang berhenti muncul bukan tanda bahwa insiden sudah selesai.', refs: [detections[0].id] })
  }
  if (ot?.incidentId === incident.id) questions.push(...otQuestions(ot, seed))
  return questions.map((q, i) => ({ q, i })).sort((a, b) => PHASE_ORDER.indexOf(a.q.phase) - PHASE_ORDER.indexOf(b.q.phase) || a.i - b.i).map(({ q }) => q)
}

export type DrillResult = { ts: number; operator: string; correct: number; total: number; seconds: number; byPhase: Record<string, boolean> }
