import { describe, expect, it } from 'vitest'
import { analyzeMessage, findLinks } from '@/core/triage/message'

describe('analyzeMessage', () => {
  const ids = (text: string) => analyzeMessage(text).signals.map((s) => s.id)

  it('recognizes what scam messages do', () => {
    expect(ids('Segera transfer ke rekening ini dan kirim kode OTP Anda')).toEqual(expect.arrayContaining(['rahasia', 'desak', 'uang']))
    expect(ids('Bapak dapat undangan pernikahan, klik untuk buka undangan.apk')).toContain('apk')
    expect(ids('Pesan dari Komandan')).toContain('atasan')
  })

  it('finds links in their usual disguises, and checks each', () => {
    expect(findLinks('Buka hxxp://evil.top/x, atau www.bank-palsu.com. Atau bit.ly/abc!')).toEqual(['http://evil.top/x', 'www.bank-palsu.com', 'bit.ly/abc'])
    const report = analyzeMessage('Klik http://bri-verif.secure-login.top/akun/update')
    expect(report.signals[0].id).toBe('tautan')
    expect(report.links[0].host).toBe('bri-verif.secure-login.top')
    expect(report.links[0].score).toBeGreaterThan(0)
  })

  it('finds nothing in plain text, which the page must not call safe', () => {
    expect(analyzeMessage('Sampai ketemu besok pagi')).toEqual({ signals: [], links: [] })
  })
})
