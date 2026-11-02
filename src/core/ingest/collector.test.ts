import { describe, expect, it } from 'vitest'
import { ingestText, sniffFormat } from '@/core/ingest'
import { runDetections } from '@/core/detect/engine'
import { loadRulePack } from '@/data/rules'

// The SIGAP collector (collector/sigap-collect.ps1) emits Windows events with EventData already
// named (taken from each event's XML). This is the "generic" shape SIGAP ingests directly.
const record = {
  EventID: 1,
  Channel: 'Microsoft-Windows-Sysmon/Operational',
  Computer: 'WS-MIN-03',
  TimeCreated: '2026-11-02T02:13:02.0000000Z',
  ProviderName: 'Microsoft-Windows-Sysmon',
  EventRecordID: '77',
  Level: 4,
  EventData: {
    Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ParentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    CommandLine: 'powershell.exe -enc SQBFAFgA',
    User: 'SATUAN\\sertu.rina',
  },
  Message: 'Process Create',
}

describe('SIGAP collector format', () => {
  const text = JSON.stringify([record])

  it('is recognized as a Windows event export', () => {
    expect(sniffFormat(text)).toBe('winevent-jsonl')
  })

  it('normalizes the event and fires the right detections', () => {
    const result = ingestText(text, 'Microsoft-Windows-Sysmon-Operational.json', 'imp')
    expect(result.errorCount).toBe(0)
    expect(result.events[0]).toMatchObject({ host: 'WS-MIN-03', user: 'sertu.rina', logsource: { category: 'process_creation' } })
    expect(result.events[0].process).toMatchObject({ name: 'powershell.exe', parent: 'WINWORD.EXE' })
    const fired = new Set(runDetections(result.events, loadRulePack()).map((d) => d.ruleId))
    expect(fired).toContain('sigap-win-ps-encoded')
    expect(fired).toContain('sigap-win-office-spawn-shell')
  })
})
