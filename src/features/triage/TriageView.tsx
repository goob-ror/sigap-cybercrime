import { useState } from "react";
import {
  Braces,
  CircleCheck,
  Globe2,
  ListChecks,
  MessageSquareWarning,
  Search,
  ShieldCheck,
  Smartphone,
  TriangleAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { Label } from "@/components/ui/Label";
import { PageTitle } from "@/components/ui/PageTitle";
import { analyzeUrl, type UrlReport } from "@/core/triage/url";
import { matchIocs, parseIndicators, type IocMatch } from "@/core/triage/match";
import type { ApkReport } from "@/core/triage/apk";
import { allIocs } from "@/core/report/ioc";
import { scorePercent } from "@/core/report/narrative";
import { formatBytes } from "@/core/ingest/kv";
import {
  analyzeApkBytes,
  buildSampleApkBytes,
} from "@/features/triage/apkFile";
import { MessageTab } from "@/features/triage/MessageTab";
import { ReputationPanel } from "@/features/triage/ReputationPanel";
import { db } from "@/db/db";
import type { Investigation } from "@/db/hooks";
import { fmtDate, fmtNumber, fmtTime } from "@/lib/format";
import { LEVEL_LABEL, levelStyle } from "@/lib/styles";

type Tab = "url" | "pesan" | "ioc" | "apk";
type Props = {
  data: Investigation;
  actor: string;
  ownDomains: readonly string[];
  notify: (message: string) => void;
  openSettings: () => void;
};
const KIND_LABEL = { ip: "IP", domain: "Domain", sha256: "Hash" } as const;

function scoreColor(score: number): string {
  if (score >= 0.6) return "#FCA5A5";
  if (score >= 0.3) return "#FBBF24";
  return "#86EFAC";
}

export function TriageView({
  data,
  actor,
  ownDomains,
  notify,
  openSettings,
}: Props) {
  const [tab, setTab] = useState<Tab>("url");
  const [urlInput, setUrlInput] = useState(
    "http://bri-verif.secure-login.top/akun/update?token=8f2a1c",
  );
  const [report, setReport] = useState<UrlReport | null>(null);
  const [iocText, setIocText] = useState("");
  const [matches, setMatches] = useState<IocMatch[] | null>(null);
  const [matching, setMatching] = useState(false);
  const [apk, setApk] = useState<ApkReport | null>(null);
  const [apkName, setApkName] = useState("");
  const [apkBusy, setApkBusy] = useState(false);
  const [apkError, setApkError] = useState("");

  const sendToIoc = (value: string) => {
    setIocText(value);
    setMatches(null);
    setTab("ioc");
  };
  const inspectUrl = (value: string) => {
    setUrlInput(value);
    setReport(analyzeUrl(value));
    setTab("url");
  };
  const loadFromIncidents = () => {
    setIocText(
      allIocs(data.incidents, data.detectionsById)
        .map((i) => i.value)
        .join("\n"),
    );
    setMatches(null);
  };
  const runMatch = async () => {
    const indicators = parseIndicators(iocText);
    if (!indicators.length) {
      setMatches([]);
      return;
    }
    setMatching(true);
    try {
      setMatches(matchIocs(indicators, await db.events.toArray()));
    } finally {
      setMatching(false);
    }
  };

  const runApk = async (name: string, load: () => Promise<Uint8Array>) => {
    setApkBusy(true);
    setApkError("");
    setApk(null);
    setApkName(name);
    try {
      setApk(await analyzeApkBytes(await load()));
    } catch (e) {
      setApkError((e as Error).message);
    } finally {
      setApkBusy(false);
    }
  };

  const found = matches?.filter((m) => m.events.length > 0) ?? [];

  return (
    <div className="w-full">
      <div className="mb-6">
        <PageTitle
          eyebrow="Triase"
          title="Triase Indikator"
          text="Pemeriksaan cepat di perangkat ini, tanpa DNS atau request ke alamat yang diperiksa. Layanan luar hanya dihubungi bila Anda menekan tombolnya."
        />
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {(
          [
            ["url", "Analisis URL", Globe2],
            ["pesan", "Pesan Mencurigakan", MessageSquareWarning],
            ["ioc", "Pencocokan IOC", ListChecks],
            ["apk", "Pemeriksa APK", Smartphone],
          ] as const
        ).map(([k, label, Icon]) => (
          <button
            key={k}
            onClick={() => setTab(k)}
            className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold ${tab === k ? "border-[#38BDF8] bg-[#38BDF8]/10 text-[#7DD3FC]" : "border-[#272E3A] text-[#8D97A6] hover:text-white"}`}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      {tab === "url" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,.9fr)]">
          <Card
            title="Inspeksi URL"
            icon={<Globe2 size={16} className="text-[#38BDF8]" />}
          >
            <Label>URL untuk diperiksa</Label>
            <textarea
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="min-h-24 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 font-mono text-xs outline-none focus:border-[#38BDF8]/50"
            />
            <button
              onClick={() => setReport(analyzeUrl(urlInput))}
              className="mt-3 w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018]"
            >
              Analisis secara lokal
            </button>
            <div className="mt-3 flex items-center gap-2 text-[10px] text-[#657080]">
              <ShieldCheck size={13} />
              URL tidak diakses; hanya strukturnya yang diperiksa.
            </div>
          </Card>
          <Card
            title="Hasil Indikatif"
            icon={<Search size={16} className="text-[#F59E0B]" />}
          >
            {!report ? (
              <div className="grid h-64 place-items-center text-center text-xs text-[#657080]">
                <div>
                  <Braces className="mx-auto mb-3" />
                  Jalankan analisis untuk melihat sinyal.
                </div>
              </div>
            ) : !report.valid ? (
              <p className="rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 p-3 text-xs text-[#FCA5A5]">
                URL tidak valid. Masukkan tautan HTTP/HTTPS.
              </p>
            ) : (
              <>
                <div className="flex items-center justify-between rounded-lg bg-[#0D1016] p-3">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-xs">
                      {report.host}
                    </div>
                    <div className="mt-1 text-[10px] text-[#657080]">
                      {report.signals.length} sinyal · skor heuristik
                    </div>
                  </div>
                  <div
                    className="font-mono text-2xl"
                    style={{ color: scoreColor(report.score) }}
                  >
                    {scorePercent(report.score)}%
                  </div>
                </div>
                <div className="mt-3 space-y-2">
                  {report.signals.length === 0 ? (
                    <p className="rounded-lg border border-[#22C55E]/25 bg-[#22C55E]/5 p-3 text-xs text-[#86EFAC]">
                      Tidak ada sinyal struktural yang menonjol. Tetap
                      verifikasi lewat jalur resmi.
                    </p>
                  ) : (
                    report.signals.map((s) => (
                      <div
                        key={s.id}
                        className="flex items-start gap-2 rounded-lg border border-[#272E3A] p-3 text-xs text-[#AEB6C1]"
                      >
                        <TriangleAlert
                          size={14}
                          className="mt-0.5 shrink-0 text-[#F59E0B]"
                        />
                        <span className="min-w-0 flex-1">{s.label}</span>
                        <Badge className={levelStyle[s.level]}>
                          {LEVEL_LABEL[s.level]}
                        </Badge>
                      </div>
                    ))
                  )}
                </div>
                {report.host && (
                  <button
                    onClick={() => sendToIoc(report.host!)}
                    className="mt-4 w-full rounded-lg border border-[#272E3A] bg-[#191F2A] py-2 text-xs font-semibold hover:border-[#38BDF8]/40"
                  >
                    Cek host ini di log →
                  </button>
                )}
                <p className="mt-3 text-[11px] leading-5 text-[#D4A64B]">
                  Hasil adalah indikasi berbasis struktur, bukan kepastian.
                  Verifikasi tetap diperlukan.
                </p>
                {report.host && (
                  <ReputationPanel
                    key={`${report.input}`}
                    url={report.input}
                    host={report.host}
                    ownDomains={ownDomains}
                    actor={actor}
                    notify={notify}
                    openSettings={openSettings}
                  />
                )}
              </>
            )}
          </Card>
        </div>
      )}

      {tab === "pesan" && <MessageTab checkLink={inspectUrl} />}

      {tab === "ioc" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1.2fr]">
          <Card
            title="Daftar Indikator"
            icon={<ListChecks size={16} className="text-[#38BDF8]" />}
          >
            <Label>IP, domain, atau hash SHA-256 (satu per baris)</Label>
            <textarea
              value={iocText}
              onChange={(e) => setIocText(e.target.value)}
              placeholder={
                "203.0.113.66\ncdn-tukin.example\nhxxp://contoh[.]top"
              }
              className="min-h-40 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 font-mono text-xs outline-none focus:border-[#38BDF8]/50"
            />
            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
              <button
                onClick={loadFromIncidents}
                disabled={data.incidents.length === 0}
                className="rounded-lg border border-[#272E3A] bg-[#191F2A] py-2 text-xs font-semibold hover:border-[#38BDF8]/40 disabled:opacity-40"
              >
                Muat dari insiden
              </button>
              <button
                onClick={() => void runMatch()}
                disabled={matching}
                className="rounded-lg bg-[#38BDF8] py-2 text-xs font-bold text-[#071018] disabled:opacity-60"
              >
                {matching ? "Mencocokkan…" : "Cocokkan dengan log"}
              </button>
            </div>
            <div className="mt-3 flex items-center gap-2 text-[10px] text-[#657080]">
              <ShieldCheck size={13} />
              Mendukung format "defang" (hxxp, [.]). Pencocokan lokal atas{" "}
              {fmtNumber(data.eventCount)} event.
            </div>
          </Card>
          <Card
            title="Hasil Pencocokan"
            icon={<Search size={16} className="text-[#F59E0B]" />}
          >
            {matches === null ? (
              <div className="grid h-64 place-items-center text-center text-xs text-[#657080]">
                <div>
                  <ListChecks className="mx-auto mb-3" />
                  Tempel indikator lalu cocokkan dengan log.
                </div>
              </div>
            ) : matches.length === 0 ? (
              <p className="rounded-lg border border-[#272E3A] p-3 text-xs text-[#8D97A6]">
                Tidak ada indikator yang terbaca dari teks.
              </p>
            ) : (
              <>
                <div
                  className={`mb-3 rounded-lg border p-3 text-xs ${found.length ? "border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]" : "border-[#22C55E]/25 bg-[#22C55E]/5 text-[#86EFAC]"}`}
                >
                  {found.length ? (
                    <>
                      <TriangleAlert size={13} className="mr-1 inline" />
                      {found.length} dari {matches.length} indikator ditemukan
                      di log satuan.
                    </>
                  ) : (
                    <>
                      <CircleCheck size={13} className="mr-1 inline" />
                      Tidak ada dari {matches.length} indikator yang muncul di
                      log.
                    </>
                  )}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[480px] text-left text-xs">
                    <thead className="text-[9px] uppercase tracking-wider text-[#657080]">
                      <tr className="border-b border-[#272E3A]">
                        {["Indikator", "Jenis", "Status", "Terlihat"].map(
                          (h) => (
                            <th key={h} className="pb-2 pr-3">
                              {h}
                            </th>
                          ),
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {[...matches]
                        .sort((a, b) => b.events.length - a.events.length)
                        .map((m) => {
                          const e = m.events[0];
                          return (
                            <tr
                              key={`${m.kind}:${m.value}`}
                              className="border-b border-[#1D232D] last:border-0 align-top"
                            >
                              <td className="max-w-[220px] break-all py-2 pr-3 font-mono text-[11px]">
                                {m.value}
                              </td>
                              <td className="py-2 pr-3 text-[#8D97A6]">
                                {KIND_LABEL[m.kind]}
                              </td>
                              <td className="py-2 pr-3">
                                {m.events.length ? (
                                  <Badge className="border-[#EF4444]/25 bg-[#EF4444]/10 text-[#FCA5A5]">
                                    {m.events.length} event
                                  </Badge>
                                ) : (
                                  <span className="text-[#657080]">—</span>
                                )}
                              </td>
                              <td className="py-2 font-mono text-[10px] text-[#8D97A6]">
                                {e
                                  ? `${e.host ?? e.srcIp ?? "?"} · ${fmtTime(e.ts, false)} ${fmtDate(e.ts)}`
                                  : "Tidak ditemukan"}
                              </td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Card>
        </div>
      )}

      {tab === "apk" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1.2fr]">
          <Card
            title="Berkas APK"
            icon={<Smartphone size={16} className="text-[#38BDF8]" />}
          >
            <p className="mb-3 text-xs leading-5 text-[#8D97A6]">
              Membaca izin dan paket aplikasi Android dari AndroidManifest.xml
              tanpa memasang atau menjalankannya.
            </p>
            <label className="block cursor-pointer rounded-lg bg-[#38BDF8] py-2.5 text-center text-xs font-bold text-[#071018]">
              Pilih berkas APK
              <input
                type="file"
                accept=".apk,application/vnd.android.package-archive"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f)
                    void runApk(
                      f.name,
                      async () => new Uint8Array(await f.arrayBuffer()),
                    );
                }}
              />
            </label>
            <button
              onClick={() =>
                void runApk("contoh-InfoTukin.apk", buildSampleApkBytes)
              }
              className="mt-2 w-full rounded-lg border border-[#272E3A] bg-[#191F2A] py-2 text-xs font-semibold hover:border-[#38BDF8]/40"
            >
              Analisis APK contoh (jinak)
            </button>
            {apkName && (
              <div className="mt-3 truncate font-mono text-[11px] text-[#7DD3FC]">
                {apkName}
              </div>
            )}
            <div className="mt-3 flex items-center gap-2 text-[10px] text-[#657080]">
              <ShieldCheck size={13} />
              APK diurai di browser ini; tidak dijalankan, tidak diunggah.
            </div>
          </Card>
          <Card
            title="Hasil Pemeriksaan"
            icon={<Search size={16} className="text-[#F59E0B]" />}
          >
            {apkBusy ? (
              <div className="grid h-64 place-items-center text-xs text-[#657080]">
                Menguraikan APK…
              </div>
            ) : apkError ? (
              <p className="rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 p-3 text-xs text-[#FCA5A5]">
                {apkError}
              </p>
            ) : !apk ? (
              <div className="grid h-64 place-items-center text-center text-xs text-[#657080]">
                <div>
                  <Smartphone className="mx-auto mb-3" />
                  Pilih berkas APK atau coba APK contoh.
                </div>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between rounded-lg bg-[#0D1016] p-3">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold">
                      {apk.label ?? apk.package ?? "Aplikasi"}
                    </div>
                    <div className="truncate font-mono text-[10px] text-[#657080]">
                      {apk.package ?? "—"}
                      {apk.versionName ? ` · v${apk.versionName}` : ""} ·{" "}
                      {formatBytes(apk.size)}
                    </div>
                  </div>
                  <div
                    className="font-mono text-2xl"
                    style={{ color: scoreColor(apk.score) }}
                  >
                    {scorePercent(apk.score)}%
                  </div>
                </div>
                <div className="mt-2 break-all font-mono text-[10px] text-[#657080]">
                  SHA-256: {apk.sha256}
                </div>
                {apk.signals.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {apk.signals.map((s) => (
                      <div
                        key={s.id}
                        className="flex items-start gap-2 rounded-lg border border-[#EF4444]/20 bg-[#EF4444]/5 p-3 text-xs text-[#FCA5A5]"
                      >
                        <TriangleAlert size={14} className="mt-0.5 shrink-0" />
                        <span className="min-w-0 flex-1 text-[#D4B4B4]">
                          {s.label}
                        </span>
                        <Badge className={levelStyle[s.level]}>
                          {LEVEL_LABEL[s.level]}
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}
                <div className="mt-4">
                  <Label>
                    Izin berisiko ({apk.permissions.length} dari{" "}
                    {apk.permissionCount})
                  </Label>
                  {apk.permissions.length === 0 ? (
                    <p className="text-xs text-[#86EFAC]">
                      Tidak ada izin berisiko yang menonjol.
                    </p>
                  ) : (
                    <div className="mt-1 space-y-1">
                      {apk.permissions.map((p) => (
                        <div
                          key={p.name}
                          className="flex items-center justify-between gap-2 rounded border border-[#272E3A] bg-[#0D1016] px-2.5 py-1.5 text-[11px]"
                        >
                          <span className="min-w-0">
                            <span className="text-[#C3CAD3]">{p.label}</span>
                            <span className="block truncate font-mono text-[9px] text-[#657080]">
                              {p.name}
                            </span>
                          </span>
                          <Badge className={levelStyle[p.level]}>
                            {LEVEL_LABEL[p.level]}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                {apk.indicators.length > 0 && (
                  <div className="mt-4">
                    <Label>Alamat tertanam</Label>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {apk.indicators.map((v) => (
                        <span
                          key={v}
                          className="rounded border border-[#272E3A] bg-[#0D1016] px-2 py-1 font-mono text-[10px] text-[#AEB6C1]"
                        >
                          {v}
                        </span>
                      ))}
                    </div>
                    <button
                      onClick={() => sendToIoc(apk.indicators.join("\n"))}
                      className="mt-2 w-full rounded-lg border border-[#272E3A] bg-[#191F2A] py-2 text-xs font-semibold hover:border-[#38BDF8]/40"
                    >
                      Cek alamat ini di log →
                    </button>
                  </div>
                )}
                <p className="mt-3 text-[11px] leading-5 text-[#D4A64B]">
                  Penilaian berdasarkan izin dan string, tanpa menjalankan
                  aplikasi. Skor rendah bukan berarti aman, dan aplikasi sah pun
                  dapat meminta izin ini. Jangan pasang aplikasi dari luar
                  sumber resmi; verifikasi sebelum menyimpulkan.
                </p>
              </>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
