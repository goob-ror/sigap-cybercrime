import { useMemo, useState } from "react";
import {
  Activity,
  ClipboardCopy,
  Factory,
  Gauge,
  ListChecks,
  Network,
  Timer,
  TriangleAlert,
  Upload,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { PageTitle } from "@/components/ui/PageTitle";
import {
  otActions,
  segmentationRules,
  type OtAnalysis,
  type OtEffect,
  type TalkerStatus,
} from "@/core/ot/analysis";
import { AttackReplay } from "@/features/ot/AttackReplay";
import { ProcessChart, RunStrip } from "@/features/ot/ProcessChart";
import { fmtNumber, fmtSpan, fmtTime } from "@/lib/format";

type Props = {
  ot: OtAnalysis | null;
  openImport: () => void;
  openDetail: (detectionId: string) => void;
  notify: (message: string) => void;
};

const EFFECT: Record<OtEffect, { label: string; style: string }> = {
  berlaku: {
    label: "Terlihat berlaku",
    style: "border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]",
  },
  "tidak-terlihat": {
    label: "Nilai tidak berubah",
    style: "border-[#2A3244] bg-[#141B27] text-[#AEB6C1]",
  },
  "belum-diketahui": {
    label: "Tidak terbaca ulang",
    style: "border-[#2A3244] bg-[#141B27] text-[#8D97A6]",
  },
  ditolak: {
    label: "Ditolak perangkat",
    style: "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]",
  },
};
const TALKER: Record<TalkerStatus, { label: string; style: string }> = {
  berwenang: {
    label: "Berwenang",
    style: "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]",
  },
  "pola-utama": {
    label: "Pola utama",
    style: "border-[#38BDF8]/30 bg-[#38BDF8]/10 text-[#7DD3FC]",
  },
  "tidak-berwenang": {
    label: "Tidak berwenang",
    style: "border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]",
  },
  menyimpang: {
    label: "Menyimpang",
    style: "border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]",
  },
};

function Tile({
  label,
  value,
  sub,
  icon: Icon,
  testId,
}: {
  label: string;
  value: string;
  sub: string;
  icon: typeof Timer;
  testId: string;
}) {
  return (
    <div className="group relative overflow-hidden rounded-xl border border-[#1E2736] bg-linear-to-b from-[#141B27] to-[#0F1520] p-5 transition-colors hover:border-[#2A3650]">
      <div className="flex items-start justify-between">
        <span className="text-[11px] font-medium uppercase tracking-widest text-[#5E6E85]">
          {label}
        </span>
        <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-[#1E2736] bg-[#0A0F18] text-[#4A5668] transition-colors group-hover:border-[#2A3650] group-hover:text-[#7DD3FC]">
          <Icon size={15} />
        </span>
      </div>
      <div
        data-testid={testId}
        className="mt-4 font-mono text-[28px] font-bold leading-none tracking-tight text-white"
      >
        {value}
      </div>
      <div className="mt-2.5 text-[11px] leading-[1.55] text-[#4A5668]">
        {sub}
      </div>
    </div>
  );
}

function Rules({
  ot,
  notify,
}: {
  ot: OtAnalysis;
  notify: (m: string) => void;
}) {
  const [kind, setKind] = useState<"mikrotik" | "iptables">("mikrotik");
  const rules = useMemo(() => segmentationRules(ot), [ot]);
  if (!rules)
    return (
      <p className="mt-3 text-[11px] leading-5 text-[#5E6E85]">
        Aturan firewall tidak disusun, karena belum ada host berwenang yang
        dikenal. Isi host HMI di Pengaturan.
      </p>
    );
  const text = rules[kind].join("\n");
  return (
    <div className="mt-5">
      <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] font-semibold text-[#AEB6C1]">
          Aturan firewall — hanya HMI yang boleh ke port Modbus
        </span>
        <div className="flex items-center gap-1.5">
          {(["mikrotik", "iptables"] as const).map((k) => (
            <button
              key={k}
              aria-pressed={kind === k}
              onClick={() => setKind(k)}
              className={`rounded-md border px-2.5 py-1 text-[10px] font-semibold transition-colors ${
                kind === k
                  ? "border-[#38BDF8]/50 bg-[#38BDF8]/10 text-[#7DD3FC]"
                  : "border-[#1E2736] text-[#5E6E85] hover:border-[#2A3650] hover:text-[#AEB6C1]"
              }`}
            >
              {k === "mikrotik" ? "MikroTik" : "iptables"}
            </button>
          ))}
          <button
            onClick={() => {
              navigator.clipboard.writeText(text).then(
                () => notify("Aturan disalin. Periksa sebelum diterapkan."),
                () => notify("Gagal menyalin"),
              );
            }}
            className="flex items-center gap-1.5 rounded-md border border-[#1E2736] px-2.5 py-1 text-[10px] font-semibold text-[#5E6E85] transition-colors hover:border-[#2A3650] hover:text-[#AEB6C1]"
          >
            <ClipboardCopy size={11} />
            Salin
          </button>
        </div>
      </div>
      <pre
        data-testid="firewall-rules"
        className="overflow-x-auto rounded-lg border border-[#1E2736] bg-[#080C14] p-4 font-mono text-[11px] leading-5 text-[#8FA3BC]"
      >
        {text}
      </pre>
      <p className="mt-2 text-[10px] leading-[1.6] text-[#3D4F63]">
        Letakkan di atas aturan yang mengizinkan lalu lintas umum, dan periksa
        dulu dengan admin jaringan: aturan yang salah dapat memutus kendali
        genset. Hanya alamat IPv4 yang valid yang dipakai.
      </p>
    </div>
  );
}

/** Where the attack crossed from IT into OT, and what it did to the equipment. */
export function OtView({ ot, openImport, openDetail, notify }: Props) {
  if (!ot) {
    return (
      <div className="mx-auto grid min-h-[60vh] max-w-lg place-items-center text-center">
        <div className="flex flex-col items-center">
          <div className="mb-5 grid size-16 place-items-center rounded-2xl border border-[#1E2736] bg-linear-to-b from-[#141B27] to-[#0F1520] text-[#38BDF8]">
            <Factory size={26} />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-white">
            Belum ada data OT
          </h1>
          <p className="mt-3 max-w-sm text-sm leading-6 text-[#5E6E85]">
            Halaman ini membaca lalu lintas Modbus/TCP dari sensor Zeek pada
            port mirror, atau log firewall ke port 502. Dengan plugin
            ICSNPP-Modbus, SIGAP juga dapat menyusun apa yang terjadi pada
            peralatan.
          </p>
          <button
            onClick={openImport}
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-[#38BDF8] px-5 py-2.5 text-[13px] font-bold text-[#071018] transition-opacity hover:opacity-90"
          >
            <Upload size={15} />
            Buka Impor Data
          </button>
        </div>
      </div>
    );
  }

  const domain: [number, number] = [ot.span.from, ot.span.to];
  const setpoint = ot.series.find(
    (s) => s.episodes.length && s.kind !== "terukur",
  );
  const stopped = ot.runs.find((r) => r.stops);
  const intruders = ot.writes.filter((w) => !w.trusted);
  const intruderNames = [...new Set(intruders.map((w) => w.srcName))];
  const applied = intruders.filter((w) => w.effect === "berlaku").length;
  const actions = otActions(ot);
  const unit = (u?: string) => (u ? ` ${u}` : "");

  return (
    <div className="w-full space-y-5">
      <PageTitle
        eyebrow="Lintas IT-OT"
        title="Dari Jaringan ke Proses Fisik"
        text="Menerjemahkan perintah Modbus di log menjadi apa yang terjadi pada peralatan: siapa memberi perintah, apakah perintahnya berlaku, berapa lama nilainya di luar batas, dan titik mana yang bisa memutus serangan."
      />

      {/* Alert banners */}
      {!ot.hasValues && (
        <div className="flex gap-3 rounded-xl border border-[#F59E0B]/20 bg-[#F59E0B]/5 px-4 py-3.5 text-[12px] leading-5 text-[#FCD34D]">
          <TriangleAlert size={15} className="mt-0.5 shrink-0 text-[#F59E0B]" />
          <span>
            Log ini tidak memuat alamat dan nilai Modbus, jadi hanya siapa yang
            berbicara dengan perangkat OT yang dapat dilihat. Untuk menyusun apa
            yang terjadi pada peralatan, pasang plugin ICSNPP-Modbus pada Zeek
            dan impor{" "}
            <code className="rounded bg-[#F59E0B]/15 px-1 font-mono text-[11px]">
              modbus_detailed.log
            </code>
            .
          </span>
        </div>
      )}
      {ot.learnedTalkers && (
        <div className="flex gap-3 rounded-xl border border-[#F59E0B]/20 bg-[#F59E0B]/5 px-4 py-3.5 text-[12px] leading-5 text-[#FCD34D]">
          <TriangleAlert size={15} className="mt-0.5 shrink-0 text-[#F59E0B]" />
          <span>
            Profil satuan belum menyebut HMI, jadi yang dianggap normal
            dipelajari dari pola lalu lintas: host yang mengirim sebagian besar
            transaksi. Bila penyerang sudah lama ada di jaringan, pola ini bisa
            keliru. Isi host HMI di Pengaturan.
          </span>
        </div>
      )}

      {/* KPI tiles */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Tile
          testId="ot-window"
          icon={Timer}
          label="Jendela respons"
          value={ot.windowMs !== undefined ? fmtSpan(ot.windowMs) : "—"}
          sub={
            ot.windowMs !== undefined
              ? `Temuan pertama ${fmtTime(ot.firstFinding!, false)} → OT tersentuh ${fmtTime(ot.firstContact!, false)} WIB`
              : "Tidak ada host tak dikenal yang menyentuh OT"
          }
        />
        <Tile
          testId="ot-writes"
          icon={Zap}
          label="Perintah tak berwenang"
          value={fmtNumber(intruders.length)}
          sub={
            intruders.length
              ? `${applied} terlihat berlaku · dari ${intruderNames.join(", ")}`
              : `${fmtNumber(ot.transactions)} transaksi Modbus diperiksa`
          }
        />
        <Tile
          testId="ot-outside"
          icon={Gauge}
          label="Di luar batas aman"
          value={setpoint ? fmtSpan(setpoint.outOfBandMs) : "—"}
          sub={
            setpoint
              ? `${setpoint.label}, mencapai ${setpoint.episodes[0].peak}${unit(setpoint.unit)}${setpoint.band?.source === "dipelajari" ? " · batas dipelajari dari log" : ""}`
              : "Tidak terlihat di log ini"
          }
        />
        <Tile
          testId="ot-stopped"
          icon={Activity}
          label="Peralatan berhenti"
          value={stopped ? fmtSpan(stopped.stoppedMs) : "—"}
          sub={
            stopped
              ? `${stopped.deviceName}, ${stopped.stops} kali`
              : ot.runs.length
                ? "Tidak berhenti selama periode log"
                : "Register status belum diisi di Pengaturan"
          }
        />
      </div>

      <AttackReplay a={ot} openDetail={openDetail} />

      {/* Process reconstruction */}
      {ot.series.length > 0 && (
        <Card
          title="Rekonstruksi Proses"
          icon={<Gauge size={16} className="text-[#38BDF8]" />}
        >
          <div className="space-y-6">
            {ot.series.map((s) => (
              <section key={`${s.device}#${s.address}`}>
                <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3">
                  <span className="text-[13px] font-semibold text-[#D4DCE8]">
                    {s.label}
                    {s.unit ? ` (${s.unit})` : ""}
                    <span className="ml-2 font-mono text-[10px] font-normal text-[#3D4F63]">
                      {s.deviceName} · register {s.address}
                    </span>
                  </span>
                  {s.band && (
                    <span className="text-[11px] text-[#5E6E85]">
                      Batas {s.band.min}–{s.band.max}
                      {unit(s.unit)} ·{" "}
                      {s.band.source === "profil"
                        ? "dari profil satuan"
                        : "dipelajari dari log sebelum gangguan"}
                    </span>
                  )}
                </div>
                <ProcessChart series={s} writes={ot.writes} domain={domain} />
              </section>
            ))}
            {ot.runs.map((r) => (
              <section key={r.device}>
                <div className="mb-2 text-[13px] font-semibold text-[#D4DCE8]">
                  Status {r.deviceName}
                </div>
                <RunStrip run={r} domain={domain} />
              </section>
            ))}
            {/* Legend */}
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-[#1E2736] pt-3.5 text-[11px] text-[#4A5668]">
              <span className="flex items-center gap-1.5">
                <i className="inline-block h-0.5 w-4 rounded bg-[#38BDF8]" />
                Nilai yang dilaporkan pengendali
              </span>
              <span className="flex items-center gap-1.5">
                <i className="inline-block size-2 rotate-45 bg-[#EF4444]" />
                Perintah tak berwenang
              </span>
              <span className="flex items-center gap-1.5">
                <i className="inline-block size-2 rounded-full bg-[#22C55E]" />
                Perintah berwenang
              </span>
              <span className="flex items-center gap-1.5">
                <i className="inline-block size-2 rounded-sm bg-[#22C55E]/25" />
                Batas aman
              </span>
              <span className="flex items-center gap-1.5">
                <i className="inline-block size-2 rounded-sm bg-[#EF4444]/25" />
                Di luar batas
              </span>
            </div>
          </div>
        </Card>
      )}

      {/* Bottom two-column section */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Action steps */}
        <Card
          title="Langkah Aman untuk OT"
          icon={<ListChecks size={16} className="text-[#22C55E]" />}
        >
          {actions.length === 0 ? (
            <p className="text-[12px] leading-5 text-[#5E6E85]">
              Tidak terlihat perintah tak berwenang pada log ini. Ini bukan
              berarti OT aman: lihat siapa saja yang berbicara dengan perangkat
              di bawah.
            </p>
          ) : (
            <ol data-testid="ot-actions" className="space-y-2.5">
              {actions.map((a, i) => (
                <li
                  key={a.title}
                  className="flex gap-3.5 rounded-xl border border-[#1E2736] bg-[#080C14] p-3.5"
                >
                  <span className="mt-0.5 shrink-0 font-mono text-[13px] font-bold text-[#38BDF8]">
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[12px] font-semibold leading-5 text-[#D4DCE8]">
                      {a.title}
                    </div>
                    <p className="mt-0.5 text-[11px] leading-[1.55] text-[#5E6E85]">
                      {a.detail}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
          <p className="mt-3.5 rounded-lg border border-[#D4A64B]/20 bg-[#D4A64B]/5 px-3 py-2 text-[11px] leading-[1.55] text-[#D4A64B]">
            Tindakan pada sistem operasional wajib seizin komandan dan dicatat.
          </p>
          <Rules ot={ot} notify={notify} />
        </Card>

        {/* Right column */}
        <div className="space-y-5">
          {/* Talkers table */}
          <Card
            title="Siapa Berbicara dengan Perangkat OT"
            icon={<Network size={16} className="text-[#38BDF8]" />}
          >
            <div className="overflow-x-auto">
              <table
                data-testid="ot-talkers"
                className="w-full min-w-120 text-left text-xs"
              >
                <thead>
                  <tr className="border-b border-[#1E2736]">
                    {[
                      "Sumber",
                      "Tujuan",
                      "Baca",
                      "Tulis",
                      "Sejak",
                      "Status",
                    ].map((h) => (
                      <th
                        key={h}
                        className="pb-2.5 pr-3 text-[10px] font-semibold uppercase tracking-widest text-[#3D4F63]"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ot.talkers.map((t) => (
                    <tr
                      key={`${t.src}>${t.dst}`}
                      className="border-b border-[#111827] last:border-0 hover:bg-[#0A0F18]/60"
                    >
                      <td className="py-2.5 pr-3 font-mono text-[11px] text-[#D4DCE8]">
                        {t.srcName}
                        {!t.inOtSegment && (
                          <span className="mt-0.5 block text-[9px] font-medium text-[#D4A64B]">
                            di luar segmen OT
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-[11px] text-[#8FA3BC]">
                        {t.dstName}
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-[11px] tabular-nums">
                        {fmtNumber(t.reads)}
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-[11px] tabular-nums">
                        {fmtNumber(t.writes)}
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-[10px] text-[#3D4F63]">
                        {fmtTime(t.firstSeen, false)}
                      </td>
                      <td className="py-2.5">
                        <Badge className={TALKER[t.status].style}>
                          {TALKER[t.status].label}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* Write commands table */}
          {ot.writes.length > 0 && (
            <Card
              title={`Perintah Tulis (${ot.writes.length})`}
              icon={<Zap size={16} className="text-[#F59E0B]" />}
            >
              <div className="max-h-72 overflow-auto">
                <table
                  data-testid="ot-writes-table"
                  className="w-full min-w-115 text-left text-xs"
                >
                  <thead className="sticky top-0 bg-[#0F1520]">
                    <tr className="border-b border-[#1E2736]">
                      {[
                        "Waktu",
                        "Oleh",
                        "Titik",
                        "Nilai",
                        "Pembacaan berikutnya",
                      ].map((h) => (
                        <th
                          key={h}
                          className="pb-2.5 pr-3 text-[10px] font-semibold uppercase tracking-widest text-[#3D4F63]"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {ot.writes.map((w) => (
                      <tr
                        key={`${w.eventId}#${w.address}`}
                        className="border-b border-[#111827] last:border-0 hover:bg-[#0A0F18]/60"
                      >
                        <td className="py-2.5 pr-3 font-mono text-[10px] text-[#3D4F63]">
                          {fmtTime(w.ts, false)}
                        </td>
                        <td className="py-2.5 pr-3 font-mono text-[11px] text-[#D4DCE8]">
                          {w.srcName}
                          {!w.trusted && (
                            <span className="mt-0.5 block text-[9px] font-medium text-[#FCA5A5]">
                              tidak berwenang
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 pr-3 text-[11px] text-[#8FA3BC]">
                          {w.kind === "coil" ? "Coil" : "Register"} {w.address}
                        </td>
                        <td className="py-2.5 pr-3 font-mono text-[11px] tabular-nums">
                          {w.value}
                          {w.outOfBand && (
                            <span className="mt-0.5 block text-[9px] font-medium text-[#FCA5A5]">
                              di luar batas
                            </span>
                          )}
                        </td>
                        <td className="py-2.5">
                          <Badge
                            className={
                              w.trusted && w.effect === "berlaku"
                                ? "border-[#1E2736] bg-[#141B27] text-[#AEB6C1]"
                                : EFFECT[w.effect].style
                            }
                          >
                            {EFFECT[w.effect].label}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* Footer disclaimer */}
      <div className="rounded-xl border border-[#1E2736] bg-[#0A0F18] px-4 py-3 text-[11px] leading-[1.6] text-[#3D4F63]">
        Nilai di halaman ini berasal dari lalu lintas Modbus/TCP yang terekam
        sensor, bukan pengukuran langsung pada peralatan, dan perubahan dari
        panel tidak meninggalkan perintah di jaringan. Selalu periksa kondisi
        fisiknya. Protokol OT lain (S7, DNP3, IEC 104) belum terbaca.
      </div>
    </div>
  );
}
