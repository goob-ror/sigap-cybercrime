import { lazy, Suspense, useEffect, useRef, useState } from "react";
import {
  Activity,
  BookOpenCheck,
  BookText,
  ChevronRight,
  CircleCheck,
  ClipboardList,
  Clock3,
  Factory,
  FileSearch,
  FileText,
  Flag,
  GitBranch,
  GraduationCap,
  LayoutDashboard,
  Menu,
  MonitorDown,
  ScanSearch,
  Settings,
  ShieldAlert,
  Trash2,
  TriangleAlert,
  Upload,
  UserRound,
  X,
} from "lucide-react";
import {
  ClearDataDialog,
  ConfirmDialog,
  OperatorDialog,
} from "@/components/Dialogs";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { LoadingState } from "@/components/LoadingState";
import { Badge } from "@/components/ui/Badge";
import type { Detection, FollowUpStatus } from "@/core/model";
import { sha256Hex } from "@/core/evidence/hash";
import {
  blocklistFiles,
  type BlocklistMeta,
  type Ioc,
} from "@/core/report/ioc";
import { CASE_STATUS_LABEL, caseStatusStyle } from "@/lib/styles";
import { fmtNumber } from "@/lib/format";
import { useInstallApp } from "@/lib/installApp";
import { RULE_PACK } from "@/data/rules/catalog";
import { setFollowUp } from "@/db/cases";
import { orderedCases, useInvestigation } from "@/db/hooks";
import { useIngest } from "@/db/ingestClient";
import { useOnline } from "@/db/online";
import { saveImportTz, saveOperator, useSettings } from "@/db/settings";
// Pages are code-split: each loads on demand, keeping the heavy ones (dagre graph, triage, report)
// out of the initial bundle.
const AttackView = lazy(() =>
  import("@/features/attack/AttackView").then((m) => ({
    default: m.AttackView,
  })),
);
const CaseView = lazy(() =>
  import("@/features/case/CaseView").then((m) => ({ default: m.CaseView })),
);
const DetailView = lazy(() =>
  import("@/features/detail/DetailView").then((m) => ({
    default: m.DetailView,
  })),
);
const GraphView = lazy(() =>
  import("@/features/graph/GraphView").then((m) => ({ default: m.GraphView })),
);
const ImportView = lazy(() =>
  import("@/features/import/ImportView").then((m) => ({
    default: m.ImportView,
  })),
);
const PlaybookView = lazy(() =>
  import("@/features/playbook/PlaybookView").then((m) => ({
    default: m.PlaybookView,
  })),
);
const LogExplorer = lazy(() =>
  import("@/features/logs/LogExplorer").then((m) => ({
    default: m.LogExplorer,
  })),
);
const ReportView = lazy(() =>
  import("@/features/report/ReportView").then((m) => ({
    default: m.ReportView,
  })),
);
const SummaryView = lazy(() =>
  import("@/features/summary/SummaryView").then((m) => ({
    default: m.SummaryView,
  })),
);
const TimelineView = lazy(() =>
  import("@/features/timeline/TimelineView").then((m) => ({
    default: m.TimelineView,
  })),
);
const TriageView = lazy(() =>
  import("@/features/triage/TriageView").then((m) => ({
    default: m.TriageView,
  })),
);
const SettingsView = lazy(() =>
  import("@/features/settings/SettingsView").then((m) => ({
    default: m.SettingsView,
  })),
);
const DrillView = lazy(() =>
  import("@/features/drill/DrillView").then((m) => ({ default: m.DrillView })),
);
const OtView = lazy(() =>
  import("@/features/ot/OtView").then((m) => ({ default: m.OtView })),
);
import { ENGINE_VERSION } from "@/workers/protocol";

type Page =
  | "Ringkasan"
  | "Impor Data"
  | "Timeline"
  | "Log Explorer"
  | "Detail"
  | "ATT&CK"
  | "Graf Investigasi"
  | "Lintas IT-OT"
  | "Kasus"
  | "Laporan"
  | "Playbook"
  | "Latihan"
  | "Triase"
  | "Pengaturan";

async function downloadSamples() {
  const [{ generateScenario }, { default: JSZip }] = await Promise.all([
    import("@/data/scenario/generate"),
    import("jszip"),
  ]);
  const zip = new JSZip();
  for (const file of generateScenario().files) zip.file(file.name, file.text);
  const url = URL.createObjectURL(
    await zip.generateAsync({ type: "blob", compression: "DEFLATE" }),
  );
  const a = Object.assign(document.createElement("a"), {
    href: url,
    download: "sigap-skenario-contoh.zip",
  });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

type PendingFollowUp = {
  caseId: string;
  detection: Detection;
  status: FollowUpStatus;
};

function App() {
  const data = useInvestigation();
  const settings = useSettings();
  const online = useOnline();
  const installer = useInstallApp();
  // The dialog below blocks the app until an operator is named, so nothing is recorded under ''.
  const actor = settings.operator ?? "";
  const [operatorOpen, setOperatorOpen] = useState(false);
  const ingest = useIngest();
  const [active, setActive] = useState<Page | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [caseId, setCaseId] = useState<string | null>(null);
  const [graphIncident, setGraphIncident] = useState<string | null>(null);
  const [logFocus, setLogFocus] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [toast, setToast] = useState("");
  const [now, setNow] = useState(new Date());
  const [confirm, setConfirm] = useState<PendingFollowUp | null>(null);
  const [clearOpen, setClearOpen] = useState(false);

  useEffect(() => {
    const clock = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(clock);
  }, []);

  // Results stored by an older version of SIGAP are recomputed from the stored events. Decided
  // once, on the first load, so an import in progress never triggers it.
  const startupChecked = useRef(false);
  useEffect(() => {
    if (!data.loaded || startupChecked.current) return;
    startupChecked.current = true;
    if (!data.eventCount || data.engine === ENGINE_VERSION) return;
    ingest.run({ type: "reanalyze" }).then(
      (s) =>
        notify(
          `Analisis diperbarui: ${fmtNumber(s.detections)} temuan · ${fmtNumber(s.incidents)} insiden`,
        ),
      (err: Error) => notify(`Gagal memperbarui analisis: ${err.message}`),
    );
  });

  // Until the user navigates, land on Ringkasan when there is data, else on Impor Data.
  const page: Page = active ?? (data.eventCount ? "Ringkasan" : "Impor Data");
  const go = (p: Page) => {
    setActive(p);
    setLogFocus(null);
    setMobileNav(false);
  };
  const notify = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 3200);
  };

  const openCases = data.cases.filter((c) => c.status !== "Resolved").length;

  // In its own window the title bar and the taskbar icon are all there is, so they say where things stand.
  useEffect(() => {
    document.title = `${page} · SIGAP`;
  }, [page]);
  useEffect(() => {
    navigator.setAppBadge?.(openCases).catch(() => {});
  }, [openCases]);

  const topCase = orderedCases(data)[0]?.c;
  const topDetection = data.incidents[0]
    ? data.detectionsById.get(data.incidents[0].detectionIds[0])
    : data.detections[0];
  const detailDetection =
    (selectedId ? data.detectionsById.get(selectedId) : undefined) ??
    topDetection;

  const runIngest = async (
    request: Parameters<typeof ingest.run>[0],
    after?: () => void,
  ) => {
    try {
      // Without this a browser short on disk space may delete the evidence to make room. Asked here because it now holds some.
      if (request.type === "import" || request.type === "scenario")
        void navigator.storage?.persist?.();
      const s = await ingest.run(request);
      if (request.type === "clear") notify("Seluruh data lokal telah dihapus");
      else if (request.type === "profile")
        notify(
          `Profil disimpan · ${fmtNumber(s.detections)} temuan · ${fmtNumber(s.incidents)} insiden`,
        );
      else if (request.type === "indicators")
        notify(
          `Daftar indikator diterapkan · ${fmtNumber(s.detections)} temuan · ${fmtNumber(s.incidents)} insiden`,
        );
      else
        notify(
          `${s.files.length} berkas · ${fmtNumber(s.events)} event · ${fmtNumber(s.detections)} temuan · ${fmtNumber(s.incidents)} insiden`,
        );
      after?.();
    } catch (err) {
      notify(`Gagal memproses: ${(err as Error).message}`);
    }
  };
  const clearAll = () => {
    setClearOpen(false);
    setSelectedId(null);
    setCaseId(null);
    setGraphIncident(null);
    void runIngest({ type: "clear" }, () => setActive("Impor Data"));
  };
  const applyFollowUp = () => {
    if (!confirm) return;
    void setFollowUp(
      confirm.caseId,
      confirm.detection.id,
      confirm.detection.title,
      confirm.status,
      actor,
    );
    notify(
      `Tindak lanjut "${confirm.detection.title}" menjadi ${confirm.status}`,
    );
    setConfirm(null);
  };
  const changeFollowUp = (
    id: string,
    detection: Detection,
    status: FollowUpStatus,
  ) => setConfirm({ caseId: id, detection, status });
  const openDetail = (id: string) => {
    setSelectedId(id);
    go("Detail");
  };
  const openCase = (id: string) => {
    setCaseId(id);
    go("Kasus");
  };
  const openGraph = (id: string) => {
    setGraphIncident(id);
    go("Graf Investigasi");
  };
  const openReport = (id: string) => {
    setCaseId(id);
    go("Laporan");
  };

  // Build and download an offline IOC blocklist package (txt + csv + DNS sinkhole + hashed manifest).
  const exportBlocklist = async (
    iocs: Ioc[],
    scope: string,
    zipName: string,
  ) => {
    if (!iocs.length) {
      notify("Tidak ada indikator eksternal untuk diekspor");
      return;
    }
    try {
      const { default: JSZip } = await import("jszip");
      const meta: BlocklistMeta = {
        unit: settings.profile.name,
        scope,
        generatedAt: Date.now(),
        actor,
        ownDomains: settings.profile.ownDomains,
      };
      const files = blocklistFiles(iocs, meta);
      const manifest = await Promise.all(
        files.map(async (f) => `${await sha256Hex(f.text)}  ${f.name}`),
      );
      files.push({
        name: "MANIFEST-SHA256.txt",
        text: `# SHA-256 berkas (verifikasi integritas)\n${manifest.join("\n")}\n`,
      });
      const zip = new JSZip();
      for (const f of files) zip.file(f.name, f.text);
      const url = URL.createObjectURL(
        await zip.generateAsync({ type: "blob", compression: "DEFLATE" }),
      );
      const a = Object.assign(document.createElement("a"), {
        href: url,
        download: `${zipName}.zip`,
      });
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      notify(`Daftar blokir diekspor: ${iocs.length} indikator`);
    } catch (err) {
      notify(`Gagal mengekspor daftar blokir: ${(err as Error).message}`);
    }
  };

  const nav = [
    ["Ringkasan", LayoutDashboard],
    ["Impor Data", Upload],
    ["Timeline", Activity],
    ["Log Explorer", FileSearch],
    ["Detail", FileText],
    ["ATT&CK", BookOpenCheck],
    ["Graf Investigasi", GitBranch],
    ["Lintas IT-OT", Factory],
    ["Kasus", ClipboardList],
    ["Laporan", Flag],
    ["Playbook", BookText],
    ["Latihan", GraduationCap],
    ["Triase", ScanSearch],
    ["Pengaturan", Settings],
  ] as const;

  return (
    <div className="min-h-screen bg-[#070A0F] text-[#E8EDF3]">
      {toast && (
        <div
          role="status"
          className="fixed right-5 top-5 z-50 flex max-w-md items-center gap-2.5 rounded-xl border border-[#22C55E]/30 bg-[#0C1A14] px-4 py-3 text-sm shadow-2xl shadow-black/40 ring-1 ring-inset ring-[#22C55E]/10"
        >
          <CircleCheck size={16} className="shrink-0 text-[#22C55E]" />
          {toast}
        </div>
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-[#161D28] bg-[#09101A] transition-transform lg:translate-x-0 ${mobileNav ? "translate-x-0" : "-translate-x-full"}`}
      >
        {/* Sidebar logo */}
        <div className="flex h-16 shrink-0 items-center justify-between border-b border-[#161D28] px-5">
          <div className="flex items-center gap-3">
            <div className="grid size-9 place-items-center rounded-xl bg-[#38BDF8] text-[#040D18] shadow-lg shadow-[#38BDF8]/20">
              <ShieldAlert size={18} />
            </div>
            <div>
              <div className="text-sm font-extrabold tracking-[0.18em] text-white">
                SIGAP
              </div>
              <div className="text-[9px] font-medium tracking-[0.1em] text-[#3D5068]">
                PENANGANAN AWAL INSIDEN
              </div>
            </div>
          </div>
          <button
            className="rounded-lg p-1 text-[#4A5E72] hover:bg-[#131F2E] hover:text-white lg:hidden"
            onClick={() => setMobileNav(false)}
            aria-label="Tutup navigasi"
          >
            <X size={16} />
          </button>
        </div>

        {/* Nav items */}
        <div className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
          <div className="mb-3 px-3 text-[9px] font-bold uppercase tracking-[0.2em] text-[#2E4058]">
            Ruang kerja
          </div>
          <nav className="space-y-0.5">
            {nav.map(([label, Icon]) => (
              <button
                key={label}
                onClick={() => go(label)}
                className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] transition-all ${
                  page === label
                    ? "bg-[#0E1E31] text-white shadow-[inset_3px_0_0_#38BDF8]"
                    : "text-[#7A8FA4] hover:bg-[#0C1726] hover:text-[#C8D4E0]"
                }`}
              >
                <Icon
                  size={15}
                  className={`shrink-0 transition-colors ${page === label ? "text-[#38BDF8]" : "text-[#3D5A72] group-hover:text-[#7FBFDF]"}`}
                />
                <span className="flex-1 text-left">{label}</span>
                {label === "Kasus" && openCases > 0 && (
                  <span className="ml-auto rounded-md bg-[#EF4444]/15 px-1.5 py-0.5 font-mono text-[10px] font-bold text-[#FCA5A5]">
                    {openCases}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        {/* Sidebar footer */}
        <div className="shrink-0 border-t border-[#161D28] p-4 space-y-2">
          {installer.canInstall && (
            <button
              onClick={() => void installer.install()}
              className="flex w-full items-center gap-2 rounded-lg border border-[#38BDF8]/25 bg-[#38BDF8]/8 px-3 py-2.5 text-left text-xs font-semibold text-[#7DD3FC] transition hover:border-[#38BDF8]/50 hover:bg-[#38BDF8]/12"
            >
              <MonitorDown size={14} className="shrink-0" />
              Pasang sebagai aplikasi
            </button>
          )}
          <button
            onClick={() => setOperatorOpen(true)}
            title="Ganti operator"
            className="flex w-full items-center gap-2.5 rounded-lg border border-[#161D28] bg-[#0C1726] px-3 py-2.5 text-left text-xs transition hover:border-[#38BDF8]/30"
          >
            <UserRound size={14} className="shrink-0 text-[#38BDF8]" />
            <span className="min-w-0 flex-1 truncate text-[#C0CAD4]">
              {settings.operator ?? "—"}
            </span>
            <span className="shrink-0 text-[10px] text-[#3D5068]">Ganti</span>
          </button>
          <div className="rounded-lg border border-[#161D28] bg-[#0C1726] p-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-semibold text-[#B0BAC6]">
                Data lokal
              </span>
              {online.active ? (
                <button
                  onClick={() => go("Pengaturan")}
                  title="Fitur online diizinkan."
                >
                  <Badge className="border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FCD34D]">
                    ONLINE DIIZINKAN
                  </Badge>
                </button>
              ) : (
                <Badge className="border-[#22C55E]/20 bg-[#22C55E]/8 text-[#86EFAC]">
                  OFFLINE
                </Badge>
              )}
            </div>
            <p className="text-[11px] leading-4 text-[#3D5068]">
              {fmtNumber(data.eventCount)} event ·{" "}
              {fmtNumber(data.detections.length)} temuan · {data.cases.length}{" "}
              kasus · {data.imports.length} berkas. Tersimpan hanya di browser
              ini.
            </p>
            <button
              disabled={ingest.busy || !data.eventCount}
              onClick={() => setClearOpen(true)}
              className="mt-2.5 flex items-center gap-1.5 text-[10px] text-[#4A5E72] transition hover:text-[#FCA5A5] disabled:opacity-40"
            >
              <Trash2 size={11} />
              Hapus data lokal
            </button>
          </div>
          <div className="flex items-center gap-2 px-1 text-[11px] text-[#3D5068]">
            <span className="size-1.5 rounded-full bg-[#22C55E] shadow-sm shadow-[#22C55E]/50" />
            {data.coverage?.rulesTotal ??
              RULE_PACK.sigma.length + RULE_PACK.native.length}{" "}
            aturan deteksi aktif
          </div>
        </div>
      </aside>

      {mobileNav && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileNav(false)}
        />
      )}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#161D28] bg-[#070A0F]/95 px-4 backdrop-blur-md md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <button
              onClick={() => setMobileNav(true)}
              className="rounded-lg p-1.5 text-[#4A5E72] hover:bg-[#0C1726] hover:text-white lg:hidden shrink-0"
              aria-label="Buka navigasi"
            >
              <Menu size={18} />
            </button>
            <div className="min-w-0">
              <div className="hidden items-center gap-1.5 text-[11px] text-[#3D5068] sm:flex">
                <span>Ruang kerja lokal</span>
                <ChevronRight size={11} className="text-[#2A3A4A]" />
                <span className="text-[#7A8FA4]">{page}</span>
              </div>
              <div className="mt-0.5 truncate text-sm font-semibold text-[#C8D4E0]">
                {data.detections.length
                  ? `${fmtNumber(data.incidents.length)} insiden · ${fmtNumber(data.detections.length)} temuan`
                  : data.eventCount
                    ? `${fmtNumber(data.eventCount)} event`
                    : "Belum ada data"}
              </div>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2 md:gap-3">
            <div className="hidden items-center gap-2 border-r border-[#161D28] pr-4 font-mono text-[11px] text-[#3D5068] md:flex">
              <Clock3 size={13} className="text-[#2A3A4A]" />
              {now.toLocaleTimeString("id-ID", {
                hour12: false,
                timeZone: "Asia/Jakarta",
              })}{" "}
              WIB
            </div>
            {settings.loaded && !settings.custom && (
              <button
                onClick={() => go("Pengaturan")}
                title="Masih memakai profil contoh fiktif. Klik untuk mengubah."
              >
                <Badge className="border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FCD34D]">
                  <TriangleAlert size={11} className="mr-1" />
                  <span className="hidden sm:inline">PROFIL CONTOH</span>
                  <span className="sm:hidden">CONTOH</span>
                </Badge>
              </button>
            )}
            {topCase && (
              <button
                onClick={() => openCase(topCase.id)}
                title="Buka kasus prioritas"
              >
                <Badge className={caseStatusStyle[topCase.status]}>
                  {topCase.status !== "Resolved" && (
                    <span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-current" />
                  )}
                  {topCase.id}
                  <span className="hidden sm:inline">
                    {" "}
                    · {CASE_STATUS_LABEL[topCase.status].toUpperCase()}
                  </span>
                </Badge>
              </button>
            )}
          </div>
        </header>

        <main className="p-5 md:p-7">
          {!window.isSecureContext && (
            <div
              role="alert"
              className="mb-5 flex gap-2.5 rounded-xl border border-[#EF4444]/25 bg-[#EF4444]/8 p-4 text-xs leading-5 text-[#FCA5A5]"
            >
              <TriangleAlert size={15} className="mt-0.5 shrink-0" />
              <span>
                SIGAP dibuka lewat HTTP biasa, sehingga impor log dan paket
                bukti tidak dapat berjalan (browser menonaktifkan fungsi hash).
                Buka lewat HTTPS, atau jalankan kit offline yang memakai
                localhost.
              </span>
            </div>
          )}
          {!data.loaded ? (
            <LoadingState />
          ) : (
            <ErrorBoundary key={page}>
              <Suspense fallback={<LoadingState />}>
                {page === "Ringkasan" && (
                  <SummaryView
                    data={data}
                    openImport={() => go("Impor Data")}
                    openCase={openCase}
                    openGraph={openGraph}
                    openTimeline={() => go("Timeline")}
                    openDetail={openDetail}
                    openOt={() => go("Lintas IT-OT")}
                  />
                )}
                {page === "Impor Data" && (
                  <ImportView
                    imports={data.imports}
                    eventCount={data.eventCount}
                    detectionCount={data.detections.length}
                    incidentCount={data.incidents.length}
                    check={data.check}
                    coverage={data.coverage}
                    tzOffset={settings.importTz}
                    onTzChange={(offset) => void saveImportTz(offset)}
                    busy={ingest.busy}
                    progress={ingest.progress}
                    onFiles={(files) =>
                      void runIngest({
                        type: "import",
                        files,
                        actor,
                        tzOffset: settings.importTz,
                      })
                    }
                    onScenario={() =>
                      void runIngest({ type: "scenario", actor }, () =>
                        setActive("Ringkasan"),
                      )
                    }
                    onDownloadSamples={() => void downloadSamples()}
                    onClear={() => setClearOpen(true)}
                    profile={settings.profile}
                    customProfile={settings.custom}
                    openSettings={() => go("Pengaturan")}
                  />
                )}
                {page === "Timeline" && (
                  <TimelineView
                    data={data}
                    selectedId={selectedId}
                    onSelect={setSelectedId}
                    openDetail={openDetail}
                    openImport={() => go("Impor Data")}
                    openCase={openCase}
                  />
                )}
                {page === "Log Explorer" && (
                  <LogExplorer
                    key={logFocus ?? "all"}
                    detections={data.detections}
                    focusEventId={logFocus}
                    openDetection={openDetail}
                    openImport={() => go("Impor Data")}
                  />
                )}
                {page === "Detail" && (
                  <DetailView
                    detection={detailDetection}
                    data={data}
                    actor={actor}
                    changeFollowUp={changeFollowUp}
                    select={setSelectedId}
                    openLogs={(eventId) => {
                      setLogFocus(eventId);
                      setActive("Log Explorer");
                    }}
                    openTimeline={() => go("Timeline")}
                    openCase={openCase}
                  />
                )}
                {page === "ATT&CK" && (
                  <AttackView
                    detections={data.detections}
                    select={openDetail}
                  />
                )}
                {page === "Graf Investigasi" && (
                  <GraphView
                    data={data}
                    incidentId={graphIncident}
                    selectIncident={setGraphIncident}
                    openDetail={openDetail}
                    openImport={() => go("Impor Data")}
                  />
                )}
                {page === "Lintas IT-OT" && (
                  <OtView
                    ot={data.ot}
                    openImport={() => go("Impor Data")}
                    openDetail={openDetail}
                    notify={notify}
                  />
                )}
                {page === "Kasus" && (
                  <CaseView
                    data={data}
                    caseId={caseId}
                    selectCase={setCaseId}
                    actor={actor}
                    notify={notify}
                    changeFollowUp={changeFollowUp}
                    openDetail={openDetail}
                    openGraph={openGraph}
                    openReport={openReport}
                    exportBlocklist={exportBlocklist}
                    openImport={() => go("Impor Data")}
                  />
                )}
                {page === "Laporan" && (
                  <ReportView
                    data={data}
                    caseId={caseId}
                    selectCase={setCaseId}
                    actor={actor}
                    profile={settings.profile}
                    notify={notify}
                    openImport={() => go("Impor Data")}
                  />
                )}
                {page === "Playbook" && <PlaybookView />}
                {page === "Latihan" && (
                  <DrillView
                    data={data}
                    actor={actor}
                    openImport={() => go("Impor Data")}
                  />
                )}
                {page === "Triase" && (
                  <TriageView
                    data={data}
                    actor={actor}
                    ownDomains={settings.profile.ownDomains ?? []}
                    notify={notify}
                    openSettings={() => go("Pengaturan")}
                  />
                )}
                {page === "Pengaturan" && (
                  <SettingsView
                    key={JSON.stringify(settings.profile)}
                    operator={settings.operator}
                    changeOperator={() => setOperatorOpen(true)}
                    profile={settings.profile}
                    custom={settings.custom}
                    busy={ingest.busy}
                    save={(profile) =>
                      void runIngest({ type: "profile", profile, actor })
                    }
                    notify={notify}
                    applyIndicators={() => {
                      if (data.eventCount)
                        void runIngest({ type: "indicators" });
                    }}
                  />
                )}
              </Suspense>
            </ErrorBoundary>
          )}
        </main>
      </div>
      {confirm && (
        <ConfirmDialog
          id={confirm.detection.title}
          status={confirm.status}
          cancel={() => setConfirm(null)}
          confirm={applyFollowUp}
        />
      )}
      {clearOpen && (
        <ClearDataDialog
          cancel={() => setClearOpen(false)}
          confirm={clearAll}
        />
      )}
      {settings.loaded && (!settings.operator || operatorOpen) && (
        <OperatorDialog
          current={settings.operator}
          cancel={settings.operator ? () => setOperatorOpen(false) : undefined}
          save={(name) => {
            void saveOperator(name);
            setOperatorOpen(false);
          }}
        />
      )}
    </div>
  );
}

export default App;
