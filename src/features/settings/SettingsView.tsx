import { useEffect, useRef, useState } from "react";
import {
  Download,
  KeyRound,
  Network,
  Plus,
  TriangleAlert,
  Upload,
  UserRound,
  WifiOff,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { Label } from "@/components/ui/Label";
import { PageTitle } from "@/components/ui/PageTitle";
import type { UnitAsset, UnitProfile } from "@/core/model";
import { keyFingerprint } from "@/core/evidence/signing";
import { parseUnitProfile } from "@/core/profile";
import { signingKey } from "@/db/settings";
import { IndicatorListsCard } from "@/features/settings/IndicatorListsCard";
import { OnlineCard } from "@/features/settings/OnlineCard";
import { useInstallApp } from "@/lib/installApp";

type Props = {
  operator: string | null;
  changeOperator: () => void;
  profile: UnitProfile;
  /** False while the fictional demo unit is in use. */
  custom: boolean;
  busy: boolean;
  /** Saves the profile (null returns to the demo unit) and re-analyzes the stored events. */
  save: (profile: UnitProfile | null) => void;
  notify: (message: string) => void;
  /** Re-checks the stored events after the indicator lists changed. */
  applyIndicators: () => void;
};

const MB = 1024 ** 2;
/** Put next to the app by `npm run build:kit`. */
const KIT_URL = "./unduh/sigap-kit.zip";
const INPUT =
  "h-9 w-full min-w-0 rounded-lg border border-[#1E2532] bg-[#080E18] px-3 text-xs text-[#D0D9E4] outline-none focus:border-[#38BDF8]/60";
const BUTTON =
  "flex items-center justify-center gap-1.5 rounded-lg border border-[#1E2532] bg-[#0C1726] px-3 py-2 text-xs text-[#A0AEBF] hover:border-[#2A3F55] hover:text-white disabled:opacity-50";

type Draft = {
  name: string;
  otSubnets: string;
  engineeringHosts: string;
  thresholdMb: string;
  assets: UnitAsset[];
  ownDomains: string;
  runCoils: string;
  setpointRegisters: string;
  setpointMin: string;
  setpointMax: string;
  runStatusRegister: string;
  measuredRegisters: string;
  reportMarking: string;
};

const toDraft = (p: UnitProfile): Draft => ({
  name: p.name,
  otSubnets: p.otSubnets.join(", "),
  engineeringHosts: p.engineeringHosts.join(", "),
  thresholdMb: String(p.uploadThresholdBytes / MB),
  assets: p.assets,
  ownDomains: (p.ownDomains ?? []).join(", "),
  runCoils: (p.ot?.runCoils ?? []).join(", "),
  setpointRegisters: (p.ot?.setpointRegisters ?? []).join(", "),
  setpointMin: p.ot?.setpointMin?.toString() ?? "",
  setpointMax: p.ot?.setpointMax?.toString() ?? "",
  runStatusRegister: p.ot?.runStatusRegister?.toString() ?? "",
  measuredRegisters: (p.ot?.measuredRegisters ?? [])
    .map((m) => `${m.address}=${m.label}${m.unit ? ` (${m.unit})` : ""}`)
    .join(", "),
  reportMarking: p.reportMarking ?? "",
});
const list = (text: string) => text.split(/[\s,]+/).filter(Boolean);
/** Text the parser can reject: a typo becomes NaN rather than quietly disappearing. */
const numbers = (text: string) => list(text).map(Number);
const optionalNumber = (text: string) =>
  text.trim() ? Number(text) : undefined;
/** `1=Tegangan keluaran (V), 3=Beban (kW)`. An entry that does not read that way stays invalid, for the parser to report. */
const measuredList = (text: string) =>
  text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((item) => {
      const match = /^(\d+)\s*=\s*(.+?)(?:\s*\(([^)]+)\))?$/.exec(item);
      return match
        ? { address: Number(match[1]), label: match[2], unit: match[3] }
        : { address: NaN, label: "" };
    });

/** Draft as the plain object `parseUnitProfile` checks. An empty threshold stays invalid (NaN) rather than becoming 0. */
const fromDraft = (d: Draft) => ({
  name: d.name,
  otSubnets: list(d.otSubnets),
  engineeringHosts: list(d.engineeringHosts),
  uploadThresholdBytes: d.thresholdMb.trim()
    ? Math.round(Number(d.thresholdMb) * MB)
    : NaN,
  assets: d.assets,
  ownDomains: list(d.ownDomains),
  ot: {
    runCoils: numbers(d.runCoils),
    setpointRegisters: numbers(d.setpointRegisters),
    setpointMin: optionalNumber(d.setpointMin),
    setpointMax: optionalNumber(d.setpointMax),
    runStatusRegister: optionalNumber(d.runStatusRegister),
    measuredRegisters: measuredList(d.measuredRegisters),
  },
  reportMarking: d.reportMarking,
});

export function SettingsView({
  operator,
  changeOperator,
  profile,
  custom,
  busy,
  save,
  notify,
  applyIndicators,
}: Props) {
  const [draft, setDraft] = useState(() => toDraft(profile));
  const [errors, setErrors] = useState<string[]>([]);
  const [confirmReset, setConfirmReset] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const setAsset = (i: number, change: Partial<UnitAsset>) =>
    setDraft({
      ...draft,
      assets: draft.assets.map((a, n) => (n === i ? { ...a, ...change } : a)),
    });

  const submit = () => {
    const parsed = parseUnitProfile(fromDraft(draft));
    if (!parsed.ok) {
      setErrors(parsed.errors);
      return;
    }
    setErrors([]);
    save(parsed.profile);
  };

  // Filled into the form rather than saved, so it can be checked first.
  const importFile = async (file: File) => {
    try {
      const parsed = parseUnitProfile(JSON.parse(await file.text()));
      if (!parsed.ok) {
        setErrors(parsed.errors);
        return;
      }
      setErrors([]);
      setDraft(toDraft(parsed.profile));
      notify("Profil dimuat ke formulir. Periksa, lalu tekan Simpan.");
    } catch (err) {
      setErrors([`Berkas bukan JSON yang valid: ${(err as Error).message}`]);
    }
  };

  const exportFile = () => {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(profile, null, 2)], {
        type: "application/json",
      }),
    );
    Object.assign(document.createElement("a"), {
      href: url,
      download: "profil-satuan.json",
    }).click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  };

  return (
    <div className="space-y-5">
      <PageTitle
        eyebrow="Sistem / Pengaturan"
        title="Pengaturan"
        text="Tersimpan hanya di browser ini, dan tetap ada setelah data lokal dihapus."
      />

      <Card
        title="Operator"
        icon={<UserRound size={16} className="text-[#38BDF8]" />}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="break-words text-sm font-semibold">
              {operator ?? "—"}
            </div>
            <p className="mt-1 text-xs leading-5 text-[#8D97A6]">
              Dicatat pada setiap impor, tindakan kasus, dan paket bukti. Nama
              ini diisi sendiri dan tidak diverifikasi, jadi gantilah setiap
              kali berganti pemakai di komputer yang sama.
            </p>
          </div>
          <button onClick={changeOperator} className={BUTTON}>
            Ganti operator
          </button>
        </div>
      </Card>

      <Card
        title="Profil Jaringan Satuan"
        icon={<Network size={16} className="text-[#38BDF8]" />}
      >
        {!custom && (
          <div className="mb-4 flex gap-2 rounded-lg border border-[#F59E0B]/30 bg-[#F59E0B]/10 p-3 text-xs leading-5 text-[#FCD34D]">
            <TriangleAlert size={15} className="mt-0.5 shrink-0" />
            <span>
              Masih memakai profil contoh fiktif. Isi dengan jaringan satuan
              Anda sebelum memakai log nyata: bila tidak, aturan OT menilai host
              berdasarkan alamat yang salah dan aset nyata tidak dikenali.
            </span>
          </div>
        )}
        {custom && (
          <div className="mb-4 flex items-center gap-2 text-xs text-[#8D97A6]">
            <Badge className="border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]">
              AKTIF
            </Badge>
            Skenario contoh ditulis untuk profil contoh, jadi hasilnya berbeda
            bila dimuat dengan profil ini.
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <Label>Nama satuan</Label>
            <input
              aria-label="Nama satuan"
              className={INPUT}
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </div>
          <div>
            <Label>Ambang unggahan (MB)</Label>
            <input
              aria-label="Ambang unggahan dalam MB"
              className={INPUT}
              inputMode="decimal"
              value={draft.thresholdMb}
              onChange={(e) =>
                setDraft({ ...draft, thresholdMb: e.target.value })
              }
            />
          </div>
          <div>
            <Label>Segmen OT (CIDR)</Label>
            <input
              aria-label="Segmen OT"
              className={`${INPUT} font-mono`}
              placeholder="192.168.50.0/24"
              value={draft.otSubnets}
              onChange={(e) =>
                setDraft({ ...draft, otSubnets: e.target.value })
              }
            />
            <p className="mt-1 text-[10px] leading-4 text-[#657080]">
              Pisahkan dengan koma. Koneksi Modbus dari luar segmen ini
              ditandai.
            </p>
          </div>
          <div>
            <Label>Host yang boleh mengirim perintah Modbus</Label>
            <input
              aria-label="Host engineering"
              className={`${INPUT} font-mono`}
              placeholder="192.168.50.10"
              value={draft.engineeringHosts}
              onChange={(e) =>
                setDraft({ ...draft, engineeringHosts: e.target.value })
              }
            />
            <p className="mt-1 text-[10px] leading-4 text-[#657080]">
              HMI atau engineering. Bila kosong, semua perintah tulis ditandai.
            </p>
          </div>
          <div>
            <Label>Domain milik satuan</Label>
            <input
              aria-label="Domain milik satuan"
              className={`${INPUT} font-mono`}
              placeholder="satuan.mil.id"
              value={draft.ownDomains}
              onChange={(e) =>
                setDraft({ ...draft, ownDomains: e.target.value })
              }
            />
            <p className="mt-1 text-[10px] leading-4 text-[#657080]">
              Beserta subdomainnya, tidak akan diusulkan untuk diblokir.
            </p>
          </div>
          <div>
            <Label>Penandaan pada laporan</Label>
            <input
              aria-label="Penandaan pada laporan"
              className={INPUT}
              placeholder="Tingkat klasifikasi sesuai ketentuan satuan"
              value={draft.reportMarking}
              onChange={(e) =>
                setDraft({ ...draft, reportMarking: e.target.value })
              }
            />
            <p className="mt-1 text-[10px] leading-4 text-[#657080]">
              Dicetak di atas dan bawah laporan. SIGAP tidak menentukan
              klasifikasi.
            </p>
          </div>
        </div>

        <div className="mt-5">
          <Label>Titik kendali genset (Modbus)</Label>
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            <input
              aria-label="Coil RUN"
              placeholder="Coil RUN"
              className={`${INPUT} font-mono`}
              value={draft.runCoils}
              onChange={(e) => setDraft({ ...draft, runCoils: e.target.value })}
            />
            <input
              aria-label="Register setpoint tegangan"
              placeholder="Register setpoint"
              className={`${INPUT} font-mono`}
              value={draft.setpointRegisters}
              onChange={(e) =>
                setDraft({ ...draft, setpointRegisters: e.target.value })
              }
            />
            <input
              aria-label="Batas bawah tegangan"
              placeholder="Batas bawah (V)"
              inputMode="decimal"
              className={`${INPUT} font-mono`}
              value={draft.setpointMin}
              onChange={(e) =>
                setDraft({ ...draft, setpointMin: e.target.value })
              }
            />
            <input
              aria-label="Batas atas tegangan"
              placeholder="Batas atas (V)"
              inputMode="decimal"
              className={`${INPUT} font-mono`}
              value={draft.setpointMax}
              onChange={(e) =>
                setDraft({ ...draft, setpointMax: e.target.value })
              }
            />
          </div>
          <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-[180px_minmax(0,1fr)]">
            <input
              aria-label="Register status RUN"
              placeholder="Register status RUN"
              className={`${INPUT} font-mono`}
              value={draft.runStatusRegister}
              onChange={(e) =>
                setDraft({ ...draft, runStatusRegister: e.target.value })
              }
            />
            <input
              aria-label="Register yang dipantau"
              placeholder="Register dipantau: 1=Tegangan keluaran (V), 3=Beban (kW)"
              className={INPUT}
              value={draft.measuredRegisters}
              onChange={(e) =>
                setDraft({ ...draft, measuredRegisters: e.target.value })
              }
            />
          </div>
          <p className="mt-1 text-[10px] leading-4 text-[#657080]">
            Nomornya berbeda untuk tiap pengendali: lihat manualnya. Bila
            kosong, aturan henti genset dan batas tegangan tidak berjalan.
            Aturan perintah tulis tak berwenang tetap berjalan, dan halaman
            Lintas IT-OT mempelajari batas normal dari log.
          </p>
        </div>

        <div className="mt-5">
          <Label>Aset</Label>
          <div className="space-y-2">
            {draft.assets.map((a, i) => (
              <div
                key={i}
                className="grid grid-cols-2 gap-2 rounded-lg border border-[#272E3A] p-2 md:grid-cols-[1.1fr_1fr_90px_1.5fr_auto] md:border-0 md:p-0"
              >
                <input
                  aria-label={`Nama aset ${i + 1}`}
                  placeholder="Nama"
                  className={`${INPUT} font-mono`}
                  value={a.name}
                  onChange={(e) => setAsset(i, { name: e.target.value })}
                />
                <input
                  aria-label={`IP aset ${i + 1}`}
                  placeholder="Alamat IP"
                  className={`${INPUT} font-mono`}
                  value={a.ip}
                  onChange={(e) => setAsset(i, { ip: e.target.value })}
                />
                <select
                  aria-label={`Jenis aset ${i + 1}`}
                  className={INPUT}
                  value={a.kind}
                  onChange={(e) =>
                    setAsset(i, { kind: e.target.value === "ot" ? "ot" : "it" })
                  }
                >
                  <option value="it">IT</option>
                  <option value="ot">OT</option>
                </select>
                <input
                  aria-label={`Peran aset ${i + 1}`}
                  placeholder="Peran"
                  className={INPUT}
                  value={a.role}
                  onChange={(e) => setAsset(i, { role: e.target.value })}
                />
                <button
                  aria-label={`Hapus aset ${i + 1}`}
                  onClick={() =>
                    setDraft({
                      ...draft,
                      assets: draft.assets.filter((_, n) => n !== i),
                    })
                  }
                  className="grid h-9 w-9 place-items-center rounded-lg border border-[#272E3A] text-[#8D97A6] hover:text-[#FCA5A5]"
                >
                  <X size={14} />
                </button>
              </div>
            ))}
          </div>
          <button
            onClick={() =>
              setDraft({
                ...draft,
                assets: [
                  ...draft.assets,
                  { name: "", ip: "", kind: "it", role: "" },
                ],
              })
            }
            className={`${BUTTON} mt-2`}
          >
            <Plus size={13} />
            Tambah aset
          </button>
          <p className="mt-2 text-[10px] leading-4 text-[#657080]">
            Workstation tidak perlu didaftarkan: SIGAP mempelajari alamatnya
            dari log.
          </p>
        </div>

        {errors.length > 0 && (
          <ul
            role="alert"
            className="mt-4 list-disc space-y-1 rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 py-3 pl-7 pr-3 text-xs text-[#FCA5A5]"
          >
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}

        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-[#1E2532] pt-5">
          <button
            disabled={busy}
            onClick={submit}
            className="rounded-lg bg-[#38BDF8] px-5 py-2.5 text-xs font-bold text-[#040D18] hover:bg-[#7DD3FC] disabled:opacity-50"
          >
            Simpan & hitung ulang temuan
          </button>
          <input
            ref={fileInput}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void importFile(f);
              e.target.value = "";
            }}
          />
          <button
            disabled={busy}
            onClick={() => fileInput.current?.click()}
            className={BUTTON}
          >
            <Upload size={13} />
            Muat dari JSON
          </button>
          <button onClick={exportFile} className={BUTTON}>
            <Download size={13} />
            Ekspor profil tersimpan
          </button>
          {custom && !confirmReset && (
            <button
              disabled={busy}
              onClick={() => setConfirmReset(true)}
              className={`${BUTTON} ml-auto`}
            >
              Kembali ke profil contoh
            </button>
          )}
          {custom && confirmReset && (
            <span className="ml-auto flex items-center gap-2 text-xs text-[#8D97A6]">
              Profil ini akan terhapus.
              <button onClick={() => setConfirmReset(false)} className={BUTTON}>
                Batal
              </button>
              <button
                disabled={busy}
                onClick={() => save(null)}
                className="rounded-lg bg-[#EF4444] px-3 py-2 text-xs font-bold text-white disabled:opacity-50"
              >
                Hapus profil
              </button>
            </span>
          )}
        </div>
        <p className="mt-3 text-[10px] leading-4 text-[#657080]">
          Menyimpan menghitung ulang semua temuan dari log yang sudah diimpor.
          Bagikan berkas ekspor kepada personel lain agar memakai profil yang
          sama; berkas yang sama juga dapat dipakai SIGAP Pos Jaga (--profil).
        </p>
      </Card>

      <OnlineCard actor={operator ?? ""} notify={notify} />
      <IndicatorListsCard
        actor={operator ?? ""}
        busy={busy}
        notify={notify}
        apply={applyIndicators}
      />
      <SigningCard />
      <OfflineCard />
    </div>
  );
}

/** The fingerprint a recipient compares to tell this browser's packages from anyone else's. */
function SigningCard() {
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    signingKey()
      .then(keyFingerprint)
      .then(setFingerprint, () => setFailed(true));
  }, []);
  return (
    <Card
      title="Kunci Tanda Tangan Paket Bukti"
      icon={<KeyRound size={16} className="text-[#38BDF8]" />}
    >
      {failed ? (
        <p className="text-xs text-[#FCA5A5]">
          Kunci tidak dapat dibuat di browser ini. Buka SIGAP lewat HTTPS atau
          localhost.
        </p>
      ) : (
        <p className="break-all font-mono text-sm font-semibold text-[#7DD3FC]">
          {fingerprint ?? "…"}
        </p>
      )}
      <p className="mt-2 text-xs leading-5 text-[#8D97A6]">
        Daftarkan sidik jari ini kepada penerima paket bukti <b>sebelum</b>{" "}
        terjadi insiden, misalnya lewat berita acara. Tanpa itu, siapa pun yang
        mengubah isi paket dapat menandatanganinya kembali dengan kuncinya
        sendiri dan penerima tidak bisa membedakannya.
      </p>
      <p className="mt-2 text-[11px] leading-4 text-[#657080]">
        Kunci tersimpan di browser ini dan tidak dapat disalin keluar. Bila data
        browser dihapus, kunci baru dibuat dan sidik jarinya berubah. Tanda
        tangan menunjukkan perangkat asal paket, bukan identitas orangnya.
      </p>
    </Card>
  );
}

/** Whether this browser can open the app without the server, and the kit for working without one at all. */
function OfflineCard() {
  const installer = useInstallApp();
  const [ready, setReady] = useState<boolean | null>(null);
  const [kit, setKit] = useState(false);
  const [persisted, setPersisted] = useState<boolean | null>(null);

  useEffect(() => {
    if ("serviceWorker" in navigator)
      void navigator.serviceWorker
        .getRegistration()
        .then((r) => setReady(!!r?.active));
    else setReady(false);
    void navigator.storage?.persisted?.().then(setPersisted);
    // A server without the kit may answer with the app's page instead of a 404.
    fetch(KIT_URL, { method: "HEAD" }).then(
      (r) =>
        setKit(r.ok && !(r.headers.get("content-type") ?? "").includes("html")),
      () => setKit(false),
    );
  }, []);

  return (
    <Card
      title="Aplikasi dan Pemakaian Offline"
      icon={<WifiOff size={16} className="text-[#38BDF8]" />}
    >
      <div
        data-testid="install-state"
        className="mb-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"
      >
        <p className="min-w-0 flex-1 text-xs leading-5 text-[#AEB6C1]">
          {installer.runningAsApp
            ? "SIGAP sedang berjalan di jendelanya sendiri, sebagai aplikasi."
            : installer.canInstall
              ? "Pasang SIGAP agar terbuka di jendelanya sendiri, dengan ikon di Start Menu atau desktop. Data tetap sama dengan yang ada di browser ini."
              : "Bila memakai Edge atau Chrome, SIGAP dapat dipasang dari ikon pasang di bilah alamat atau dari menu browser. Perlu HTTPS atau localhost."}
        </p>
        {installer.canInstall && (
          <button
            onClick={() => void installer.install()}
            className="rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]"
          >
            Pasang sebagai aplikasi
          </button>
        )}
      </div>
      <p className="text-xs leading-5 text-[#AEB6C1]">
        {ready
          ? "Siap: browser ini menyimpan salinan aplikasi, sehingga SIGAP dan kasus di dalamnya tetap dapat dibuka bila server tidak terjangkau."
          : "Salinan aplikasi belum tersimpan di browser ini. Buka SIGAP lewat HTTPS atau localhost, lalu muat ulang halaman ini."}
      </p>
      <p className="mt-3 text-xs leading-5 text-[#8D97A6]">
        Untuk komputer yang tidak pernah terhubung ke server, pakai kit offline:
        berisi aplikasi, pengumpul log Windows, dan Pos Jaga, dan berjalan tanpa
        internet. Data tersimpan di browser komputer tempat kit dijalankan,
        bukan di USB.
      </p>
      {persisted === false && (
        <p className="mt-3 flex gap-2 rounded-lg border border-[#F59E0B]/30 bg-[#F59E0B]/10 p-2.5 text-[11px] leading-4 text-[#FCD34D]">
          <TriangleAlert size={13} className="mt-0.5 shrink-0" />
          Browser belum menjamin penyimpanan ini tetap ada saat ruang disk
          menipis. Ekspor paket bukti untuk kasus penting; jangan andalkan
          browser sebagai satu-satunya salinan.
        </p>
      )}
      {kit && (
        <a href={KIT_URL} download className={`${BUTTON} mt-3 w-fit`}>
          <Download size={13} />
          Unduh kit offline (ZIP)
        </a>
      )}
    </Card>
  );
}
