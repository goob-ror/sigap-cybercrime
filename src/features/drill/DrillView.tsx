import { useEffect, useState } from "react";
import {
  Check,
  CircleX,
  GraduationCap,
  History,
  Target,
  Timer,
  Upload,
} from "lucide-react";
import { AssessmentBadge } from "@/components/AssessmentBadge";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { Label } from "@/components/ui/Label";
import { PageTitle } from "@/components/ui/PageTitle";
import { localDrill, type DrillQuestion, type DrillResult } from "@/core/drill";
import type { Incident } from "@/core/model";
import { RULES } from "@/data/rules/catalog";
import type { Investigation } from "@/db/hooks";
import { saveDrillResult, useSettings } from "@/db/settings";
import { fmtDate, fmtDuration, fmtTime } from "@/lib/format";

type Props = { data: Investigation; actor: string; openImport: () => void };
type Run = { questions: DrillQuestion[]; startedAt: number; answers: number[] };

const PHASE_STYLE: Record<string, string> = {
  Deteksi: "border-[#38BDF8]/30 bg-[#38BDF8]/10 text-[#7DD3FC]",
  Analisis: "border-[#C4B5FD]/30 bg-[#C4B5FD]/10 text-[#C4B5FD]",
  Containment: "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FBBF24]",
  Recovery: "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]",
};

function Clock({ from }: { from: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return (
    <span className="flex items-center gap-1.5 font-mono text-xs text-[#AEB6C1]">
      <Timer size={13} />
      {fmtDuration(now - from)}
    </span>
  );
}

function HistoryCard({ results }: { results: DrillResult[] }) {
  if (!results.length) return null;
  return (
    <Card
      title="Riwayat Latihan"
      icon={<History size={16} className="text-[#38BDF8]" />}
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[420px] text-left text-xs">
          <thead className="text-[9px] uppercase tracking-wider text-[#657080]">
            <tr className="border-b border-[#272E3A]">
              {["Waktu", "Personel", "Skor", "Durasi"].map((h) => (
                <th key={h} className="pb-2 pr-3">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.slice(0, 10).map((r) => (
              <tr
                key={r.ts}
                className="border-b border-[#1D232D] last:border-0"
              >
                <td className="py-2 pr-3 font-mono text-[10px] text-[#8D97A6]">
                  {fmtDate(r.ts)} {fmtTime(r.ts, false)}
                </td>
                <td className="max-w-[140px] truncate pr-3">{r.operator}</td>
                <td className="pr-3 font-mono">
                  {r.correct}/{r.total}
                </td>
                <td className="font-mono text-[#8D97A6]">
                  {fmtDuration(r.seconds * 1000)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Question({
  question,
  index,
  total,
  answered,
  choose,
  next,
}: {
  question: DrillQuestion;
  index: number;
  total: number;
  answered: number | undefined;
  choose: (option: number) => void;
  next: () => void;
}) {
  const done = answered !== undefined;
  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <Badge className={PHASE_STYLE[question.phase]}>
          {question.phase.toUpperCase()}
        </Badge>
        <span className="font-mono text-[11px] text-[#657080]">
          Soal {index + 1} dari {total}
        </span>
      </div>
      <h2 className="text-base font-semibold leading-6">{question.question}</h2>
      <div className="mt-4 space-y-2">
        {question.options.map((option, i) => {
          const right = done && i === question.answer;
          const wrong = done && i === answered && i !== question.answer;
          return (
            <button
              key={i}
              disabled={done}
              onClick={() => choose(i)}
              className={`flex w-full items-start gap-3 rounded-lg border p-3 text-left text-sm leading-5 transition ${right ? "border-[#22C55E]/50 bg-[#22C55E]/10" : wrong ? "border-[#EF4444]/50 bg-[#EF4444]/10" : done ? "border-[#272E3A] opacity-60" : "border-[#272E3A] bg-[#0D1016] hover:border-[#38BDF8]/50"}`}
            >
              <span className="font-mono text-xs text-[#8D97A6]">
                {String.fromCharCode(65 + i)}
              </span>
              <span className="min-w-0 flex-1">{option}</span>
              {right && (
                <Check size={15} className="mt-0.5 shrink-0 text-[#22C55E]" />
              )}
              {wrong && (
                <CircleX size={15} className="mt-0.5 shrink-0 text-[#EF4444]" />
              )}
            </button>
          );
        })}
      </div>
      {done && (
        <div className="mt-4 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3">
          <div
            className={`text-xs font-bold ${answered === question.answer ? "text-[#86EFAC]" : "text-[#FCA5A5]"}`}
          >
            {answered === question.answer ? "Benar" : "Belum tepat"}
          </div>
          <p className="mt-1 text-xs leading-5 text-[#AEB6C1]">
            {question.explanation}
          </p>
        </div>
      )}
      {done && (
        <button
          onClick={next}
          className="mt-4 w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]"
        >
          {index + 1 < total ? "Soal berikutnya" : "Lihat hasil"}
        </button>
      )}
    </div>
  );
}

/**
 * Practising the response before it is needed. Readiness is a question of people, not only tools, so
 * this works with no network: the questions come from the incident's own data.
 */
export function DrillView({ data, actor, openImport }: Props) {
  const { drillResults } = useSettings();
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [at, setAt] = useState(0);
  const [result, setResult] = useState<DrillResult | null>(null);

  const incident: Incident | undefined =
    data.incidents.find((i) => i.id === incidentId) ?? data.incidents[0];

  if (!incident) {
    return (
      <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center">
        <div>
          <div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]">
            <Upload size={22} />
          </div>
          <h1 className="text-lg font-semibold">
            Belum ada insiden untuk latihan
          </h1>
          <p className="mt-2 text-sm text-[#7E8998]">
            Soal disusun dari insiden. Muat skenario contoh di Impor Data untuk
            mulai berlatih.
          </p>
          <button
            onClick={openImport}
            className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]"
          >
            Buka Impor Data
          </button>
        </div>
      </div>
    );
  }

  const questions = localDrill(incident, data.detectionsById, RULES, data.ot);

  const begin = () => {
    setRun({ questions, startedAt: Date.now(), answers: [] });
    setAt(0);
    setResult(null);
  };

  const finish = (current: Run) => {
    const byPhase: Record<string, boolean> = {};
    current.questions.forEach((q, i) => {
      byPhase[q.phase] = current.answers[i] === q.answer;
    });
    const summary: DrillResult = {
      ts: Date.now(),
      operator: actor,
      correct: current.questions.filter(
        (q, i) => current.answers[i] === q.answer,
      ).length,
      total: current.questions.length,
      seconds: Math.round((Date.now() - current.startedAt) / 1000),
      byPhase,
    };
    setResult(summary);
    setRun(null);
    void saveDrillResult(summary);
  };

  return (
    <div className="w-full space-y-5">
      <PageTitle
        eyebrow="Kesiapan Personel"
        title="Mode Latihan"
        text="Berlatih memutuskan langkah pada tiap fase penanganan, dengan soal yang disusun dari insiden di SIGAP. Tidak mengubah kasus atau bukti."
      />

      {run ? (
        <Card
          title="Latihan"
          icon={<Target size={16} className="text-[#38BDF8]" />}
        >
          <div className="mb-4 flex justify-end">
            <Clock from={run.startedAt} />
          </div>
          <Question
            question={run.questions[at]}
            index={at}
            total={run.questions.length}
            answered={run.answers[at]}
            choose={(option) =>
              setRun({
                ...run,
                answers: Object.assign([...run.answers], { [at]: option }),
              })
            }
            next={() => {
              if (at + 1 < run.questions.length) setAt(at + 1);
              else finish(run);
            }}
          />
        </Card>
      ) : result ? (
        <Card
          title="Hasil Latihan"
          icon={<GraduationCap size={16} className="text-[#22C55E]" />}
        >
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-[#0D1016] p-4">
              <div className="text-[10px] uppercase text-[#657080]">Skor</div>
              <div
                data-testid="drill-score"
                className="mt-1 font-mono text-3xl"
              >
                {result.correct}/{result.total}
              </div>
            </div>
            <div className="rounded-lg bg-[#0D1016] p-4">
              <div className="text-[10px] uppercase text-[#657080]">Waktu</div>
              <div className="mt-1 font-mono text-3xl">
                {fmtDuration(result.seconds * 1000)}
              </div>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {Object.entries(result.byPhase).map(([phase, ok]) => (
              <Badge
                key={phase}
                className={
                  ok
                    ? "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]"
                    : "border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]"
                }
              >
                {phase}: {ok ? "benar" : "perlu dilatih"}
              </Badge>
            ))}
          </div>
          <p className="mt-3 text-xs leading-5 text-[#8D97A6]">
            Latihan ini membantu mengenali keputusan yang tepat. Tidak
            menggantikan latihan tanggap insiden satuan atau penilaian resmi.
          </p>
          <button
            onClick={() => setResult(null)}
            className="mt-4 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]"
          >
            Latihan lagi
          </button>
        </Card>
      ) : (
        <Card
          title="Mulai Latihan"
          icon={<Target size={16} className="text-[#38BDF8]" />}
        >
          <Label>Insiden sebagai bahan soal</Label>
          <select
            aria-label="Insiden sebagai bahan soal"
            value={incident.id}
            onChange={(e) => setIncidentId(e.target.value)}
            className="h-9 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] px-3 text-xs"
          >
            {data.incidents.map((i) => (
              <option key={i.id} value={i.id}>
                {i.caseId ?? i.id}: {i.title}
              </option>
            ))}
          </select>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <AssessmentBadge incident={incident} />
            <span className="text-[11px] text-[#8D97A6]">
              {incident.detectionIds.length} temuan · {questions.length} soal
            </span>
          </div>
          <button
            disabled={!questions.length}
            onClick={begin}
            className="mt-4 w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC] disabled:opacity-50 sm:w-auto sm:px-6"
          >
            Mulai latihan
          </button>
          <p className="mt-3 text-[10px] leading-4 text-[#657080]">
            Soal disusun di browser ini tanpa internet, sehingga tetap dapat
            dipakai dengan kit offline.
          </p>
        </Card>
      )}

      <HistoryCard results={drillResults} />
    </div>
  );
}
