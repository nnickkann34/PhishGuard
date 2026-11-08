import { useMemo, useState } from "react";
import {
  CartesianGrid, ReferenceLine, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis,
} from "recharts";

// Chart 2 answers a different question: "Across everything I've checked this
// session, how risky were my links, and how close to the line were they?"

const DANGER = "#f2615f";
const SAFE = "#2dd4bf";

function ChartTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <strong>Check #{d.n}</strong>
      <div className="tooltip-url">{d.url.length > 60 ? `${d.url.slice(0, 57)}…` : d.url}</div>
      <div>{Math.round(d.p * 100)}% chance of phishing · {d.verdict}</div>
    </div>
  );
}

export default function HistoryChart({ items, onSelect }) {
  const [filter, setFilter] = useState("all");

  const points = useMemo(() => {
    // Oldest first so the x-axis reads left to right in time order.
    const ordered = [...items].sort((a, b) => a.id - b.id);
    return ordered.map((it, i) => ({
      n: i + 1, p: it.malicious_probability, verdict: it.verdict, url: it.url, id: it.id,
    }));
  }, [items]);

  const shown = points.filter((p) => filter === "all" || p.verdict === filter);
  const phishing = shown.filter((p) => p.verdict === "phishing");
  const legit = shown.filter((p) => p.verdict === "legitimate");
  const maxX = Math.max(points.length, 5);
  const ticks = Array.from({ length: maxX }, (_, i) => i + 1).filter((t) => maxX <= 12 || t % Math.ceil(maxX / 10) === 0 || t === 1);
  const close = points.filter((p) => Math.abs(p.p - 0.5) < 0.15).length;

  return (
    <section className="card chart-card" aria-labelledby="session-heading">
      <div className="chart-head">
        <div>
          <h2 id="session-heading">Your checks this session</h2>
          <p className="chart-desc">
            Each dot is one link you checked, in order. Higher means more likely phishing; the dashed line is the 50% decision threshold.
            Click a dot to see that result again.
          </p>
        </div>
        <fieldset className="segmented">
          <legend className="sr-only">Show which checks</legend>
          {[["all", "All"], ["phishing", "Phishing"], ["legitimate", "Legitimate"]].map(([val, label]) => (
            <label key={val} className={filter === val ? "active" : ""}>
              <input type="radio" name="verdict-filter" value={val} checked={filter === val} onChange={() => setFilter(val)} />
              {label}
            </label>
          ))}
        </fieldset>
      </div>

      {points.length === 0 ? (
        <p className="empty">Your checks will appear here. Try checking a link above.</p>
      ) : (
        <>
          <div className="chart-box" role="img" aria-label={`Scatter chart of ${points.length} checks: ${points.filter((p) => p.verdict === "phishing").length} phishing, ${points.filter((p) => p.verdict === "legitimate").length} legitimate. The same checks are listed below.`}>
            <ResponsiveContainer width="100%" height={260}>
              <ScatterChart margin={{ top: 10, right: 24, bottom: 18, left: 0 }}>
                <CartesianGrid stroke="var(--grid)" />
                <XAxis
                  type="number" dataKey="n" name="Check" allowDecimals={false}
                  domain={[0.5, maxX + 0.5]} ticks={ticks}
                  tick={{ fill: "var(--muted)", fontSize: 12 }}
                  label={{ value: "Check number", position: "insideBottom", offset: -8, fill: "var(--muted)", fontSize: 12 }}
                />
                <YAxis
                  type="number" dataKey="p" domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`}
                  tick={{ fill: "var(--muted)", fontSize: 12 }} width={48}
                />
                <ReferenceLine y={0.5} stroke="var(--muted)" strokeDasharray="5 4" label={{ value: "threshold", position: "insideTopRight", fill: "var(--muted)", fontSize: 11 }} />
                <Tooltip content={<ChartTooltip />} cursor={{ strokeDasharray: "3 3" }} />
                <Scatter name="Phishing" data={phishing} fill={DANGER} shape="triangle" onClick={(d) => onSelect?.(d.id)} style={{ cursor: "pointer" }} isAnimationActive={false} />
                <Scatter name="Legitimate" data={legit} fill={SAFE} onClick={(d) => onSelect?.(d.id)} style={{ cursor: "pointer" }} isAnimationActive={false} />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
          <ul className="legend" aria-hidden="true">
            <li><span className="swatch tri" style={{ borderBottomColor: DANGER }} /> Phishing</li>
            <li><span className="swatch dot" style={{ background: SAFE }} /> Legitimate</li>
          </ul>
          {close > 0 && (
            <p className="chart-detail">{close} of your checks scored between 35% and 65% — the model was less certain about those, so treat them with extra care.</p>
          )}
        </>
      )}
    </section>
  );
}
