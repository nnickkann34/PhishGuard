import { useState } from "react";
import {
  Bar, BarChart, Cell, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

// Chart 1 answers: "WHY did the model give this verdict for this one link?"
// Each bar is a feature's SHAP contribution (in log-odds). Right = pushed towards phishing.

const DANGER = "#f2615f";
const SAFE = "#2dd4bf";

function formatValue(v) {
  if (Number.isInteger(v)) return String(v);
  return v.toFixed(2);
}

function ChartTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <strong>{d.label}</strong>
      <div>Value in this address: {formatValue(d.value)}</div>
      <div>{d.contribution > 0 ? "Pushed towards phishing" : "Pushed towards legitimate"} ({d.contribution > 0 ? "+" : ""}{d.contribution.toFixed(2)})</div>
    </div>
  );
}

export default function ContributionChart({ contributions }) {
  const [showTable, setShowTable] = useState(false);
  const [selected, setSelected] = useState(null);
  const data = contributions.slice(0, 8).map((c) => ({ ...c }));
  const chosen = data.find((d) => d.feature === selected);

  return (
    <section className="card chart-card" aria-labelledby="why-heading">
      <div className="chart-head">
        <div>
          <h2 id="why-heading">Why this verdict?</h2>
          <p className="chart-desc">
            The features that mattered most for <em>this</em> address.
            Orange bars pushed the model towards <strong>phishing</strong>; teal bars pushed it towards <strong>legitimate</strong>.
            Click a bar for details.
          </p>
        </div>
        <button className="btn btn-ghost" type="button" onClick={() => setShowTable((s) => !s)} aria-pressed={showTable}>
          {showTable ? "Show chart" : "Show as table"}
        </button>
      </div>

      {data.length === 0 ? (
        <p className="empty">No feature details are available for this result.</p>
      ) : showTable ? (
        <table className="data-table">
          <caption className="sr-only">Feature contributions for this address</caption>
          <thead><tr><th scope="col">Feature</th><th scope="col">Value</th><th scope="col">Effect</th></tr></thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.feature}>
                <th scope="row">{d.label}</th>
                <td>{formatValue(d.value)}</td>
                <td className={d.contribution > 0 ? "txt-danger" : "txt-safe"}>
                  {d.contribution > 0 ? "Towards phishing" : "Towards legitimate"} ({d.contribution > 0 ? "+" : ""}{d.contribution.toFixed(2)})
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <>
          <div className="chart-box" role="img" aria-label={`Bar chart of the ${data.length} most important features. Largest: ${data[0].label}, ${data[0].contribution > 0 ? "towards phishing" : "towards legitimate"}. Use "Show as table" for full details.`}>
            <ResponsiveContainer width="100%" height={Math.max(220, data.length * 38)}>
              <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 8 }}>
                <CartesianGrid horizontal={false} stroke="var(--grid)" />
                <XAxis type="number" tick={{ fill: "var(--muted)", fontSize: 12 }} />
                <YAxis type="category" dataKey="label" width={190} tick={{ fill: "var(--text)", fontSize: 12 }} />
                <ReferenceLine x={0} stroke="var(--muted)" />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--hover)" }} />
                <Bar
                  dataKey="contribution"
                  radius={[3, 3, 3, 3]}
                  onClick={(d) => setSelected(d.feature === selected ? null : d.feature)}
                  style={{ cursor: "pointer" }}
                  isAnimationActive={false}
                >
                  {data.map((d) => (
                    <Cell
                      key={d.feature}
                      fill={d.contribution > 0 ? DANGER : SAFE}
                      fillOpacity={selected && selected !== d.feature ? 0.35 : 1}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="chart-detail" aria-live="polite">
            {chosen
              ? <>
                  <strong>{chosen.label}</strong> is {formatValue(chosen.value)} for this address, which moved the score
                  {chosen.contribution > 0 ? " towards phishing" : " towards legitimate"} by {Math.abs(chosen.contribution).toFixed(2)} points.
                </>
              : "Tip: click a bar to explain that feature."}
          </p>
        </>
      )}
    </section>
  );
}
