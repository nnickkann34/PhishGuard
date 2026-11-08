import { AlertIcon, CheckIcon, InfoIcon } from "./Icons.jsx";

const pct = (x) => `${Math.round(x * 100)}%`;

function confidenceWord(c) {
  if (c >= 0.9) return "VERY HIGH";
  if (c >= 0.75) return "HIGH";
  if (c >= 0.6) return "MODERATE";
  return "LOW";
}

function RiskGauge({ score, phishing }) {
  const r = 58;
  const c = 2 * Math.PI * r;
  const offset = c * (1 - score / 100);
  return (
    <div className={`gauge ${phishing ? "sev-danger" : "sev-safe"}`}>
      <svg width="132" height="132" viewBox="0 0 132 132" aria-hidden="true">
        <circle className="track" cx="66" cy="66" r={r} fill="none" strokeWidth="9" />
        <circle
          className="arc" cx="66" cy="66" r={r} fill="none" strokeWidth="9"
          strokeLinecap="round" strokeDasharray={c} strokeDashoffset={offset}
        />
      </svg>
      <div className="gauge-center">
        <span className="gauge-score">{score}</span>
        <span className="gauge-unit">Risk / 100</span>
      </div>
    </div>
  );
}

export default function ResultCard({ result }) {
  const phishing = result.verdict === "phishing";
  const sev = phishing ? "sev-danger" : "sev-safe";
  const score = Math.round(result.malicious_probability * 100);

  return (
    <section
      className={`card result ${sev}`}
      aria-labelledby="result-heading"
      tabIndex={-1}
      id="result"
    >
      <div className="result-head">
        <div>
          <p className="eyebrow plain">Verdict</p>
          <h2 id="result-heading" className="verdict-label">
            {phishing ? "Likely phishing" : "Looks legitimate"}
          </h2>
        </div>
        <span className="sev-tag">{phishing ? "Dangerous" : "Clear"}</span>
      </div>

      <div className="gauge-wrap">
        <div
          role="meter" aria-label="Phishing risk score out of 100"
          aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}
          aria-valuetext={`${score} out of 100 risk, decision threshold 50`}
        >
          <RiskGauge score={score} phishing={phishing} />
        </div>
        <div className="gauge-side">
          <p className="eyebrow plain">Model confidence</p>
          <p className="verdict-label" style={{ fontSize: "1.5rem" }}>{confidenceWord(result.confidence)}</p>
          <p className="conf">
            {pct(result.confidence)} confident · {pct(result.malicious_probability)} chance of phishing · threshold 50
          </p>
        </div>
      </div>

      <div className="readout" aria-hidden="true">
        <div className="row"><span className="k">verdict</span><span className={`v ${phishing ? "danger" : "safe"}`}>{phishing ? "PHISHING" : "LEGITIMATE"}</span></div>
        <div className="row"><span className="k">risk_score</span><span className="v">{score} / 100</span></div>
        <div className="row"><span className="k">confidence</span><span className="v">{confidenceWord(result.confidence)}</span></div>
        <div className="row"><span className="k">lookalike_chars</span><span className={`v ${result.lookalike_characters ? "warn" : ""}`}>{result.lookalike_characters ? "DETECTED" : "none"}</span></div>
      </div>

      <dl className="checked-url">
        <dt>Address checked</dt>
        {/* Plain text: React escapes it, and it is never made into a link. */}
        <dd><code>{result.url}</code></dd>
      </dl>

      <div className="indicators">
        {result.warnings.length > 0 ? (
          <>
            <h3>Risk indicators</h3>
            <ul className="ind-list">
              {result.warnings.map((w) => (
                <li key={w}><AlertIcon width={16} height={16} /> <span>{w}</span></li>
              ))}
            </ul>
          </>
        ) : (
          <p className="no-warnings"><InfoIcon width={16} height={16} /> <span>No obviously suspicious parts were found in this address.</span></p>
        )}
      </div>

      {phishing ? (
        <p className="advice"><strong>What to do:</strong> don't open this link or enter any details. If it claims to be from a company you use, go to their website by typing the address yourself.</p>
      ) : (
        <p className="advice"><strong>Remember:</strong> a clean result isn't a guarantee. Still check that the site is the one you expect before entering a password.</p>
      )}
    </section>
  );
}
