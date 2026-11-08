import { MAX_URL_LENGTH } from "../validation.js";

const EXAMPLES = [
  "https://www.swinburne.edu.au/",
  "http://paypal.com.secure-login.xyz/verify",
  "https://metamask-usa-walet.godaddysites.com/",
];

export default function UrlForm({ value, onChange, onSubmit, error, loading }) {
  const describedBy = ["url-help", error ? "url-error" : null].filter(Boolean).join(" ");
  const near = value.length > MAX_URL_LENGTH * 0.9;

  return (
    <form
      className="card url-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
      aria-busy={loading}
    >
      <div className="form-bar" aria-hidden="true">
        <span className="dots"><i /><i /><i /></span>
        <span className="title">url_scanner — paste a link to analyze</span>
      </div>
      <div className="form-body">
      <label htmlFor="url-input" className="field-label">Web address to check</label>
      <p id="url-help" className="field-help">
        Paste a link from an email, text message or QR code. PhishGuard reads it as text and never opens it.
      </p>
      <div className="input-row">
        <input
          id="url-input"
          type="text"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck="false"
          placeholder="e.g. paypal-account-verify.com/login"
          value={value}
          maxLength={MAX_URL_LENGTH + 200}
          onChange={(e) => onChange(e.target.value)}
          aria-invalid={Boolean(error)}
          aria-describedby={describedBy}
          disabled={loading}
        />
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? <><span className="spinner" aria-hidden="true" /> Checking…</> : "Check link"}
        </button>
      </div>
      <div className="field-meta">
        {error ? (
          <p id="url-error" className="field-error" role="alert">{error}</p>
        ) : <span />}
        <span className={`char-count ${near ? "warn" : ""}`} aria-live="polite">
          {value.length > 0 ? `${value.length} / ${MAX_URL_LENGTH}` : ""}
        </span>
      </div>
      <div className="examples">
        <span>Try an example:</span>
        {EXAMPLES.map((ex) => (
          <button key={ex} type="button" className="chip" onClick={() => onChange(ex)} disabled={loading}>
            {ex.replace(/^https?:\/\//, "")}
          </button>
        ))}
      </div>
      </div>
    </form>
  );
}
