import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client.js";
import { validateUrl } from "../validation.js";
import UrlForm from "../components/UrlForm.jsx";
import ResultCard from "../components/ResultCard.jsx";
import ContributionChart from "../components/ContributionChart.jsx";
import HistoryChart from "../components/HistoryChart.jsx";
import HistoryList from "../components/HistoryList.jsx";
import { AlertIcon } from "../components/Icons.jsx";

export default function Home() {
  const [url, setUrl] = useState("");
  const [fieldError, setFieldError] = useState(null);
  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [requestError, setRequestError] = useState(null);
  const [result, setResult] = useState(null);
  const [fullResults, setFullResults] = useState({}); // id -> full CheckResult from this page

  const [history, setHistory] = useState([]);
  const [allHistory, setAllHistory] = useState([]);
  const [search, setSearch] = useState("");
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState(null);
  const [clearing, setClearing] = useState(false);
  const [toast, setToast] = useState(null);

  const resultRef = useRef(null);
  const abortRef = useRef(null);

  useEffect(() => { document.title = "PhishGuard — check a link"; }, []);

  const loadHistory = useCallback(async (term) => {
    setHistoryLoading(true);
    try {
      const [filtered, everything] = await Promise.all([
        api.history(term),
        term ? api.history("") : null,
      ]);
      setHistory(filtered.items);
      setAllHistory(everything ? everything.items : filtered.items);
      setHistoryError(null);
    } catch (err) {
      setHistoryError(`Couldn't load your history: ${err.message}`);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  // Debounced search so we don't send a request on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => loadHistory(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search, loadHistory]);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  async function handleSubmit() {
    const problem = validateUrl(url);
    setFieldError(problem);
    if (problem) {
      document.getElementById("url-input")?.focus();
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setStatus("loading");
    setRequestError(null);
    try {
      const res = await api.check(url.trim(), controller.signal);
      setResult(res);
      if (res.id != null) setFullResults((m) => ({ ...m, [res.id]: res }));
      setStatus("success");
      setToast("Check complete — saved to your history.");
      loadHistory(search.trim());
      requestAnimationFrame(() => resultRef.current?.querySelector("#result")?.focus());
    } catch (err) {
      if (err.code === "cancelled") return;
      if (err.status === 422 && err.details?.length) {
        setFieldError(err.details[0].problem || err.message);
        setStatus("idle");
      } else {
        setRequestError(err.message);
        setStatus("error");
      }
    }
  }

  function selectFromHistory(id) {
    const full = fullResults[id];
    if (full) {
      setResult(full);
    } else {
      const item = allHistory.find((h) => h.id === id) || history.find((h) => h.id === id);
      if (!item) return;
      setResult({ ...item, contributions: [], lookalike_characters: false });
    }
    setStatus("success");
    requestAnimationFrame(() => resultRef.current?.querySelector("#result")?.focus());
  }

  async function handleClear() {
    setClearing(true);
    try {
      const res = await api.clearHistory();
      setHistory([]);
      setAllHistory([]);
      setFullResults({});
      setResult(null);
      setStatus("idle");
      setToast(`Cleared ${res.deleted} check${res.deleted === 1 ? "" : "s"} from your history.`);
    } catch (err) {
      setHistoryError(`Couldn't clear history: ${err.message}`);
    } finally {
      setClearing(false);
    }
  }

  return (
    <div className="home">
      <section className="hero">
        <p className="eyebrow">Live URL Analysis</p>
        <h1>Is this link <span className="hl">safe to open?</span></h1>
        <p>Paste a suspicious web address and PhishGuard's machine-learning model tells you whether it looks like phishing — and shows you exactly why.</p>
      </section>

      <UrlForm
        value={url}
        onChange={(v) => { setUrl(v); if (fieldError) setFieldError(null); }}
        onSubmit={handleSubmit}
        error={fieldError}
        loading={status === "loading"}
      />

      <div aria-live="polite" className="sr-only">
        {status === "loading" ? "Checking the link…" : ""}
      </div>

      {status === "error" && (
        <div className="card alert-error" role="alert">
          <AlertIcon />
          <div>
            <strong>We couldn't check that link.</strong>
            <p>{requestError}</p>
            <button type="button" className="btn btn-secondary" onClick={handleSubmit}>Try again</button>
          </div>
        </div>
      )}

      {status === "loading" && (
        <div className="card skeleton" aria-hidden="true">
          <div className="sk sk-title" /><div className="sk sk-line" /><div className="sk sk-bar" />
        </div>
      )}

      <div ref={resultRef} className="result-grid">
        {result && status !== "loading" && (
          <>
            <ResultCard result={result} />
            {result.contributions.length > 0 ? (
              <ContributionChart key={result.id ?? result.url} contributions={result.contributions} />
            ) : (
              <section className="card chart-card">
                <h2>Why this verdict?</h2>
                <p className="empty">Feature details are only kept for links checked since this page was opened. Check the link again to see them.</p>
              </section>
            )}
          </>
        )}
      </div>

      <div className="section-rule"><span className="eyebrow">Session activity</span></div>

      <div className="session-grid">
        <HistoryChart items={allHistory} onSelect={selectFromHistory} />
        <HistoryList
          items={history}
          search={search}
          onSearch={setSearch}
          onClear={handleClear}
          onSelect={selectFromHistory}
          loading={historyLoading}
          error={historyError}
          selectedId={result?.id}
          clearing={clearing}
        />
      </div>

      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
