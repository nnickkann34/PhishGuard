import { SearchIcon } from "./Icons.jsx";

function timeLabel(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function HistoryList({
  items, search, onSearch, onClear, onSelect, loading, error, selectedId, clearing,
}) {
  return (
    <section className="card ledger" aria-labelledby="history-heading">
      <div className="chart-head">
        <h2 id="history-heading">Scan ledger</h2>
        <button
          type="button"
          className="btn btn-ghost danger"
          onClick={onClear}
          disabled={clearing || items.length === 0}
        >
          {clearing ? "Clearing…" : "Clear history"}
        </button>
      </div>
      <form className="search-row" role="search" onSubmit={(e) => e.preventDefault()}>
        <label htmlFor="history-search" className="sr-only">Search your history</label>
        <SearchIcon />
        <input
          id="history-search"
          type="search"
          placeholder="Search your checked links"
          value={search}
          maxLength={200}
          onChange={(e) => onSearch(e.target.value)}
        />
      </form>

      {error && <p className="inline-error" role="alert">{error}</p>}
      {loading && items.length === 0 ? (
        <p className="empty" aria-live="polite">Loading your history…</p>
      ) : items.length === 0 ? (
        <p className="empty">{search ? "No checked links match that search." : "Nothing here yet — links you check are saved for this browser tab only."}</p>
      ) : (
        <ul className="history-list">
          {items.map((it) => (
            <li key={it.id}>
              <button
                type="button"
                className={`history-item ${selectedId === it.id ? "selected" : ""}`}
                onClick={() => onSelect(it.id)}
                aria-current={selectedId === it.id ? "true" : undefined}
              >
                <span className={`led-dot ${it.verdict === "phishing" ? "danger" : "safe"}`} aria-hidden="true" />
                <span className="history-url">
                  <span className="sr-only">{it.verdict === "phishing" ? "Phishing" : "Legitimate"}, checked {timeLabel(it.checked_at)}: </span>
                  {it.url}
                </span>
                <span className={`led-score ${it.verdict === "phishing" ? "danger" : "safe"}`}>{Math.round(it.malicious_probability * 100)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
