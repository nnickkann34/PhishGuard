import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";

export default function NotFound() {
  const { pathname } = useLocation();
  useEffect(() => { document.title = "Page not found — PhishGuard"; }, []);
  return (
    <section className="fallback">
      <p className="eyebrow">Error 404</p>
      <h1>We couldn't find that page</h1>
      {/* The path is shown as plain text (React escapes it). */}
      <p>There's nothing at <code>{pathname}</code>. It may have moved, or the address may have a typo.</p>
      <div className="fallback-actions">
        <Link className="btn btn-primary" to="/">Check a link</Link>
        <Link className="btn btn-secondary" to="/about">How it works</Link>
      </div>
    </section>
  );
}
