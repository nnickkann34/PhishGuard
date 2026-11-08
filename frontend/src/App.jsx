import { NavLink, Route, Routes } from "react-router-dom";
import Home from "./pages/Home.jsx";
import About from "./pages/About.jsx";
import NotFound from "./pages/NotFound.jsx";
import { ShieldIcon } from "./components/Icons.jsx";

export default function App() {
  return (
    <>
      <a className="skip-link" href="#main">Skip to main content</a>
      <header className="site-header">
        <div className="container header-inner">
          <NavLink to="/" className="brand" aria-label="PhishGuard home">
            <span className="brand-mark"><ShieldIcon width={17} height={17} /></span>
            <span className="brand-name">PhishGuard</span>
            <span className="brand-tag">URL Threat Analysis</span>
          </NavLink>
          <nav aria-label="Main">
            <NavLink to="/" end>Analyze</NavLink>
            <NavLink to="/about">How it works</NavLink>
            <span className="status-pill">Model online</span>
          </nav>
        </div>
      </header>
      <main id="main" className="container" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
      <footer className="site-footer">
        <div className="container">
          <p>PhishGuard reads addresses as text only and never visits them. It is a second opinion,
          not a guarantee — if in doubt, don't click.</p>
          <p className="mono-note">phishguard · xgboost url classifier · reads addresses as text, never fetches them</p>
        </div>
      </footer>
    </>
  );
}
