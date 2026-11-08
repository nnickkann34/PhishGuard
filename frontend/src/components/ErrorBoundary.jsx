import { Component } from "react";

// Catches any rendering crash so the user sees a helpful page, never a blank screen.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, info) {
    // Logged for developers only; nothing technical is shown to the user.
    console.error("PhishGuard crashed:", error, info.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <main className="container fallback" role="alert">
        <h1>Something went wrong</h1>
        <p>
          PhishGuard hit an unexpected problem and couldn't show this page. Your checks are safe —
          reloading usually fixes it.
        </p>
        <div className="fallback-actions">
          <button className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload the page
          </button>
          <a className="btn btn-secondary" href="/">Go to the home page</a>
        </div>
      </main>
    );
  }
}
