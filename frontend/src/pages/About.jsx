import { useEffect } from "react";
import { Link } from "react-router-dom";

export default function About() {
  useEffect(() => { document.title = "How PhishGuard works"; }, []);
  return (
    <article className="prose">
      <h1>How PhishGuard works</h1>
      <p>
        PhishGuard looks only at the text of a web address. It never visits the site, so checking a
        dangerous link here cannot harm your device.
      </p>

      <h2>The model</h2>
      <p>
        The verdict comes from an XGBoost model trained on about 860,000 labelled addresses from two
        public datasets. It looks at 26 features of the address — its length, how many subdomains it has,
        whether it uses an IP address instead of a name, whether it mentions a well-known brand outside
        that brand's own domain, suspicious words such as "verify" or "login", and so on.
      </p>
      <p>
        The "Why this verdict?" chart shows which of those features pushed the score up or down for the
        address you checked, using SHAP values calculated by the model.
      </p>

      <h2>Look-alike characters</h2>
      <p>
        Attackers sometimes swap letters for characters from other alphabets that look identical — a
        Cyrillic "а" instead of a Latin "a", for example. PhishGuard converts these back to the letters
        they imitate before scoring, and tells you when it finds them.
      </p>

      <h2>Your privacy</h2>
      <p>
        Your checks are linked to a random ID that lives only in this browser tab. Close the tab and the
        page forgets the ID; you can also clear your history at any time.
      </p>

      <h2>Limits</h2>
      <ul>
        <li>No model is perfect. A "legitimate" result is a second opinion, not a guarantee.</li>
        <li>PhishGuard can't see what a page contains, only its address.</li>
        <li>New attack styles the model hasn't seen may be missed.</li>
      </ul>

      <p><Link className="btn btn-primary" to="/">Check a link</Link></p>
    </article>
  );
}
