"""2.8 Advanced attack: detection evasion via homoglyph (look-alike) substitution.

Attack
------
The model scores a URL from its *characters*. An attacker who wants a phishing
URL to slip past it can replace ordinary Latin letters with visually identical
characters from other Unicode blocks — a Cyrillic 'а' (U+0430) for a Latin 'a',
a Greek 'ο' for an 'o', and so on. To a human the address looks the same; to a
naive feature extractor the tokens ("paypal", "login", "secure") no longer match
the patterns learned in training, so suspicious-word and brand features stop
firing and the phishing score drops below the 0.5 threshold — an evasion.

This is an *adversarial input* attack (brief 2.8): it manipulates the input to
defeat the model without touching the model or the server.

Defence
-------
Before any feature is computed, `normalise.py` applies Unicode NFKC, strips
invisible/zero-width characters, decodes punycode hosts, and maps known
confusables back to the Latin letters they imitate. The model therefore scores
the *canonical* address, so the homoglyph version is treated the same as the
plain one.

Measurement
-----------
We take phishing URLs the model catches when written plainly, generate homoglyph
variants at several substitution rates and random seeds, and measure the
**evasion rate** (share of variants scored 'legitimate') with normalisation OFF
vs ON. The attacker chooses homoglyphs from its own public look-alike table,
independent of the server's map — so this is a fair test, not a rigged one.
A PNG chart of the result is written next to this script.
"""
from __future__ import annotations

import json
import random
import statistics
import urllib.request
from pathlib import Path

from _harness import running_api, rule

# An attacker's own look-alike table (Latin -> visually similar non-Latin).
# Chosen independently of the server's confusables map.
ATTACKER_HOMOGLYPHS = {
    "a": "а",  # Cyrillic a
    "c": "с",  # Cyrillic s -> looks like c
    "e": "е",  # Cyrillic e
    "i": "і",  # Cyrillic i
    "j": "ј",  # Cyrillic je
    "o": "о",  # Cyrillic o
    "p": "р",  # Cyrillic r -> looks like p
    "s": "ѕ",  # Cyrillic dze -> looks like s
    "x": "х",  # Cyrillic ha -> looks like x
    "y": "у",  # Cyrillic u -> looks like y
    "d": "ԁ",  # Cyrillic komi de
    "g": "ɡ",  # Latin small script g
    "l": "ӏ",  # Cyrillic palochka small
    "n": "ո",  # Armenian vo -> looks like n
}

PHISH_URLS = [
    "http://paypal.com.secure-login.xyz/verify/account",
    "http://appleid.apple.com-verify-login.info/signin",
    "http://secure-chase-online.com/login/update/account",
    "http://amazon-account-security-check.com/signin/verify",
    "http://netflix-billing-update.com/account/login/confirm",
    "http://microsoft-support-login.com/verify/password/reset",
    "http://facebook-security-alert.com/login/confirm/identity",
    "http://wellsfargo-online-verify.com/account/signin/update",
    "http://bankofamerica-secure-alert.net/login/verify",
    "http://instagram-copyright-appeal.com/verify/login/account",
]

RATES = [0.3, 0.5, 0.8, 1.0]      # fraction of eligible letters replaced
SEEDS = list(range(8))            # repeats per (url, rate)


def homoglyph(url: str, rate: float, rng: random.Random) -> str:
    out = []
    for ch in url:
        low = ch.lower()
        if low in ATTACKER_HOMOGLYPHS and rng.random() < rate:
            out.append(ATTACKER_HOMOGLYPHS[low])
        else:
            out.append(ch)
    return "".join(out)


def check(base: str, url: str) -> dict:
    data = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        f"{base}/api/check", data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def measure(label: str, normalise: bool):
    env = {"PG_NORMALISE_HOMOGLYPHS": "true" if normalise else "false"}
    with running_api(label, env) as base:
        # Keep only URLs the model actually catches when written plainly.
        caught = []
        for u in PHISH_URLS:
            if check(base, u)["verdict"] == "phishing":
                caught.append(u)
        print(f"\n  {label}")
        print(f"    phishing URLs caught when written plainly: {len(caught)}/{len(PHISH_URLS)}")

        by_rate: dict[float, list[int]] = {r: [] for r in RATES}
        for u in caught:
            for rate in RATES:
                for seed in SEEDS:
                    rng = random.Random(f"{u}|{rate}|{seed}")
                    variant = homoglyph(u, rate, rng)
                    evaded = check(base, variant)["verdict"] == "legitimate"
                    by_rate[rate].append(1 if evaded else 0)

        rates_out = {}
        for rate in RATES:
            flags = by_rate[rate]
            er = 100 * statistics.mean(flags) if flags else 0.0
            rates_out[rate] = er
            print(f"    substitution {int(rate*100):3d}%  ->  evasion rate {er:5.1f}%  "
                  f"({sum(flags)}/{len(flags)} variants slipped through)")
        return len(caught), rates_out


def make_chart(off: dict, on: dict, path: Path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # noqa: BLE001
        print(f"  (chart skipped: matplotlib unavailable: {e})")
        return
    xs = [int(r * 100) for r in RATES]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(xs, [off[r] for r in RATES], "o-", color="#c2410c", linewidth=2, label="Normalisation OFF (vulnerable)")
    ax.plot(xs, [on[r] for r in RATES], "s-", color="#0f766e", linewidth=2, label="Normalisation ON (defended)")
    ax.set_xlabel("Share of letters replaced with look-alikes (%)")
    ax.set_ylabel("Evasion rate (% scored 'legitimate')")
    ax.set_title("Homoglyph evasion vs. Unicode normalisation")
    ax.set_ylim(-3, 103)
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print(f"\n  Chart written to {path}")


def main():
    rule("2.8  DETECTION EVASION  —  homoglyph substitution")
    print("Scenario: an attacker rewrites caught phishing URLs with look-alike\n"
          "Unicode characters to push the model's score below the threshold.")

    n_off, off = measure("NORMALISATION OFF (vulnerable)", normalise=False)
    n_on, on = measure("NORMALISATION ON (defended)", normalise=True)

    rule("SUMMARY")
    print(f"{'substitution rate':>20}{'evasion OFF':>14}{'evasion ON':>14}")
    for r in RATES:
        print(f"{int(r*100):>18}% {off[r]:>12.1f}%{on[r]:>13.1f}%")
    worst_off = max(off.values())
    worst_on = max(on.values())
    print(f"\n  Peak evasion with normalisation OFF: {worst_off:.1f}%")
    print(f"  Peak evasion with normalisation ON:  {worst_on:.1f}%")
    print("\nReading: without normalisation, homoglyph variants evade detection at a\n"
          "high rate. With NFKC + confusable mapping applied before feature\n"
          "extraction, the variants collapse back to the plain address and evasion\n"
          "falls to near zero.")

    make_chart(off, on, Path(__file__).resolve().parent / "evasion_result.png")


if __name__ == "__main__":
    main()
