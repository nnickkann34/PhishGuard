// Talks to the PhishGuard API. Every error comes back as an ApiError with a
// message that is safe to show to the user.

const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/$/, "");
const TIMEOUT_MS = 15000;
const SESSION_KEY = "phishguard-session-id";

export class ApiError extends Error {
  constructor(message, { status = 0, code = "network_error", details = null, retryAfter = null } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

// A random id per browser tab session, so each visitor sees only their own history.
export function getSessionId() {
  try {
    let id = sessionStorage.getItem(SESSION_KEY);
    if (!id) {
      id = crypto.randomUUID();
      sessionStorage.setItem(SESSION_KEY, id);
    }
    return id;
  } catch {
    // Storage blocked (private mode): fall back to an in-memory id.
    if (!getSessionId.fallback) getSessionId.fallback = crypto.randomUUID();
    return getSessionId.fallback;
  }
}

async function request(path, { method = "GET", body, signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);
  if (signal) signal.addEventListener("abort", () => controller.abort("cancelled"), { once: true });

  let response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Session-ID": getSessionId(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    if (controller.signal.reason === "timeout") {
      throw new ApiError("The server took too long to answer. Please try again.", { code: "timeout" });
    }
    if (controller.signal.reason === "cancelled") {
      throw new ApiError("Request cancelled.", { code: "cancelled" });
    }
    throw new ApiError("Can't reach the PhishGuard server. Check that it is running and try again.");
  } finally {
    clearTimeout(timer);
  }

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const err = data?.error;
    const retryAfter = Number(response.headers.get("Retry-After")) || null;
    let message = err?.message || `The server returned an error (${response.status}).`;
    if (response.status === 503 && retryAfter) {
      message = `${message} Please try again in ${retryAfter} second${retryAfter === 1 ? "" : "s"}.`;
    }
    throw new ApiError(message, {
      status: response.status,
      code: err?.code || "http_error",
      details: err?.details || null,
      retryAfter,
    });
  }
  return data;
}

export const api = {
  check: (url, signal) => request("/api/check", { method: "POST", body: { url }, signal }),
  history: (search = "") =>
    request(`/api/history${search ? `?search=${encodeURIComponent(search)}` : ""}`),
  clearHistory: () => request("/api/history", { method: "DELETE" }),
  stats: () => request("/api/stats"),
  health: () => request("/api/health"),
};
