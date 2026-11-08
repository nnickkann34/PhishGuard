// Client-side checks, for usability only: they give instant feedback before
// anything is sent. The back end repeats every check, because an attacker can
// skip this page entirely and call the API directly.

export const MAX_URL_LENGTH = 2048;

export function validateUrl(raw) {
  const value = raw.trim();
  if (!value) return "Enter a web address to check.";
  if (value.length > MAX_URL_LENGTH) {
    return `That address is too long (${value.length} characters). The limit is ${MAX_URL_LENGTH}.`;
  }
  if (/\s/.test(value)) return "A web address can't contain spaces or line breaks.";
  if (!value.includes(".") && !value.includes(":")) {
    return "That doesn't look like a web address. Try something like example.com/login.";
  }
  return null;
}
