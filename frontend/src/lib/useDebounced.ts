import { useEffect, useState } from "react";

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** Random id for idempotency keys (crypto.randomUUID where available). */
export function randomId(): string {
  const c = globalThis.crypto;
  if (c?.randomUUID) return c.randomUUID();
  const b = new Uint8Array(16);
  c?.getRandomValues ? c.getRandomValues(b) : b.forEach((_, i) => (b[i] = Math.floor(Math.random() * 256)));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
