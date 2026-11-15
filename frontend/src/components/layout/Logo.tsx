export function LogoMark({ className = "size-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <path d="M16 2 4 6.5v8.2c0 7.3 5.1 13.6 12 15.3 6.9-1.7 12-8 12-15.3V6.5L16 2Z" fill="var(--primary)" />
      <path
        d="M11 22V10h5.2a3.9 3.9 0 0 1 0 7.8H13.4"
        fill="none"
        stroke="var(--primary-foreground)"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="flex items-center gap-2">
      <LogoMark />
      <span className="text-[15px] font-semibold tracking-[0.12em]">PATHOS</span>
    </span>
  );
}
