// Placeholder "AGH" wordmark. TODO: replace with the official AGH logo from
// the visual identity book once we have a cleanly licensed file.
export function Logo({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 120 40" role="img" aria-label="AGH" className={className}>
      <rect x="0" y="0" width="40" height="40" rx="4" className="fill-brand" />
      <path d="M8 32 L20 8 L32 32 Z" className="fill-white" />
      <rect x="17" y="22" width="6" height="10" className="fill-accent" />
      <text x="48" y="29" className="fill-current" fontFamily="inherit" fontSize="22" fontWeight="700">
        AGH
      </text>
    </svg>
  )
}
