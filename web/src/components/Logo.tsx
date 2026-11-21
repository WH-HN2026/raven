import logo from '../assets/agh-logo-white.svg'

/** The AGH logo (white), for the black top bar. Used with the challenge authors' permission. */
export function Logo({ className = '' }: { className?: string }) {
  return <img src={logo} alt="AGH" className={className} />
}
