import logo from '../assets/agh-logo-white.svg'
import ravenLogoWhite from '../assets/raven-logo-white.svg'

/** The AGH logo (white), for the black top bar. Used with the challenge authors' permission. */
export function Logo({ className = '' }: { className?: string }) {
  return <img src={logo} alt="AGH" className={className} />
}

/** The RAVEN wordmark SVG (white), for dark backgrounds such as the black top bar. */
export function RavenLogo({ className = '' }: { className?: string }) {
  return <img src={ravenLogoWhite} alt="RAVEN" className={className} />
}
