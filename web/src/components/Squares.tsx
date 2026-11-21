import full from '../assets/agh-squares.svg'
import masthead from '../assets/agh-squares-masthead.svg'

/**
 * The AGH squares band (docs/design/canvas/Squares.dc.html).
 * masthead: right half of the decor, beside the page title on black.
 * footer: the whole decor mirrored, straddling the white/black edge.
 */
export function Squares({ variant = 'masthead', className = '' }: { variant?: 'masthead' | 'footer'; className?: string }) {
  return (
    <img
      src={variant === 'footer' ? full : masthead}
      alt=""
      aria-hidden
      className={'block h-auto w-full ' + (variant === 'footer' ? '-scale-x-100 ' : '') + className}
    />
  )
}
