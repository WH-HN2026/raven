import { useState } from 'react'

/** Texts longer than this are collapsed to their first COLLAPSE_AT characters. */
export const COLLAPSE_AT = 80

/**
 * Long raw strings (service banners, fingerprints): collapsed to the first
 * COLLAPSE_AT characters with an ellipsis; clicking toggles the full text.
 * Short texts render as plain text.
 */
export function CollapsibleText({ text, label = 'Banner' }: { text: string; label?: string }) {
  const [open, setOpen] = useState(false)
  if (text.length <= COLLAPSE_AT) return <>{text}</>
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-label={open ? `${label}: show less` : `${label}: show all`}
      onClick={() => setOpen((v) => !v)}
      className="block w-full cursor-pointer border-0 bg-transparent p-0 text-left font-[inherit] text-[length:inherit] text-inherit break-all hover:underline focus-visible:outline-2 focus-visible:outline-black"
    >
      {open ? text : text.slice(0, COLLAPSE_AT) + '…'}
      <span aria-hidden className="ml-1 text-red">
        {open ? '▴' : '▾'}
      </span>
    </button>
  )
}
