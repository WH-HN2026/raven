# Shared UI components

Building blocks for every page, after [`docs/design/README.md`](../../../docs/design/README.md). Use these instead of
hand-rolled class strings so pages stay consistent. Colours only through the tokens in `src/theme.css`
(`bg-red`, `text-muted`, `border-line`, `bg-band`, `bg-sev-high`, …); Tailwind's default palette, radii and
shadows are disabled.

## Page frame

- `Layout` (top bar + `<Outlet/>` + `Footer`) wraps every route. Pages render **their own** `PageHeader` first,
  then `Section`s. Nothing else adds padding around the page.
- `PageHeader` (`PageHeader.tsx`): black header, breadcrumb (`crumbs`, "Dashboard" is prepended), 64px light
  title, `badges` beside the title, `meta` line with a red rule, actions as children (use `onDark` buttons),
  squares band on the right.
- `Section` (`ui.tsx`): 1440px max width, 40px side padding, 48px vertical; `band` for the grey alternating
  background. `SectionHeading`: red square + 28px bold (`size="sm"` 22px; `square="green"`; `aside` for
  right-aligned links/counts).
- `FilterBar`: the grey `role="search"` form under the header; put `Field`s and a `ToggleGroup` in it.

## Controls

- `Button` / `buttonClass(variant, size, onDark)`: `primary` (red), `secondary` (outline), `danger` (red outline),
  `ghost` (link look); sizes `lg` 48px, `md` 44px, `sm` 36px. Use `buttonClass` for a `<Link>` that looks like a button.
- `ToggleGroup`: joined squares, selected is black (`role="group"`, `aria-pressed`).
- `Field` (label above, 13px medium) + `inputClass` / `textareaClass` for inputs and selects (44px, 1px dark border).
  Add `font-mono` for IPs/URLs.

## Data

- `Table` + `THeadRow` + `Th` / `Tr` + `Td`: 12px uppercase header with a 2px black rule, 1px row separators,
  first/last cells flush. `EmptyRow` for "No …" rows, `Pagination` for "1–50 of N" + Previous/Next.
- `KeyNumber` / `KeyNumbers`: coloured left rule, label, big light value (`size` lg 52px, md 30px, sm 20px), note.
- `Badge`: solid uppercase 12px. Tones: `new` (green), `changed`/`rose`, `gone` (grey), `done` (black), `red`,
  `neutral`, `outline`, `outline-dark` (on black).
- `Chip`: tags/ports/technologies; `outline` (default), `filled` (rose tag), `light` (on black).
- `SeverityLabel`: colour square + text, never colour alone.
- `EmptyState`: muted text under a black rule, for empty areas outside tables.
- `CollapsibleText`: long raw strings (banners) cut at `COLLAPSE_AT` (80) chars with an ellipsis; click toggles the full text.

## Messages

- `Alert` (`tone="error"` → `role="alert"`, `tone="ok"` → `role="status"`), `ErrorText` for query errors,
  `LineErrors` for per-line input errors, `AdminOnly` (lock + "Admin only") for read-only areas.

Copy is data, labels and actions only: no sentences explaining how the system works.
