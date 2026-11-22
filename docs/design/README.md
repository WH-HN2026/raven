# RAVEN — UI design reference

**Source of truth:** the Claude Design canvas https://claude.ai/artifact/PESJcHPukpJRU98snr4Zon (private; ask a teammate to share it with you). This folder is a snapshot of it, so agents can read the design without access to the canvas. If the canvas changes, re-export it here.

The look follows agh.edu.pl. The challenge authors gave us permission to use the AGH visual identity and logo.

## Contents

| Path | What |
|---|---|
| `canvas/*.dc.html` | One file per screen or shared component, in Claude Design's format: HTML with inline styles, plus sample data in the `<script>` at the bottom. **Reference only, not production code.** The files need the Claude Design runtime (`support.js`, not included) to render. Read the markup and styles and rebuild them as React components. |
| `canvas/canvas.json` | Canvas layout: which screens exist and their titles. |
| `assets/agh-logo-white.svg` | AGH logo (mark + "AGH"), white, for the black top bar. |
| `assets/agh-squares.svg` | AGH squares band, the decor artwork from agh.edu.pl. |
| `assets/raven-logo-black.svg` | RAVEN wordmark (E drawn as a feather), black, for light backgrounds. |
| `assets/raven-logo-white.svg` | RAVEN wordmark, white, for dark backgrounds (e.g. the black top bar). |
| `assets/raven-favicon.svg` | Favicon: black feather E on an AGH-red square. Copy of `web/public/favicon.svg`. |
| `assets/raven-favicon-1000.png` | The favicon rendered as a 1000×1000 PNG (avatars, social images). |

| Screen | File | Route (suggested) |
|---|---|---|
| Dashboard | `Main.dc.html` | `/` |
| Hosts | `Hosts.dc.html` | `/hosts` |
| Host detail | `HostDetail.dc.html` | `/hosts/:ip` |
| Findings | `Findings.dc.html` | `/findings` |
| Changes – compare runs | `Changes.dc.html` | `/changes` |
| Targets & scope | `Targets.dc.html` | `/targets` |
| Runs & schedules | `Scans.dc.html` | `/runs` |
| Top bar (shared) | `Nav.dc.html` | layout |
| Footer (shared) | `Footer.dc.html` | layout |
| Squares band (shared) | `Squares.dc.html` | component |

Not designed yet: Signatures, Import/Export, Users. Build them from the same patterns.

## Tokens (put these in `web/src/theme.css`)

```css
:root {
  --agh-red: #C10D14;        /* primary buttons, active nav bar, section bullets, accent rules */
  --agh-black: #000000;      /* top bar, page header, footer, selected toggles, table header rule */
  --text: #212121;
  --text-secondary: #505157; /* labels, meta text (7.5:1 on white) */
  --text-on-dark: #D8D7D7;
  --text-on-dark-muted: #BDBDBD;
  --border: #DEDEDE;         /* row separators */
  --border-strong: #212121;  /* inputs, outlined buttons and chips */
  --band: #EDEDED;           /* alternating full-width section background */
  --agh-green: #006837;      /* new / up / done / high confidence */
  --agh-rose: #F9BEAD;       /* changed / re-probed / running / medium confidence */
  --sev-critical: #C10D14;
  --sev-high: #E35205;
  --sev-medium: #E8A800;
  --sev-low: #2F6DB5;
  --sev-info: #808187;
  --heat-0: #EDEDED; --heat-1: #CFE3D3; --heat-2: #8DC29B; --heat-3: #2E8A4F; --heat-4: #006837;
  --font-sans: Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: "Roboto Mono", monospace;
  --radius: 0;
}
```

Fonts: Roboto 300/400/500/700 and Roboto Mono 400/500. Self-host them (e.g. `@fontsource/roboto`) so the app works offline in the lab.

## Rules

- **Square corners everywhere:** buttons, inputs, badges, cards, bars, heatmap cells. No shadows, no gradients.
- **Page frame:**
  - black top bar (80px: logo, RAVEN wordmark, nav, DefectDojo link, user + role badge);
  - black page header (breadcrumb, 64px Roboto Light title, actions, squares band on the right);
  - content;
  - footer: the mirrored squares band across the white/black edge, then one status line.
- **Content width:** max 1440px, 40px side padding. Sections alternate white and `--band`.
- **Section heading:** a 10×10 red square + Roboto Bold 28px (22px in narrow columns).
- **Key numbers:** a 2px coloured left rule, a 14px label, a 52px Roboto Light value, an optional 13px note.
- **Tables:**
  - header row: 12px uppercase, letter-spacing 0.06em, `--text-secondary`, 2px black bottom border;
  - rows: 1px `--border` separators;
  - IPs, ports, URLs and headers in mono.
- **Badges:** solid, uppercase 12px. `+ NEW` green/white, `~ CHANGED` rose/black, `− GONE` grey/black, `DONE` black/white, `SUSPENDED` rose. Severity is always a colour square plus its text label, never colour alone.
- **Buttons:**
  - primary: red with white text, 48px tall;
  - secondary: 1px outline (white on black, black on white);
  - destructive: red outline;
  - toggle groups are joined squares, and the selected one is black.
- **Inputs:** 44px tall, 1px `#212121` border, labels above in 13px medium.
- **Links:** text colour, red underline; hover turns red.
- **Role-aware UI:** hide controls the role can't use, and show a lock + "Admin only" where a read-only area needs explaining. Only admins see Users in the nav. The backend still enforces everything (see architecture §6).
- **Copy: data, labels and actions only.** No sentences explaining how the system works (encryption, write-through to Dojo, re-probing, scheduling rules). Those go in the docs.
