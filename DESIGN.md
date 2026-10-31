---
name: SentinelStream
description: A live intrusion-detection console read like a warning bulletin. The level leads, and an alert visibly expires once its 30 s window closes.
colors:
  page: "#f3f5f8"
  surface: "#ffffff"
  sunk: "#e9edf2"
  ink: "#141b24"
  muted: "#4a5666"
  hairline: "#d3dae3"
  edge: "#7b8796"
  accent: "#2447c2"
  accent-tint: "#e8edfb"
  sev-high: "#b42318"
  sev-high-tint: "#fdecea"
  sev-high-ink: "#8a1a11"
  sev-medium: "#b54708"
  sev-medium-tint: "#fef0db"
  sev-medium-ink: "#7a3406"
  sev-low: "#0e7490"
  sev-low-tint: "#e3f3f7"
  sev-low-ink: "#0b4f63"
  live: "#17703a"
  live-tint: "#e4f5ea"
  stale: "#8a5300"
  stale-tint: "#fcf1d6"
  changed: "#fff3c4"
typography:
  wordmark:
    fontFamily: "Public Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "22px"
    fontWeight: 700
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Public Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.556
  body:
    fontFamily: "Public Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.429
    fontFeature: "\"tnum\""
  label:
    fontFamily: "Public Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.333
  data:
    fontFamily: "JetBrains Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "13px"
    fontWeight: 400
  count:
    fontFamily: "JetBrains Mono Variable, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
  full: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
components:
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lg}"
    padding: "16px"
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "8px 12px"
  button-primary-disabled:
    backgroundColor: "{colors.sunk}"
    textColor: "{colors.muted}"
  button-quiet:
    textColor: "{colors.accent}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "36px"
  button-quiet-hover:
    backgroundColor: "{colors.accent-tint}"
  tab:
    textColor: "{colors.muted}"
    rounded: "{rounded.md}"
    padding: "6px 12px"
  tab-hover:
    backgroundColor: "{colors.sunk}"
    textColor: "{colors.ink}"
  tab-selected:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
  select:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "36px"
  level-chip-high-active:
    backgroundColor: "{colors.sev-high}"
    textColor: "{colors.surface}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "2px 8px"
  level-chip-medium-tint:
    backgroundColor: "{colors.sev-medium-tint}"
    textColor: "{colors.sev-medium-ink}"
    rounded: "{rounded.sm}"
    padding: "2px 8px"
  level-chip-low-tint:
    backgroundColor: "{colors.sev-low-tint}"
    textColor: "{colors.sev-low-ink}"
    rounded: "{rounded.sm}"
    padding: "2px 8px"
  level-chip-expired:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    rounded: "{rounded.sm}"
    padding: "2px 8px"
  level-block:
    rounded: "{rounded.md}"
    padding: "8px 12px"
    width: "176px"
    height: "64px"
  status-pill-live:
    backgroundColor: "{colors.live-tint}"
    textColor: "{colors.live}"
    rounded: "{rounded.full}"
    padding: "4px 12px"
  status-pill-stale:
    backgroundColor: "{colors.stale-tint}"
    textColor: "{colors.stale}"
    rounded: "{rounded.full}"
    padding: "4px 12px"
  status-pill-offline:
    backgroundColor: "{colors.sunk}"
    textColor: "{colors.ink}"
    rounded: "{rounded.full}"
    padding: "4px 12px"
---

# Design System: SentinelStream

## Overview

**Creative North Star: "The Warning Bulletin"**

Every alert reads as a bulletin in effect. Its level comes first, as a word plus an icon, and it visibly lapses when the backend's 30 s aggregation window after its last activity closes. The console is cool paper with white panels, ink type and fine hairlines, so the only saturated colour on a calm screen is severity. When nothing is wrong, the screen is quiet.

The density suits someone working in other tabs who glances over: one header line, a strip of three level counts that doubles as the filter, then a 2:1 grid with the alert table on the left and a stack of evidence panels on the right. State is carried by form as well as hue. A solid chip means in effect and an outline chip means expired, a draining rail counts down the window, and a row whose count grew stays lit until someone looks at it. Every number is mono, and every score names the detector that produced it.

Light only. Public Sans and JetBrains Mono are self-hosted, icons are lucide-react, and nothing loads from outside (strict CSP).

**Key Characteristics:**
- Cool paper page, white hairline panels, ink text, no shadows.
- Severity owns saturation. Blue is reserved for things you can press, and for focus.
- Loudness follows urgency: only an in-effect High is solid.
- State by form: solid, tint or outline chips, a draining rail, and held "New / Updated" marks.
- Mono for addresses, times and counts. Public Sans for everything else.

## Colors

A cool, near-neutral paper ground. Three severity hues and two connection-status hues are the only saturated colours.

### Primary
- **Press Blue** (`accent`): the selected view tab, the primary Analyse/Save buttons, quiet text buttons (Clear filters, Browse files), the drop zone while dragging, the pressed ring on a level block, the 2px focus outline, the caret and native accent-color. **Press Blue Tint** (`accent-tint`) is the hover ground for quiet buttons and the text selection colour.

### Secondary (severity)
- **High Signal Red** (`sev-high`): the solid fill of an in-effect High chip and level block, the High icon on neutral grounds, and the High rail. **High Tint / High Ink** (`sev-high-tint`, `sev-high-ink`) pair for tinted High chips (history), error text and failed upload status.
- **Medium Rust Amber** (`sev-medium`): the Medium icon and rail. Tint/ink pair for Medium chips and blocks. The "no model loaded" banner also uses this pair.
- **Low Deep Teal** (`sev-low`): the Low icon and rail. Tint/ink pair for Low chips and blocks.

### Tertiary (connection status)
- **Live Green** (`live` on `live-tint`): only the Live status pill and its pulsing dot.
- **Stale Ochre** (`stale` on `stale-tint`): the Stale pill, the held-counts note and a stopped chart's label.
- **Changed Butter** (`changed`): the ground of a row that is new or grew, held until it is hovered for 700 ms or focused.

### Neutral
- **Cool Paper** (`page`): the page, the "Expired" divider row, the ring offset.
- **White Panel** (`surface`): panels, inputs, outline chips.
- **Sunk Slate** (`sunk`): table header, open row, detail well, hover ground for neutral controls, offline pill and banner. At 60% opacity it is the chart ground.
- **Ink** (`ink`): text, both chart series, bar labels.
- **Slate Muted** (`muted`): secondary text, expired-row text, axis ticks, unselected tabs.
- **Hairline** (`hairline`): 1px panel borders, row rules, chart grid, outline chips, rail track.
- **Edge** (`edge`): borders on inputs, selects and the drop zone (3.6:1 on white), scrollbars, the frozen rail.

### Named Rules
**The Severity Owns Saturation Rule.** On a calm screen, the only saturated colour comes from the three severity hues. Charts are ink on a sunk ground and never colour-code categories.

**The Pressable Blue Rule.** Accent blue appears only on controls that can be pressed and on focus. It never decorates text, headings or data.

**The Mirrored Literal Rule.** Recharts cannot read CSS variables, so `TrafficChart.tsx` and `AttackDistribution.tsx` each declare literal hex constants (INK `#141b24`, MUTED `#4a5666`, HAIRLINE `#d3dae3`, SUNK `#e9edf2`) that mirror `index.css` `@theme`. A token change in `index.css` must be made in both chart files in the same commit.

## Typography

**Display Font:** none. The wordmark is Public Sans Variable at 700.
**Body Font:** Public Sans Variable (with ui-sans-serif, system-ui)
**Label/Mono Font:** JetBrains Mono Variable (with ui-monospace, SFMono-Regular, Menlo)

**Character:** Public Sans is a sober civic sans for words. JetBrains Mono is a tool face reserved for what gets compared digit by digit. Tabular numerals are set globally on body.

### Hierarchy
- **Wordmark** (700, 22px, tight tracking): "SentinelStream" in the header. Used once.
- **Title** (600, 18px): panel and strip headings (Alerts, In effect now, Packets per second, Attack types, Analyse a capture file).
- **Body** (400, 14px): table cells, panel descriptions, banners, buttons (500 to 600 on controls). `p` and `li` use `text-wrap: pretty`.
- **Label** (500, 12px): filter labels, table header, detail `dt` labels, chip text (600), rail text.
- **Data** (mono 400, 13px): endpoints, times, repeat counts, file names, chart labels. Chart ticks are mono at 12px.
- **Count** (mono 600, 24px, line-height 1): the in-effect number in each level block.

### Named Rules
**The Mono Means Data Rule.** JetBrains Mono is used only for addresses, ports, times, counts, file names and code paths. Labels and prose are always Public Sans.

**The Sentence Case Rule.** Labels, headings and chips are sentence case with normal tracking. The system has no uppercase labels and no tracked-out labels.

## Layout

A centred column up to 1440px wide, with 16px padding (24px horizontal from 640px). Vertical rhythm is a 16px stack between header, notes, strip and grid. The header is one wrapping flex row (wordmark, view tabs, status pill pushed right) over a hairline rule. From 1024px the main grid splits `minmax(0,2fr) minmax(0,1fr)`: alerts on the left, a 16px stack of the traffic chart, attack types and upload on the right. Below that the grid is one column. `grid-cols-1` is required so the table cannot widen the column on phones.

The in-effect strip is three equal blocks on phones and fixed 176px blocks from 640px. From 1280px the alert table has six columns: Level | Attack | Source → destination | Repeats | Evidence | Last activity. Below 1280px each row becomes a two-line grid (level, attack, time, then endpoints and evidence), with the header kept for screen readers only, so nothing time-critical is cut off. Panels pad 16px, the token form pads 24px, controls pad 8 to 12px, and the gap between chips and blocks is 8px.

## Elevation & Depth

Flat. There are no box shadows anywhere. Depth is tonal: page, then white panel, then sunk wells (table header, open row, detail well, chart ground), separated by 1px hairlines. Rings stand in for borders on pills, empty level blocks and banners. The only offset effect is the pressed level block's 2px accent ring with a 2px page-coloured offset.

### Named Rules
**The Hairline Not Shadow Rule.** Separate surfaces with a 1px hairline or a tonal step, never with a shadow.

## Shapes

Gently rounded, and tighter on smaller things. Chips, inputs, selects and buttons use 4px. Level blocks, view tabs, the detail card, banners and the drop zone use 6px. Panels use 8px. The status pill is fully round, which keeps it apart from the chips. Bars have a 3px radius on the value end only. The drop zone is the only dashed border (2px).

## Components

### Buttons
- **Shape:** small radius (4px).
- **Primary:** Press Blue with white 14px semibold text, 8px by 12 to 16px. Hover is the accent at 90%. Disabled is sunk with muted text.
- **Quiet:** accent text with no fill, at least 36px tall. Hover fills with accent tint (Clear filters). Browse files is the bordered variant: edge border, white, accent text.
- **Icon:** 32px square, muted, sunk on hover (close details).
- **Focus:** a 2px accent outline with a 2px offset everywhere.

### Chips (level chips)
- **Style:** a word plus a lucide icon whose shape differs per level (ShieldAlert, TriangleAlert, Info), 12px semibold, 2px by 8px, 4px radius.
- **State:** an in-effect High is solid red with white text. In-effect Medium/Low and uploaded history use the tint ground with on-tint ink. Expired is a white outline with a hairline border, muted text and only the icon in the level hue.

### Cards / Containers
- **Corner Style:** 8px.
- **Background:** white on cool paper.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px hairline.
- **Internal Padding:** 16px. Panel headings are 18px semibold with an optional 14px muted line below.

### Inputs / Fields
- **Style:** 1px edge border, white, 4px radius, at least 36px tall. The token input is mono.
- **Focus:** the global accent outline.
- **Error:** a 14px message in `sev-high-ink`, announced with role=alert. The submit button is disabled while the file is invalid.

### Navigation
- **View tabs:** Live, plus one tab per finished upload. 14px medium, 6px radius. Selected is accent with white text. Others are muted, with sunk ground and ink on hover. Arrow keys move between tabs, and long names truncate at 192px.
- **Status pill:** fully round, 14px medium, an icon plus words. Live is green tint with a pulsing dot. Stale is ochre tint. Offline is sunk with an edge ring. Waiting is white with a hairline ring. The visible text changes every second, so the live region gets only the state word.

### In-Effect Strip (signature)
Three level blocks, each with an icon, a word and a 24px mono count. A High block is solid while High alerts are in effect. Medium/Low blocks use the tint. An empty block, or any block while data is frozen, turns white with a hairline ring and a muted label. A block is a toggle filter (`aria-pressed`, accent ring when pressed). The heading reads "In effect now", "In effect as of HH:MM:SS" when frozen, or "In this capture".

### Alert Row and Expiry Rail (signature)
Expired rows mute their text, and one "Expired: no activity for 30 s" divider row on the page ground separates them from live ones. An in-effect row shows a 48 by 2px rail in its level hue that drains over the window, with "N s left" beside it. The rail turns edge grey and says "held" while frozen. A new or grown row takes the `changed` ground and a hairline-ringed "New" or "Updated" tag until it is seen. The attack name is an underlined disclosure button (hairline underline, ink on hover) that opens the detail in place.

### Evidence Detail
A white 6px card in a sunk well under its row. Labelled segments sit in a 2-column grid (3 from 640px) with hairline rules, a 12px muted label over a 14px value, and spans chosen so no row ends in an empty cell. Evidence always spells out its detector's meaning.

### Charts
Both charts share one ground, axis style and ink: a sunk ground at 60%, hairline grid, muted 12px ticks, and an ink series (a 1.75px line, or 16px bars with mono value labels). No legends, no animation, no category colour. A stale traffic chart drops to 50% opacity and its label says when the data stopped.

## Do's and Don'ts

### Do:
- **Do** put the level first, as a word plus its icon, and reserve a solid fill for an in-effect High.
- **Do** show state by form as well as hue: solid, tint or outline chips, the draining rail, and the held "New / Updated" marks.
- **Do** set addresses, times and counts in JetBrains Mono at 13px. Body is Public Sans 14px with tabular numerals.
- **Do** separate surfaces with 1px hairlines (`hairline`) and tonal steps (page, then surface, then sunk).
- **Do** update the literal hex constants in both chart files whenever an `index.css` colour token changes.
- **Do** freeze, rather than decay, any "in effect" judgement while data is not arriving, and say so in Stale Ochre.

### Don't:
- **Don't** use accent blue on anything that cannot be pressed.
- **Don't** colour-code chart series or categories. Bars encode magnitude in ink.
- **Don't** add shadows. Depth is tonal.
- **Don't** show a detector score as one bare percentage. Each score names its detector and its meaning.
- **Don't** add uppercase or tracked-out labels, or eyebrow text above headings.
- **Don't** add a dark theme (AGENTS.md: light only).
