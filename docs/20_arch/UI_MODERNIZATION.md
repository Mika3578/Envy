# Envy desktop UI modernization architecture

Status: **PLANNED** (Phase 0 audit complete; Phase 1+ not started)  
Last updated: 2026-09-20  
Tracker: [#295](https://github.com/Mika3578/Envy/issues/295)  
Audit base: `develop` @ `d3095e97f2ddb1b5a654a7eee41441c7d0cdd1ae`

This document is the single source of truth for progressive modernization of the
**Windows MFC** desktop UI. Labels used below:

| Label | Meaning |
| --- | --- |
| VERIFIED CURRENT IMPLEMENTATION | Confirmed in current `develop` source |
| OBSERVED DEFECT | Seen in runtime screenshots and/or code |
| HYPOTHESIS | Plausible cause; needs runtime confirmation |
| RECOMMENDATION | Proposed direction |
| IMPLEMENTED | Landed on `develop` |
| PARTIAL | Some work done; remainder open |
| PLANNED | On the staged PR sequence; not started |
| NOT SUPPORTED | Explicitly out of scope |

Do **not** claim “UI modernization complete” after one or two screens.

---

## 1. Non-goals

- **NOT SUPPORTED:** Replace MFC with Qt, WinUI, WPF, or any other toolkit
- **NOT SUPPORTED:** Protocol / wire-format changes as part of UI PRs
- **NOT SUPPORTED:** Big-bang rewrite of `WindowManager` / all workspaces
- **NOT SUPPORTED:** Silently breaking the skin XML contract
- **NOT SUPPORTED:** Inventing Transfer tags/categories UI without core model (#232 owns that)
- **NOT SUPPORTED:** Claiming Linux/macOS UI support (MFC Windows frontend only)

---

## 2. Preflight snapshot (2026-09-20)

### Develop

- SHA: `d3095e97f2ddb1b5a654a7eee41441c7d0cdd1ae`
- Local matched `origin/develop` at audit time

### Open development PRs (cap = 3)

| PR | Title | Branch |
| --- | --- | --- |
| #292 | refactor(hashstring): drop register storage class (#84) | `refactor/hashstring-drop-register` |
| #293 | chore(workflow): consolidate agent rules and strict review policy | `chore/consolidate-agent-workflow` |
| #294 | test(interop): prepare current ED2K/Kad live evidence runs (#160) | `test/ed2k-kad-live-interop-evidence` |

Phase 0/1 PRs must wait until capacity is &lt; 3 (AGENTS.md hard rule 13).

### Existing UI / DPI work already merged (reuse)

| PR | Title | Precedent to reuse |
| --- | --- | --- |
| #134 | CoolMenu selection double-band under scaled items | `SCALE()` on owner-draw geometry; stretch one skin state |
| #135 | Clamp Search panel width to `SCALE(200)` | Per-window floor without raising global `SidebarWidth` |
| #137 | Search panel layout font/DPI aware | Font metrics + progressive Y layout |
| #138 | Skin engine P0 metrics hardening | Strict metric parse/clamp; HiDPI logical units deferred |
| #176 | System/Network log top-align (`CTextCtrl`) | Viewport helpers + EnvyTests |

### Related branches / docs

- No existing `docs/ui-modernization-plan` or `fix/ui-adaptive-network-lists` branch
- No prior dedicated UI-modernization architecture doc under `docs/20_arch/`
- Skin metrics remain pixel-oriented settings (`ToolbarHeight` 28, `GroupsbarHeight` 24, `HeaderbarHeight` 64, `SidebarWidth` default `SCALE(200)`, `RowSize` default `SCALE(17)`, `Splitter` 6)

---

## 3. Design target (references only)

Use a restrained combination of:

- **Windows / Fluent** principles for hierarchy, spacing, navigation, command placement
- **qBittorrent** density for transfer/peer tables and filters
- **Transmission** for simplicity where advanced chrome is unnecessary
- **BiglyBT / AirDC++** for power-user organization patterns
- **Historical Envy / Shareaza** only where needed for multi-network semantics

Do not copy competing clients’ code. Do not add WinUI merely to imitate Fluent.

---

## 4. Screen-by-screen architecture map

### 4.1 Shell / navigation — OBSERVED DEFECT + VERIFIED

| Layer | Primary files | Notes |
| --- | --- | --- |
| Menu bar | `WndMain.*` | Standard MFC menus |
| Document / profile tab strip | `CtrlMainTabBar.*` | e.g. `groland [33/33]` |
| Main workspace toolbar | `CtrlCoolBar.*`, `CoolInterface.*` | Large icon+text: Home, Transfers, Network, … |
| Panel chrome | `WndPanel.*` | Yellow header; plain-text “Close” when unskinned |
| Window manager | `WindowManager.*` | Child workspace lifecycle |

**OBSERVED:** Four vertical navigation layers before content. Search appears in multiple places. Protocol selectors and actions share bottom bars on Network panes.

**PLANNED target navigation** (Phase 2+; map functions, do not delete):

```
Home
Search
Transfers
Library
Network
  Connections   → Neighbors (current peers/hubs/servers)
  Discovery     → Host Cache (G1/G2/ED2K/Kad/DC/BT as supported)
  Diagnostics   → System log, traffic, packet/search monitors
Media
Chat
Settings
```

Do not confuse **protocol** with **discovery mechanism**.

### 4.2 Network — Neighbors — VERIFIED + OBSERVED DEFECT

- Files: `WndNeighbours.*`, `LiveList.*`, `LiveListSizer.*`
- Default columns (current `develop`): Address 110, Port 42, Time 56, Traffic 84, Total 96, Packets 70, Flow 0, Leaves 52, Mode 84, Client 110, Name 100, Country 54
- `OnSize` → `SizeListAndBar` only (list + toolbar chrome); no adaptive fill
- Persistence: `Settings.LoadList` / `SaveList` (`CNeighboursWnd`) for widths/order/sort
- `CLiveListSizer` attached **without** `bScale`; gated by `Settings.General.SizeLists` default **false**

### 4.3 Network — Host Cache — VERIFIED + OBSERVED DEFECT

- Files: `WndHostCache.*`
- Default columns: Address 140, Port 60, Last Seen 128, Failures 60, CurUsers 60, MaxUsers 60, Name 140, Description 140, Client 100, Country 60 (+ debug cols width 0)
- Same `SizeListAndBar` / non-adaptive behavior
- Protocol view modes (selectors must expose only real support): **G2, G1, ED2K, Kad, DC, BT**, plus “all” (`PROTOCOL_NULL`)
- Persistence: `CHostCacheWnd` list state

### 4.4 Network — System / Discovery — PARTIAL interest

- `WndSystem.*` — log (`CTextCtrl`); top-align fixed in #176
- `WndDiscovery.*` — discovery services list; same list/bar pattern

### 4.5 Transfers — PLANNED (Phase 3)

- Files: `WndDownloads.*`, `WndUploads.*`, `CtrlDownloads.*`, `CtrlUploads.*`, `CtrlDownloadTabBar.*`
- Uses `GroupsbarHeight` + `ToolbarHeight`; fragmented top/bottom command areas
- Target: compact command bar, optional categories sidebar **only when #232 core exists**, main table, optional details; no fake protocol-only tabs

### 4.6 Home — PLANNED (Phase 4)

- Files: `WndHome.*`, `CtrlHome*.*`
- Fixed `SidebarWidth` split; large branding banner (`HeaderbarHeight`)
- Target compact dashboard: connection summary, speeds, quick search, add link/torrent, recent activity/library, actionable warnings — **no fake core data**

### 4.7 Library — PLANNED (Phase 5)

- Files: `WndLibrary.*`, `CtrlLibraryFrame.*`, `CtrlLibrary*View.*`, `CtrlLibrary*Panel.*`
- Visually fragmented bars; preserve storage/indexing semantics

### 4.8 Settings — PLANNED (Phase 6)

- Existing settings pages; navigation/layout only in that phase

### 4.9 Media — PLANNED (Phase 7)

- Files: `WndMedia.*`, `CtrlMediaFrame.*`, `CtrlMediaList.*`
- Historical fixed geometry, tiny controls, dark surface vs yellow chrome

### 4.10 Chat / IRC — PLANNED (Phase 8)

- Files: `WndIRC.*`, `CtrlIRCFrame.*`, `WndChat.*`, `CtrlPrivateChatFrame.*`
- Task-pane style; manual layout; `EDIT_HEIGHT` / toolbar stacks

### 4.11 Scalable assets — PLANNED (Phase 9)

- Audit licenses, skin compatibility, resource loading **before** bulk icon work
- Prefer multi-resolution assets compatible with current MFC/skin pipeline

---

## 5. Fixed geometry / DPI inventory (selected)

| Token / pattern | Location / default | Status |
| --- | --- | --- |
| `SCALE(size)` | `StdAfx.h` — uses `Settings.Interface.DisplayScaling` (100–200) | VERIFIED; threshold `&lt; 110` skips scale |
| `DisplayScaling` | Settings; Init clamps 101–200 with system DPI | VERIFIED |
| `InsertColumn` fixed px | `WndHostCache`, `WndNeighbours`, many lists | OBSERVED DEFECT for Network lists |
| `ToolbarHeight` | Skin setting default 28 | VERIFIED |
| `GroupsbarHeight` | default 24 | VERIFIED |
| `HeaderbarHeight` | default 64 | VERIFIED |
| `SidebarWidth` | default `SCALE(200)` | VERIFIED; Search floor in #135 |
| `Splitter` | default 6 | VERIFIED |
| `RowSize` | default `SCALE(17)`, clamp 16–40 | VERIFIED |
| 16px icon assumptions | Image lists, flags imagelist height | VERIFIED; Phase 9 concern |
| `SizeListAndBar` | `WndChild.cpp` | VERIFIED — resizes chrome only |
| `CLiveListSizer` | Proportional; requires `SizeLists` | VERIFIED CURRENT; insufficient for fill columns |
| `LoadList`/`SaveList` | Registry `ListStates` hex widths/order | VERIFIED — preserve in Phase 1 |
| Panel Close text | `WndPanel.cpp` hard-coded `L"Close"` | OBSERVED DEFECT |
| Owner-draw hit rects | CoolBar, Panel, Media, IRC | Audit per phase |

---

## 6. Reusable UI foundation (RECOMMENDATION)

Before screen-by-screen cosmetics, introduce first-party helpers (names indicative):

| Concern | Approach |
| --- | --- |
| DPI/font spacing | Build on `SCALE()` + font metrics (#137 style); prefer logical tokens over raw literals |
| Min control / hit size | Document minimums (e.g. ≥ SCALE(24) touch-friendly where practical) |
| Toolbar / header / row metrics | Centralize reads of Skin.* with DPI-aware clamps; do not break skin XML readers |
| Adaptive list columns | Pure layout calculator (unit-testable) classifying columns: **fixed**, **bounded**, **flexible** |
| Fill columns | At least one flexible column absorbs unused width |
| User widths / order | Preserve `LoadList`/`SaveList`; mark user-resized columns as sticky; no registry write storms on `WM_SIZE` |
| Empty states | Shared pattern later; not Phase 1 |
| Command bars / page headers | Shared spacing after shell phase |
| Semantic colors | Prefer `Colors.*` roles; light/dark later if feasible |
| Skin contract | If metrics semantics change: document old → new → fallback → migration |

### Adaptive column algorithm (Phase 1)

1. Measure client width (minus scrollbar)
2. Sum sticky user widths + fixed mins for remaining
3. Clamp bounded columns to [min, max]
4. Distribute remainder to flexible columns by weight
5. Guard: no negative widths, no overflow, no resize feedback loop, degrade on narrow windows
6. Anticipate long IPv6 textual addresses (#89) in Address column bounds

Prefer extracting pure functions under something like `Envy/AdaptiveListColumns.h` (or `tests/`-friendly header) with EnvyTests coverage.

**Relation to `CLiveListSizer`:** keep for compatibility when `SizeLists` is enabled; Phase 1 adaptive allocator is a **new**, column-class-aware path used explicitly by Neighbors / Host Cache (do not silently change global SizeLists semantics for all lists).

---

## 7. Resource-loading diagnosis

Runtime System log (Debug) reported failures. Classification:

| Message | Classification | Evidence |
| --- | --- | --- |
| `Failed to load Emoticons.` | **HYPOTHESIS:** packaging / `DataPath` / XML load failure — **not** missing repo assets | `Emoticons.Load()` reads `Settings.General.DataPath + L"Emoticons.xml"`; repo ships `Data/Emoticons.xml` + `Emoticons.png`. Logged from `Envy.cpp` on startup always (not Debug-only). |
| `Failed to load Flags.` | **HYPOTHESIS:** runtime `DataPath` / skin watermark / decode path — default `Flags.png` **passes** 26× grid checks (468×312) | `Flags.Load()` from `WndMain` skin change; returns FALSE on load/validate failure. |
| `Failed to load string 40100.` | **VERIFIED CURRENT:** Debug-only `Skin::LoadString` | `40100` = `ID_OPEN_DOWNLOADS_FOLDER`. Logged only under `#ifdef _DEBUG` when skin map + `CString::LoadString` both miss. Often menu/command ID without STRINGTABLE entry at call site. |
| `Failed to load string 40408.` | Same | `40408` = `ID_TOOLS_CREATETORRENT` |

**RECOMMENDATION:** Track as dedicated issue/PR when root cause is verified:

- Issue: `[ui][resources] Fix missing runtime UI resources and string mappings`
- Branch: `fix/ui-resource-loading`
- PR: `fix(ui): restore missing runtime resources and string mappings`

Do **not** hide these messages during UI layout PRs.

---

## 8. Skin compatibility risks

| Risk | Notes |
| --- | --- |
| Pixel metrics in skin XML | Skins encode toolbar/sidebar heights; changing interpretation needs fallback |
| Watermarks / bitmaps | List backgrounds, flags via `Skin.GetWatermark(L"CFlags")` |
| Icon strips | 16px assumptions; Phase 9 only after license audit |
| PeerProject / Shareaza skins | ~182 px sidebars still valid (#135 deliberately avoided global floor raise) |
| Language XML | Do not hardcode English when localized resource exists; panel “Close” currently hard-coded |

---

## 9. Accessibility (audit checklist)

Apply per phase; do not regress:

- Keyboard navigation and tab order
- Visible focus
- Screen-reader-friendly labels where MFC allows
- Minimum clickable areas
- Text contrast / high-contrast
- Status not color-only
- DPI 100/125/150/175/200
- Long translations (e.g. French)
- RTL smoke if supported

---

## 10. Comparison (design references)

| Client | Useful for | Not copying |
| --- | --- | --- |
| qBittorrent | Dense transfer tables, filters, details tabs | Qt widgets / WebUI |
| Transmission | Sparse chrome, clear primary actions | GTK simplicity as a rewrite mandate |
| BiglyBT | Advanced organization | Java SWT UI |
| AirDC++ | Multi-hub power-user density | Exact DC++ layouts |
| Envy/Shareaza lineage | Multi-network Host Cache / Neighbors semantics | Frozen 2000s density without DPI |

---

## 11. Host Cache protocol selector truth table

| Selector | Backed by HostCache list | Notes |
| --- | --- | --- |
| All (`PROTOCOL_NULL`) | Aggregate view | VERIFIED |
| Gnutella2 | Yes | VERIFIED |
| Gnutella1 | Yes; UI gated by G1 enable/show | VERIFIED |
| eDonkey / ED2K | Yes; server.met import | VERIFIED |
| Kad | Yes; bootstrap via nodes.dat paths | Kad2 still partial/unverified overall |
| Direct Connect | Yes; hublist import | NMDC; ADC hubs NOT SUPPORTED |
| BitTorrent | Yes | DHT/bootstrap hosts; not “full BT UI” |

---

## 12. PR sequence (exact names)

| Order | Branch | PR title | Status |
| --- | --- | --- | --- |
| 0 | `docs/ui-modernization-plan` | `docs(ui): define desktop modernization architecture` | This document |
| 1 | `fix/ui-adaptive-network-lists` | `fix(ui): make network lists adaptive and DPI-aware` | PLANNED — Neighbors + Host Cache + helpers only |
| 2 | `refactor/ui-shell-navigation` | `refactor(ui): simplify main shell and navigation hierarchy` | PLANNED after Phase 1 merge |
| 3 | `refactor/ui-transfers-layout` | `refactor(ui): modernize transfers workspace layout` | PLANNED |
| 4 | `refactor/ui-home-dashboard` | `refactor(ui): modernize home dashboard` | PLANNED |
| 5 | `refactor/ui-library-layout` | `refactor(ui): simplify library workspace layout` | PLANNED |
| 6 | `refactor/ui-settings-layout` | `refactor(ui): modernize settings layout and navigation` | PLANNED |
| 7 | `refactor/ui-media-layout` | `refactor(ui): modernize media player workspace` | PLANNED |
| 8 | `refactor/ui-chat-layout` | `refactor(ui): modernize chat and IRC workspace` | PLANNED |
| 9 | `refactor/ui-scalable-assets` | `refactor(ui): improve scalable icons and visual resources` | PLANNED after asset audit |
| * | `fix/ui-resource-loading` | `fix(ui): restore missing runtime resources and string mappings` | Optional parallel when cause verified |

---

## 13. Phase 1 scope bound

**In scope**

- Reusable adaptive column layout helpers (+ EnvyTests)
- `WndNeighbours` / `WndHostCache` adoption
- DPI-aware default column mins via `SCALE()` where appropriate
- Preserve user column widths/order via existing `LoadList`/`SaveList`
- Docs / CHANGELOG updates for the slice

**Out of scope**

- Shell / Home / Transfers / Library / Media / Chat rewrites
- Global `SizeLists` behavior change for all windows
- Icon pack replacement
- Protocol behavior
- Resource-loading fix unless trivial and caused by touched code

**Expected files (indicative)**

- New: adaptive column helper header (+ test)
- `Envy/WndNeighbours.cpp` / `.h` (minimal)
- `Envy/WndHostCache.cpp` / `.h` (minimal)
- Possibly `LiveListSizer` touch only if shared safely
- `CHANGELOG.md`, `docs/DEVELOPMENT_PLAN.md`, this doc status → PARTIAL/IMPLEMENTED for Phase 1 items

---

## 14. Test / validation matrix

### Automated

- Release x64 + Release Win32 Envy builds
- Debug x64 where practical
- EnvyTests for layout helpers: width 0 / tiny / min / normal / wide / ultrawide; hidden/reordered/user widths; multiple flex columns; scale factors 100–200; arithmetic boundaries

### Manual (Phase 1)

- Resolutions: 1280×720, 1920×1080, 2560×1440
- Scaling: 100%, 125%, 150%, 200%
- Continuous resize narrow ↔ wide
- Default skin + one alternate/legacy skin
- English + one longer translation (e.g. French)
- RTL smoke if available
- Neighbors + Host Cache every protocol mode
- Restart preserves list state
- No crash / ASSERT / negative width / resize loop / persistent flicker

---

## 15. Protect develop / CI

Follow live Protect develop ruleset and AGENTS.md:

- Squash-only, signed commits, ≥1 non-author APPROVED review
- Required checks green; no ruleset bypass
- Max 3 open development PRs
- After push: `gh pr checks <PR> --repo Mika3578/Envy --required --watch --fail-fast --interval 5`

---

## 16. Runtime evidence index

Screenshots used for this audit (Debug run, 2026-09-20): Host Cache, Neighbors+System, Neighbors, Home, Transfers, Library, Media, Chat — supplied by maintainer; truncated Network columns and multi-layer chrome are OBSERVED DEFECTS reconciled with source above.
