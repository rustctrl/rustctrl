---
status: accepted
---

# Adopt GPUI Kit design system and Tokyo Night theme

IT staff require a responsive, high-density desktop Controller to monitor ~120 fleet devices, inspect real-time hardware telemetry, and operate interactive Remote Sessions across AlmaLinux and Windows. The initial GUI implementation relied on procedural GPUI primitives and hundreds of scattered inline RGB literals in a single scrolling view, lacking virtual scrolling, standard form overlays, and cohesive design tokens.

RustCtrl resolves this by adopting `gpui-kit` (v0.8.1, Apache-2.0) as the design system and UI component foundation for `rustctrl_controller`:

1. **Design System & Component Library**: Standardize UI layouts on `gpui-kit`'s desktop primitives (`Sidebar`, `DataTable`, `Sheet`, `Dialog`, `Badge`, `Button`, `Toast`), retiring ad hoc GPUI view code and replacing inline colors with semantic design tokens.
2. **Default Visual Identity**: Apply **Tokyo Night** as the default dark theme, providing high-contrast, low-fatigue slate/navy surfaces with cyan and neon accents suitable for multi-monitor IT control rooms. Support theme switching (e.g. *Tokyo Storm*, *Catppuccin Mocha*, *Default Dark*) backed by local user preference persistence (`preferences.toml`).
3. **Data Density & Virtualization**: The Fleet Inventory utilizes `DataTable` with virtualized scrolling, column sorting, and instant search/filtering across Windows endpoints and Android TV targets. Single-clicking a row opens a slide-over `Sheet` (Inspector drawer) for telemetry and device management without losing scroll position; double-clicking directly launches a Remote Session.
4. **Clean Dependency & License Boundary**: Adopting `gpui-kit` avoids importing Zed's internal `crates/ui` and `crates/theme` (which carry copyleft GPL-3.0-or-later licenses) and delivers built-in Lucide icons (`gpui-kit-assets`), keeping the Controller build Apache-2.0/MIT clean.
5. **Role-Tailored Navigation**: The left `Sidebar` dynamically conceals administrative destinations (*Staff Accounts*, *Agent Deployment*, *Audit History*) for Operator accounts, maintaining a focused and secure operator experience.
6. **Unified Remote Session Workspace**: Remote Sessions take over the primary workspace with an auto-collapsing sidebar, tab-based switching back to the Fleet Inventory without disconnecting, and an auto-hiding floating toolbar providing display selection, SAS (Ctrl+Alt+Del), interactive/view-only toggles, latency/FPS metrics, and keyboard ungrab shortcuts.

## Consequences and Trade-offs

- **Performance & Polish**: The Controller achieves smooth 60–120 FPS rendering on AlmaLinux (X11/Wayland) and Windows with accessible focus rings, keyboard navigation, and virtualized tables.
- **Dependency Scope**: Pulls `gpui-kit` and its pre-release platform crates instead of raw git-pinned Zed core primitives, adding a unified GUI toolkit layer while drastically reducing boilerplate in `rustctrl_controller`.
- **Maintainability**: Future UI additions (e.g., advanced audit filters, queue monitor profiles, task dispatch wizards) compose cleanly from existing `gpui-kit` components.
