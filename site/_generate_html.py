#!/usr/bin/env python3
"""One-shot generator for static site pages. Run from repo root if pages need regeneration."""
from html import escape
from pathlib import Path

SITE = Path(__file__).resolve().parent
PAGES_URL = "https://mika3578.github.io/Envy/"
REPO = "https://github.com/Mika3578/Envy"
DEVELOP = f"{REPO}/blob/develop"

NAV = [
    ("index.html", "Home"),
    ("features.html", "Features"),
    ("networks.html", "Networks"),
    ("download.html", "Download"),
    ("history.html", "History"),
    ("roadmap.html", "Roadmap"),
    ("contribute.html", "Contribute"),
    ("community.html", "Community"),
    ("documentation.html", "Docs"),
]


def shell(current: str, title: str, description: str, body: str) -> str:
    title = escape(title)
    description = escape(description, quote=True)
    nav_items = []
    for href, label in NAV:
        cur = ' aria-current="page"' if href == current else ""
        nav_items.append(f'<li><a href="{href}"{cur}>{label}</a></li>')
    nav_html = "\n          ".join(nav_items)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{description}">
  <link rel="canonical" href="{PAGES_URL}{current}">
  <meta property="og:title" content="{title}">
  <meta property="og:description" content="{description}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="{PAGES_URL}{current}">
  <link rel="icon" href="assets/images/envy-logo.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/css/main.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="index.html">
        <img src="assets/images/envy-logo.svg" width="40" height="48" alt="">
        <span>Envy</span>
      </a>
      <nav class="site-nav" aria-label="Primary">
        <ul>
          {nav_html}
        </ul>
      </nav>
    </div>
  </header>
  <main id="main">
{body}
  </main>
  <footer class="site-footer">
    <p>Envy is AGPL-3.0-or-later. Community site source: <a href="{REPO}/tree/develop/site">{REPO}/tree/develop/site</a>.
    Current implementation status is defined in the <a href="{DEVELOP}/docs/10_dev/status.md">repository status matrix</a>, not on this site alone.</p>
  </footer>
</body>
</html>
"""


PAGES = {
    "index.html": (
        "Envy — multi-network P2P client for Windows",
        "Envy is a Windows-native multi-network peer-to-peer client under active modernization. Open source, evidence-based status, preview builds.",
        """
    <h1>Multi-network P2P for Windows</h1>
    <p class="muted">Maintained fork · active modernization · open source (AGPL-3.0-or-later)</p>
    <p>Envy is a legacy-rich Windows client for BitTorrent, Gnutella/G2, ED2K/Kad, Direct Connect, library management, and multi-network search.
    The <a href="https://github.com/Mika3578/Envy">Mika3578/Envy</a> repository continues development from the historical
    <a href="https://github.com/GetEnvy/Envy">GetEnvy/Envy</a> line with updated tooling, CI, and honest protocol status reporting.</p>
    <div class="callout">
      <strong>Preview software.</strong> There is no advertised stable GA release on the maintained fork yet.
      See <a href="download.html">Download / build</a> and <a href="{DEVELOP}/docs/KNOWN_LIMITATIONS.md">known limitations</a>.
    </div>
    <div class="cta-grid">
      <a href="{DEVELOP}/docs/10_dev/status.md">View project status</a>
      <a href="download.html">Download / build</a>
      <a href="{DEVELOP}/docs/TESTING.md">Help test Envy</a>
      <a href="https://github.com/Mika3578/Envy/discussions">Join Discussions</a>
      <a href="contribute.html">Contribute</a>
      <a href="roadmap.html">Browse roadmap</a>
    </div>
    <h2>Heritage</h2>
    <p>Envy inherits Shareaza-lineage code paths and continued PeerProject-era development before the Envy rebrand.
    That is <em>not</em> the same as “Shareaza renamed.” See <a href="history.html">History</a>.</p>
""".format(DEVELOP=DEVELOP),
    ),
    "features.html": (
        "Features — Envy",
        "Feature areas for the Envy client with pointers to the canonical implementation status matrix.",
        """
    <h1>Features</h1>
    <p>Do not treat this page as a separate feature database. Status vocabulary and evidence live in the
    <a href="{DEVELOP}/docs/10_dev/status.md">canonical status matrix</a> (implemented, partial, unverified, planned, …).</p>
    <h2>Transfers and library</h2>
    <p>Multi-source downloads, queuing, and library organization across supported networks. Maturity varies by protocol; see the matrix.</p>
    <h2>Search</h2>
    <p>Multi-network search UI with network-specific backends. Live interoperability for ED2K/Kad remains a focus area on <code>develop</code>.</p>
    <h2>Network engines</h2>
    <p>BitTorrent v1/v2 (partial v2), Gnutella, Gnutella2, ED2K, Kad2, NMDC Direct Connect, and HTML Remote — each with documented current status on the
    <a href="networks.html">Networks</a> page.</p>
    <h2>Modernization foundations</h2>
    <ul>
      <li>Visual Studio 2026 / MSVC v145 builds and manifest vcpkg dependencies</li>
      <li>Expanded CI, static analysis, and targeted protocol tests</li>
      <li>Crash reporting integration (platform-specific; see status matrix)</li>
      <li>Portable-core planning documented under <code>docs/20_arch/</code></li>
    </ul>
    <h2>Security and reliability</h2>
    <p>Report vulnerabilities via <a href="{REPO}/security/policy">SECURITY.md</a>. Do not post exploit details in public Issues.</p>
""".format(DEVELOP=DEVELOP, REPO=REPO),
    ),
    "networks.html": (
        "Networks — Envy",
        "Networks Envy targets with current status from the repository status matrix.",
        """
    <h1>Networks</h1>
    <p class="muted">Current status snapshot — verify on <a href="{DEVELOP}/docs/10_dev/status.md">docs/10_dev/status.md</a> before citing in bug reports.</p>
    <table>
      <thead><tr><th scope="col">Network</th><th scope="col">Current status (summary)</th><th scope="col">Canonical doc</th></tr></thead>
      <tbody>
        <tr><td>BitTorrent v1</td><td>implemented</td><td><a href="{DEVELOP}/docs/10_dev/status.md">status matrix</a></td></tr>
        <tr><td>BitTorrent v2</td><td>partial</td><td><a href="{DEVELOP}/docs/30_protocols/bittorrent/BITTORRENT_V2_PLAN.md">BEP 52 plan</a></td></tr>
        <tr><td>Gnutella (G1)</td><td>implemented (Shareaza lineage)</td><td>status matrix</td></tr>
        <tr><td>Gnutella2 (G2)</td><td>implemented (Shareaza lineage)</td><td>status matrix</td></tr>
        <tr><td>ED2K / eMule family</td><td>partial / live interop unverified</td><td><a href="{DEVELOP}/docs/30_protocols/ed2k/README.md">ED2K docs</a></td></tr>
        <tr><td>Kad2</td><td>partial / live interop unverified</td><td><a href="{DEVELOP}/docs/30_protocols/kad/kad2-compatibility-report.md">Kad report</a></td></tr>
        <tr><td>Direct Connect (NMDC)</td><td>implemented; live hub interop unverified</td><td>status matrix</td></tr>
        <tr><td>ADC / ADCS</td><td>not implemented</td><td>status matrix</td></tr>
        <tr><td>Remote / Web UI</td><td>implemented (HTML remote; not REST API)</td><td><a href="{DEVELOP}/docs/API.md">API notes</a></td></tr>
      </tbody>
    </table>
    <div class="callout">
      <strong>Historical vs current:</strong> Archived getenvy.com and SourceForge pages may list protocols or features that are not implemented on today&apos;s <code>develop</code> branch.
      Label historical marketing separately.</div>
""".format(DEVELOP=DEVELOP),
    ),
    "download.html": (
        "Download and build — Envy",
        "How to obtain preview builds, build from source, and avoid unofficial binaries.",
        """
    <h1>Download and build</h1>
    <h2>Current maintained fork (preview)</h2>
    <p>Target preview: <strong>Envy 4.2.0 Preview 1</strong> (<code>v4.2.0-preview.1</code>) when published on
    <a href="https://github.com/Mika3578/Envy/releases">GitHub Releases</a>. Releases may remain in <em>draft</em> until maintainers publish them.</p>
    <ul>
      <li>Windows x64 — recommended</li>
      <li>Windows x86 (Win32) — legacy compatibility</li>
      <li>Portable ZIP — diagnostic runs without installer</li>
    </ul>
    <p>Preview installers are <strong>not Authenticode-signed</strong>; SmartScreen may warn. See
    <a href="{DEVELOP}/docs/KNOWN_LIMITATIONS.md">known limitations</a>.</p>
    <h2>Build from source</h2>
    <p>Authoritative path: Visual Studio 2026 and <code>Visual Studio/Envy.sln</code>. See
    <a href="{DEVELOP}/docs/10_dev/build.md">build documentation</a> and <a href="{DEVELOP}/.github/CONTRIBUTING.md">CONTRIBUTING</a>.</p>
    <h2>Historical upstream releases</h2>
    <p>GetEnvy/Envy tags <code>1.0</code> through <code>4.0</code> (2016–2020) remain on
    <a href="https://github.com/GetEnvy/Envy/releases">GetEnvy/Envy releases</a> and
    <a href="https://sourceforge.net/projects/getenvy/files/">SourceForge</a>. These are <strong>not</strong> maintained by Mika3578/Envy.</p>
    <div class="callout">
      <strong>Safety:</strong> Do not download Envy binaries from unknown mirrors or file-hosting sites.
      Prefer this repository&apos;s Releases or your own reproducible build.</div>
""".format(DEVELOP=DEVELOP),
    ),
    "history.html": (
        "Project history — Envy",
        "Shareaza, PeerProject, and Envy lineage with sourced timeline.",
        """
    <h1>Project history</h1>
    <p>Paraphrased community history with citations. Full ledger:
    <a href="{DEVELOP}/docs/history/SOURCES.md">docs/history/SOURCES.md</a>.</p>
    <h2>Lineage (short)</h2>
    <ol>
      <li><strong>Shareaza</strong> — open-source multi-network client; G1/G2 heritage in Envy&apos;s codebase.</li>
      <li><strong>PeerProject</strong> — Shareaza-lineage fork; continued development under its own name.</li>
      <li><strong>Envy (GetEnvy)</strong> — rebrand and continuation; tagged releases 2016–2020.</li>
      <li><strong>Mika3578/Envy</strong> — active modernization fork with evidence-based status reporting.</li>
    </ol>
    <p>Details: <a href="{DEVELOP}/docs/history/LINEAGE.md">LINEAGE.md</a>.</p>
    <h2>Release timeline (historical tags)</h2>
    <p>See <a href="{DEVELOP}/docs/history/TIMELINE.md">TIMELINE.md</a>. Notable GetEnvy tags:</p>
    <ul>
      <li><code>1.0.0.0.Pre</code> — 2016-04-08</li>
      <li><code>2.0</code> — 2019-08-01 (announced on <a href="https://shareaza.sourceforge.net/phpbb/viewtopic.php?f=9&amp;t=2626">Shareaza forum</a>)</li>
      <li><code>4.0</code> — 2020-01-22 (last upstream &quot;Latest&quot; at time of research)</li>
    </ul>
    <h2>Archived web presence</h2>
    <ul>
      <li><a href="https://web.archive.org/web/*/http://getenvy.com/">getenvy.com (Wayback)</a></li>
      <li><a href="https://sourceforge.net/projects/getenvy/">SourceForge getenvy</a></li>
      <li><a href="https://sourceforge.net/projects/peerproject/">SourceForge PeerProject</a></li>
    </ul>
    <h2>Sources</h2>
    <p>Primary: GetEnvy releases, upstream ReadMe, in-repo <code>ShareazaCommits.txt</code>, maintainer forum post (2019).
    Current behaviour: <a href="{DEVELOP}/docs/10_dev/status.md">status matrix</a> only.</p>
""".format(DEVELOP=DEVELOP),
    ),
    "roadmap.html": (
        "Roadmap — Envy",
        "High-level modernization themes with links to canonical roadmap documents.",
        """
    <h1>Roadmap themes</h1>
    <p>This page summarizes direction only. Sequencing and decisions live in version-controlled docs:</p>
    <ul>
      <li><a href="{DEVELOP}/docs/DEVELOPMENT_PLAN.md">Development plan</a></li>
      <li><a href="{DEVELOP}/docs/10_dev/roadmap.md">Technical roadmap</a></li>
      <li><a href="{DEVELOP}/docs/DECISIONS.md">Decision log</a></li>
    </ul>
    <h2>Current themes (non-exhaustive)</h2>
    <ul>
      <li>Windows x64 product quality and CI-backed builds</li>
      <li>ED2K/Kad interoperability evidence and honest capability advertisement</li>
      <li>Security and dependency hygiene</li>
      <li>Portable-core foundations without claiming unsupported platforms</li>
      <li>UI modernization planning (see UI_MODERNIZATION.md)</li>
    </ul>
""".format(DEVELOP=DEVELOP),
    ),
    "contribute.html": (
        "Contribute — Envy",
        "Ways to help develop, test, document, and translate Envy.",
        """
    <h1>Contribute</h1>
    <p>Read <a href="{DEVELOP}/.github/CONTRIBUTING.md">CONTRIBUTING</a> and <a href="{DEVELOP}/AGENTS.md">AGENTS.md</a> before opening PRs.</p>
    <h2>Development</h2>
    <p>C++ / MFC work on <code>develop</code> via feature branches (<code>feat/</code>, <code>fix/</code>, …). Visual Studio solution is authoritative for full builds.</p>
    <h2>Protocol interoperability</h2>
    <p>Capture reproducible evidence; consult <a href="{DEVELOP}/docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md">reference implementations</a> (spec first).</p>
    <h2>Testing</h2>
    <p><a href="{DEVELOP}/docs/TESTING.md">Testing guide</a> — unit tests, interop harness, preview builds on Windows.</p>
    <h2>Documentation and translations</h2>
    <p>Technical docs under <code>docs/</code>. Translation XML under <code>Languages/</code> needs fluent native speakers.</p>
    <h2>Security</h2>
    <p>Private reports via <a href="{REPO}/security/policy">GitHub Security Advisories</a> / SECURITY.md — no tokens or private peer data in public posts.</p>
""".format(DEVELOP=DEVELOP, REPO=REPO),
    ),
    "community.html": (
        "Community — Envy",
        "Discussions, Issues, Wiki, and historical community resources.",
        """
    <h1>Community</h1>
    <ul>
      <li><a href="https://github.com/Mika3578/Envy/discussions">GitHub Discussions</a> — questions, ideas, show-and-tell</li>
      <li><a href="https://github.com/Mika3578/Envy/issues">Issues</a> — confirmed bugs and scoped work</li>
      <li><a href="https://github.com/Mika3578/Envy/wiki">GitHub Wiki</a> — community history and guides (source in <code>community/wiki/</code>)</li>
    </ul>
    <h2>Historical communities</h2>
    <p>Shareaza and PeerProject forums remain useful for <em>historical</em> context. Link archives when citing old threads.</p>
    <h2>Code of conduct</h2>
    <p>Follow repository governance and be constructive in interoperability discussions.</p>
""",
    ),
    "documentation.html": (
        "Documentation — Envy",
        "Index of canonical repository documentation.",
        """
    <h1>Documentation</h1>
    <p class="muted">Canonical technical docs stay in the git repository; the Wiki holds community/history material.</p>
    <ul>
      <li><a href="{REPO}#readme">README</a></li>
      <li><a href="{DEVELOP}/docs/10_dev/status.md">Implementation status matrix</a></li>
      <li><a href="{DEVELOP}/docs/10_dev/roadmap.md">Roadmap</a></li>
      <li><a href="{DEVELOP}/docs/ARCHITECTURE.md">Architecture</a></li>
      <li><a href="{DEVELOP}/docs/30_protocols/README.md">Protocol documentation</a></li>
      <li><a href="{DEVELOP}/docs/10_dev/build.md">Build</a></li>
      <li><a href="{DEVELOP}/docs/TESTING.md">Testing</a></li>
      <li><a href="{DEVELOP}/docs/history/SOURCES.md">History research ledger</a></li>
      <li><a href="https://github.com/Mika3578/Envy/wiki">GitHub Wiki</a></li>
    </ul>
""".format(REPO=REPO, DEVELOP=DEVELOP),
    ),
}

for filename, (title, desc, body) in PAGES.items():
    html = shell(filename, title, desc, body)
    (SITE / filename).write_text(html, encoding="utf-8", newline="\n")

print(f"Wrote {len(PAGES)} pages to {SITE}")
