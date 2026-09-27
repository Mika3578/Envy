# Envy community website (GitHub Pages)

Static HTML/CSS site served from the `/site` directory via GitHub Actions (see `.github/workflows/pages.yml`).

## Design choices

- **No SSG or npm toolchain** — plain files for low maintenance and minimal supply-chain risk.
- **`_generate_html.py`** — optional helper to regenerate pages with shared navigation; committed HTML is authoritative for Pages.
- **Status and protocols** — always link to [`docs/10_dev/status.md`](../docs/10_dev/status.md); this site does not mirror the feature matrix.

## Assets

| File | Provenance |
| --- | --- |
| `assets/images/envy-logo.svg` | Copied from [`Repository/Images/Envy.svg`](../Repository/Images/Envy.svg) (repository-owned project art) |

Do not add scraped third-party artwork.

## Local preview

```bash
cd site
python3 -m http.server 8080
```

Open `http://127.0.0.1:8080/`.

## Validation

```bash
# HTML (install html-validate if needed)
npx --yes html-validate site/*.html

python3 site/scripts/check-site-links.py
```

## Public URL (after maintainer enables Pages)

Expected: `https://mika3578.github.io/Envy/`

Post-merge steps are documented in the community PR description.
