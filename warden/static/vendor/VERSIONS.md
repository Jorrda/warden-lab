# Vendored asset versions

This file records the provenance and integrity of every third party asset committed under `warden/static/vendor/`. Paths below are relative to this directory (`warden/static/vendor/`).

| Path | Library and version | Source URL | Download date | SHA-256 |
|---|---|---|---|---|
| `bootstrap/css/bootstrap.min.css` | Bootstrap 5.3.8 | https://github.com/twbs/bootstrap/releases/download/v5.3.8/bootstrap-5.3.8-dist.zip | 2026-09-11 | d85327d99c7a3ee1f9b5d0500d1370acea3ad2db39c163c2f51f232baedbdede |
| `bootstrap/js/bootstrap.bundle.min.js` | Bootstrap 5.3.8 | https://github.com/twbs/bootstrap/releases/download/v5.3.8/bootstrap-5.3.8-dist.zip | 2026-09-11 | e4fd49181388c48ec5040bd3fe66f57c29c8e67fcd8502b3354b96ec7ab47cc7 |
| `bootstrap/LICENSE` | Bootstrap 5.3.8 (MIT) | https://raw.githubusercontent.com/twbs/bootstrap/v5.3.8/LICENSE | 2026-09-11 | 4620c84ad5ce8602ff65640ed6b7c8b78ebb9e036584f0ebc1ccc88206a4bb51 |
| `icons/bootstrap-icons.min.css` | Bootstrap Icons 1.13.1 | https://github.com/twbs/icons/releases/download/v1.13.1/bootstrap-icons-1.13.1.zip | 2026-09-11 | a5d6387a32ca3baec4d02336b5b3edab50c9dd518355576a011ea3dd9c1d884e |
| `icons/fonts/bootstrap-icons.woff2` | Bootstrap Icons 1.13.1 | https://github.com/twbs/icons/releases/download/v1.13.1/bootstrap-icons-1.13.1.zip | 2026-09-11 | 6c75710364a1ca5604267716f6d28997b26319fdb078cf11e0b42ab66ff2ea61 |
| `icons/fonts/bootstrap-icons.woff` | Bootstrap Icons 1.13.1 | https://github.com/twbs/icons/releases/download/v1.13.1/bootstrap-icons-1.13.1.zip | 2026-09-11 | f55513b7b591cb84a3b87ff0e34ea24d4831d6fedc22e54b911ca64b5b544a15 |
| `icons/LICENSE` | Bootstrap Icons 1.13.1 (MIT) | https://raw.githubusercontent.com/twbs/icons/v1.13.1/LICENSE | 2026-09-11 | 0fb3e11bd57e896c5a512afd64864d28a37de45d19835016c87ca1ad19ead969 |
| `chartjs/chart.umd.js` | Chart.js 4.5.1 | https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.js | 2026-09-12 | ecc3cd1eeb8c34d2178e3f59fd63ec5a3d84358c11730af0b9958dc886d7652a |
| `chartjs/LICENSE.md` | Chart.js 4.5.1 (MIT) | https://raw.githubusercontent.com/chartjs/Chart.js/v4.5.1/LICENSE.md | 2026-09-12 | 41a84aa2caba645f966a18d9c2056b73e6d3a81d80bc0046bc0011a2634d4cce |

Notes:

- The Bootstrap files were verified against the SRI values published in the Bootstrap 5.3 documentation (getbootstrap.com). Both matched exactly:
  - `bootstrap.min.css`: `sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB`
  - `bootstrap.bundle.min.js`: `sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI`
- The `bootstrap-icons.min.css` file references its fonts with relative paths `fonts/bootstrap-icons.woff2` and `fonts/bootstrap-icons.woff`, so the `fonts/` folder next to this CSS file is required.
- No `.map` files are vendored.
- `chart.umd.js` is the UMD build the Chart.js 4.5.1 release ships (the GitHub release tag is v4.5.1), read from jsDelivr, which serves the npm package as published. The bundle is self-contained, contains no `eval` and injects no style element; it runs under the application's Content Security Policy (`script-src 'self'`) with the chart data in a non-executing JSON block (decision D-057).
