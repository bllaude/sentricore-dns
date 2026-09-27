# Sentricore DNS — Technical Marketing Site

Static marketing + docs microsite for **[Sentricore DNS Proxy](https://github.com/SentriCore/sentricore-dns-proxy)**, the security-first, self-hosted DNS proxy.

Pure HTML/CSS/JS — no build step, no dependencies. Deployable on GitHub Pages, Netlify, or any static host.

## Pages

| Page | Path | Purpose |
|------|------|---------|
| Landing | `index.html` | Hero, features, architecture, quickstart tabs, comparison, use cases |
| Capabilities | `pages/features.html` | Full capability matrix (blocking, performance, observability, security, deployment) |
| API reference | `pages/api.html` | REST endpoints, auth, metrics list, PromQL examples |
| Docs | `pages/docs.html` | Configuration reference, env vars, endpoints, Prometheus setup |
| Getting started | `pages/getting-started.html` | 5-minute install: Docker / bare metal / Raspberry Pi |
| Pricing | `pages/pricing.html` | Free OSS + optional support tiers, FAQ |
| Security | `pages/security.html` | Design principles, hardening checklist, disclosure policy |
| About | `pages/about.html` | Project story and values |
| Blog | `pages/blog.html` | Engineering notes index |

## Local preview

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

Or just open `index.html` directly in a browser — everything is relative-path based.

## Structure

```
.
├── index.html          # landing page
├── pages/              # interior pages
├── styles/main.css     # single stylesheet (dark technical theme)
├── scripts/main.js     # progressive enhancement only (tabs, copy buttons, mobile nav)
└── images/             # inline SVG logo, favicon, architecture diagrams
```

## Deploying with GitHub Pages

1. Push this repository to GitHub.
2. **Settings → Pages → Source:** deploy from branch `main`, folder `/ (root)`.
3. The included workflow (`.github/workflows/pages.yml`) also publishes automatically via the official Pages action.

## License

Content and code: MIT (same as the product).
