<!-- Improved compatibility of back to top link -->
<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![project_license][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<br />
<div align="center">

<h3 align="center">CRACY Cryptographic Assessment Tool</h3>

  <p align="center">
    A tool for ensuring that your software uses state-of-the-art cryptography. The tool leverages Cryptography Bill of Materials (CBOM).
    <br />
    <a href="https://github.com/CRA-tools/crypto-assessment"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/CRA-tools/crypto-assessment">View Project</a>
    &middot;
    <a href="https://github.com/CRA-tools/crypto-assessment/issues/new?labels=bug">Report Bug</a>
    &middot;
    <a href="https://github.com/CRA-tools/crypto-assessment/issues/new?labels=enhancement">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#what-it-checks">What It Checks</a></li>
    <li><a href="#project-structure">Project Structure</a></li>
    <li><a href="#getting-started">Getting Started</a></li>
    <li><a href="#configuration">Configuration</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#compliance-decision">Compliance Decision</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#troubleshooting">Troubleshooting</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

This project implements a lightweight static web frontend for checking cryptographic compliance of a Git repository.

Docker Compose serves the static frontend through Nginx at
`http://localhost:8000` and starts the backend services.

The tool coordinates three checks:

1. CBOM generation through CBOMkit.
2. REGO policy evaluation through OPA on the previously generated CBOM.
3. Semgrep rule evaluation through the local Semgrep service.

The interface is intentionally simple: the user enters repository details and presses a single **Check compliance** button. The compliance result is shown first, while detailed findings remain hidden until the user chooses to display them.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- WHAT IT CHECKS -->
## What It Checks

The CRA Compliance Checker evaluates repository cryptography usage using:

- **CBOMkit** to generate a CycloneDX CBOM for the selected repository or subfolder.
- **OPA / REGO** to evaluate CBOM components against ECCG policy rules.
- **Semgrep** to detect source-code patterns that may not be visible from the CBOM alone.

The code is considered **not compliant** with the ECCG policy when at least one finding has one of the following severities:

- `critical`
- `error`
- `high`

Medium, warning, low, and informational findings are still displayed, but they do not make the code non-compliant by themselves.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- PROJECT STRUCTURE -->
## Project Structure

```text
cbomkit-site-html/
├── app.js
├── config
│   └── endpoints.js
├── img
│   ├── cracy.png
│   ├── eccc-logo.svg
│   ├── eu-cofunded-logo.png
│   └── excid-logo.svg
├── index.html
├── styles.css
└── utils
    ├── regoFindings.js
    ├── semgrepFindings.js
    ├── sleep.js
    └── urls.js
```

Important files:

* `index.html` contains the static page structure.
* `styles.css` contains the UI styling, including the footer logos and dark mode styling.
* `app.js` owns the frontend flow for CBOM generation, REGO evaluation, Semgrep evaluation, and rendering results.
* `config/endpoints.js` defines the backend service URLs.
* `utils/regoFindings.js` normalizes and groups REGO findings.
* `utils/semgrepFindings.js` normalizes and groups Semgrep findings.
* `utils/urls.js` builds CBOMkit and Semgrep request payloads.
* `utils/sleep.js` provides cancellable polling delay support.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

### Prerequisites

You need:

* Docker with Docker Compose.
* Internet access to download container images and clone repositories for scanning.

### Start the Docker services

From the root of the main project repository, start all Docker services:

```bash
docker compose up -d --build
```

This starts the **CRA Compliance Checker** frontend
at `http://localhost:8000`, the CBOMkit backend and database, OPA and its proxy,
and the local Semgrep service. 

The upstream CBOMkit frontend previously served
on port 8001 is currently commented out.

Wait for the backend to finish starting before checking compliance. Inspect
service status and startup logs with:

```bash
docker compose ps -a
docker compose logs --tail=100 backend semgrep-local opa-local opa-proxy
```

Compose reads `.env` automatically. The backend at `http://localhost:8081` and
the OPA proxy both allow the origin set by `CBOMKIT_FRONTEND_URL_CORS`, which
defaults to `http://localhost:8000`. The backend already uses the Docker service
address `http://opa-local:8181` for OPA.

The Semgrep service uses the pinned `semgrep/semgrep:1.177.0` image, which includes
the scanner, Python, and Git. Its application build only copies the HTTP server
files; it does not run `apt-get` or install packages from PyPI.

To start only OPA and the local OPA proxy:

```bash
docker compose up -d opa-local opa-proxy
```

The frontend calls the proxy by default:

```text
http://localhost:8182/v1/data/cbom/eccg
```

The proxy forwards requests to OPA inside Docker:

```text
http://opa-local:8181/v1/data/cbom/eccg
```

This avoids browser CORS issues when the static frontend is served from:

```text
http://localhost:8000
```

To rebuild and start only the Semgrep service:

```bash
docker compose up -d --build semgrep-local
```

### Open the frontend

Once the Docker services are running, open:

```text
http://localhost:8000
```

Nginx serves `cbomkit-site-html` from a read-only bind mount. Changes to the
frontend files are available on browser refresh without rebuilding the container.

Do not open `index.html` directly with `file://`, because browser JavaScript modules require an HTTP origin.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONFIGURATION -->

## Configuration

The frontend reads backend endpoints from `config/endpoints.js`.

Default local development values:

```js
export const HTTP_API_BASE =
  window.CRA_COMPLIANCE_CONFIG?.CBOMKIT_HTTP_API_BASE ||
  "http://localhost:8081";

export const WS_API_BASE =
  window.CRA_COMPLIANCE_CONFIG?.CBOMKIT_WS_API_BASE ||
  HTTP_API_BASE.replace(/^http:/, "ws:").replace(/^https:/, "wss:");

export const SEMGREP_API_BASE =
  window.CRA_COMPLIANCE_CONFIG?.SEMGREP_API_BASE ||
  "http://localhost:9091";

export const POLICY_API_BASE =
  window.CRA_COMPLIANCE_CONFIG?.POLICY_API_BASE ||
  "http://localhost:8182";

export const OPA_DECISION_PATH =
  window.CRA_COMPLIANCE_CONFIG?.OPA_DECISION_PATH ||
  "/v1/data/cbom/eccg";
```

The expected local services are:

| Service                   | Default URL             |
| ------------------------- | ----------------------- |
| CRA Compliance Checker frontend | `http://localhost:8000` |
| CBOMkit backend           | `http://localhost:8081` |
| CBOMkit scan stream       | `ws://localhost:8081`   |
| OPA proxy                 | `http://localhost:8182` |
| OPA service inside Docker | `http://opa-local:8181` |
| Semgrep local service     | `http://localhost:9091` |

Important settings:

| Setting                     | Purpose                                                                 | Local value             |
| --------------------------- | ----------------------------------------------------------------------- | ----------------------- |
| `CBOMKIT_FRONTEND_URL_CORS` | `.env` setting used by the CBOMkit backend and OPA proxy to allow the frontend origin | `http://localhost:8000` |
| `CBOMKIT_OPA_API_BASE`      | Allows the CBOMkit backend to call OPA inside Docker                    | `http://opa-local:8181` |
| `HTTP_API_BASE`             | Frontend URL for CBOMkit backend                                        | `http://localhost:8081` |
| `WS_API_BASE`               | Frontend WebSocket URL for live CBOMkit scans                           | `ws://localhost:8081`   |
| `POLICY_API_BASE`           | Frontend URL for OPA proxy                                              | `http://localhost:8182` |
| `SEMGREP_API_BASE`          | Frontend URL for Semgrep service                                        | `http://localhost:9091` |

If the browser calls services on different origins, those services must allow CORS from:

```text
http://localhost:8000
```

For local development, the OPA proxy is used to add CORS headers before forwarding requests to OPA.

### Changing the frontend port

> [!IMPORTANT]
> **Changing `.env` alone does not change the frontend port.** Update both the
> frontend port mapping in `docker-compose.yml` and the allowed browser origin
> in `.env`, then recreate the affected services.

For example, to serve the frontend at `http://localhost:8001`:

1. In `docker-compose.yml`, change the `frontend` service's port mapping:

   ```yaml
   ports:
     - "8001:80"
   ```

   The left-hand value is the host port; the container still serves on port 80.

2. In `.env`, set the matching browser origin:

   ```env
   CBOMKIT_FRONTEND_URL_CORS=http://localhost:8001
   ```

   If you access the frontend through a different hostname or IP address, use
   that exact browser origin, including its scheme and port.

3. Apply both changes by recreating the frontend, backend, and OPA proxy:

   ```bash
   docker compose up -d --force-recreate frontend backend opa-proxy
   ```

Open `http://localhost:8001` after the services finish starting. If you only
change the frontend origin without changing its port mapping, update
`CBOMKIT_FRONTEND_URL_CORS` in `.env` and recreate the backend and OPA proxy:

```bash
docker compose up -d --force-recreate backend opa-proxy
```

Browser endpoint overrides use `window.CRA_COMPLIANCE_CONFIG`, set before
`app.js` loads; Compose environment variables do not rewrite the static
JavaScript files.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE -->

## Usage

1. Open the frontend at:

   ```text
   http://localhost:8000
   ```

2. Enter the Git repository URL.

   Example:

   ```text
   https://github.com/CRA-tools/crypto-assessment.git
   ```

3. Optionally enter:

   * Scan path, for example `demo/code`.
   * Branch, for example `main`.
   * Commit SHA.
   * PAT for private repositories or rate-limit avoidance.

4. Press **Check compliance**.

5. Review the compliance result.

6. Press **Show findings** only when you want to inspect detailed REGO and Semgrep findings.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- COMPLIANCE DECISION -->

## Compliance Decision

The frontend computes the compliance decision from the combined REGO and Semgrep findings.

The result is:

```text
Compliant
```

when there are no findings with severity:

* `critical`
* `error`
* `high`

The result is:

```text
Not compliant
```

when at least one finding has severity:

* `critical`
* `error`
* `high`

The detailed findings section groups results by policy area and shows severity counts per group. Individual findings can be expanded to view references such as file paths and line numbers.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->

## Roadmap

See the [open issues](https://github.com/CRA-tools/crypto-assessment/issues) for proposed features and known issues.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- TROUBLESHOOTING -->

## Troubleshooting

### Browser blocks `app.js`

If you see an error such as:

```text
Access to script at file:///.../app.js has been blocked by CORS policy
```

you opened the file directly. Start the Compose frontend from the repository root:

```bash
docker compose up -d frontend
```

Then open:

```text
http://localhost:8000
```

### CBOMkit scan connection is blocked

If the browser blocks:

```text
ws://localhost:8081/v1/scan/<client-id>
```

make sure `.env` allows the frontend origin:

```dotenv
CBOMKIT_FRONTEND_URL_CORS=http://localhost:8000
```

Then recreate the backend and OPA proxy containers:

```bash
docker compose up -d --force-recreate backend opa-proxy
```

When the frontend is served over HTTPS, configure
`CBOMKIT_WS_API_BASE` with a `wss://` URL. If it is omitted, the frontend
derives the WebSocket URL from `CBOMKIT_HTTP_API_BASE` (`http` becomes `ws`,
and `https` becomes `wss`).

### OPA request is refused

If you see:

```text
POST http://localhost:8181/v1/data/cbom/eccg net::ERR_CONNECTION_REFUSED
```

OPA is not exposed on the host or is not running.

For this frontend, the browser should call the OPA proxy, not OPA directly. Make sure `config/endpoints.js` uses:

```js
export const POLICY_API_BASE =
  window.CRA_COMPLIANCE_CONFIG?.POLICY_API_BASE ||
  "http://localhost:8182";
```

Then start both OPA and the proxy:

```bash
docker compose up -d opa-local opa-proxy
```

### OPA request is blocked by CORS

The static frontend should call the local OPA proxy, not OPA directly.

Make sure `config/endpoints.js` uses:

```js
export const POLICY_API_BASE =
  window.CRA_COMPLIANCE_CONFIG?.POLICY_API_BASE ||
  "http://localhost:8182";
```

Then start both OPA and the proxy:

```bash
docker compose up -d opa-local opa-proxy
```

The proxy should forward to:

```text
http://opa-local:8181
```

### Semgrep request is refused

If you see:

```text
POST http://localhost:9091/scan net::ERR_CONNECTION_REFUSED
```

start the Semgrep service:

```bash
docker compose up -d --build semgrep-local
```

Check that `http://localhost:9091/health` returns `"ok": true`. If the image build
fails, capture the full build output:

```bash
docker compose --progress plain build --pull semgrep-local
```

The build should start from `semgrep/semgrep:1.177.0` and copy the server files.
If it still runs `pip install semgrep`, your checkout has the older Dockerfile.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->

## Contributing

Contributions are welcome and greatly appreciated.

If you have a suggestion that would improve this frontend, please fork the repository and create a pull request. You can also open an issue with the tag `enhancement`.

1. Fork the project.

2. Create your feature branch.

   ```bash
   git checkout -b feature/AmazingFeature
   ```

3. Commit your changes.

   ```bash
   git commit -m "Add some AmazingFeature"
   ```

4. Push to the branch.

   ```bash
   git push origin feature/AmazingFeature
   ```

5. Open a pull request.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->

## License

Distributed under the Apache License, Version 2.0. See `LICENSE` for the full
license text and `NOTICE` / `THIRD_PARTY_NOTICES.md` for attribution and
third-party notices.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->

## Contact

The CRACY project: [info@cra-cy.eu](mailto:info@cra-cy.eu)

Project Link: https://github.com/CRA-tools/crypto-assessment

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

* [Initial contribution by ExcID](https://excid.io)
* [CRACY](https://cra-cy.eu/)
* European Cybersecurity Competence Centre
* Co-funded by the European Union

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->

[contributors-shield]: https://img.shields.io/github/contributors/CRA-tools/crypto-assessment.svg?style=for-the-badge
[contributors-url]: https://github.com/CRA-tools/crypto-assessment/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/CRA-tools/crypto-assessment.svg?style=for-the-badge
[forks-url]: https://github.com/CRA-tools/crypto-assessment/network/members
[stars-shield]: https://img.shields.io/github/stars/CRA-tools/crypto-assessment.svg?style=for-the-badge
[stars-url]: https://github.com/CRA-tools/crypto-assessment/stargazers
[issues-shield]: https://img.shields.io/github/issues/CRA-tools/crypto-assessment.svg?style=for-the-badge
[issues-url]: https://github.com/CRA-tools/crypto-assessment/issues
[license-shield]: https://img.shields.io/github/license/CRA-tools/crypto-assessment.svg?style=for-the-badge
[license-url]: https://github.com/CRA-tools/crypto-assessment/blob/main/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/company/cracy/
