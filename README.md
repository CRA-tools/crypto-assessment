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

Medium, warning, low, and informational findings do not make the code
non-compliant by themselves. REGO findings are displayed only for critical,
error, high, medium, and warning severities; Semgrep findings are displayed
at all returned severities.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- PROJECT STRUCTURE -->
## Project Structure

Main files used by the static frontend:

```text
cbomkit-site-html/
├── api
│   └── cbomApi.js
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
    └── urls.js
```

Important files:

* `index.html` contains the static page structure.
* `styles.css` contains the UI styling, including the footer logos and dark mode styling.
* `app.js` owns the frontend flow for CBOM generation, REGO evaluation, Semgrep evaluation, and rendering results.
* `api/cbomApi.js` manages CBOM generation over WebSocket, including scan progress and errors.
* `config/endpoints.js` defines the backend service URLs.
* `utils/regoFindings.js` normalizes and groups REGO findings.
* `utils/semgrepFindings.js` normalizes and groups Semgrep findings.
* `utils/urls.js` builds CBOMkit and Semgrep request payloads.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

### Prerequisites

You need:

* Docker with Docker Compose.
* Internet access to download container images and clone repositories for scanning.

### Configure the environment

From the repository root, create `.env` from the example if you do not already
have one:

```bash
cp -n .env.example .env
```

Edit `.env` to set `CBOMKIT_VERSION`, `POSTGRESQL_AUTH_USERNAME`, and
`POSTGRESQL_AUTH_PASSWORD`. Replace the example password before starting the
services. For local access, keep
`CBOMKIT_FRONTEND_URL_CORS=http://localhost:8000`.

If you already have a database volume, use its existing credentials. Editing
`.env` does not change stored database users or passwords; see
[Database password authentication fails](#database-password-authentication-fails)
if the credentials no longer match.

For access from another machine, follow
[Accessing the services on a different IP and port](#accessing-the-services-on-a-different-ip-and-port)
to set the allowed frontend origin before starting the services.

### Start the Docker services

From the repository root, start all Docker services:

```bash
docker compose up -d --build
```

This starts the **CRA Compliance Checker** frontend
at `http://localhost:8000`, the CBOMkit backend and database, OPA and its proxy,
and the local Semgrep service.

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

The frontend reads backend endpoints from `config/endpoints.js`. By default,
it uses the page's hostname and HTTP/HTTPS scheme, with port `8081` for CBOMkit,
`9091` for Semgrep, and `8182` for the OPA proxy. The WebSocket URL is derived
from the CBOMkit HTTP URL (`http` becomes `ws`, `https` becomes `wss`).

To use services on different hosts or behind a reverse proxy, set overrides
in `index.html` before the module script that loads `app.js`:

```html
<script>
  window.CRA_COMPLIANCE_CONFIG = {
    CBOMKIT_HTTP_API_BASE: "https://api.example.com/cbom",
    CBOMKIT_WS_API_BASE: "wss://api.example.com/cbom",
    SEMGREP_API_BASE: "https://api.example.com/semgrep",
    POLICY_API_BASE: "https://api.example.com/opa",
    OPA_DECISION_PATH: "/v1/data/cbom/eccg",
  };
</script>
```

All overrides are optional. HTTPS endpoints require TLS support at the service
or reverse proxy; the default Compose services expose plain HTTP.

The expected local services are:

| Service                   | Default URL             |
| ------------------------- | ----------------------- |
| CRA Compliance Checker frontend | `http://localhost:8000` |
| CBOMkit backend           | `http://localhost:8081` |
| CBOMkit scan stream       | `ws://localhost:8081`   |
| OPA proxy                 | `http://localhost:8182` |
| OPA service inside Docker | `http://opa-local:8181` |
| Semgrep local service     | `http://localhost:9091` |

Compose settings in the repository-root `.env`:

| Setting | Purpose | Example value |
| ------- | ------- | ------------- |
| `CBOMKIT_VERSION` | CBOMkit container image tag | `latest` |
| `POSTGRESQL_AUTH_USERNAME` | Database username shared by PostgreSQL and CBOMkit | `cbomkit` |
| `POSTGRESQL_AUTH_PASSWORD` | Database password shared by PostgreSQL and CBOMkit | Replace the example password |
| `CBOMKIT_FRONTEND_URL_CORS` | Frontend origin allowed by the CBOMkit backend and OPA proxy | `http://localhost:8000` |

`CBOMKIT_OPA_API_BASE` is set directly in `docker-compose.yml` to
`http://opa-local:8181` so the backend can reach OPA inside Docker.

Browser overrides in `window.CRA_COMPLIANCE_CONFIG`:

| Setting | Purpose | Default when opened at `http://localhost:8000` |
| ------- | ------- | --------------------------------------------- |
| `CBOMKIT_HTTP_API_BASE` | CBOMkit backend URL | `http://localhost:8081` |
| `CBOMKIT_WS_API_BASE` | WebSocket URL for live CBOMkit scans | `ws://localhost:8081` |
| `POLICY_API_BASE` | OPA proxy URL | `http://localhost:8182` |
| `SEMGREP_API_BASE` | Semgrep service URL | `http://localhost:9091` |
| `OPA_DECISION_PATH` | OPA decision path appended to the proxy URL | `/v1/data/cbom/eccg` |

The CBOMkit overrides are exported by `config/endpoints.js` as `HTTP_API_BASE`
and `WS_API_BASE`; use the `CBOMKIT_` names when setting browser overrides.

The CBOMkit backend and OPA proxy must allow the origin of the page opened in
the browser. Set `CBOMKIT_FRONTEND_URL_CORS` in the repository-root `.env` to
that origin: scheme, hostname or IP address, and port, with no path or trailing
slash. For local access, use `http://localhost:8000`; for a different IP or
port, follow the steps below. The Semgrep service already allows cross-origin
requests and requires no additional CORS setting.

### Accessing the services on a different IP and port

For a VM at `192.168.122.251`, open `http://192.168.122.251:8000`.
The frontend automatically uses that IP for CBOMkit (`8081`), its WebSocket
scan stream (`ws://192.168.122.251:8081`), the OPA proxy (`8182`), and Semgrep
(`9091`). `localhost` in a browser refers to the machine running the browser.
With the updated frontend files on the VM and the default Compose ports,
**the only configuration change needed is `CBOMKIT_FRONTEND_URL_CORS` in `.env`.**
The frontend automatically selects the service URLs; no endpoint overrides
are needed for this setup.

1. On the VM, create `.env` from `.env.example` if needed and configure the
   image tag and database credentials as described in
   [Configure the environment](#configure-the-environment). Edit `.env`
   alongside `docker-compose.yml` and set:

   ```dotenv
   CBOMKIT_FRONTEND_URL_CORS=http://192.168.122.251:8000
   ```

   Use the frontend origin shown in your browser, including its scheme and
   port, with no path or trailing slash. Replace the example IP with your VM's
   IP or hostname. This is the frontend URL on port `8000`, not a backend URL.

2. From that same project directory on the VM, apply the setting:

   ```bash
   docker compose up -d --force-recreate backend opa-proxy
   ```

   Compose reads `.env` and passes the value to both services when creating
   their containers. A plain `docker compose restart` does not apply changed
   environment variables. For a first deployment, use
   `docker compose up -d --build` to start all services with the setting.

3. Open `http://192.168.122.251:8000` and hard-refresh the page to load the
   updated frontend files.

Ports `8000`, `8081`, `8182`, and `9091` must be reachable from the browser's
machine. Use the same frontend hostname or IP consistently: `localhost`, a
VM IP, and a DNS hostname are different origins. If you also change the
frontend port, follow [Changing the frontend port](#changing-the-frontend-port).

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

**Use the sample code in [`demo/code`](demo/code) to run a test assessment
or get familiar with the tool.** Enter this repository's URL, shown below,
and set **Scan path** to `demo/code` to try the assessment workflow and explore
the resulting findings. The [demo guide](demo/README.md) explains example
findings and their severities.

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
   * Commit SHA (used by Semgrep only; CBOMkit scans the selected branch).
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

### Database password authentication fails

If the backend reports `FATAL: password authentication failed for user "cbomkit"`,
it reached PostgreSQL, but the database rejected its credentials. Compose passes
the same `.env` credentials to both services. However, the
[PostgreSQL image](https://github.com/docker-library/docs/blob/master/postgres/content.md#environment-variables)
only creates the user and sets its password when `pg-volume` is first initialized.
Recreating containers with different `.env` values leaves the stored credentials
unchanged.

Run these steps on the machine and in the Compose project that produced the logs:

1. Set `POSTGRESQL_AUTH_USERNAME` and `POSTGRESQL_AUTH_PASSWORD` in `.env` to the
   credentials originally used for this database. Check for exported variables
   with these names in your shell, since they override `.env` values. If the
   backend logs a different username from the one you configured, it may still
   be running with old container settings.

2. If you need to reset the password, keep `POSTGRESQL_AUTH_USERNAME` set to an
   existing database role and start the database:

   ```bash
   docker compose up -d db
   docker compose exec db psql -U cbomkit -d postgres
   ```

   Replace `cbomkit` with the original database username if necessary (for
   example, `postgres`). This uses a local Unix socket, which the standard image
   allows without a password. At the `psql` prompt, run:

   ```text
   \password cbomkit
   \q
   ```

   Again, use the existing role name. Enter the password you want to use at the
   prompts, and set the same value in `.env`. Use single quotes around a password
   containing `$` so Compose reads it literally. Changing the username in `.env`
   does not create that role in an existing database.

3. Apply the matching credentials to both containers and check startup:

   ```bash
   docker compose up -d --force-recreate db backend
   docker compose ps -a
   docker compose logs --tail=100 db backend
   ```

The database health check runs an authenticated query over the same TCP hostname
as the backend. Incorrect credentials make `db` unhealthy and prevent backend
startup. `pg_isready` alone can report readiness even when credentials are wrong.
These recovery steps preserve the database; `docker compose down -v` deletes
the project's named volumes and their data.

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

The browser is calling OPA directly on port `8181`. The frontend should use
the OPA proxy on port `8182`, which supplies the browser CORS headers.

Remove any outdated `POLICY_API_BASE` override from
`window.CRA_COMPLIANCE_CONFIG` to use the default proxy URL at the page's
hostname. If you need an override, set it to the proxy URL using the
[Configuration](#configuration) example. Refresh the page after updating
the frontend files.

Then start both OPA and the proxy:

```bash
docker compose up -d opa-local opa-proxy
```

### OPA request is blocked by CORS

The frontend uses the OPA proxy on port `8182` at the page's hostname by
default. If you set a `POLICY_API_BASE` override, make sure it points to the
proxy rather than OPA directly on port `8181`.

Set `CBOMKIT_FRONTEND_URL_CORS` in `.env` to the exact frontend origin
opened in your browser, then apply it:

```bash
docker compose up -d --force-recreate backend opa-proxy
```

See [Accessing the services on a different IP and port](#accessing-the-services-on-a-different-ip-and-port)
for the complete example. The proxy forwards to:

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
