import json
import logging
import os
import shutil
import tempfile
from http.server import BaseHTTPRequestHandler
from typing import Any

from helpers import (
    checkout_repo,
    find_semgrep_configs,
    redact_token,
    safe_subfolder_path,
    summarize_semgrep,
)

from run_command import run_command
from semgrep_types import SemgrepScanRequest


logger = logging.getLogger(__name__)

CONFIGS_DIR = os.environ.get("SEMGREP_CONFIGS_DIR", "/configs")
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(5 * 1024 * 1024)))
SEMGREP_TIMEOUT_SECONDS = int(os.environ.get("SEMGREP_TIMEOUT_SECONDS", "600"))


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    """Send a JSON response with basic CORS headers for local React development."""
    body = json.dumps(payload, indent=2).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
    handler.end_headers()
    handler.wfile.write(body)


class SemgrepRequestHandler(BaseHTTPRequestHandler):
    """HTTP API for the local Semgrep runner."""

    def do_OPTIONS(self) -> None:
        """Handle browser CORS preflight requests."""
        logger.info("Received CORS preflight request from %s", self.client_address)

        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        """Expose a simple health check endpoint."""
        logger.info("Received GET request: path=%s client=%s", self.path, self.client_address)

        if self.path == "/health":
            send_json(
                self,
                200,
                {
                    "ok": True,
                    "service": "semgrep-runner",
                    "configsDir": CONFIGS_DIR,
                },
            )
            return

        send_json(self, 404, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:
        """Run a Semgrep scan for POST /scan."""
        logger.info("Received POST request: path=%s client=%s", self.path, self.client_address)

        if self.path != "/scan":
            send_json(self, 404, {"ok": False, "error": "Not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        logger.info("Incoming Semgrep scan request body size: %s bytes", content_length)

        if content_length > MAX_BODY_BYTES:
            logger.warning(
                "Rejected request because body is too large: size=%s max=%s",
                content_length,
                MAX_BODY_BYTES,
            )
            send_json(self, 413, {"ok": False, "error": "Request body too large"})
            return

        pat = ""
        temp_dir = ""

        try:
            payload: SemgrepScanRequest = json.loads(
                self.rfile.read(content_length).decode("utf-8")
            )

            git_url = payload.get("gitUrl")
            branch = payload.get("branch")
            commit = payload.get("commit")
            subfolder = payload.get("subfolder") or ""

            credentials = payload.get("credentials") or {}
            pat = credentials.get("pat") or ""

            logger.info(
                "Parsed Semgrep scan request: gitUrl=%s branch=%s commit=%s subfolder=%s hasPat=%s",
                git_url,
                branch or "",
                commit or "",
                subfolder,
                bool(pat),
            )

            if not git_url:
                logger.warning("Rejected Semgrep scan request because gitUrl is missing")
                send_json(self, 400, {"ok": False, "error": "Missing gitUrl"})
                return

            if not os.path.isdir(CONFIGS_DIR):
                logger.error("Semgrep configs directory does not exist: %s", CONFIGS_DIR)

                send_json(
                    self,
                    500,
                    {
                        "ok": False,
                        "error": f"Semgrep configs directory does not exist: {CONFIGS_DIR}",
                    },
                )
                return

            temp_dir = tempfile.mkdtemp(prefix="semgrep-scan-")
            repo_dir = os.path.join(temp_dir, "repo")

            logger.info("Created temporary Semgrep workspace: %s", temp_dir)

            try:
                checkout_repo(
                    git_url=git_url,
                    branch=branch,
                    commit=commit,
                    pat=pat,
                    destination=repo_dir,
                )

                scan_target = safe_subfolder_path(repo_dir, subfolder)

                logger.info(
                    "Resolved Semgrep scan target: target=%s exists=%s fileCount=%s",
                    scan_target,
                    os.path.exists(scan_target),
                    sum(len(files) for _, _, files in os.walk(scan_target)),
                )

                semgrep_configs = find_semgrep_configs(CONFIGS_DIR)

                semgrep_args = ["semgrep", "scan"]

                for config_path in semgrep_configs:
                    semgrep_args.extend(["--config", config_path])

                python_targets: list[str] = []

                if os.path.isfile(scan_target):
                    if scan_target.endswith(".py"):
                        python_targets.append(scan_target)
                else:
                    for root, _dirs, files in os.walk(scan_target):
                        for filename in files:
                            if filename.endswith(".py"):
                                target_file = os.path.join(root, filename)

                                if os.path.islink(target_file):
                                    logger.info(
                                        "Skipping symbolic-link Semgrep target: %s",
                                        target_file,
                                    )
                                    continue

                                python_targets.append(target_file)
                
                python_targets.sort()
                
                if not python_targets:
                    raise ValueError(f"No Python files found under scan target: {subfolder}")
                
                logger.info(
                    "Resolved %s Python Semgrep target files under scan target",
                    len(python_targets),
                )
                
                semgrep_args.extend(
                    [
                        "--json",
                        "--metrics",
                        "off",
                        "--disable-version-check",
                        "--no-git-ignore",
                    ]
                )
                
                semgrep_args.extend(python_targets)

                logger.info(
                    "Running Semgrep with %s config files against target=%s",
                    len(semgrep_configs),
                    scan_target,
                )

                semgrep_stdout = run_command(
                    semgrep_args,
                    timeout=SEMGREP_TIMEOUT_SECONDS,
                    secrets=[pat],
                )

                raw = json.loads(semgrep_stdout)
                summary = summarize_semgrep(raw)

                logger.info(
                    "Semgrep scan completed: gitUrl=%s branch=%s commit=%s findingCount=%s",
                    git_url,
                    branch or "",
                    commit or "",
                    summary["count"],
                )

                send_json(
                    self,
                    200,
                    {
                        "ok": True,
                        "gitUrl": git_url,
                        "branch": branch,
                        "commit": commit,
                        "subfolder": subfolder,
                        "result": summary,
                    },
                )

            finally:
                if temp_dir:
                    logger.info("Removing temporary Semgrep workspace: %s", temp_dir)
                    shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as error:
            logger.exception("Semgrep scan request failed")

            send_json(
                self,
                500,
                {
                    "ok": False,
                    "error": redact_token(str(error), pat),
                },
            )
