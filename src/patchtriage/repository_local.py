"""Opt-in local scanner for public HTTPS Git repositories.

This adapter is intentionally unavailable in hosted/public mode. It clones a
public repository into a disposable directory and asks the pinned
``osv-scanner`` binary to inspect lockfiles without installing dependencies or
executing repository code. Provider-backed imports remain preferable because
they avoid exposing the web process to arbitrary Git servers.
"""

from __future__ import annotations

import ipaddress
import json
import os
import signal
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .repository import (
    RepositoryFetchError,
    RepositoryTooLargeError,
    normalize_repository_url,
)


DEFAULT_CLONE_TIMEOUT = 120
DEFAULT_SCAN_TIMEOUT = 180
DEFAULT_REPOSITORY_BYTES = 512 * 1024 * 1024
DEFAULT_REPOSITORY_FILES = 100_000
DEFAULT_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_TOOL_LOG_BYTES = 1024 * 1024
_PROCESS_POLL_SECONDS = 0.1

_MANIFEST_NAMES = {
    "cargo.lock", "composer.lock", "deps.edn", "gemfile.lock", "go.mod",
    "gradle.lockfile", "mix.lock", "package-lock.json", "packages.lock.json",
    "packages.resolved", "pipfile.lock", "pnpm-lock.yaml", "poetry.lock",
    "pubspec.lock", "renv.lock", "yarn.lock",
}


def osv_source_scan_command(scanner: str, output: Path, config: Path,
                            target: Path) -> list[str]:
    """OSV-Scanner 2.x source scan; nested lockfiles need ``--recursive``."""
    return [
        scanner, "scan", "source", "--format", "json",
        "--output-file", str(output), "--config", str(config),
        "--all-packages", "--no-resolve",
        "--recursive", str(target),
    ]


@dataclass(frozen=True)
class LocalRepositoryEvidence:
    content: str
    format: str
    provenance: dict[str, Any]


def _public_addresses(host: str, port: int = 443) -> list[str]:
    """Resolve a host once and reject every non-global destination.

    This is a defense-in-depth application check, not a replacement for an
    egress firewall. For that reason the adapter is disabled in public mode.
    """
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RepositoryFetchError(
            f"repository host could not be resolved: {host}") from exc
    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses:
        raise RepositoryFetchError("repository host resolved to no addresses")
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise RepositoryFetchError(
                "repository host returned an invalid address") from exc
        if not address.is_global:
            raise RepositoryFetchError(
                "repository host resolves to a private, local, reserved, or "
                f"otherwise non-public address ({value})")
    return addresses


def _tool_environment(home: Path) -> dict[str, str]:
    keep = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR",
                           "COMSPEC", "TEMP", "TMP", "LANG", "LC_ALL"}
    }
    keep.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "HOME": str(home),
        "USERPROFILE": str(home),
    })
    return keep


def _enforce_path_limits(path: Path, *, max_bytes: int | None,
                         max_files: int | None, label: str) -> None:
    """Bound a growing file or tree while an external tool is running."""
    if not path.exists() and not path.is_symlink():
        return
    total = 0
    count = 0
    candidates: Any
    if path.is_file() or path.is_symlink():
        candidates = [path]
    else:
        candidates = (
            Path(directory) / filename
            for directory, _dirs, files in os.walk(path, followlinks=False)
            for filename in files
        )
    for candidate in candidates:
        count += 1
        if max_files is not None and count > max_files:
            raise RepositoryTooLargeError(
                f"{label} contains more than {max_files} files")
        try:
            total += candidate.lstat().st_size
        except OSError:
            continue
        if max_bytes is not None and total > max_bytes:
            raise RepositoryTooLargeError(
                f"{label} exceeds the {max_bytes}-byte limit")


def _stop_process(process: subprocess.Popen) -> None:
    """Best-effort tree termination after a timeout or resource violation."""
    pid = getattr(process, "pid", None)
    tree_stopped = False
    if os.name == "nt" and pid:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = str(Path(system_root) / "System32" / "taskkill.exe")
        try:
            result = subprocess.run(
                [taskkill, "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False)
            tree_stopped = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    elif pid:
        try:
            os.killpg(pid, signal.SIGTERM)
            tree_stopped = True
        except (OSError, ProcessLookupError):
            pass
    if not tree_stopped:
        try:
            process.terminate()
        except OSError:
            pass
    parent_exited = False
    try:
        process.wait(timeout=2)
        parent_exited = True
    except (OSError, subprocess.TimeoutExpired):
        pass
    # On POSIX the group can outlive its leader, so always escalate the group
    # after the grace period even when wait() says the direct parent exited.
    if os.name == "nt":
        if pid and not tree_stopped:
            system_root = os.environ.get("SystemRoot", r"C:\Windows")
            taskkill = str(Path(system_root) / "System32" / "taskkill.exe")
            try:
                subprocess.run(
                    [taskkill, "/PID", str(pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
    elif pid:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if not parent_exited:
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _run_monitored(
    command: list[str], *, env: dict[str, str], timeout: int,
    monitor_path: Path, max_bytes: int | None, max_files: int | None,
    label: str,
) -> subprocess.CompletedProcess:
    """Run a tool while bounding its filesystem growth and captured logs."""
    with (
        tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout_file,
        tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr_file,
    ):
        try:
            process_options: dict[str, Any] = {}
            if os.name == "nt":
                process_options["creationflags"] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                process_options["start_new_session"] = True
            process = subprocess.Popen(
                command, stdout=stdout_file, stderr=stderr_file,
                text=True, encoding="utf-8", errors="replace", env=env,
                **process_options)
        except OSError as exc:
            raise RepositoryFetchError(
                f"{label} could not start: {exc}") from exc
        deadline = time.monotonic() + timeout
        try:
            while True:
                _enforce_path_limits(
                    monitor_path, max_bytes=max_bytes, max_files=max_files,
                    label=label)
                if (os.fstat(stdout_file.fileno()).st_size > DEFAULT_TOOL_LOG_BYTES
                        or os.fstat(stderr_file.fileno()).st_size >
                        DEFAULT_TOOL_LOG_BYTES):
                    raise RepositoryFetchError(
                        f"{label} produced excessive diagnostic output")
                if process.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(_PROCESS_POLL_SECONDS)
            # Close the race between the final pre-poll check and process exit.
            _enforce_path_limits(
                monitor_path, max_bytes=max_bytes, max_files=max_files,
                label=label)
            if (os.fstat(stdout_file.fileno()).st_size > DEFAULT_TOOL_LOG_BYTES
                    or os.fstat(stderr_file.fileno()).st_size >
                    DEFAULT_TOOL_LOG_BYTES):
                raise RepositoryFetchError(
                    f"{label} produced excessive diagnostic output")
        except (RepositoryFetchError, RepositoryTooLargeError,
                subprocess.TimeoutExpired):
            _stop_process(process)
            raise
        stdout_file.seek(0)
        stderr_file.seek(0)
        return subprocess.CompletedProcess(
            command, process.returncode,
            stdout=stdout_file.read(), stderr=stderr_file.read())


def _repository_inventory(root: Path, max_bytes: int,
                          max_files: int) -> tuple[int, int, list[str]]:
    total = 0
    count = 0
    manifests: list[str] = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name != ".git"]
        for filename in files:
            path = Path(directory) / filename
            if path.is_symlink():
                continue
            count += 1
            if count > max_files:
                raise RepositoryTooLargeError(
                    f"repository contains more than {max_files} files")
            try:
                total += path.stat().st_size
            except OSError:
                continue
            if total > max_bytes:
                raise RepositoryTooLargeError(
                    f"repository checkout exceeds the {max_bytes}-byte limit")
            lower = filename.lower()
            if lower in _MANIFEST_NAMES or lower.endswith((
                    ".csproj", ".fsproj", ".gemspec", ".gradle")):
                manifests.append(str(path.relative_to(root)).replace("\\", "/"))
    return count, total, manifests[:500]


def scan_public_repository(
    repository_url: str,
    *,
    git_binary: str | None = None,
    scanner_binary: str | None = None,
    clone_timeout: int = DEFAULT_CLONE_TIMEOUT,
    scan_timeout: int = DEFAULT_SCAN_TIMEOUT,
    max_bytes: int = DEFAULT_REPOSITORY_BYTES,
    max_files: int = DEFAULT_REPOSITORY_FILES,
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
) -> LocalRepositoryEvidence:
    """Clone and statically scan an explicitly allowed public repository."""
    reference = normalize_repository_url(repository_url)
    _public_addresses(reference.host, 443)
    git = git_binary or shutil.which("git")
    scanner = scanner_binary or shutil.which("osv-scanner")
    if not git or not scanner:
        raise RepositoryFetchError(
            "generic repository scanning requires git and osv-scanner; use "
            "the Docker GUI or install both tools locally")

    with tempfile.TemporaryDirectory(prefix="patchtriage-repository-") as tmp:
        temp_root = Path(tmp)
        checkout = temp_root / "checkout"
        output = temp_root / "osv-results.json"
        scanner_config = temp_root / "trusted-osv-scanner.toml"
        # Never honor ignore rules supplied by the repository being assessed.
        scanner_config.write_text("", encoding="utf-8")
        environment = _tool_environment(temp_root / "home")
        (temp_root / "home").mkdir()
        clone = [
            git,
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", "credential.helper=",
            "-c", "http.followRedirects=false",
            "-c", f"core.hooksPath={os.devnull}",
            "-c", "submodule.recurse=false",
            "clone", "--quiet", "--depth", "1", "--single-branch",
            "--no-recurse-submodules", "--filter=blob:limit=20m",
            reference.normalized_url, str(checkout),
        ]
        try:
            completed = _run_monitored(
                clone, env=environment, timeout=clone_timeout,
                monitor_path=checkout, max_bytes=max_bytes,
                max_files=max_files, label="repository clone")
        except subprocess.TimeoutExpired as exc:
            raise RepositoryFetchError(
                f"repository clone exceeded {clone_timeout} seconds") from exc
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).strip()[-600:]
            raise RepositoryFetchError(
                "repository clone failed" + (f": {detail}" if detail else ""))

        file_count, repository_bytes, manifests = _repository_inventory(
            checkout, max_bytes, max_files)
        command = osv_source_scan_command(
            scanner, output, scanner_config, checkout)
        try:
            completed = _run_monitored(
                command, env=environment, timeout=scan_timeout,
                monitor_path=output, max_bytes=max_output_bytes,
                max_files=1, label="osv-scanner output")
        except subprocess.TimeoutExpired as exc:
            raise RepositoryFetchError(
                f"repository scan exceeded {scan_timeout} seconds") from exc
        no_packages = completed.returncode == 128
        if completed.returncode not in (0, 1, 128):
            detail = (completed.stderr or completed.stdout).strip()[-600:]
            raise RepositoryFetchError(
                "osv-scanner failed" + (f": {detail}" if detail else ""))
        if no_packages and not output.exists():
            content = json.dumps({"results": []})
        elif not output.exists():
            raise RepositoryFetchError("osv-scanner did not produce JSON output")
        else:
            try:
                output_size = output.stat().st_size
            except OSError as exc:
                raise RepositoryFetchError(
                    "osv-scanner output could not be inspected") from exc
            if output_size > max_output_bytes:
                raise RepositoryTooLargeError(
                    "osv-scanner output exceeds the "
                    f"{max_output_bytes}-byte limit")
            content = output.read_text(encoding="utf-8")
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RepositoryFetchError(
                "osv-scanner produced invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(
                payload.get("results"), list):
            raise RepositoryFetchError(
                "osv-scanner JSON is missing its results list")

        commit = subprocess.run(
            [git, "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, env=environment,
            check=False).stdout.strip()
        packages = sum(len(result.get("packages") or [])
                       for result in payload.get("results") or []
                       if isinstance(result, dict))
        if not manifests:
            coverage_status = "no_supported_manifest"
        elif no_packages or packages == 0:
            coverage_status = "no_package_inventory"
        else:
            coverage_status = "complete"
        warnings = [] if coverage_status == "complete" else [
            "OSV-Scanner produced no supported package inventory; zero "
            "findings must not be interpreted as a clean repository."
        ]
        provenance = {
            "provider": "local_osv_scanner",
            "repository": reference.repository,
            "resolved_url": reference.normalized_url,
            "resolved_commit": commit,
            "format": "osv",
            "scanner": "osv-scanner",
            "scanner_config": "trusted-empty-config",
            "file_count": file_count,
            "repository_bytes": repository_bytes,
            "manifests_detected": manifests,
            "component_count": packages,
            "coverage_status": coverage_status,
            "coverage": {
                "status": coverage_status,
                "complete": coverage_status == "complete",
                "manifests_detected": len(manifests),
                "packages_detected": packages,
            },
            "warnings": warnings,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }
        return LocalRepositoryEvidence(
            content=content, format="osv", provenance=provenance)
