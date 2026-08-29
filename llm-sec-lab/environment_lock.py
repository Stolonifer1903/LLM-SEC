"""Capture and verify the immutable container/runtime environment used by scans."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests


LAB_DIR = Path(__file__).resolve().parent
DEFAULT_LOCK_PATH = LAB_DIR / "environment-lock.json"
DEFAULT_COMPOSE_ENV_PATH = LAB_DIR / "pinned-images.env"
JUICE_CHALLENGE_CONTAINER_PATH = "/juice-shop/data/static/challenges.yml"
BOOTSTRAP_IMAGES = {
    "juice_shop": {
        "container": "juice-shop",
        "repository": "bkimminich/juice-shop",
        "image": "bkimminich/juice-shop",
        "env": "JUICE_SHOP_IMAGE",
    },
    "vulnerable_app": {
        "container": "vulnerable-app",
        "repository": "sasanlabs/owasp-vulnerableapp",
        "image": "sasanlabs/owasp-vulnerableapp:latest",
        "env": "VULNERABLE_APP_IMAGE",
    },
    "zap": {
        "container": "zap",
        "repository": "ghcr.io/zaproxy/zaproxy",
        "image": "ghcr.io/zaproxy/zaproxy:stable",
        "env": "ZAP_IMAGE",
    },
}
SECRET_KEYS = {"password", "token", "authorization", "cookie", "secret", "api_key"}


def _run(command: list[str], *, check: bool = True) -> str:
    completed = subprocess.run(
        command,
        cwd=LAB_DIR,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _json_command(command: list[str]):
    output = _run(command)
    value = json.loads(output)
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(value, encoding="utf-8", newline="\n")
    temporary.replace(path)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def lock_sha256(lock: dict) -> str:
    canonical = json.dumps(lock, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_bytes(canonical.encode("utf-8"))


def is_pinned_image_ref(value: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@sha256:[0-9a-fA-F]{64}", str(value or "").strip()))


def redact_secrets(value):
    if isinstance(value, dict):
        return {
            key: "<redacted>" if str(key).lower() in SECRET_KEYS else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def _canonical_addons(addons) -> list:
    return sorted(
        addons if isinstance(addons, list) else [],
        key=lambda item: json.dumps(item, sort_keys=True, default=str),
    )


def _inspect_image(reference: str) -> dict:
    return _json_command(["docker", "image", "inspect", reference])


def _inspect_existing_image(spec: dict, *, pull_missing: bool) -> dict:
    try:
        container = _json_command(["docker", "container", "inspect", spec["container"]])
        return _inspect_image(container["Image"])
    except (subprocess.CalledProcessError, KeyError, json.JSONDecodeError):
        try:
            return _inspect_image(spec["image"])
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            local_ids = _run([
                "docker", "image", "ls", "--filter",
                f"reference={spec['repository']}:*", "--no-trunc", "--format", "{{.ID}}",
            ], check=False).splitlines()
            if local_ids:
                return _inspect_image(local_ids[0].strip())
            if not pull_missing:
                raise RuntimeError(
                    f"No existing image was found for {spec['container']}; rerun with image resolution enabled."
                )
            _run(["docker", "pull", spec["image"]])
            return _inspect_image(spec["image"])


def _matching_repo_digest(image: dict, repository: str) -> str:
    digests = [str(value) for value in image.get("RepoDigests", [])]
    for digest in digests:
        if digest.split("@", 1)[0].lower() == repository.lower():
            return digest
    if digests:
        digest = digests[0].split("@", 1)[-1]
        return f"{repository}@{digest}"
    raise RuntimeError(f"Image {image.get('Id', '<unknown>')} has no immutable RepoDigest")


def _image_record(key: str, spec: dict, image: dict) -> dict:
    pinned_ref = _matching_repo_digest(image, spec["repository"])
    if not is_pinned_image_ref(pinned_ref):
        raise RuntimeError(f"Resolved image reference is not immutable: {pinned_ref}")
    labels = (image.get("Config") or {}).get("Labels") or {}
    return {
        "service": key,
        "container_name": spec["container"],
        "bootstrap_reference": spec["image"],
        "pinned_reference": pinned_ref,
        "image_id": str(image.get("Id", "")),
        "repo_digests": sorted(str(value) for value in image.get("RepoDigests", [])),
        "oci_version": str(labels.get("org.opencontainers.image.version", "")),
        "oci_revision": str(labels.get("org.opencontainers.image.revision", "")),
    }


def _write_compose_env(images: dict, path: Path) -> None:
    values = []
    for key, spec in BOOTSTRAP_IMAGES.items():
        reference = images[key]["pinned_reference"]
        if not is_pinned_image_ref(reference):
            raise RuntimeError(f"Refusing to write floating Compose image reference: {reference}")
        values.append(f"{spec['env']}={reference}")
    _atomic_text(path, "\n".join(values) + "\n")


def _http_json(url: str) -> dict | list:
    response = requests.get(url, timeout=(3, 15))
    response.raise_for_status()
    return response.json()


def _runtime_metadata() -> dict:
    juice_response = _http_json("http://localhost:3000/rest/admin/application-version")
    vulnerable_catalogue = _http_json(
        "http://localhost:9090/VulnerableApp/allEndPointJson"
    )
    zap_version = _http_json("http://localhost:8090/JSON/core/view/version/")
    try:
        addons = _http_json("http://localhost:8090/JSON/autoupdate/view/installedAddons/")
    except requests.RequestException:
        addons = {"addons": [], "capture_warning": "installedAddons endpoint unavailable"}
    return {
        "juice_shop": {
            "application_version": str(
                juice_response.get("version", juice_response.get("data", {}).get("version", ""))
                if isinstance(juice_response, dict) else ""
            ),
        },
        "vulnerable_app": {
            "application_version": "",
            "catalogue_sha256": sha256_bytes(json.dumps(
                vulnerable_catalogue, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")),
        },
        "zap": {
            "application_version": str(zap_version.get("version", "")),
            "installed_addons": _canonical_addons(
                addons.get("addons", addons.get("installedAddons", []))
                if isinstance(addons, dict) else []
            ),
            "addon_capture_warning": addons.get("capture_warning", "")
            if isinstance(addons, dict) else "",
        },
    }


def _capture_challenge_catalogue(version: str) -> dict:
    content = _read_container_file_bytes(
        BOOTSTRAP_IMAGES["juice_shop"]["container"], JUICE_CHALLENGE_CONTAINER_PATH,
    )
    safe_version = re.sub(r"[^A-Za-z0-9._-]+", "_", version or "unknown")
    relative = Path("ground_truth_sources") / "juice_shop" / safe_version / "challenges.yml"
    destination = LAB_DIR / relative
    _atomic_text(destination, content.decode("utf-8"))
    return {
        "container_path": JUICE_CHALLENGE_CONTAINER_PATH,
        "local_path": relative.as_posix(),
        "sha256": sha256_bytes(content),
        "source_revision": "",
    }


def _read_container_file_bytes(container: str, container_path: str) -> bytes:
    """Read a distroless-container file through Docker without requiring a shell."""
    with tempfile.TemporaryDirectory(prefix="llm-sec-lock-") as directory:
        destination = Path(directory) / Path(container_path).name
        _run(["docker", "cp", f"{container}:{container_path}", str(destination)])
        return destination.read_bytes()


def capture_environment_lock(
    lock_path: Path = DEFAULT_LOCK_PATH,
    compose_env_path: Path = DEFAULT_COMPOSE_ENV_PATH,
    *,
    pull_missing: bool = True,
    start_services: bool = True,
) -> dict:
    """Inspect first, resolve only missing images, then capture runtime provenance."""
    if lock_path.is_file():
        try:
            existing = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
        if isinstance(existing, dict) and existing.get("status") == "captured":
            _write_compose_env(existing["images"], compose_env_path)
            if start_services:
                _run([
                    "docker", "compose", "--env-file", str(compose_env_path),
                    "up", "-d", "--no-build",
                ])
                verify_environment_lock(lock_path)
            return existing
    images = {
        key: _image_record(key, spec, _inspect_existing_image(spec, pull_missing=pull_missing))
        for key, spec in BOOTSTRAP_IMAGES.items()
    }
    _write_compose_env(images, compose_env_path)
    if start_services:
        _run([
            "docker", "compose", "--env-file", str(compose_env_path),
            "up", "-d", "--no-build",
        ])
    runtime = _runtime_metadata()
    for key in images:
        images[key].update(runtime[key])
        version = str(images[key].get("application_version", "")).strip()
        if version:
            digest = images[key]["pinned_reference"].split("@", 1)[1]
            repository = BOOTSTRAP_IMAGES[key]["repository"]
            images[key]["pinned_reference"] = f"{repository}:{version}@{digest}"
    _write_compose_env(images, compose_env_path)
    catalogue = _capture_challenge_catalogue(images["juice_shop"]["application_version"])
    catalogue["source_revision"] = (
        images["juice_shop"].get("oci_revision", "")
        or images["juice_shop"]["pinned_reference"]
    )
    lock = {
        "schema_version": 1,
        "status": "captured",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "images": images,
        "juice_shop_challenge_catalogue": catalogue,
    }
    _atomic_json(lock_path, redact_secrets(lock))
    return lock


def load_environment_lock(path: Path = DEFAULT_LOCK_PATH) -> dict:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Environment lock does not exist: {path}") from exc
    if not isinstance(lock, dict) or lock.get("status") != "captured":
        raise RuntimeError(
            f"Environment lock is not captured: {path}. Run --capture-environment-lock first."
        )
    for key in BOOTSTRAP_IMAGES:
        reference = lock.get("images", {}).get(key, {}).get("pinned_reference", "")
        if not is_pinned_image_ref(reference):
            raise RuntimeError(f"Environment lock contains a floating or missing {key} image: {reference!r}")
    return lock


def verify_environment_lock(path: Path = DEFAULT_LOCK_PATH) -> dict:
    """Fail closed when running containers/runtime metadata differ from the lock."""
    expected = load_environment_lock(path)
    observed_images = {}
    mismatches = []
    for key, spec in BOOTSTRAP_IMAGES.items():
        container = _json_command(["docker", "container", "inspect", spec["container"]])
        image = _inspect_image(container["Image"])
        observed = _image_record(key, spec, image)
        observed_images[key] = observed
        expected_image = expected["images"][key]
        if observed["image_id"] != expected_image.get("image_id"):
            mismatches.append(f"{key}.image_id")
        expected_digest = expected_image["pinned_reference"].split("@", 1)[1]
        if not any(value.endswith(expected_digest) for value in observed["repo_digests"]):
            mismatches.append(f"{key}.repo_digest")

    runtime = _runtime_metadata()
    for key in BOOTSTRAP_IMAGES:
        expected_version = str(expected["images"][key].get("application_version", ""))
        observed_version = str(runtime[key].get("application_version", ""))
        if expected_version and observed_version != expected_version:
            mismatches.append(f"{key}.application_version")
    expected_addons = expected["images"]["zap"].get("installed_addons", [])
    observed_addons = runtime["zap"].get("installed_addons", [])
    if _canonical_addons(expected_addons) != _canonical_addons(observed_addons):
        mismatches.append("zap.installed_addons")
    if runtime["vulnerable_app"].get("catalogue_sha256") != expected["images"][
        "vulnerable_app"
    ].get("catalogue_sha256"):
        mismatches.append("vulnerable_app.catalogue_sha256")

    challenge_content = _read_container_file_bytes(
        BOOTSTRAP_IMAGES["juice_shop"]["container"], JUICE_CHALLENGE_CONTAINER_PATH,
    )
    observed_catalogue_sha = sha256_bytes(challenge_content)
    if observed_catalogue_sha != expected["juice_shop_challenge_catalogue"].get("sha256"):
        mismatches.append("juice_shop_challenge_catalogue.sha256")
    if mismatches:
        raise RuntimeError("Environment lock mismatch: " + ", ".join(sorted(set(mismatches))))
    return redact_secrets({
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "lock_file": str(path.resolve()),
        "environment_lock_sha256": lock_sha256(expected),
        "images": observed_images,
        "runtime": runtime,
        "juice_shop_challenge_catalogue_sha256": observed_catalogue_sha,
        "status": "verified",
    })
