"""Client-side helpers for the shared Modal endpoint, reused from
epistemic-fingerprints (personas/personas.py). Import get_modal_url() and
wait_for_server() rather than hardcoding a URL -- Modal assigns server URLs
at deploy time and they aren't predictable from the app/class names.
"""

from __future__ import annotations

import time

import httpx


def wait_for_server(base_url: str, timeout: int = 600, interval: int = 5) -> None:
    """Block until the vLLM server answers /models.

    Modal's Flash routing (used by @app.server) returns 503 "no upstreams
    available" immediately while a container is still cold-starting, instead
    of queueing the request - so callers must poll before sending traffic.
    Every collaborator hitting the shared endpoint needs this, not just
    whoever deploys it.
    """
    models_url = base_url.rstrip("/") + "/models"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(models_url, timeout=10).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        print(f"Waiting for model server at {base_url} ...")
        time.sleep(interval)
    raise RuntimeError(f"Server at {base_url} did not become ready within {timeout}s.")


def get_modal_url(app_name: str = "containment-vllm-server", server_name: str = "Server") -> str:
    """Look up the live URL of a deployed Modal server (`modal deploy
    protocols/serve_model.py` must have already run). Share this app_name
    with the team so everyone resolves the same endpoint."""
    import modal

    server = modal.Server.from_name(app_name, server_name)
    url = server.get_url()
    if not url:
        raise RuntimeError(f"Server '{app_name}/{server_name}' has no live URL. Is it deployed and running?")
    return url.rstrip("/") + "/v1"
