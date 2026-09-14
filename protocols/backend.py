"""Model-agnostic backend interface and dependency-free vLLM HTTP client."""
from __future__ import annotations

import math
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol

from .contracts import ContractError, canonical, digest, strict_json, utc_now


class BackendError(RuntimeError):
    def __init__(self, message: str, *, code="backend_error", retriable=False, attempts=None):
        super().__init__(message)
        self.code = code
        self.retriable = retriable
        self.attempts = attempts or []


@dataclass
class ModelReply:
    content: str
    attempts: list[dict]
    model: str
    finish_reason: str = "stop"


class Backend(Protocol):
    def prepare(self) -> dict: ...
    def count_tokens(self, messages: list[dict]) -> int: ...
    def generate(self, messages: list[dict], schema: dict, config, seed: int) -> ModelReply: ...
    def metadata(self) -> dict: ...


def normalize_base_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError("Set CONTAINMENT_BASE_URL to the deployed API base URL")
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ContractError("base URL must be an absolute HTTP(S) URL")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ContractError("use HTTPS for remote endpoints")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ContractError("supply credentials separately; base URL cannot contain credentials or a query")
    path = parsed.path.rstrip("/")
    if not path.endswith("/v1"):
        path += "/v1"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class VLLMBackend:
    """No Modal SDK or login is needed when a deployed API URL is supplied.

    Token counts come from the vLLM /tokenize API. Other providers can implement
    Backend with their own exact tokenizer. No silent context truncation.
    """

    def __init__(self, base_url: str | None = None, model: str | None = None, *,
                 api_key: str | None = None, readiness_timeout: float = 600,
                 request_timeout: float = 120, poll_interval: float = 2,
                 max_attempts: int = 3, retry_delay: float = 1,
                 transport: Callable | None = None, sleep: Callable = time.sleep):
        self.base_url = normalize_base_url(base_url or os.getenv("CONTAINMENT_BASE_URL", ""))
        self.root_url = self.base_url[:-3]
        self.model = model or os.getenv("CONTAINMENT_MODEL") or None
        self.api_key = api_key or os.getenv("CONTAINMENT_API_KEY") or None
        for name, value in (("readiness_timeout", readiness_timeout),
                            ("request_timeout", request_timeout), ("poll_interval", poll_interval)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ContractError(f"{name} must be finite and positive")
        if type(max_attempts) is not int or max_attempts < 1:
            raise ContractError("max_attempts must be a positive integer")
        if not isinstance(retry_delay, (int, float)) or not math.isfinite(retry_delay) or retry_delay < 0:
            raise ContractError("retry_delay must be finite and nonnegative")
        self.readiness_timeout = readiness_timeout
        self.request_timeout = request_timeout
        self.poll_interval = poll_interval
        self.max_attempts = max_attempts
        self.retry_delay = retry_delay
        self._transport = transport
        self._sleep = sleep
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._lock = threading.Lock()
        self._ready = False
        self._startup_seconds = None
        self._readiness_requests = 0
        self._tokenization_requests = 0
        self.max_model_len = None

    def metadata(self) -> dict:
        # Endpoint, authorization headers, and credentials are intentionally absent.
        return {
            "mode": "live", "model": self.model, "tokenization": "vllm-tokenize",
            "structured_output": "json_schema", "startup_seconds": self._startup_seconds,
            "readiness_requests": self._readiness_requests,
            "tokenization_requests": self._tokenization_requests,
            "max_model_len": self.max_model_len, "max_attempts": self.max_attempts,
            "request_timeout_seconds": self.request_timeout,
        }

    def _request(self, method: str, path: str, body=None, *, root=False, timeout=None):
        url = (self.root_url if root else self.base_url) + path
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        timeout = timeout or self.request_timeout
        if self._transport is not None:
            return self._transport(method, url, body, headers, timeout)
        req = urllib.request.Request(
            url, data=canonical(body).encode() if body is not None else None,
            headers=headers, method=method,
        )
        try:
            with self._opener.open(req, timeout=timeout) as response:
                content = response.read(2_000_001)
                if len(content) > 2_000_000:
                    raise BackendError("API response exceeds size limit", code="response_too_large")
                return strict_json(content.decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise BackendError(
                f"API returned HTTP {error.code}", code=f"http_{error.code}",
                retriable=error.code in (408, 429, 500, 502, 503, 504),
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            cause = getattr(error, "reason", error)
            raise BackendError(
                "Network request failed", code="network_error",
                retriable=not isinstance(cause, PermissionError),
            ) from None
        except (ContractError, UnicodeError):
            raise BackendError("API response is not valid JSON", code="invalid_api_json") from None

    def prepare(self) -> dict:
        with self._lock:
            if self._ready:
                return self.metadata()
            started = time.monotonic()
            deadline = started + self.readiness_timeout
            while time.monotonic() < deadline:
                self._readiness_requests += 1
                try:
                    body = self._request("GET", "/models", timeout=min(
                        30, self.request_timeout, max(.001, deadline - time.monotonic())))
                    models = body.get("data") if isinstance(body, dict) else None
                    if not isinstance(models, list) or not models:
                        raise BackendError("API returned no model list", code="invalid_model_list")
                    ids = [m.get("id") for m in models if isinstance(m, dict) and isinstance(m.get("id"), str)]
                    if self.model is None:
                        if len(ids) != 1:
                            raise BackendError("Set CONTAINMENT_MODEL when the endpoint serves multiple models",
                                               code="ambiguous_model")
                        self.model = ids[0]
                    if self.model not in ids:
                        raise BackendError("Configured model is absent from /models", code="model_not_found")
                    entry = next(m for m in models if isinstance(m, dict) and m.get("id") == self.model)
                    length = entry.get("max_model_len")
                    self.max_model_len = length if type(length) is int and length > 0 else None
                    self._ready = True
                    self._startup_seconds = time.monotonic() - started
                    return self.metadata()
                except BackendError as error:
                    if not error.retriable:
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        self._sleep(min(self.poll_interval, remaining))
            raise BackendError("Model readiness deadline exceeded", code="readiness_timeout")

    def count_tokens(self, messages: list[dict]) -> int:
        self.prepare()
        with self._lock:
            self._tokenization_requests += 1
        body = self._request("POST", "/tokenize", {
            "model": self.model, "messages": messages, "add_generation_prompt": True,
        }, root=True)
        count = body.get("count") if isinstance(body, dict) else None
        if type(count) is not int or count < 0:
            raise BackendError("Tokenization endpoint did not return a valid count", code="invalid_token_count")
        return count

    @staticmethod
    def _usage(body) -> tuple[dict | None, str]:
        usage = body.get("usage") if isinstance(body, dict) else None
        if usage is None:
            return None, "missing"
        keys = ("prompt_tokens", "completion_tokens", "total_tokens")
        if not isinstance(usage, dict) or any(type(usage.get(k)) is not int or usage[k] < 0 for k in keys):
            return None, "invalid"
        if usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]:
            return None, "invalid"
        return {k: usage[k] for k in keys}, "complete"

    def generate(self, messages: list[dict], schema: dict, config, seed: int) -> ModelReply:
        self.prepare()
        payload = {
            "model": self.model, "messages": messages,
            "temperature": config.temperature, "top_p": config.top_p,
            "max_tokens": config.max_output_tokens, "seed": seed, "stream": False,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "containment_review", "strict": True, "schema": schema},
            },
        }
        attempts = []
        for number in range(1, self.max_attempts + 1):
            start = time.monotonic()
            attempt = {
                "attempt": number, "started_at": utc_now(), "request_sha256": digest(payload),
                "seed": seed, "status": "error", "usage": None, "usage_status": "missing",
            }
            try:
                body = self._request("POST", "/chat/completions", payload)
                attempt["response_sha256"] = digest(body)
                attempt["usage"], attempt["usage_status"] = self._usage(body)
                if not isinstance(body, dict):
                    raise BackendError("Completion response must be an object", code="invalid_completion")
                choices = body.get("choices")
                if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                    raise BackendError("Expected one completion choice", code="invalid_completion")
                message = choices[0].get("message")
                content = message.get("content") if isinstance(message, dict) else None
                if not isinstance(content, str):
                    raise BackendError("Completion content must be text", code="invalid_completion")
                actual_model = body.get("model", self.model)
                if actual_model != self.model:
                    raise BackendError("Returned model differs from configured model", code="model_mismatch")
                reason = choices[0].get("finish_reason")
                attempt.update({
                    "status": "ok", "finish_reason": reason,
                    "system_fingerprint": body.get("system_fingerprint"),
                })
                return ModelReply(content, attempts + [attempt], actual_model, reason)
            except BackendError as error:
                attempt["error_code"] = error.code
                if not error.retriable or number == self.max_attempts:
                    error.attempts = attempts + [attempt]
                    raise
            finally:
                attempt["completed_at"] = utc_now()
                attempt["latency_seconds"] = time.monotonic() - start
                attempts.append(attempt)
            self._sleep(min(8, self.retry_delay * 2 ** (number - 1)))
        raise AssertionError("unreachable")


class MockBackend:
    """Constant responses for software tests ONLY. Never an empirical monitor."""
    max_model_len = None

    def metadata(self):
        return {"mode": "mock", "model": "mock-constant-v1", "tokenization": "mock-estimate",
                "startup_seconds": 0, "readiness_requests": 0, "tokenization_requests": 0}

    def prepare(self):
        return self.metadata()

    def count_tokens(self, messages):
        return math.ceil(len(canonical(messages).encode("utf-8")) / 4)

    def generate(self, messages, schema, config, seed):
        return ModelReply(canonical({
            "decision": "continue", "reasoning": "Mock response for software verification only.",
            "signals_detected": [],
        }), [], "mock-constant-v1")
