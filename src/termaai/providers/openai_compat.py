"""OpenAI-compatible chat completions client (used for OpenAI and Groq).

Uses only the standard library so no SDK is required. Opt-in via environment variables.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

from termaai.providers.base import Generation, ProviderError, extract_script

GENERATE_PROMPT = (
    "You write Bash scripts for a Linux shell. Reply with one ```bash fenced block and "
    "nothing else. The script runs with the current directory set to a disposable "
    "workspace: only read and write files inside it, never use sudo, never touch "
    "system paths, and avoid network access unless the user explicitly asks for it."
)
EXPLAIN_PROMPT = (
    "Explain what this Bash script does, step by step, in plain English. Point out "
    "anything destructive or risky. Be concise."
)
REVISE_PROMPT = (
    "You write Bash scripts for a Linux shell. A previous version of the script below "
    "was rejected by a static analyzer. Reply with one ```bash fenced block and "
    "nothing else: a corrected script that still does what the user asked for while "
    "fixing every listed problem. Only read and write files inside the current "
    "directory, never use sudo, never touch system paths, and avoid network access "
    "unless the user explicitly asked for it."
)


class OpenAICompatibleProvider:
    def __init__(
        self,
        name: str,
        api_key: str,
        model: str,
        base_url: str,
        timeout: float = 60.0,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise ProviderError(f"{name}: missing API key")
        self.name = name
        self._api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleep = sleep

    def _chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        body = self._post_with_retries(payload)
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"{self.name}: unexpected response shape") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError(f"{self.name}: empty response (the model may have refused)")
        return content

    @staticmethod
    def _retry_delay(exc: Exception, attempt: int) -> float | None:
        """Seconds to wait before the next attempt, or None when not retryable.

        Retries cover transient failures: HTTP 429 and 5xx, connection errors
        and timeouts. Other 4xx codes and malformed responses fail fast.
        """
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code == 429 or exc.code >= 500:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after:
                    try:
                        return min(float(retry_after), 30.0)
                    except ValueError:
                        pass
                return min(2.0**attempt, 16.0)
            return None
        if isinstance(exc, urllib.error.URLError | TimeoutError):
            return min(2.0**attempt, 16.0)
        return None

    def _post_with_retries(self, payload: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body: dict[str, Any] = json.loads(resp.read().decode())
                    return body
            except urllib.error.HTTPError as exc:
                delay = self._retry_delay(exc, attempt)
                if delay is None or attempt >= self.max_retries:
                    raise ProviderError(f"{self.name}: HTTP {exc.code} from API") from exc
                last = exc
            except (urllib.error.URLError, TimeoutError) as exc:
                delay = self._retry_delay(exc, attempt)
                if delay is None or attempt >= self.max_retries:
                    raise ProviderError(f"{self.name}: request failed ({exc})") from exc
                last = exc
            except json.JSONDecodeError as exc:
                raise ProviderError(f"{self.name}: request failed ({exc})") from exc
            self._sleep(delay)
        raise ProviderError(f"{self.name}: request failed ({last})") from last

    def generate(self, request: str) -> Generation:
        reply = self._chat(GENERATE_PROMPT, request)
        return Generation(script=extract_script(reply), summary=f"Generated by {self.model}")

    def explain(self, script: str) -> str:
        return self._chat(EXPLAIN_PROMPT, script).strip()

    def revise(self, request: str, script: str, problems: Sequence[str]) -> Generation:
        listed = "\n".join(f"- {p}" for p in problems)
        user = (
            f"Request: {request}\n\n"
            f"Rejected script:\n```bash\n{script}```\n\n"
            f"Problems reported by the analyzer:\n{listed}"
        )
        reply = self._chat(REVISE_PROMPT, user)
        return Generation(script=extract_script(reply), summary=f"Revised by {self.model}")
