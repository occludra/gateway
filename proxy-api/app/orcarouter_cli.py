"""OrcaRouter operator CLI: choose API key or Connect with OrcaRouter (PKCE).

Both sub-commands end in the same place -- an ``sk-orca-`` key stored in
``providers.orcarouter.api_key`` of gateway.yaml -- and the gateway then routes
``x-provider: orcarouter`` traffic through ``https://api.orcarouter.ai/v1``.

Usage::

    python -m app.orcarouter_cli api-key            # paste an existing key
    python -m app.orcarouter_cli login              # OAuth 2.0 + PKCE (Flow A/B)
    python -m app.orcarouter_cli models --capability chat
    python -m app.orcarouter_cli test --model orcarouter/auto --prompt "hi"
    python -m app.orcarouter_cli status

The PKCE verifier never leaves this process and is never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import socket
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .credentials import (
    CredentialError,
    PKCECredentialSource,
    resolve_origins,
)
from .orcarouter_catalog import ModelCatalog, cyber_models_from, filter_models

DEFAULT_MODEL = "orcarouter/auto"


def _console_write(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def credential_choices() -> list[str]:
    """Both OrcaRouter credential choices, discoverable from --help and status."""
    return ["api-key", "login"]


def _store(api_key: str) -> None:
    from .dev_mode import _persist, key_state

    _persist(api_key)
    key_state.replace(api_key)


def _load_catalog(api_key: str, capability: str) -> dict:
    return asyncio.run(_catalog(api_key, capability))


async def _catalog(api_key: str, capability: str) -> dict:
    result = await ModelCatalog().fetch(api_key, force=True)
    filtered = filter_models(result.models, capability=capability)
    return {
        "catalog_source": result.source,
        "degraded": result.degraded,
        "error": result.error,
        "models": [m["id"] for m in filtered],
        "cyber": [m["id"] for m in cyber_models_from(result.models)],
    }


def cmd_api_key(_: argparse.Namespace) -> int:
    api_key = getpass.getpass("OrcaRouter API key (sk-orca-...): ").strip()
    if not api_key.startswith("sk-orca-"):
        _console_write("Not an OrcaRouter key (expected sk-orca- prefix).")
        return 2
    _store(api_key)
    _console_write("Stored as providers.orcarouter.api_key.")
    _console_write(_json(_load_catalog(api_key, "chat")))
    return 0


class _CallbackReceiver:
    """Loopback listener for Flow A (127.0.0.1, random port)."""

    def __init__(self) -> None:
        self.result: dict[str, str] = {}
        self.done = threading.Event()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(  # noqa: N802
                self,
            ) -> None:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                receiver.result = {k: v[0] for k, v in query.items() if v}
                body = b"OrcaRouter responded. You can close this tab."
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                receiver.done.set()

            def log_message(self, *args) -> None:  # quiet, never log query strings
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def callback_url(self) -> str:
        port = self.server.server_address[1]
        return f"http://127.0.0.1:{port}/cb"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def cmd_login(args: argparse.Namespace) -> int:
    flow = args.flow
    if flow == "auto":
        flow = "loopback" if _has_browser() else "oob"
    source = PKCECredentialSource()
    receiver: _CallbackReceiver | None = None
    try:
        if flow == "loopback":
            receiver = _CallbackReceiver()
            receiver.start()
            callback_url = receiver.callback_url
        else:
            callback_url = "oob"
        prepared = source.prepare(callback_url)
    except CredentialError as exc:
        _console_write(f"Could not start login: {exc}")
        return 2

    _console_write("Open this URL and approve access for this gateway:")
    _console_write(prepared.authorize_url)
    if not args.no_browser:
        try:
            webbrowser.open(prepared.authorize_url)
        except Exception:
            pass

    try:
        if flow == "loopback" and receiver is not None:
            _console_write(f"Waiting for the redirect on {receiver.callback_url} ...")
            if not receiver.done.wait(timeout=prepared.expires_in_seconds):
                _console_write("Login timed out. Nothing was changed.")
                return 3
            query = urllib.parse.urlencode(receiver.result)
            callback = f"{receiver.callback_url}?{query}"
            credential = asyncio.run(source.obtain(callback_url=callback))
        else:
            code = input("Code shown on the consent screen: ").strip()
            credential = asyncio.run(source.obtain(code=code))
    except CredentialError as exc:
        _console_write(f"Login failed: {exc}")
        return 3
    except KeyboardInterrupt:
        _console_write("Login cancelled. Nothing was changed.")
        return 130
    finally:
        if receiver is not None:
            receiver.stop()

    _store(credential.api_key)
    _console_write(f"Connected (source={credential.source}, scope={credential.scope}). Key stored.")
    _console_write(_json(_load_catalog(credential.api_key, "chat")))
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    from .dev_mode import stored_orcarouter_key

    key = stored_orcarouter_key()
    if not key:
        _console_write("No OrcaRouter key stored. Run `api-key` or `login` first.")
        return 2
    _console_write(_json(_load_catalog(key, args.capability)))
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    from .dev_mode import stored_orcarouter_key
    from .providers import forward_chat_completion

    key = stored_orcarouter_key()
    spec = providers.get_provider(providers.ORCAROUTER_PROVIDER)
    if not key or spec is None:
        _console_write("No OrcaRouter key stored. Run `api-key` or `login` first.")
        return 2
    body = {"model": args.model, "messages": [{"role": "user", "content": args.prompt}]}
    reply = asyncio.run(forward_chat_completion(spec, key, body))
    text = reply.choices[0].message.content
    _console_write(f"OK model={args.model} reply={text[:200]!r}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    from .dev_mode import status_payload

    _console_write(_json(status_payload()))
    return 0


def _json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _has_browser() -> bool:
    try:
        socket.gethostbyname("localhost")
    except OSError:
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.orcarouter_cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("api-key", help="store an existing OrcaRouter API key").set_defaults(func=cmd_api_key)
    login = sub.add_parser("login", help="Connect with OrcaRouter (OAuth 2.0 + PKCE)")
    login.add_argument("--flow", choices=["auto", "loopback", "oob"], default="auto")
    login.add_argument("--no-browser", action="store_true")
    login.set_defaults(func=cmd_login)
    models = sub.add_parser("models", help="list capability-filtered models")
    models.add_argument("--capability", default="chat", choices=["chat", "embedding", "image", "video", "rerank"])
    models.set_defaults(func=cmd_models)
    test = sub.add_parser("test", help="one real chat completion through the gateway path")
    test.add_argument("--model", default=DEFAULT_MODEL)
    test.add_argument("--prompt", default="Reply with the single word: ready")
    test.set_defaults(func=cmd_test)
    sub.add_parser("status", help="masked credential status").set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
