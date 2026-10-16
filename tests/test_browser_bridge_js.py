"""
The extension's crypto.js against the program's BridgeService (needs Node.js;
skipped when it is not installed).
"""

import json
import os
import shutil
import subprocess

import pytest

from integration.service import BridgeService
from test_browser_bridge import RecordingUI, add_entry, app, endpoint_name  # noqa: F401 (fixtures)

NODE = shutil.which("node")
SCRIPT = os.path.join(os.path.dirname(__file__), "js", "client_flow.js")


class ApprovingUI(RecordingUI):
    def ask_pairing(self, browser, code, on_answer):
        super().ask_pairing(browser, code, on_answer)
        on_answer(True)


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_extension_crypto_works_with_the_program(app):  # noqa: F811
    add_entry(app, "Example", "https://example.com", "alice")
    ui = ApprovingUI()
    service = BridgeService(app, ui)

    process = subprocess.Popen([NODE, SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        while True:
            line = process.stdout.readline()
            assert line, "the Node client stopped without an answer"
            message = json.loads(line)
            if message.get("done"):
                break
            process.stdin.write(json.dumps(service.handle(message)) + "\n")
            process.stdin.flush()
    finally:
        process.stdin.close()
        process.wait(timeout=10)

    assert "error" not in message, message.get("error")
    assert message["code"] == ui.questions[0][1]
    assert message["results"][0] == {"ok": True}
    assert message["results"][1]["logins"][0]["username"] == "alice"


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_background_script_through_native_host(qtbot, app, endpoint_name):  # noqa: F811
    """background.js -> native host -> local socket -> program, as in Firefox"""
    import sys
    from integration.server import BridgeServer
    from test_browser_bridge import HOST_SCRIPT

    add_entry(app, "Example", "https://example.com", "alice", "Alice-Pass-1")
    ui = ApprovingUI()
    server = BridgeServer(BridgeService(app, ui))
    assert server.start(endpoint_name)
    try:
        process = subprocess.Popen([NODE, os.path.join(os.path.dirname(__file__), "js", "background_flow.js"),
                                    sys.executable, HOST_SCRIPT], stdout=subprocess.PIPE, text=True)
        qtbot.waitUntil(lambda: process.poll() is not None, timeout=60000)
        result = json.loads(process.stdout.read())
    finally:
        server.stop()

    assert "error" not in result, result.get("error")
    assert result["statusBefore"] == "unpaired"
    assert result["pairStart"]["code"] == ui.questions[0][1]
    assert ui.questions[0][0] == "Firefox"
    assert result["pairPoll"] == "approved"

    status = result["status"]
    assert status["state"] == "ready" and status["site"] == "example.com"
    assert [(l["title"], l["username"]) for l in status["logins"]] == [("Example", "alice")]

    assert result["fill"] == {"filled": True}
    filled = result["filledMessage"]
    assert filled["options"] == {"frameId": 0}
    assert filled["message"]["password"] == "Alice-Pass-1"

    assert result["saveBar"]["message"] == {"type": "show_save_bar", "prompt": {
        "state": "new", "site": "shop.example.org", "username": "carol"}}
    assert "password" not in json.dumps(result["pending"])
    assert "id" in result["save"]
    assert result["pendingAfter"] is None
    assert result["statusShop"]["logins"][0]["username"] == "carol"

    assert result["pageFill"] is None
    assert len(result["generate"]["password"]) == 20
    assert result["storedKeys"] == ["clientId", "pairingKey"]
