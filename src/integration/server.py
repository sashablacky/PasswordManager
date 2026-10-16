"""
Local socket server of the browser bridge, running in the Qt event loop.

Messages are handled in the GUI thread, like everything else that touches the
vault, so no locking is needed. Only the current user can connect
(UserAccessOption), and what a client may do is decided by BridgeService.
"""

import logging
import sys

from PyQt5.QtCore import QObject, QTimer, Qt
from PyQt5.QtNetwork import QLocalServer, QLocalSocket
from PyQt5.QtWidgets import QMessageBox

from integration import protocol
from integration.endpoint import default_endpoint, safari_endpoints
from integration.protocol import ProtocolError
from integration.service import BridgeService, BridgeUI

logger = logging.getLogger(__name__)

SAFARI_RESCAN_MS = 30_000


class BridgeServer(QObject):

    def __init__(self, service: BridgeService, parent=None):
        super().__init__(parent)
        self.service = service
        self._servers = {}
        self._buffers = {}
        self._rescan_timer = None

    # ------------------------------------------------------------ lifecycle

    def start(self, endpoint: str = None) -> bool:
        ok = self._listen(endpoint or default_endpoint())
        if sys.platform == "darwin" and endpoint is None:
            self._listen_safari()
            # The Safari extension's folder appears when it is first used
            self._rescan_timer = QTimer(self)
            self._rescan_timer.timeout.connect(self._listen_safari)
            self._rescan_timer.start(SAFARI_RESCAN_MS)
        return ok

    def stop(self) -> None:
        if self._rescan_timer:
            self._rescan_timer.stop()
        for server in self._servers.values():
            server.close()
        self._servers.clear()
        for socket in list(self._buffers):
            socket.abort()
        self._buffers.clear()

    def is_listening(self) -> bool:
        return any(server.isListening() for server in self._servers.values())

    def _listen_safari(self) -> None:
        for name in safari_endpoints():
            if name not in self._servers:
                self._listen(name)

    def _listen(self, name: str) -> bool:
        if _endpoint_in_use(name):
            logger.warning(f"Browser bridge: {name} is used by another running copy of the program")
            return False
        # A socket file left by a crash would make listen() fail
        QLocalServer.removeServer(name)
        server = QLocalServer(self)
        server.setSocketOptions(QLocalServer.UserAccessOption)
        server.setMaxPendingConnections(8)
        if not server.listen(name):
            logger.warning(f"Browser bridge: cannot listen on {name}: {server.errorString()}")
            return False
        server.newConnection.connect(lambda s=server: self._accept(s))
        self._servers[name] = server
        logger.info(f"Browser bridge listening on {name}")
        return True

    # ------------------------------------------------------------ connections

    def _accept(self, server: QLocalServer) -> None:
        while server.hasPendingConnections():
            socket = server.nextPendingConnection()
            self._buffers[socket] = bytearray()
            socket.readyRead.connect(lambda s=socket: self._on_ready_read(s))
            socket.disconnected.connect(lambda s=socket: self._drop(s))

    def _drop(self, socket: QLocalSocket) -> None:
        self._buffers.pop(socket, None)
        socket.deleteLater()

    def _on_ready_read(self, socket: QLocalSocket) -> None:
        buffer = self._buffers.get(socket)
        if buffer is None:
            return
        buffer.extend(bytes(socket.readAll()))
        try:
            messages = protocol.decode_frames(buffer)
        except ProtocolError as e:
            logger.warning(f"Browser bridge: closing connection ({e})")
            socket.abort()
            return
        for message in messages:
            reply = self.service.handle(message)
            socket.write(protocol.encode_frame(reply))
        socket.flush()


def _endpoint_in_use(name: str) -> bool:
    probe = QLocalSocket()
    probe.connectToServer(name)
    connected = probe.waitForConnected(150)
    if connected:
        probe.disconnectFromServer()
    probe.abort()
    return connected


class AppBridgeUI(BridgeUI):
    """Connects the bridge to the running PasswordManagerApp"""

    def __init__(self, app):
        self.app = app
        self._questions = []

    def _window(self):
        return self.app.main_window or self.app.login_widget

    def ask_pairing(self, browser, code, on_answer):
        window = self.app.main_window
        if window is None:
            on_answer(False)
            return
        self.show_app()
        box = QMessageBox(QMessageBox.Question, "Connect browser",
                          f"<b>{_html(browser)}</b> wants to use passwords from this vault.<br><br>"
                          f"Check that the browser shows the same code:<br>"
                          f"<span style='font-size:20pt; letter-spacing:4px'><b>{code[:3]} {code[3:]}</b></span>"
                          f"<br><br>Allow this browser to fill in and save passwords?",
                          QMessageBox.Yes | QMessageBox.No, window)
        box.button(QMessageBox.Yes).setText("Allow")
        box.button(QMessageBox.No).setText("Deny")
        box.setDefaultButton(QMessageBox.No)
        box.setWindowModality(Qt.WindowModal)
        box.setAttribute(Qt.WA_DeleteOnClose)
        # Locking the vault rejects open dialogs, which counts as "Deny"
        box.finished.connect(lambda result: on_answer(result == QMessageBox.Yes))
        box.finished.connect(lambda _=None, b=box: self._questions.remove(b) if b in self._questions else None)
        self._questions.append(box)
        box.open()

    def show_app(self):
        window = self._window()
        if window is None:
            return
        if window.isMinimized():
            window.showNormal()
        window.show()
        window.raise_()
        window.activateWindow()

    def unlock(self, master_password):
        return self.app.unlock_from_browser(master_password)

    def entries_changed(self, message):
        window = self.app.main_window
        if window is not None:
            window.load_passwords()
            window.toast(message)

    def user_activity(self):
        self.app.reset_auto_lock()


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def create_bridge(app) -> BridgeServer:
    """Bridge server for a PasswordManagerApp (not started yet)"""
    return BridgeServer(BridgeService(app, AppBridgeUI(app)))
