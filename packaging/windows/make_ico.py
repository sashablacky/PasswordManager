"""
Draw the application icon and save it as SecureVault.ico for the Windows build.

The same lock tile as the window icon and the macOS .icns (ui.theme.app_icon_pixmap,
default theme), at every size Windows uses (16 to 256 px):

    python packaging/windows/make_ico.py
"""

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image  # noqa: E402
from PyQt5.QtCore import QBuffer, QIODevice  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def main(out_path=os.path.join(HERE, "SecureVault.ico")):
    app = QApplication.instance() or QApplication(sys.argv[:1])  # noqa: F841 (needed for painting)
    from ui import theme

    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    theme.app_icon_pixmap(256).save(buffer, "PNG")
    image = Image.open(io.BytesIO(bytes(buffer.data()))).convert("RGBA")
    image.save(out_path, format="ICO", sizes=[(s, s) for s in SIZES])
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main(*sys.argv[1:2])
