"""
Draw the application icon and save it as SecureVault.icns for the macOS bundle.

The icon is the same lock tile as the window icon (ui.theme.app_icon_pixmap,
default theme), placed on the 1024 px macOS icon grid with the usual margin.
Runs on any system (Qt offscreen + Pillow), so the .icns can be regenerated on
Windows as well:

    python packaging/macos/make_icns.py
"""

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image  # noqa: E402
from PyQt5.QtCore import QBuffer, QIODevice, Qt  # noqa: E402
from PyQt5.QtGui import QPainter, QPixmap  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

CANVAS = 1024
TILE = 824  # Apple's icon grid: the shape is about 80% of the canvas


def render_icon() -> Image.Image:
    from ui import theme

    canvas = QPixmap(CANVAS, CANVAS)
    canvas.fill(Qt.transparent)
    painter = QPainter(canvas)
    offset = (CANVAS - TILE) // 2
    painter.drawPixmap(offset, offset, theme.app_icon_pixmap(TILE))
    painter.end()

    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    canvas.save(buffer, "PNG")
    return Image.open(io.BytesIO(bytes(buffer.data()))).convert("RGBA")


def main(out_path=os.path.join(HERE, "SecureVault.icns")):
    app = QApplication.instance() or QApplication(sys.argv[:1])  # noqa: F841 (needed for painting)
    image = render_icon()
    # Pillow writes every size of the .icns (16 px ... 1024 px) from the large image
    image.save(out_path, format="ICNS")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main(*sys.argv[1:2])
