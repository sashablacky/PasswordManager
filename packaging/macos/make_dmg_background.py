"""
Draw the background of the .dmg window: "drag the app onto Applications".

The icons are placed by packaging/macos/dmg_settings.py: the app on the left,
the Applications link on the right, the first-start notes below. Run on any
desktop system; the result is committed, so the Mac build does not
depend on fonts being available there:

    python packaging/macos/make_dmg_background.py
"""

import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Not offscreen: that platform has no fonts on Windows. Nothing is shown on screen.

from PyQt5.QtCore import QPointF, QRectF, Qt  # noqa: E402
from PyQt5.QtGui import QColor, QFont, QImage, QPainter, QPainterPath, QPen  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

WIDTH, HEIGHT = 640, 440
# Icon centres, must match dmg_settings.py
APP_POS, APPLICATIONS_POS, NOTES_POS = (160, 190), (480, 190), (320, 362)


def draw(scale: int) -> QImage:
    image = QImage(WIDTH * scale, HEIGHT * scale, QImage.Format_ARGB32)
    image.fill(QColor("#F4EFE6"))
    p = QPainter(image)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(scale, scale)

    title = QFont("Segoe UI", 0, QFont.DemiBold)
    title.setPixelSize(22)
    p.setFont(title)
    p.setPen(QColor("#1C2127"))
    p.drawText(QRectF(0, 26, WIDTH, 34), Qt.AlignCenter, "Перетащите замок в «Программы»")

    small = QFont("Segoe UI")
    small.setPixelSize(14)
    p.setFont(small)
    p.setPen(QColor("#4A4F55"))
    p.drawText(QRectF(0, 60, WIDTH, 22), Qt.AlignCenter,
               "Потом извлеките этот диск и запускайте программу только из «Программ»")

    # Arrow between the two icons
    pen = QPen(QColor("#C8B898"), 7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    y = APP_POS[1]
    start, end = APP_POS[0] + 75, APPLICATIONS_POS[0] - 75
    path = QPainterPath(QPointF(start, y))
    path.cubicTo(QPointF(start + 60, y - 40), QPointF(end - 60, y - 40), QPointF(end, y))
    p.drawPath(path)
    # Arrow head along the curve's direction at its end (from the last control point)
    dx, dy = 60, 40
    length = math.hypot(dx, dy)
    ux, uy = dx / length, dy / length
    tip = QPointF(end + ux * 10, y + uy * 10)
    back = QPointF(end - ux * 12, y - uy * 12)
    side = QPointF(-uy * 13, ux * 13)
    head = QPainterPath(tip)
    head.lineTo(back + side)
    head.lineTo(back - side)
    head.closeSubpath()
    p.setBrush(QColor("#C8B898"))
    p.setPen(Qt.NoPen)
    p.drawPath(head)

    p.setFont(small)
    p.setPen(QColor("#4A4F55"))
    p.drawText(QRectF(0, NOTES_POS[1] - 78, WIDTH, 20), Qt.AlignCenter,
               "Первый запуск: откройте эту памятку ↓")
    p.end()
    return image


def main():
    app = QApplication.instance() or QApplication(sys.argv[:1])  # noqa: F841
    draw(1).save(os.path.join(HERE, "dmg-background.png"))
    draw(2).save(os.path.join(HERE, "dmg-background@2x.png"))
    print("Wrote dmg-background.png and dmg-background@2x.png")


if __name__ == "__main__":
    main()
