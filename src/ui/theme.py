"""
One place for the look of the whole application.

Three dark palettes (Midnight, Slate, Dusk) are defined here. apply_theme()
switches the Fluent widgets (qfluentwidgets) to the palette's accent colour,
sets the application palette and one application-wide style sheet for the
plain Qt widgets (message boxes, input dialogs, labels with a "role"), and
emits `signals.changed` so custom-painted widgets repaint. Switching works
live, without restarting.

The small custom widgets used across the UI (glass cards, the window
backdrop, strength meters, letter avatars, chips) live here as well, so every
window draws them the same way.
"""

import hashlib
import logging
import sys
from dataclasses import dataclass

from PyQt5.QtCore import Qt, QObject, QEvent, QPointF, QRectF, QSize, pyqtSignal
from PyQt5.QtGui import (QColor, QFont, QFontDatabase, QIcon, QPainter,
                         QPalette, QPen, QPixmap, QRadialGradient)
from PyQt5.QtWidgets import QAbstractButton, QApplication, QFrame, QSizePolicy, QWidget

import platform_utils

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Palette:
    key: str
    name: str
    n0: str          # deepest tone, window background
    n1: str          # panels
    n2: str          # glass, selection
    accent: str      # primary buttons
    on_accent: str   # text on the accent colour
    accent2: str     # indicators, links
    text: str
    well: str        # input fields
    glass_alpha: float
    muted_alpha: float
    ok: str
    warn: str
    high: str
    bad: str

    def color(self, name: str, alpha: float = 1.0) -> QColor:
        c = QColor(getattr(self, name))
        c.setAlphaF(alpha)
        return c

    def rgba(self, name: str, alpha: float = 1.0) -> str:
        c = self.color(name, alpha)
        return f"rgba({c.red()}, {c.green()}, {c.blue()}, {c.alpha()})"

    # Derived tones, the same as in the design mock-up (design/ui-mockup.html)
    @property
    def muted(self) -> QColor:
        return self.color("text", self.muted_alpha)

    @property
    def faint(self) -> QColor:
        return self.color("text", 0.40)

    @property
    def glass(self) -> QColor:
        return self.color("n2", self.glass_alpha)

    @property
    def glass_line(self) -> QColor:
        return self.color("text", 0.12)

    @property
    def glass_hi(self) -> QColor:
        return self.color("text", 0.07)


THEMES = {
    "midnight": Palette(
        key="midnight", name="Midnight",
        n0="#010736", n1="#0D1C42", n2="#22396F",
        accent="#FCF1D0", on_accent="#010736", accent2="#FCF1D0",
        text="#F3ECDC", well="#010736", glass_alpha=0.30, muted_alpha=0.60,
        ok="#8FD9B6", warn="#F3C77A", high="#F6B38A", bad="#F29A93",
    ),
    "slate": Palette(
        key="slate", name="Slate",
        n0="#16222F", n1="#213448", n2="#547792",
        accent="#EAE0CF", on_accent="#213448", accent2="#94B4C1",
        text="#EDF0F1", well="#121C28", glass_alpha=0.26, muted_alpha=0.60,
        ok="#8FD9B6", warn="#EBCB8B", high="#F0B48E", bad="#EE9A93",
    ),
    "dusk": Palette(
        key="dusk", name="Dusk",
        n0="#1C2127", n1="#252B32", n2="#3E4954",
        accent="#C8B898", on_accent="#1C2127", accent2="#9DB1A5",
        text="#D6D1C7", well="#181C21", glass_alpha=0.32, muted_alpha=0.62,
        ok="#9CC3A8", warn="#D4B57E", high="#D39E82", bad="#CF8F88",
    ),
}

THEME_ORDER = ["midnight", "slate", "dusk"]
DEFAULT_THEME = "dusk"

_current = THEMES[DEFAULT_THEME]


class ThemeSignals(QObject):
    changed = pyqtSignal(str)   # key of the new theme


signals = ThemeSignals()


def current() -> Palette:
    return _current


def current_key() -> str:
    return _current.key


# ---------------------------------------------------------------- fonts

def _first_family(candidates):
    families = set(QFontDatabase().families())
    for family in candidates:
        if family in families:
            return family
    return candidates[-1]


def ui_font(pixel_size=14, weight=QFont.Normal, display=False) -> QFont:
    font = QFont(_first_family(platform_utils.ui_font_families(display)))
    font.setPixelSize(pixel_size)
    font.setWeight(weight)
    return font


def mono_font(pixel_size=14, weight=QFont.Normal) -> QFont:
    font = QFont(_first_family(platform_utils.mono_font_families()))
    font.setStyleHint(QFont.Monospace)
    font.setPixelSize(pixel_size)
    font.setWeight(weight)
    return font


def apply_platform_fonts() -> None:
    """Fluent widgets ask for Segoe UI, which a Mac does not have: give them the Mac fonts.

    Only fonts that are installed are listed, so Qt does not search for missing ones.
    Windows keeps the Fluent defaults.
    """
    if not platform_utils.is_mac():
        return
    from qfluentwidgets import setFontFamilies
    installed = set(QFontDatabase().families())
    families = [f for f in platform_utils.ui_font_families() if f in installed]
    setFontFamilies(families + ["PingFang SC"])


# ---------------------------------------------------------------- strength and risk

def strength_text(score: int) -> str:
    if score < 30:
        return "Very Weak"
    if score < 50:
        return "Weak"
    if score < 75:
        return "Medium"
    return "Strong"


def strength_role(score: int) -> str:
    """Palette colour name for a strength score"""
    if score < 30:
        return "bad"
    if score < 50:
        return "high"
    if score < 75:
        return "warn"
    return "ok"


def strength_color(score: int) -> QColor:
    return current().color(strength_role(score))


RISK_ROLES = {"critical": "bad", "high": "high", "medium": "warn", "low": "ok"}


def risk_color(level: str) -> QColor:
    role = RISK_ROLES.get((level or "").lower())
    return current().color(role) if role else current().faint


# ---------------------------------------------------------------- applying a theme

def qss(p: Palette) -> str:
    """Application style sheet for plain Qt widgets; Fluent widgets style themselves"""
    return f"""
        QToolTip {{
            color: {p.text}; background-color: {p.n1};
            border: 1px solid {p.rgba('text', 0.16)}; padding: 4px 6px;
        }}
        QLabel {{ color: {p.text}; background: transparent; }}
        QLabel[role="muted"] {{ color: {p.rgba('text', p.muted_alpha)}; }}
        QLabel[role="faint"] {{ color: {p.rgba('text', 0.40)}; }}
        QLabel[role="accent2"] {{ color: {p.accent2}; }}
        QLabel[role="ok"] {{ color: {p.ok}; }}
        QLabel[role="warn"] {{ color: {p.warn}; }}
        QLabel[role="high"] {{ color: {p.high}; }}
        QLabel[role="bad"] {{ color: {p.bad}; }}

        QScrollArea#pageScroll, QWidget#pageScrollContent, QWidget#scrollContent {{
            background: transparent; border: none;
        }}

        QDialog, QMessageBox, QInputDialog {{ background-color: {p.n1}; }}
        QMessageBox QLabel, QInputDialog QLabel {{ color: {p.text}; }}
        QMessageBox QPushButton, QInputDialog QPushButton, QDialogButtonBox QPushButton {{
            color: {p.text}; background-color: {p.rgba('text', 0.06)};
            border: 1px solid {p.rgba('text', 0.12)}; border-radius: 5px;
            padding: 6px 18px; min-width: 64px;
        }}
        QMessageBox QPushButton:hover, QInputDialog QPushButton:hover,
        QDialogButtonBox QPushButton:hover {{ background-color: {p.rgba('text', 0.10)}; }}
        QMessageBox QPushButton:default, QInputDialog QPushButton:default,
        QDialogButtonBox QPushButton:default {{
            color: {p.on_accent}; background-color: {p.accent}; border-color: {p.accent};
        }}
        QInputDialog QLineEdit {{
            color: {p.text}; background-color: {p.rgba('well', 0.6)};
            border: 1px solid {p.rgba('text', 0.12)}; border-bottom: 2px solid {p.accent};
            border-radius: 5px; padding: 6px 8px;
            selection-background-color: {p.n2};
        }}
    """


def qpalette(p: Palette) -> QPalette:
    pal = QPalette()
    text, n0, n1, n2 = QColor(p.text), QColor(p.n0), QColor(p.n1), QColor(p.n2)
    for group in (QPalette.Active, QPalette.Inactive):
        pal.setColor(group, QPalette.Window, n1)
        pal.setColor(group, QPalette.WindowText, text)
        pal.setColor(group, QPalette.Base, QColor(p.well))
        pal.setColor(group, QPalette.AlternateBase, n1)
        pal.setColor(group, QPalette.Text, text)
        pal.setColor(group, QPalette.Button, n2)
        pal.setColor(group, QPalette.ButtonText, text)
        pal.setColor(group, QPalette.ToolTipBase, n1)
        pal.setColor(group, QPalette.ToolTipText, text)
        pal.setColor(group, QPalette.Highlight, QColor(p.accent))
        pal.setColor(group, QPalette.HighlightedText, QColor(p.on_accent))
        pal.setColor(group, QPalette.Link, QColor(p.accent2))
        pal.setColor(group, QPalette.PlaceholderText, p.faint)
        pal.setColor(group, QPalette.Light, n2)
        pal.setColor(group, QPalette.Mid, n1)
        pal.setColor(group, QPalette.Dark, n0)
    pal.setColor(QPalette.Disabled, QPalette.WindowText, p.faint)
    pal.setColor(QPalette.Disabled, QPalette.Text, p.faint)
    pal.setColor(QPalette.Disabled, QPalette.ButtonText, p.faint)
    return pal


def style_primary(button) -> None:
    """Text on accent-coloured Fluent buttons uses the palette's on-accent colour"""
    from qfluentwidgets import setCustomStyleSheet
    p = current()
    # Fluent brightens the theme colour in dark mode; primary buttons keep the exact palette accent
    accent = QColor(p.accent)
    hover, pressed = accent.lighter(108).name(), accent.darker(112).name()
    edge, bottom = accent.lighter(112).name(), accent.darker(108).name()
    qss_text = f"""
        PrimaryPushButton, PrimaryToolButton {{
            color: {p.on_accent}; background-color: {p.accent};
            border: 1px solid {edge}; border-bottom: 1px solid {bottom};
        }}
        PrimaryPushButton:hover, PrimaryToolButton:hover {{
            background-color: {hover}; border: 1px solid {edge}; border-bottom: 1px solid {bottom};
        }}
        PrimaryPushButton:pressed, PrimaryToolButton:pressed {{
            color: {p.rgba('on_accent', 0.7)}; background-color: {pressed}; border: 1px solid {pressed};
        }}
    """
    setCustomStyleSheet(button, qss_text, qss_text)


def apply_theme(key: str, save: bool = False) -> Palette:
    """Switch the whole application to the theme `key` (unknown keys fall back to the default)"""
    global _current
    from qfluentwidgets import setTheme, setThemeColor, Theme, PrimaryPushButton, PrimaryToolButton

    _current = THEMES.get(key, THEMES[DEFAULT_THEME])
    p = _current

    app = QApplication.instance()
    if app is not None:
        setTheme(Theme.DARK)
        setThemeColor(QColor(p.accent))
        app.setPalette(qpalette(p))
        app.setStyleSheet(qss(p))
        for widget in app.allWidgets():
            if isinstance(widget, (PrimaryPushButton, PrimaryToolButton)):
                style_primary(widget)
        _install_title_bar_filter(app)
        for widget in app.topLevelWidgets():
            if widget.isVisible():
                set_dark_title_bar(widget)
                widget.update()

    if save:
        import app_settings
        try:
            app_settings.save_settings(theme=p.key)
        except OSError as e:
            logger.warning(f"Could not save the theme setting: {e}")

    signals.changed.emit(p.key)
    return p


def init_theme() -> Palette:
    """Apply the theme saved in the settings file"""
    import app_settings
    apply_platform_fonts()
    return apply_theme(app_settings.load_settings().get("theme", DEFAULT_THEME))


# ---------------------------------------------------------------- native title bars

def set_dark_title_bar(widget: QWidget) -> None:
    """Dark title bar for native (non-Fluent) windows such as dialogs and message boxes"""
    if sys.platform != "win32" or QApplication.platformName() != "windows":
        return
    if not widget.isWindow() or widget.windowFlags() & Qt.FramelessWindowHint:
        return
    try:
        import ctypes
        hwnd = int(widget.winId())
        dwm = ctypes.windll.dwmapi
        on = ctypes.c_int(1)
        # DWMWA_USE_IMMERSIVE_DARK_MODE: 20 on Windows 10 20H1+ and 11, 19 on older builds
        if dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(on), ctypes.sizeof(on)) != 0:
            dwm.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(on), ctypes.sizeof(on))
        if sys.getwindowsversion().build >= 22000:
            # DWMWA_CAPTION_COLOR (Windows 11): caption in the panel colour, as COLORREF 0x00BBGGRR
            c = QColor(current().n1)
            colorref = ctypes.c_int(c.red() | (c.green() << 8) | (c.blue() << 16))
            dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(colorref), ctypes.sizeof(colorref))
    except Exception as e:  # cosmetic only
        logger.debug(f"Dark title bar not applied: {e}")


class _TitleBarFilter(QObject):
    def eventFilter(self, obj, event):
        if event.type() == QEvent.Show and isinstance(obj, QWidget) and obj.isWindow():
            set_dark_title_bar(obj)
        return False


_title_bar_filter = None


def _install_title_bar_filter(app):
    global _title_bar_filter
    if _title_bar_filter is None:
        _title_bar_filter = _TitleBarFilter()
        app.installEventFilter(_title_bar_filter)


# ---------------------------------------------------------------- painting helpers

def paint_backdrop(painter: QPainter, rect, p: Palette = None, opacity: float = 1.0) -> None:
    """The window background: soft radial glows over the deepest tone (as in the mock-up)"""
    p = p or current()
    rect = QRectF(rect)
    w, h = rect.width(), rect.height()
    k = max(w / 1200.0, 0.6)

    painter.save()
    painter.setOpacity(opacity)
    painter.setPen(Qt.NoPen)
    painter.fillRect(rect, QColor(p.n0))

    # Bottom to top, matching the CSS layers of the mock-up
    glows = [
        (0.40, 0.80, 500, 400, p.color("n1", 1.0)),
        (0.72, 0.10, 380, 300, p.color("accent2", 0.14)),
        (0.88, 0.92, 620, 520, p.color("n2", 0.80)),
        (0.12, 0.18, 520, 420, p.color("n2", 0.95)),
    ]
    for fx, fy, rx, ry, color in glows:
        rx, ry = rx * k, ry * k
        painter.save()
        painter.translate(rect.left() + fx * w, rect.top() + fy * h)
        painter.scale(1.0, ry / rx)
        gradient = QRadialGradient(QPointF(0, 0), rx)
        transparent = QColor(color)
        transparent.setAlpha(0)
        gradient.setColorAt(0.0, color)
        gradient.setColorAt(0.7, transparent)
        gradient.setColorAt(1.0, transparent)
        painter.setBrush(gradient)
        painter.drawEllipse(QPointF(0, 0), rx, rx)
        painter.restore()
    painter.restore()


def paint_glass(painter: QPainter, rect, radius=10.0, p: Palette = None, fill: QColor = None) -> None:
    """A semi-transparent panel with a hairline border and a light top edge"""
    p = p or current()
    r = QRectF(rect).adjusted(0.5, 0.5, -0.5, -0.5)
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(p.glass_line, 1))
    painter.setBrush(fill if fill is not None else p.glass)
    painter.drawRoundedRect(r, radius, radius)
    # inner highlight along the top edge
    painter.setPen(QPen(p.glass_hi, 1))
    painter.drawLine(QPointF(r.left() + radius, r.top() + 1), QPointF(r.right() - radius, r.top() + 1))
    painter.restore()


# The default categories are stored with flat, saturated colours; on the dark
# backgrounds the softer tones of the mock-up read better
_CATEGORY_TINTS = {
    "#3498db": "#7FA8F5", "#e74c3c": "#F29A93", "#2ecc71": "#8FD9B6",
    "#f39c12": "#F3C77A", "#9b59b6": "#C4A8F0", "#1abc9c": "#7FD6D0",
}


def category_color(color) -> str:
    color = (color or "").strip()
    if not color:
        return current().accent2
    return _CATEGORY_TINTS.get(color.lower(), color)


AVATAR_COLORS = ["#E8E4DA", "#F2B8B2", "#9DB8F2", "#A7B6CF", "#F6D49A",
                 "#F29A93", "#8FB4E8", "#9FD8C4", "#C9B3F2", "#7FD6D0"]


def avatar_color(title: str) -> QColor:
    digest = hashlib.md5((title or "?").lower().encode("utf-8")).digest()
    return QColor(AVATAR_COLORS[digest[0] % len(AVATAR_COLORS)])


def paint_avatar(painter: QPainter, rect, title: str, radius=8.0) -> None:
    """Rounded tile with the first letter of the title"""
    r = QRectF(rect)
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(avatar_color(title))
    painter.drawRoundedRect(r, radius, radius)
    painter.setPen(QColor("#121A2B"))
    painter.setFont(ui_font(int(r.height() * 0.44), QFont.Bold))
    letter = (title or "?").strip()[:1].upper() or "?"
    painter.drawText(r, Qt.AlignCenter, letter)
    painter.restore()


def dot_icon(color, size=16, diameter=8) -> QIcon:
    """A small coloured circle, used for categories in the navigation"""
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(color))
    painter.drawEllipse(QPointF(size / 2, size / 2), diameter / 2, diameter / 2)
    painter.end()
    return QIcon(pixmap)


def app_icon() -> QIcon:
    """Window icon: a lock on an accent-coloured tile"""
    return QIcon(app_icon_pixmap(64))


def app_icon_pixmap(size: int = 64) -> QPixmap:
    """The window icon drawn at size x size pixels (large sizes are used for the macOS .icns)"""
    from ui.icons import AppIcon
    p = current()
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size / 64, size / 64)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(p.accent))
    painter.drawRoundedRect(QRectF(2, 2, 60, 60), 15, 15)
    AppIcon.LOCK.render(painter, QRectF(14, 14, 36, 36), fill=p.on_accent)
    painter.end()
    return pixmap


# ---------------------------------------------------------------- widgets

class ThemedWidget(QWidget):
    """Repaints itself when the theme changes"""

    def __init__(self, parent=None):
        super().__init__(parent)
        signals.changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, key):
        try:
            self.update()
        except RuntimeError:  # the C++ widget is already gone
            pass


class Backdrop(ThemedWidget):
    """A widget whose background is the theme backdrop"""

    def paintEvent(self, e):
        painter = QPainter(self)
        paint_backdrop(painter, self.rect())


class GlassCard(QFrame):
    """Semi-transparent card ("glass") laid over the window backdrop"""

    def __init__(self, parent=None, radius=10.0):
        super().__init__(parent)
        self.radius = radius
        self.setAttribute(Qt.WA_StyledBackground, False)
        signals.changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, key):
        try:
            self.update()
        except RuntimeError:
            pass

    def paintEvent(self, e):
        painter = QPainter(self)
        paint_glass(painter, self.rect(), self.radius)


class WellFrame(GlassCard):
    """A recessed field (a darker, see-through box), e.g. one field of an entry"""

    def __init__(self, parent=None, radius=8.0, alpha=0.32):
        super().__init__(parent, radius)
        self.alpha = alpha

    def paintEvent(self, e):
        painter = QPainter(self)
        paint_glass(painter, self.rect(), self.radius, fill=current().color("well", self.alpha))


class StrengthMeter(ThemedWidget):
    """Strength as `segments` short bars, coloured by the score"""

    def __init__(self, parent=None, segments=5, height=4):
        super().__init__(parent)
        self.segments = segments
        self.score = 0
        self.setFixedHeight(height)
        self.setMinimumWidth(60)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_score(self, score: int):
        self.score = max(0, min(100, int(score)))
        self.update()

    def paintEvent(self, e):
        p = current()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        gap = 4
        w = (self.width() - gap * (self.segments - 1)) / self.segments
        lit = 0 if self.score <= 0 else max(1, round(self.score / 100 * self.segments))
        on = strength_color(self.score)
        off = p.color("text", 0.12)
        for i in range(self.segments):
            painter.setBrush(on if i < lit else off)
            painter.drawRoundedRect(QRectF(i * (w + gap), 0, w, self.height()), 2, 2)


class StrengthBar(ThemedWidget):
    """Continuous strength bar (generator, add/edit dialog)"""

    def __init__(self, parent=None, height=6):
        super().__init__(parent)
        self.score = 0
        self.setFixedHeight(height)
        self.setMinimumWidth(60)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_score(self, score: int):
        self.score = max(0, min(100, int(score)))
        self.update()

    def paintEvent(self, e):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        r = self.height() / 2
        painter.setBrush(current().color("text", 0.10))
        painter.drawRoundedRect(QRectF(self.rect()), r, r)
        if self.score:
            painter.setBrush(strength_color(self.score))
            painter.drawRoundedRect(QRectF(0, 0, self.width() * self.score / 100, self.height()), r, r)


class Avatar(ThemedWidget):
    def __init__(self, title="", size=34, radius=8.0, parent=None):
        super().__init__(parent)
        self.title = title
        self.radius = radius
        self.setFixedSize(size, size)

    def set_title(self, title):
        self.title = title
        self.update()

    def paintEvent(self, e):
        painter = QPainter(self)
        paint_avatar(painter, self.rect(), self.title, self.radius)


class Chip(QAbstractButton):
    """Small rounded counter ("31 strong"), checkable so it can act as a filter"""

    def __init__(self, label, role=None, parent=None):
        super().__init__(parent)
        self.label = label
        self.role = role          # palette colour of the dot, None for no dot
        self.value = "0"
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(30)
        self.setFont(ui_font(13))
        signals.changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, key):
        try:
            self.update()
        except RuntimeError:
            pass

    def set_value(self, value):
        self.value = str(value)
        self.updateGeometry()
        self.update()

    def text(self):
        return f"{self.value} {self.label}"

    def sizeHint(self):
        fm = self.fontMetrics()
        bold = QFont(self.font())
        bold.setBold(True)
        from PyQt5.QtGui import QFontMetrics
        width = 24 + QFontMetrics(bold).horizontalAdvance(self.value) + 5 + fm.horizontalAdvance(self.label)
        if self.role:
            width += 15
        return QSize(width, 30)

    def enterEvent(self, e):
        self.update()

    def leaveEvent(self, e):
        self.update()

    def paintEvent(self, e):
        p = current()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        fill = p.color("text", 0.10) if self.isChecked() else (
            p.color("n2", p.glass_alpha + 0.12) if self.underMouse() else p.glass)
        paint_glass(painter, self.rect(), self.height() / 2, fill=fill)
        if self.isChecked():
            painter.setPen(QPen(QColor(p.accent2), 1))
            painter.setBrush(Qt.NoBrush)
            r = self.height() / 2
            painter.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), r, r)

        x = 12
        if self.role:
            painter.setPen(Qt.NoPen)
            painter.setBrush(p.color(self.role))
            painter.drawEllipse(QPointF(x + 3.5, self.height() / 2), 3.5, 3.5)
            x += 15
        bold = QFont(self.font())
        bold.setBold(True)
        painter.setFont(bold)
        painter.setPen(QColor(p.text))
        value_width = painter.fontMetrics().horizontalAdvance(self.value)
        painter.drawText(QRectF(x, 0, value_width + 2, self.height()), Qt.AlignVCenter, self.value)
        painter.setFont(self.font())
        painter.setPen(p.muted)
        painter.drawText(QRectF(x + value_width + 5, 0, self.width(), self.height()),
                         Qt.AlignVCenter, self.label)


def reveal_line_edit(parent=None):
    """Fluent password field whose eye button toggles the password on click (not press-and-hold)"""
    from qfluentwidgets import PasswordLineEdit, FluentIcon

    class RevealLineEdit(PasswordLineEdit):
        def eventFilter(self, obj, e):
            if obj is self.viewButton and self.isEnabled():
                if e.type() == QEvent.MouseButtonRelease:
                    self.setPasswordVisible(not self.isPasswordVisible())
                if e.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease):
                    return QWidget.eventFilter(self, obj, e)
            return super().eventFilter(obj, e)

        def setPasswordVisible(self, visible):
            super().setPasswordVisible(visible)
            self.viewButton.setIcon(FluentIcon.HIDE if visible else FluentIcon.VIEW)
            self.viewButton.setToolTip("Hide password" if visible else "Show password")

    edit = RevealLineEdit(parent)
    edit.viewButton.setToolTip("Show password")
    return edit


def label(text="", role=None, size=None, weight=None, display=False, mono=False, parent=None):
    """QLabel in the theme's text colours; role = muted / faint / accent2 / ok / warn / bad"""
    from PyQt5.QtWidgets import QLabel
    widget = QLabel(text, parent)
    if role:
        widget.setProperty("role", role)
    if size or weight or display or mono:
        if mono:
            widget.setFont(mono_font(size or 14, weight or QFont.Normal))
        else:
            widget.setFont(ui_font(size or 14, weight or QFont.Normal, display))
    return widget


def title_label(text="", parent=None):
    return label(text, size=26, weight=QFont.DemiBold, display=True, parent=parent)


def primary_button(text, icon=None, parent=None):
    from qfluentwidgets import PrimaryPushButton
    button = PrimaryPushButton(icon, text, parent) if icon is not None else PrimaryPushButton(text, parent)
    style_primary(button)
    return button
