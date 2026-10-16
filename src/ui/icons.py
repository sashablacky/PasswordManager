"""
Icons that the Fluent icon set (FluentIcon) does not have: star, lock, shield, warning, key, dice.

They are drawn in the same thin-stroke style and coloured with the text colour
of the current theme, so they can be used anywhere a FluentIcon is accepted.
"""

from enum import Enum

from PyQt5.QtGui import QIcon, QColor
from qfluentwidgets import FluentIconBase, Theme
from qfluentwidgets.common.icon import drawSvgIcon, SvgIconEngine

_SHAPES = {
    "lock": '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/>'
            '<path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><path d="M12 14.5v2.5"/>',
    "star": '<path d="M12 3.8l2.5 5.2 5.6.7-4.1 3.9 1 5.6L12 16.5l-5 2.7 1-5.6-4.1-3.9 5.6-.7z"/>',
    "shield": '<path d="M12 3l7 3v5.5c0 4.4-3 8-7 9.5-4-1.5-7-5.1-7-9.5V6z"/><path d="M9 12l2 2 4-4"/>',
    "warning": '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17v.1"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l2 2M14 9l2 2"/>',
    "dice": '<rect x="4" y="4" width="16" height="16" rx="3.5"/><circle cx="9" cy="9" r=".6"/>'
            '<circle cx="15" cy="15" r=".6"/><circle cx="15" cy="9" r=".6"/><circle cx="9" cy="15" r=".6"/>',
}

_FILLED = {"star_filled": "star"}


class AppIcon(FluentIconBase, Enum):
    LOCK = "lock"
    STAR = "star"
    STAR_FILLED = "star_filled"
    SHIELD = "shield"
    WARNING = "warning"
    KEY = "key"
    DICE = "dice"

    def path(self, theme=Theme.AUTO) -> str:
        return ""  # drawn from inline SVG, there is no file

    def svg(self, color: str) -> str:
        shape = _SHAPES[_FILLED.get(self.value, self.value)]
        fill = color if self.value in _FILLED else "none"
        return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
                f'fill="{fill}" stroke="{color}" stroke-width="1.6" '
                f'stroke-linecap="round" stroke-linejoin="round">{shape}</svg>')

    @staticmethod
    def _color(theme, color=None) -> str:
        if color is not None:
            return QColor(color).name()

        from ui import theme as app_theme
        palette = app_theme.current()
        # Theme.LIGHT is what Fluent asks for on accent-coloured (primary) buttons
        return palette.on_accent if theme == Theme.LIGHT else palette.text

    def icon(self, theme=Theme.AUTO, color=None) -> QIcon:
        return QIcon(SvgIconEngine(self.svg(self._color(theme, color))))

    def render(self, painter, rect, theme=Theme.AUTO, indexes=None, **attributes):
        color = attributes.get("fill") or attributes.get("stroke")
        drawSvgIcon(self.svg(self._color(theme, color)).encode(), painter, rect)
