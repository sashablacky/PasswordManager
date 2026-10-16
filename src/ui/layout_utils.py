from PyQt5.QtWidgets import QWidget, QFrame, QVBoxLayout, QApplication
from qfluentwidgets import ScrollArea


def resize_to_fit_screen(window, width, height, margin=40):
    """Resize to width x height, but never larger than the free screen area
    (e.g. 1366x768 minus the taskbar), so the window edges and buttons stay visible"""
    screen = QApplication.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        width = min(width, available.width() - margin)
        height = min(height, available.height() - margin)
    window.resize(max(width, window.minimumWidth()), max(height, window.minimumHeight()))


def set_scrollable_layout(dialog, content_layout, footer=None, footer_alignment=None):
    """
    Put content_layout in a scroll area so the dialog still fits on small screens,
    with an optional footer (e.g. OK/Cancel buttons) that always stays visible.
    """
    content = QWidget()
    content.setObjectName("scrollContent")
    content.setLayout(content_layout)

    scroll = ScrollArea()  # Fluent scroll bars
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.setWidget(content)
    scroll.setStyleSheet("QScrollArea, #scrollContent { background: transparent; border: none; }")
    scroll.viewport().setStyleSheet("background: transparent;")

    outer = QVBoxLayout()
    outer.setContentsMargins(0, 0, 0, 0)
    outer.addWidget(scroll)

    if footer is not None:
        footer_layout = QVBoxLayout()
        footer_layout.setContentsMargins(30, 10, 30, 20)
        if footer_alignment is None:
            footer_layout.addWidget(footer)
        else:
            footer_layout.addWidget(footer, alignment=footer_alignment)
        outer.addLayout(footer_layout)

    dialog.setLayout(outer)
