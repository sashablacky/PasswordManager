# Settings for dmgbuild (https://dmgbuild.readthedocs.io): the window of the
# .dmg with a background arrow "drag the app onto Applications" and the
# first-start notes. Used by build_macos.sh:
#   python -m dmgbuild -s packaging/macos/dmg_settings.py \
#       -D app=... -D notes=... -D background=... "Password Manager" out.dmg
# Icon positions must match make_dmg_background.py.
import os.path

app = defines["app"]  # noqa: F821 (provided by dmgbuild)
notes = defines["notes"]  # noqa: F821
background = defines["background"]  # noqa: F821

format = "UDZO"
files = [app, notes]
symlinks = {"Applications": "/Applications"}
icon_locations = {
    os.path.basename(app): (160, 190),
    "Applications": (480, 190),
    os.path.basename(notes): (320, 362),
}

# 640x440 content plus the title bar
window_rect = ((200, 120), (640, 462))
default_view = "icon-view"
icon_size = 96
text_size = 13
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
