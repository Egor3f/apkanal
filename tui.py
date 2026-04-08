"""Curses-based TUI for apkanal — Borland/MC style."""

import curses
import re
import subprocess
from pathlib import Path


DECOMPILE_DONE_MARKER = ".decompile_done"


def _get_status(name: str) -> str:
    has_report = bool(list(Path(".").glob(f"apkanal_report_{name}_*.md")))
    if has_report:
        return "done"
    state_file = Path("apkanal_output") / name / "analysis_state.json"
    if state_file.exists():
        return "incomplete"
    marker = Path("apkanal_output") / name / "decompiled" / DECOMPILE_DONE_MARKER
    if marker.exists():
        return "decompiled"
    return ""


def _list_previous() -> list[str]:
    out_dir = Path("apkanal_output")
    if not out_dir.exists():
        return []
    return sorted(
        d.name for d in out_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


def _check_device() -> bool:
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        lines = [l for l in r.stdout.strip().splitlines()[1:] if l.strip()]
        return bool(lines)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _get_packages(search: str = "", third_party: bool = True) -> list[str]:
    cmd = ["adb", "shell", "pm", "list", "packages"]
    if third_party:
        cmd.append("-3")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return []
        pkgs = sorted(l.removeprefix("package:") for l in r.stdout.strip().splitlines())
        if search:
            s = search.lower()
            pkgs = [p for p in pkgs if s in p.lower()]
        return pkgs
    except Exception:
        return []


def _get_labels_batch(pkgs: list[str]) -> dict[str, str]:
    if not pkgs:
        return {}
    labels = {}
    try:
        parts = []
        for p in pkgs:
            parts.append(
                f'l=$(dumpsys package "{p}" 2>/dev/null '
                f'| grep -m1 "nonLocalizedLabel=" '
                f'| sed "s/.*nonLocalizedLabel=//;s/ .*//"); '
                f'echo "{p}|$l"'
            )
        batch = ";".join(parts)
        r = subprocess.run(
            ["adb", "shell", batch],
            capture_output=True, text=True, timeout=15,
        )
        for line in r.stdout.strip().splitlines():
            if "|" in line:
                pkg, label = line.split("|", 1)
                label = label.strip()
                if label and label != "null":
                    labels[pkg.strip()] = label
    except Exception:
        pass
    return labels


def _draw_box(win, title: str = ""):
    h, w = win.getmaxyx()
    win.attron(curses.A_DIM)
    # Corners and borders
    win.addch(0, 0, curses.ACS_ULCORNER)
    win.addch(0, w - 1, curses.ACS_URCORNER)
    try:
        win.addch(h - 1, 0, curses.ACS_LLCORNER)
    except curses.error:
        pass
    try:
        win.addch(h - 1, w - 1, curses.ACS_LRCORNER)
    except curses.error:
        pass
    for x in range(1, w - 1):
        win.addch(0, x, curses.ACS_HLINE)
        try:
            win.addch(h - 1, x, curses.ACS_HLINE)
        except curses.error:
            pass
    for y in range(1, h - 1):
        win.addch(y, 0, curses.ACS_VLINE)
        try:
            win.addch(y, w - 1, curses.ACS_VLINE)
        except curses.error:
            pass
    win.attroff(curses.A_DIM)

    if title:
        title_str = f" {title} "
        win.addstr(0, 2, title_str, curses.A_BOLD)


def _draw_statusbar(win, text: str):
    h, w = win.getmaxyx()
    # Draw separator line
    win.addch(h - 2, 0, curses.ACS_LTEE, curses.A_DIM)
    for x in range(1, w - 1):
        win.addch(h - 2, x, curses.ACS_HLINE, curses.A_DIM)
    try:
        win.addch(h - 2, w - 1, curses.ACS_RTEE, curses.A_DIM)
    except curses.error:
        pass
    # Status text
    text = text[:w - 4]
    win.addstr(h - 1, 2, " " * (w - 4))
    win.addstr(h - 1, 2, text, curses.A_DIM)


def _safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0:
        return
    max_len = w - x - 1
    if max_len <= 0:
        return
    try:
        win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass


def _find_reports(name: str) -> list[Path]:
    """Find report files for a package, newest first."""
    reports = sorted(Path(".").glob(f"apkanal_report_{name}_*.md"), reverse=True)
    return reports


def _parse_md_lines(text: str, width: int) -> list[tuple[str, int]]:
    """Parse markdown into (text, attr) lines for display.

    Returns list of (line_text, curses_attr) tuples, word-wrapped to width.
    """
    lines: list[tuple[str, int]] = []
    for raw_line in text.splitlines():
        # Determine style
        attr = 0
        display = raw_line

        if raw_line.startswith("# "):
            display = raw_line[2:]
            attr = curses.A_BOLD | curses.A_UNDERLINE
        elif raw_line.startswith("## "):
            display = raw_line[3:]
            attr = curses.A_BOLD
        elif raw_line.startswith("### "):
            display = raw_line[4:]
            attr = curses.A_BOLD
        elif raw_line.startswith("- "):
            display = "  \u2022 " + raw_line[2:]
        elif raw_line.startswith("_") and raw_line.endswith("_"):
            display = raw_line.strip("_")
            attr = curses.A_DIM

        # Strip remaining markdown formatting for display
        display = re.sub(r'\*\*(.+?)\*\*', r'\1', display)
        display = re.sub(r'`(.+?)`', r'\1', display)

        # Word-wrap
        if not display.strip():
            lines.append(("", 0))
            continue
        while len(display) > width:
            # Find last space before width
            brk = display.rfind(" ", 0, width)
            if brk <= 0:
                brk = width
            lines.append((display[:brk], attr))
            display = display[brk:].lstrip()
        lines.append((display, attr))

    return lines


def _md_viewer(stdscr, filepath: Path):
    """Full-screen markdown viewer with scrolling."""
    try:
        text = filepath.read_text()
    except OSError:
        return

    curses.curs_set(0)
    h, w = stdscr.getmaxyx()
    content_w = w - 6  # margins
    parsed = _parse_md_lines(text, content_w)
    scroll = 0
    max_scroll = max(0, len(parsed) - (h - 4))

    while True:
        stdscr.clear()
        _draw_box(stdscr, filepath.name)
        _draw_statusbar(stdscr, "\u2191\u2193/PgUp/PgDn Scroll   q Back")

        view_h = h - 4
        for i in range(view_h):
            line_idx = scroll + i
            if line_idx >= len(parsed):
                break
            text_line, attr = parsed[line_idx]
            # Color severity keywords
            display_attr = attr
            if "[CRITICAL]" in text_line:
                display_attr |= curses.color_pair(6)
            elif "[HIGH]" in text_line:
                display_attr |= curses.color_pair(6)
            elif "[MEDIUM]" in text_line:
                display_attr |= curses.color_pair(1)
            _safe_addstr(stdscr, 1 + i, 3, text_line, display_attr)

        # Scroll indicator
        if max_scroll > 0:
            pct = int(scroll / max_scroll * 100) if max_scroll else 100
            _safe_addstr(stdscr, h - 2, w - 8, f" {pct}% ", curses.A_DIM)

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return
        elif key == curses.KEY_UP or key == ord("k"):
            scroll = max(0, scroll - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            scroll = min(max_scroll, scroll + 1)
        elif key == curses.KEY_PPAGE:
            scroll = max(0, scroll - view_h)
        elif key == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + view_h)
        elif key == curses.KEY_HOME or key == ord("g"):
            scroll = 0
        elif key == curses.KEY_END or key == ord("G"):
            scroll = max_scroll


def _previous_submenu(stdscr, name: str) -> str | None:
    """Sub-menu for a previous analysis: view report, interactive REPL, or re-analyze.
    Returns 'analyze', 'interactive', or None to go back."""
    reports = _find_reports(name)
    has_state = (Path("apkanal_output") / name / "analysis_state.json").exists()
    has_decompiled = (Path("apkanal_output") / name / "decompiled" / DECOMPILE_DONE_MARKER).exists()
    curses.curs_set(0)

    items = []
    for rpt in reports:
        ts = rpt.stem.rsplit("_", 1)[-1]
        try:
            import time as _time
            label = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(int(ts)))
        except (ValueError, OSError):
            label = ts
        items.append((f"View report: {label}", "report", rpt))
    if has_decompiled and has_state:
        items.append(("Interactive REPL (explore findings)", "interactive"))
    items.append(("Re-analyze", "analyze"))

    sel = 0
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        _draw_box(stdscr, name)
        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   Enter Select   q Back")

        for i, item in enumerate(items):
            y = 2 + i
            if y >= h - 2:
                break
            label = item[0]
            if i == sel:
                line = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, line, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, "\u25b8 ", curses.color_pair(5))
                _safe_addstr(stdscr, y, 5, label, curses.color_pair(5) | curses.A_BOLD)
            else:
                _safe_addstr(stdscr, y, 5, label)

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return None
        elif key == curses.KEY_UP or key == ord("k"):
            sel = max(0, sel - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            sel = min(len(items) - 1, sel + 1)
        elif key == ord("\n") or key == curses.KEY_ENTER:
            item = items[sel]
            if item[1] == "analyze":
                return "analyze"
            elif item[1] == "interactive":
                return "interactive"
            elif item[1] == "report":
                _md_viewer(stdscr, item[2])
            elif item[1] == "back":
                return None


def main_menu(stdscr) -> tuple[str | None, Path | None, str]:
    """Main menu. Returns (package_name, apk_path, mode).
    mode is 'analyze' (default) or 'interactive'."""
    curses.curs_set(0)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_YELLOW, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, -1, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(6, curses.COLOR_RED, -1)

    previous = _list_previous()
    has_device = _check_device()

    # Build menu items: (label, type, value)
    items = []
    if previous:
        for name in previous:
            status = _get_status(name)
            items.append((name, "previous", name, status))
    # Separator
    items.append(("---", "separator", None, ""))
    if has_device:
        items.append(("Search packages on device", "action", "search", ""))
        items.append(("Browse installed apps", "action", "browse", ""))
    else:
        items.append(("(no device connected)", "disabled", None, ""))
    items.append(("Enter package name", "action", "manual", ""))
    items.append(("Open local APK file", "action", "file", ""))

    # Find first selectable
    sel = 0
    while sel < len(items) and items[sel][1] in ("separator", "disabled"):
        sel += 1

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        _draw_box(stdscr, "apkanal")
        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   Enter Select   q Quit")

        # Content area
        content_h = h - 4  # box top/bottom + status separator + status
        scroll_start = 0
        if sel > content_h - 1:
            scroll_start = sel - content_h + 1

        y = 1
        for i, (label, typ, val, status) in enumerate(items):
            if i < scroll_start:
                continue
            if y >= h - 2:
                break

            if typ == "separator":
                for x in range(2, w - 2):
                    _safe_addstr(stdscr, y, x, "\u2500", curses.A_DIM)
                y += 1
                continue

            if typ == "disabled":
                _safe_addstr(stdscr, y, 4, label, curses.A_DIM)
                y += 1
                continue

            if i == sel:
                # Highlighted
                line = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, line, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, "\u25b8 ", curses.color_pair(5))
                _safe_addstr(stdscr, y, 5, label, curses.color_pair(5) | curses.A_BOLD)
                if status == "incomplete":
                    _safe_addstr(stdscr, y, 5 + len(label) + 2, "(incomplete)",
                                 curses.color_pair(5))
                elif status == "done":
                    _safe_addstr(stdscr, y, 5 + len(label) + 2, "(done)",
                                 curses.color_pair(5))
            else:
                _safe_addstr(stdscr, y, 5, label)
                if status == "incomplete":
                    _safe_addstr(stdscr, y, 5 + len(label) + 2, "(incomplete)",
                                 curses.color_pair(1))
                elif status == "done":
                    _safe_addstr(stdscr, y, 5 + len(label) + 2, "(done)",
                                 curses.color_pair(2) | curses.A_DIM)

            y += 1

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return None, None, "analyze"

        elif key == curses.KEY_UP or key == ord("k"):
            sel -= 1
            while sel >= 0 and items[sel][1] in ("separator", "disabled"):
                sel -= 1
            if sel < 0:
                sel = len(items) - 1
                while items[sel][1] in ("separator", "disabled"):
                    sel -= 1

        elif key == curses.KEY_DOWN or key == ord("j"):
            sel += 1
            while sel < len(items) and items[sel][1] in ("separator", "disabled"):
                sel += 1
            if sel >= len(items):
                sel = 0
                while items[sel][1] in ("separator", "disabled"):
                    sel += 1

        elif key == ord("\n") or key == curses.KEY_ENTER:
            _, typ, val, _ = items[sel]
            if typ == "previous":
                action = _previous_submenu(stdscr, val)
                if action == "analyze":
                    return val, None, "analyze"
                elif action == "interactive":
                    return val, None, "interactive"
                # else back to main menu
            elif typ == "action":
                if val == "search":
                    result = _search_screen(stdscr)
                    if result:
                        return result, None, "analyze"
                elif val == "browse":
                    result = _browse_screen(stdscr)
                    if result:
                        return result, None, "analyze"
                elif val == "manual":
                    result = _input_screen(stdscr, "Enter package name:", "Package name")
                    if result:
                        return result, None, "analyze"
                elif val == "file":
                    result = _input_screen(stdscr, "Enter APK file path:", "APK path")
                    if result:
                        p = Path(result)
                        if p.exists() and p.suffix == ".apk":
                            return p.stem, p, "analyze"


def _input_screen(stdscr, title: str, placeholder: str) -> str | None:
    """Simple text input screen. Supports Unicode (Russian, etc.)."""
    curses.curs_set(1)
    h, w = stdscr.getmaxyx()
    buf = ""

    while True:
        stdscr.clear()
        _draw_box(stdscr, title)
        _draw_statusbar(stdscr, "Enter Confirm   Esc Cancel")

        prefix = f"{placeholder}: "
        _safe_addstr(stdscr, 2, 3, prefix, curses.A_BOLD)
        # Display buf — truncate to fit screen
        display_buf = buf[-(w - 3 - len(prefix) - 2):]
        _safe_addstr(stdscr, 2, 3 + len(prefix), display_buf)

        try:
            stdscr.move(2, 3 + len(prefix) + len(display_buf.encode("utf-8").decode("utf-8", "replace")))
        except curses.error:
            pass
        stdscr.refresh()

        try:
            wch = stdscr.get_wch()
        except curses.error:
            continue

        if isinstance(wch, int):
            # Special key
            if wch == 27:  # Escape
                curses.curs_set(0)
                return None
            elif wch in (curses.KEY_ENTER, 10, 13):
                curses.curs_set(0)
                return buf.strip() if buf.strip() else None
            elif wch in (curses.KEY_BACKSPACE, 127, 8):
                buf = buf[:-1]
        else:
            # Regular character (str)
            if wch == "\n":
                curses.curs_set(0)
                return buf.strip() if buf.strip() else None
            elif wch == "\x1b":  # Escape
                curses.curs_set(0)
                return None
            elif ord(wch) >= 32:
                buf += wch

    curses.curs_set(0)
    return None


def _search_screen(stdscr) -> str | None:
    """Search for packages, then browse results."""
    term = _input_screen(stdscr, "Search packages", "Search")
    if not term:
        return None

    curses.curs_set(0)
    stdscr.clear()
    _draw_box(stdscr, "Searching...")
    stdscr.refresh()

    pkgs = _get_packages(term)
    if not pkgs:
        stdscr.clear()
        _draw_box(stdscr, "Search")
        _safe_addstr(stdscr, 2, 3, f"No packages matching '{term}'")
        _draw_statusbar(stdscr, "Press any key")
        stdscr.refresh()
        stdscr.getch()
        return None

    return _package_list_screen(stdscr, pkgs, f"Search: {term}")


def _browse_screen(stdscr) -> str | None:
    """Browse all installed (3rd party) packages."""
    curses.curs_set(0)
    stdscr.clear()
    _draw_box(stdscr, "Loading...")
    _safe_addstr(stdscr, 2, 3, "Loading package list from device...")
    stdscr.refresh()

    pkgs = _get_packages()
    if not pkgs:
        stdscr.clear()
        _draw_box(stdscr, "Browse")
        _safe_addstr(stdscr, 2, 3, "No packages found")
        _draw_statusbar(stdscr, "Press any key")
        stdscr.refresh()
        stdscr.getch()
        return None

    return _package_list_screen(stdscr, pkgs, "Installed apps")


def _package_list_screen(stdscr, pkgs: list[str], title: str,
                         labels: dict[str, str] | None = None) -> str | None:
    """Scrollable package list with inline filter and app labels.
    Type to filter immediately — no need to press / first."""
    curses.curs_set(0)
    sel = 0
    scroll = 0
    filter_text = ""
    filtered = pkgs[:]
    if labels is None:
        labels = {}

    def _apply_filter():
        nonlocal filtered, sel, scroll
        if filter_text:
            ft = filter_text.lower()
            filtered = [p for p in pkgs
                        if ft in p.lower() or ft in labels.get(p, "").lower()]
        else:
            filtered = pkgs[:]
        sel = 0
        scroll = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        list_h = h - 5  # box top + filter line + separator + status + box bottom

        _draw_box(stdscr, title)

        # Filter line
        if filter_text:
            _safe_addstr(stdscr, 1, 2, " Filter: ", curses.A_BOLD)
            _safe_addstr(stdscr, 1, 11, filter_text, curses.color_pair(4))
        else:
            _safe_addstr(stdscr, 1, 2, " Type to filter...", curses.A_DIM)

        # Clamp selection
        if sel >= len(filtered):
            sel = max(0, len(filtered) - 1)
        if sel < scroll:
            scroll = sel
        if sel >= scroll + list_h:
            scroll = sel - list_h + 1

        # Draw list
        for i in range(list_h):
            idx = scroll + i
            y = 2 + i
            if idx >= len(filtered):
                break

            pkg = filtered[idx]
            label = labels.get(pkg, "")

            if idx == sel:
                line = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, line, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, "\u25b8 ", curses.color_pair(5))
                if label:
                    _safe_addstr(stdscr, y, 5, label, curses.color_pair(5) | curses.A_BOLD)
                    _safe_addstr(stdscr, y, 5 + len(label) + 1, pkg, curses.color_pair(5))
                else:
                    _safe_addstr(stdscr, y, 5, pkg, curses.color_pair(5) | curses.A_BOLD)
            else:
                if label:
                    _safe_addstr(stdscr, y, 5, label, curses.A_BOLD)
                    _safe_addstr(stdscr, y, 5 + len(label) + 1, pkg, curses.A_DIM)
                else:
                    _safe_addstr(stdscr, y, 5, pkg)

        # Scroll indicator
        if len(filtered) > list_h:
            pct = f" {sel + 1}/{len(filtered)} "
            _safe_addstr(stdscr, h - 2, w - len(pct) - 2, pct, curses.A_DIM)

        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   Enter Select   q Back")
        stdscr.refresh()

        key = stdscr.getch()

        if key == ord("q") and not filter_text:
            return None

        elif key == curses.KEY_UP:
            if sel > 0:
                sel -= 1

        elif key == curses.KEY_DOWN:
            if sel < len(filtered) - 1:
                sel += 1

        elif key == curses.KEY_PPAGE:
            sel = max(0, sel - list_h)

        elif key == curses.KEY_NPAGE:
            sel = min(len(filtered) - 1, sel + list_h)

        elif key == curses.KEY_HOME:
            sel = 0
            scroll = 0

        elif key == curses.KEY_END:
            sel = len(filtered) - 1

        elif key in (ord("\n"), curses.KEY_ENTER):
            if filtered:
                return filtered[sel]

        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if filter_text:
                filter_text = filter_text[:-1]
                _apply_filter()

        elif 32 <= key <= 126:
            filter_text += chr(key)
            _apply_filter()

    return None


def run_tui() -> tuple[str | None, Path | None, str]:
    """Entry point. Runs curses TUI, returns (package_name, apk_path, mode)."""
    return curses.wrapper(main_menu)


# ---------------------------------------------------------------------------
# Interactive TUI (replaces text-based REPL)
# ---------------------------------------------------------------------------

def _severity_color(sev: str) -> int:
    """Return curses color pair for severity."""
    return {
        "CRITICAL": curses.color_pair(6) | curses.A_BOLD,
        "HIGH": curses.color_pair(6),
        "MEDIUM": curses.color_pair(1),
        "LOW": curses.color_pair(2),
    }.get(sev, curses.A_DIM)


def _text_viewer(stdscr, title: str, text: str):
    """Generic scrollable text viewer."""
    curses.curs_set(0)
    h, w = stdscr.getmaxyx()
    content_w = w - 6
    lines = _parse_md_lines(text, content_w)
    scroll = 0
    max_scroll = max(0, len(lines) - (h - 4))

    while True:
        stdscr.clear()
        _draw_box(stdscr, title)
        _draw_statusbar(stdscr, "\u2191\u2193/PgUp/PgDn Scroll   q Back")

        view_h = h - 4
        for i in range(view_h):
            idx = scroll + i
            if idx >= len(lines):
                break
            text_line, attr = lines[idx]
            _safe_addstr(stdscr, 1 + i, 3, text_line, attr)

        if max_scroll > 0:
            pct = int(scroll / max_scroll * 100) if max_scroll else 100
            _safe_addstr(stdscr, h - 2, w - 8, f" {pct}% ", curses.A_DIM)

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return
        elif key == curses.KEY_UP or key == ord("k"):
            scroll = max(0, scroll - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            scroll = min(max_scroll, scroll + 1)
        elif key == curses.KEY_PPAGE:
            scroll = max(0, scroll - view_h)
        elif key == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + view_h)
        elif key == curses.KEY_HOME or key == ord("g"):
            scroll = 0
        elif key == curses.KEY_END or key == ord("G"):
            scroll = max_scroll


def _findings_screen(stdscr, findings: list) -> None:
    """Scrollable findings list. Enter to view detail."""
    if not findings:
        _text_viewer(stdscr, "Findings", "No findings.")
        return

    sel = 0
    scroll = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        _draw_box(stdscr, f"Findings ({len(findings)})")
        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   Enter View   q Back")

        list_h = h - 4
        if sel < scroll:
            scroll = sel
        if sel >= scroll + list_h:
            scroll = sel - list_h + 1

        for i in range(list_h):
            idx = scroll + i
            if idx >= len(findings):
                break
            f = findings[idx]
            y = 1 + i
            sev_str = f"[{f.severity}]"
            line = f"#{idx + 1} {sev_str} {f.title}"
            detail = f"{f.file_path} ({f.confidence:.0%})"

            if idx == sel:
                bg = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, bg, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, f"#{idx + 1} ", curses.color_pair(5))
                _safe_addstr(stdscr, y, 3 + len(f"#{idx + 1} "), sev_str,
                             curses.color_pair(5) | curses.A_BOLD)
                rest = f" {f.title}"
                _safe_addstr(stdscr, y, 3 + len(f"#{idx + 1} ") + len(sev_str), rest,
                             curses.color_pair(5))
            else:
                _safe_addstr(stdscr, y, 3, f"#{idx + 1} ", curses.A_DIM)
                _safe_addstr(stdscr, y, 3 + len(f"#{idx + 1} "), sev_str,
                             _severity_color(f.severity))
                _safe_addstr(stdscr, y, 3 + len(f"#{idx + 1} ") + len(sev_str),
                             f" {f.title}")
                _safe_addstr(stdscr, y, 3 + len(line) + 1, detail, curses.A_DIM)

        if len(findings) > list_h:
            _safe_addstr(stdscr, h - 2, w - 12, f" {sel + 1}/{len(findings)} ", curses.A_DIM)

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return
        elif key == curses.KEY_UP or key == ord("k"):
            sel = max(0, sel - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            sel = min(len(findings) - 1, sel + 1)
        elif key == curses.KEY_PPAGE:
            sel = max(0, sel - list_h)
        elif key == curses.KEY_NPAGE:
            sel = min(len(findings) - 1, sel + list_h)
        elif key == curses.KEY_HOME:
            sel = 0
            scroll = 0
        elif key == curses.KEY_END:
            sel = len(findings) - 1
        elif key in (ord("\n"), curses.KEY_ENTER):
            f = findings[sel]
            text = (f"## [{f.severity}] {f.title}\n\n"
                    f"**Category:** {f.category}\n"
                    f"**File:** {f.file_path}\n"
                    f"**Confidence:** {f.confidence:.0%}\n\n"
                    f"{f.description}\n")
            if f.code_snippet:
                text += f"\n**Code:**\n```\n{f.code_snippet}\n```\n"
            _text_viewer(stdscr, f"Finding #{sel + 1}", text)


def _files_screen(stdscr, source_files: list) -> str | None:
    """Scrollable file list with scores. Returns selected file path or None."""
    sel = 0
    scroll = 0
    filter_text = ""
    filtered = source_files[:]

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        list_h = h - 5
        _draw_box(stdscr, f"Source files ({len(filtered)})")

        if filter_text:
            _safe_addstr(stdscr, 1, 2, " / ", curses.A_BOLD)
            _safe_addstr(stdscr, 1, 5, filter_text, curses.color_pair(4))
        else:
            _safe_addstr(stdscr, 1, 2, " / type to filter", curses.A_DIM)

        if sel >= len(filtered):
            sel = max(0, len(filtered) - 1)
        if sel < scroll:
            scroll = sel
        if sel >= scroll + list_h:
            scroll = sel - list_h + 1

        for i in range(list_h):
            idx = scroll + i
            if idx >= len(filtered):
                break
            sf = filtered[idx]
            y = 2 + i
            score_str = f" ({sf.score})" if sf.score > 0 else ""

            if idx == sel:
                bg = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, bg, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, sf.relative_path,
                             curses.color_pair(5) | curses.A_BOLD)
                if score_str:
                    _safe_addstr(stdscr, y, 3 + len(sf.relative_path), score_str,
                                 curses.color_pair(5))
            else:
                _safe_addstr(stdscr, y, 3, sf.relative_path)
                if score_str:
                    _safe_addstr(stdscr, y, 3 + len(sf.relative_path), score_str,
                                 curses.color_pair(1))

        if len(filtered) > list_h:
            _safe_addstr(stdscr, h - 2, w - 12, f" {sel + 1}/{len(filtered)} ", curses.A_DIM)

        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   Enter View   / Filter   q Back (Bksp clear filter)")
        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q") and not filter_text:
            return None
        elif key == curses.KEY_UP or key == ord("k"):
            sel = max(0, sel - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            sel = min(len(filtered) - 1, sel + 1)
        elif key == curses.KEY_PPAGE:
            sel = max(0, sel - list_h)
        elif key == curses.KEY_NPAGE:
            sel = min(len(filtered) - 1, sel + list_h)
        elif key == curses.KEY_HOME:
            sel = 0
            scroll = 0
        elif key == curses.KEY_END:
            sel = len(filtered) - 1
        elif key in (ord("\n"), curses.KEY_ENTER):
            if filtered:
                return filtered[sel].relative_path
        elif key == ord("/"):
            filter_text = ""
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if filter_text:
                filter_text = filter_text[:-1]
                if filter_text:
                    ft = filter_text.lower()
                    filtered = [sf for sf in source_files if ft in sf.relative_path.lower()]
                else:
                    filtered = source_files[:]
                sel = 0
                scroll = 0
        elif 32 <= key <= 126:
            filter_text += chr(key)
            ft = filter_text.lower()
            filtered = [sf for sf in source_files if ft in sf.relative_path.lower()]
            sel = 0
            scroll = 0

    return None


def _search_code_screen(stdscr, source_files: list) -> None:
    """Search source files for a regex pattern, show results."""
    term = _input_screen(stdscr, "Search source code", "Pattern")
    if not term:
        return

    # Collect matches
    results = []
    for sf in source_files:
        for i, line in enumerate(sf.content.splitlines(), 1):
            try:
                if re.search(term, line, re.IGNORECASE):
                    results.append((sf.relative_path, i, line.strip()[:200]))
            except re.error:
                if term.lower() in line.lower():
                    results.append((sf.relative_path, i, line.strip()[:200]))
            if len(results) >= 200:
                break
        if len(results) >= 200:
            break

    if not results:
        _text_viewer(stdscr, "Search", f"No matches for '{term}'")
        return

    # Show results in a scrollable list
    sel = 0
    scroll = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        list_h = h - 4
        _draw_box(stdscr, f"Search: {term} ({len(results)} matches)")
        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   q Back")

        if sel < scroll:
            scroll = sel
        if sel >= scroll + list_h:
            scroll = sel - list_h + 1

        for i in range(list_h):
            idx = scroll + i
            if idx >= len(results):
                break
            path, lineno, content = results[idx]
            y = 1 + i
            prefix = f"{path}:{lineno} "
            if idx == sel:
                bg = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, bg, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, prefix, curses.color_pair(5) | curses.A_BOLD)
                _safe_addstr(stdscr, y, 3 + len(prefix), content, curses.color_pair(5))
            else:
                _safe_addstr(stdscr, y, 3, prefix, curses.color_pair(4))
                _safe_addstr(stdscr, y, 3 + len(prefix), content)

        if len(results) > list_h:
            _safe_addstr(stdscr, h - 2, w - 12, f" {sel + 1}/{len(results)} ", curses.A_DIM)

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return
        elif key == curses.KEY_UP or key == ord("k"):
            sel = max(0, sel - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            sel = min(len(results) - 1, sel + 1)
        elif key == curses.KEY_PPAGE:
            sel = max(0, sel - list_h)
        elif key == curses.KEY_NPAGE:
            sel = min(len(results) - 1, sel + list_h)


def _run_claude_with_spinner(stdscr, title: str, claude_fn, prompt: str,
                              system_prompt: str, model: str) -> str:
    """Show a spinner while running a Claude call, return result text."""
    import threading

    result_box = [None]
    error_box = [None]

    def _worker():
        try:
            result_box[0] = claude_fn(prompt, system_prompt, model=model, cache=False)
        except Exception as e:
            error_box[0] = str(e)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    spinner = "|/-\\"
    tick = 0
    stdscr.nodelay(True)
    try:
        while t.is_alive():
            stdscr.clear()
            _draw_box(stdscr, title)
            h, w = stdscr.getmaxyx()
            _safe_addstr(stdscr, h // 2, w // 2 - 10,
                         f" {spinner[tick % len(spinner)]} Asking Claude... ", curses.A_BOLD)
            _draw_statusbar(stdscr, "Please wait...")
            stdscr.refresh()
            curses.napms(200)
            tick += 1
            # Check if user pressed q to cancel
            try:
                k = stdscr.getch()
                if k == ord("q"):
                    break
            except curses.error:
                pass
    finally:
        stdscr.nodelay(False)

    t.join(timeout=1)

    if error_box[0]:
        return f"Error: {error_box[0]}"
    if result_box[0] is None:
        return "(cancelled or timed out)"
    r = result_box[0]
    return r if isinstance(r, str) else str(r)


def _interactive_main(stdscr, findings, source_files, manifest_result,
                       decompile_dir, model, claude_fn):
    """Main interactive TUI screen."""
    curses.curs_set(0)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_YELLOW, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, -1, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(6, curses.COLOR_RED, -1)

    file_index = {sf.relative_path: sf for sf in source_files}

    # Build menu
    items = []
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    sev_summary = ", ".join(f"{c} {s}" for s, c in
                            sorted(sev_counts.items(),
                                   key=lambda kv: ["CRITICAL","HIGH","MEDIUM","LOW"].index(kv[0])
                                   if kv[0] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99))
    findings_label = f"Findings ({sev_summary})" if findings else "Findings (none)"

    items.append((findings_label, "findings"))
    items.append((f"Source files ({len(source_files)})", "files"))
    items.append(("Search source code", "search"))
    items.append(("---", "separator"))
    items.append(("Analyze a file with Claude", "analyze"))
    items.append(("Ask Claude a question", "ask"))
    items.append(("---", "separator"))
    # Reports
    reports = _find_reports(decompile_dir.parent.name)
    for rpt in reports:
        ts = rpt.stem.rsplit("_", 1)[-1]
        try:
            import time as _time
            label = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(int(ts)))
        except (ValueError, OSError):
            label = ts
        items.append((f"View report: {label}", "report", rpt))
    if reports:
        items.append(("---", "separator"))
    items.append(("Quit", "quit"))

    sel = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        pkg_name = decompile_dir.parent.name
        _draw_box(stdscr, f"apkanal \u2014 {pkg_name}")
        _draw_statusbar(stdscr, "\u2191\u2193 Navigate   Enter Select   q Quit")

        content_h = h - 4
        scroll_start = 0
        if sel > content_h - 1:
            scroll_start = sel - content_h + 1

        y = 1
        for i, item in enumerate(items):
            if i < scroll_start:
                continue
            if y >= h - 2:
                break

            if item[1] == "separator":
                for x in range(2, w - 2):
                    _safe_addstr(stdscr, y, x, "\u2500", curses.A_DIM)
                y += 1
                continue

            label = item[0]
            if i == sel:
                bg = " " * (w - 4)
                _safe_addstr(stdscr, y, 2, bg, curses.color_pair(5))
                _safe_addstr(stdscr, y, 3, "\u25b8 ", curses.color_pair(5))
                _safe_addstr(stdscr, y, 5, label, curses.color_pair(5) | curses.A_BOLD)
            else:
                _safe_addstr(stdscr, y, 5, label)

            y += 1

        stdscr.refresh()
        key = stdscr.getch()

        if key == ord("q"):
            return

        elif key == curses.KEY_UP or key == ord("k"):
            sel -= 1
            while sel >= 0 and items[sel][1] == "separator":
                sel -= 1
            if sel < 0:
                sel = len(items) - 1
                while items[sel][1] == "separator":
                    sel -= 1

        elif key == curses.KEY_DOWN or key == ord("j"):
            sel += 1
            while sel < len(items) and items[sel][1] == "separator":
                sel += 1
            if sel >= len(items):
                sel = 0
                while items[sel][1] == "separator":
                    sel += 1

        elif key in (ord("\n"), curses.KEY_ENTER):
            action = items[sel][1]

            if action == "quit":
                return

            elif action == "findings":
                _findings_screen(stdscr, findings)

            elif action == "files":
                selected_path = _files_screen(stdscr, source_files)
                if selected_path and selected_path in file_index:
                    sf = file_index[selected_path]
                    _text_viewer(stdscr, selected_path,
                                 f"**Score:** {sf.score}\n\n```\n{sf.content}\n```")

            elif action == "search":
                _search_code_screen(stdscr, source_files)

            elif action == "analyze":
                # Pick a file first
                selected_path = _files_screen(stdscr, source_files)
                if selected_path and selected_path in file_index:
                    sf = file_index[selected_path]
                    from config import SYSTEM_PROMPT_ANALYSIS
                    prompt = (f"Deep-analyze this file for backdoors and malicious behavior. "
                              f"Be thorough — examine every method.\n\n"
                              f"File: {sf.relative_path}\n"
                              f"Static pre-scan score: {sf.score}/100\n\n"
                              f"```java\n{sf.content}\n```")
                    result = _run_claude_with_spinner(
                        stdscr, f"Analyzing {sf.relative_path}",
                        claude_fn, prompt, SYSTEM_PROMPT_ANALYSIS, model)
                    _text_viewer(stdscr, f"Analysis: {sf.relative_path}", result)

            elif action == "ask":
                question = _input_screen(stdscr, "Ask Claude", "Question")
                if question:
                    from config import SYSTEM_PROMPT_INTERACTIVE
                    context_parts = ["Known findings so far:"]
                    for i, f in enumerate(findings[:10], 1):
                        context_parts.append(
                            f"  #{i} [{f.severity}] {f.title} in {f.file_path}")
                    context_parts.append("")
                    context_chars = 0
                    for sf in source_files[:20]:
                        if sf.score > 0 and context_chars + sf.size < 50000:
                            context_parts.append(
                                f"--- {sf.relative_path} (score {sf.score}) ---")
                            context_parts.append(sf.content)
                            context_chars += sf.size
                    prompt = "\n".join(context_parts) + f"\n\nUser question: {question}"
                    result = _run_claude_with_spinner(
                        stdscr, "Asking Claude",
                        claude_fn, prompt, SYSTEM_PROMPT_INTERACTIVE, model)
                    _text_viewer(stdscr, f"Answer: {question[:40]}", result)

            elif action == "report":
                _md_viewer(stdscr, items[sel][2])


def run_interactive_tui(findings, source_files, manifest_result,
                        decompile_dir, model, claude_fn):
    """Entry point for interactive TUI."""
    curses.wrapper(lambda stdscr: _interactive_main(
        stdscr, findings, source_files, manifest_result,
        decompile_dir, model, claude_fn))
