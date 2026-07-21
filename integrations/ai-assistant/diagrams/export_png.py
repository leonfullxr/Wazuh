#!/usr/bin/env python3
"""Export draw.io diagrams in this directory to PNG.

Requires the draw.io desktop CLI (`drawio`, from draw.io / diagrams.net).
On headless Linux, uses xvfb-run (and dbus-run-session when available).

Examples:
  ./export_png.py
  ./export_png.py --scale 2 --transparent
  ./export_png.py --file wazuh-ai-v3-workflow.drawio
  DRAWIO_BIN=/opt/drawio/drawio ./export_png.py --output-dir ./png
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "png"


def slugify(name: str) -> str:
    text = name.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[-\s]+", "-", text)
    return text.strip("-") or "page"


def find_drawio_bin(explicit: str | None) -> str:
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return str(path)
        found = shutil.which(explicit)
        if found:
            return found
        raise SystemExit(f"draw.io binary not found: {explicit!r}")
    for candidate in ("drawio", "draw.io"):
        found = shutil.which(candidate)
        if found:
            return found
    raise SystemExit(
        "draw.io CLI not found (install draw.io desktop, or set DRAWIO_BIN). "
        "Debian/Ubuntu: https://github.com/jgraph/drawio-desktop/releases"
    )


def list_diagram_pages(drawio_path: Path) -> list[tuple[int, str]]:
    """Return (1-based page index, page title) for each sheet in the file."""
    root = ET.parse(drawio_path).getroot()
    pages: list[tuple[int, str]] = []
    for index, diagram in enumerate(root.findall("diagram"), start=1):
        title = (diagram.get("name") or f"page-{index}").strip()
        pages.append((index, title))
    if not pages:
        pages.append((1, drawio_path.stem))
    return pages


def should_use_headless(force: bool | None) -> bool:
    if force is not None:
        return force
    return sys.platform.startswith("linux") and not os.environ.get("DISPLAY")


def build_export_command(
    drawio_bin: str,
    drawio_path: Path,
    output_path: Path,
    *,
    page_index: int | None,
    scale: float | None,
    transparent: bool,
    border: int | None,
    headless: bool,
) -> list[str]:
    cmd = [
        drawio_bin,
        "--export",
        "--format",
        "png",
        "--output",
        str(output_path),
    ]
    if page_index is not None:
        cmd.extend(["--page-index", str(page_index)])
    if scale is not None:
        cmd.extend(["--scale", str(scale)])
    if transparent:
        cmd.append("--transparent")
    if border is not None:
        cmd.extend(["--border", str(border)])
    cmd.append(str(drawio_path))
    if headless:
        cmd.extend(["--no-sandbox", "--disable-gpu"])
    return cmd


def wrap_for_headless(cmd: list[str], headless: bool) -> list[str]:
    if not headless:
        return cmd
    if not shutil.which("xvfb-run"):
        print(
            "warning: no DISPLAY and xvfb-run missing; export may fail",
            file=sys.stderr,
        )
        return cmd
    inner = ["xvfb-run", "-a", *cmd]
    if shutil.which("dbus-run-session"):
        return ["dbus-run-session", "--", *inner]
    return inner


def export_diagram(
    drawio_bin: str,
    drawio_path: Path,
    output_dir: Path,
    *,
    scale: float | None,
    transparent: bool,
    border: int | None,
    headless: bool,
    dry_run: bool,
) -> list[Path]:
    pages = list_diagram_pages(drawio_path)
    multi = len(pages) > 1
    written: list[Path] = []

    for page_index, page_title in pages:
        if multi:
            out_name = f"{drawio_path.stem}--{slugify(page_title)}.png"
            page_arg = page_index
        else:
            out_name = f"{drawio_path.stem}.png"
            page_arg = None
        output_path = output_dir / out_name
        cmd = build_export_command(
            drawio_bin,
            drawio_path,
            output_path,
            page_index=page_arg,
            scale=scale,
            transparent=transparent,
            border=border,
            headless=headless,
        )
        cmd = wrap_for_headless(cmd, headless)
        print(f"{drawio_path.name} page {page_index} -> {output_path.name}")
        if dry_run:
            print("  ", " ".join(cmd))
            written.append(output_path)
            continue
        env = os.environ.copy()
        if headless:
            env["ELECTRON_DISABLE_GPU"] = "1"
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = (result.stderr or result.stdout or "").strip()
            raise SystemExit(
                f"export failed for {drawio_path} page {page_index} "
                f"(exit {result.returncode}): {stderr}"
            )
        if not output_path.is_file():
            raise SystemExit(f"export produced no file: {output_path}")
        written.append(output_path)
    return written


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        "-f",
        action="append",
        dest="files",
        help="draw.io file to export (default: all *.drawio in this directory)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=DEFAULT_OUT,
        help=f"output directory (default: {DEFAULT_OUT.relative_to(HERE)}/)",
    )
    parser.add_argument(
        "--drawio-bin",
        default=os.environ.get("DRAWIO_BIN"),
        help="path to draw.io CLI (default: $DRAWIO_BIN or drawio in PATH)",
    )
    parser.add_argument("--scale", "-s", type=float, help="scale factor (e.g. 2 for retina)")
    parser.add_argument("--transparent", "-t", action="store_true", help="transparent PNG background")
    parser.add_argument("--border", "-b", type=int, help="border width in pixels")
    parser.add_argument(
        "--headless",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force xvfb-run wrapper (default: auto when DISPLAY is unset on Linux)",
    )
    parser.add_argument("--dry-run", action="store_true", help="print commands without exporting")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    drawio_bin = find_drawio_bin(args.drawio_bin)
    headless = should_use_headless(args.headless)

    if args.files:
        sources = [HERE / Path(name).name if not Path(name).is_absolute() else Path(name) for name in args.files]
    else:
        sources = sorted(HERE.glob("*.drawio"))

    if not sources:
        raise SystemExit(f"no .drawio files found in {HERE}")

    output_dir = args.output_dir
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    exported: list[Path] = []
    for drawio_path in sources:
        if not drawio_path.is_file():
            raise SystemExit(f"diagram not found: {drawio_path}")
        exported.extend(
            export_diagram(
                drawio_bin,
                drawio_path,
                output_dir,
                scale=args.scale,
                transparent=args.transparent,
                border=args.border,
                headless=headless,
                dry_run=args.dry_run,
            )
        )

    print(f"done: {len(exported)} PNG file(s) -> {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
