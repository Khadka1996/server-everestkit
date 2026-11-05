#!/usr/bin/env python3
"""PDF -> DOCX / XLSX / PPTX converter used by services/officeService.js.

Usage: pdf_convert.py <word|excel|powerpoint> <input.pdf> <output> [options-json]
Prints a one-line JSON summary on success; exits non-zero with a message on stderr on failure.

Requires (install in Server/.venv-tools):
    pip install pdf2docx pdfplumber openpyxl python-pptx pymupdf
"""
import json
import sys


def to_word(src, dst, opts):
    from pdf2docx import Converter

    cv = Converter(src)
    try:
        cv.convert(dst, start=0, end=None)
    finally:
        cv.close()
    return _shrink_docx_images(dst)


def _shrink_docx_images(path, max_side=2000, min_bytes=150_000):
    """pdf2docx stores photos as lossless PNG, so a 2MB PDF can become a 20MB
    .docx. Re-encode large opaque images as JPEG (and cap their size)."""
    import io
    import os
    import zipfile

    from PIL import Image

    with zipfile.ZipFile(path) as zin:
        entries = [(i, zin.read(i.filename)) for i in zin.infolist()]

    renamed = {}
    out = []
    for info, data in entries:
        name = info.filename
        if name.startswith("word/media/") and name.lower().endswith(".png") and len(data) > min_bytes:
            try:
                img = Image.open(io.BytesIO(data))
                has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
                if has_alpha and img.convert("RGBA").getextrema()[3][0] < 255:
                    raise ValueError("transparent")  # keep real transparency as PNG
                img = img.convert("RGB")
                img.thumbnail((max_side, max_side))
                buf = io.BytesIO()
                img.save(buf, "JPEG", quality=85, optimize=True, progressive=True)
                if buf.tell() < len(data):
                    new_name = name[:-4] + ".jpeg"
                    renamed[name.split("/")[-1]] = new_name.split("/")[-1]
                    out.append((new_name, buf.getvalue()))
                    continue
            except Exception:
                pass
        out.append((name, data))

    if renamed:
        fixed = []
        for name, data in out:
            if name.endswith(".rels"):
                text = data.decode("utf-8")
                for old, new in renamed.items():
                    text = text.replace(f"media/{old}", f"media/{new}")
                data = text.encode("utf-8")
            elif name == "[Content_Types].xml":
                text = data.decode("utf-8")
                if 'Extension="jpeg"' not in text:
                    text = text.replace("<Types ", "<Types ", 1).replace(
                        "</Types>", '<Default Extension="jpeg" ContentType="image/jpeg"/></Types>', 1)
                data = text.encode("utf-8")
            fixed.append((name, data))
        tmp = path + ".tmp"
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for name, data in fixed:
                zout.writestr(name, data)
        os.replace(tmp, path)
    return {"imagesRecompressed": len(renamed)}


def to_excel(src, dst, opts):
    import pdfplumber
    from openpyxl import Workbook
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    wb.remove(wb.active)
    tables_found = 0

    with pdfplumber.open(src) as pdf:
        for page_no, page in enumerate(pdf.pages, start=1):
            tables = page.extract_tables() or []
            if tables:
                for t_no, table in enumerate(tables, start=1):
                    tables_found += 1
                    name = f"Page {page_no}" if len(tables) == 1 else f"Page {page_no} - T{t_no}"
                    ws = wb.create_sheet(title=name[:31])
                    for r, row in enumerate(table, start=1):
                        for c, value in enumerate(row, start=1):
                            ws.cell(row=r, column=c, value=_clean(value))
                    for cell in ws[1]:
                        cell.font = Font(bold=True)
                    _autosize(ws, get_column_letter)
            else:
                # No ruled table on this page: keep its text, one line per row,
                # splitting on runs of 2+ spaces so column-aligned text lands in columns.
                text = page.extract_text(layout=True) or ""
                lines = [ln for ln in text.splitlines() if ln.strip()]
                if not lines:
                    continue
                import re

                ws = wb.create_sheet(title=f"Page {page_no} (text)"[:31])
                for r, line in enumerate(lines, start=1):
                    for c, part in enumerate(re.split(r"\s{2,}", line.strip()), start=1):
                        ws.cell(row=r, column=c, value=_clean(part))
                _autosize(ws, get_column_letter)

    if not wb.sheetnames:
        ws = wb.create_sheet(title="Sheet1")
        ws["A1"] = "No text or tables could be extracted from this PDF (it may be a scanned image)."
    wb.save(dst)
    return {"tables": tables_found, "sheets": len(wb.sheetnames)}


def to_powerpoint(src, dst, opts):
    import io

    import pymupdf
    from pptx import Presentation
    from pptx.util import Emu

    dpi = int(opts.get("dpi", 150))
    doc = pymupdf.open(src)
    try:
        if doc.page_count == 0:
            raise ValueError("PDF has no pages")
        first = doc[0].rect
        prs = Presentation()
        # 1pt = 12700 EMU; size the deck to the first page's aspect ratio.
        prs.slide_width = Emu(int(first.width * 12700))
        prs.slide_height = Emu(int(first.height * 12700))
        blank = prs.slide_layouts[6]
        for page in doc:
            pix = page.get_pixmap(dpi=dpi)
            slide = prs.slides.add_slide(blank)
            slide.shapes.add_picture(io.BytesIO(pix.tobytes("png")), 0, 0, prs.slide_width, prs.slide_height)
            text = page.get_text().strip()
            if text:
                slide.notes_slide.notes_text_frame.text = text[:5000]
        prs.save(dst)
        return {"slides": doc.page_count}
    finally:
        doc.close()


def _clean(value):
    if value is None:
        return None
    value = str(value).replace("\x00", "").strip()
    # openpyxl rejects control characters
    return "".join(ch for ch in value if ch in "\t\n" or ord(ch) >= 32) or None


def _autosize(ws, get_column_letter):
    widths = {}
    for row in ws.iter_rows():
        for cell in row:
            if cell.value is not None:
                longest = max(len(part) for part in str(cell.value).split("\n"))
                widths[cell.column] = max(widths.get(cell.column, 0), longest)
    for col, width in widths.items():
        ws.column_dimensions[get_column_letter(col)].width = min(60, max(8, width + 2))


MODES = {"word": to_word, "excel": to_excel, "powerpoint": to_powerpoint}

if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] not in MODES:
        sys.stderr.write("usage: pdf_convert.py <word|excel|powerpoint> <input.pdf> <output> [options-json]\n")
        sys.exit(2)
    mode, src, dst = sys.argv[1:4]
    options = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
    try:
        info = MODES[mode](src, dst, options)
    except Exception as exc:  # noqa: BLE001 - report any failure to the Node caller
        msg = str(exc) or exc.__class__.__name__
        if "password" in msg.lower() or "encrypted" in msg.lower():
            msg = "This PDF is password-protected. Please remove the password and try again."
        sys.stderr.write(msg[:500] + "\n")
        sys.exit(1)
    print(json.dumps({"ok": True, **(info or {})}))
