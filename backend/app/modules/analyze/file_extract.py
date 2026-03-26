from io import BytesIO
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional at runtime in some environments
    PdfReader = None


def extract_text_from_file(filename: str, file_bytes: bytes) -> str:
    suffix = Path(filename).suffix.lower()

    if suffix in {".txt", ".log", ".sql", ".csv", ".json"}:
        return file_bytes.decode("utf-8", errors="ignore")

    if suffix == ".docx":
        return _extract_docx_text(file_bytes)

    if suffix == ".pdf":
        return _extract_pdf_text(file_bytes)

    return file_bytes.decode("utf-8", errors="ignore")


def _extract_docx_text(file_bytes: bytes) -> str:
    try:
        with ZipFile(BytesIO(file_bytes)) as archive:
            raw = archive.read("word/document.xml")
    except Exception:
        return ""

    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    root = ET.fromstring(raw)
    paragraphs: list[str] = []

    for paragraph in root.findall(".//w:p", ns):
        runs = paragraph.findall(".//w:t", ns)
        text = "".join((run.text or "") for run in runs).strip()
        if text:
            paragraphs.append(text)

    return "\n".join(paragraphs)


def _extract_pdf_text(file_bytes: bytes) -> str:
    if PdfReader is None:
        return ""

    try:
        reader = PdfReader(BytesIO(file_bytes))
    except Exception:
        return ""

    pages: list[str] = []
    for page in reader.pages:
        pages.append(page.extract_text() or "")

    return "\n".join(pages)
