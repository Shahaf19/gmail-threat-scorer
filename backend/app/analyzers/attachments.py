"""Judges attachments by name, real type and fingerprint: the file contents never reach us."""

import unicodedata

from app.analyzers.base import Detection
from app.data.file_types import (
    ARCHIVE_EXTENSIONS,
    DECOY_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    MACRO_EXTENSIONS,
    PROGRAM_SIGNATURES,
    WEB_PAGE_EXTENSIONS,
)
from app.parsed_email import ParsedEmail
from app.schemas import AttachmentInfo

ATTACHMENT_EXECUTABLE = "attachment_executable"
ATTACHMENT_MACRO = "attachment_macro_document"
ATTACHMENT_WEB_PAGE = "attachment_web_page"
ATTACHMENT_ARCHIVE = "attachment_archive"
ATTACHMENT_DOUBLE_EXTENSION = "attachment_double_extension"
ATTACHMENT_REVERSED_NAME = "attachment_reversed_name"
ATTACHMENT_DISGUISED_PROGRAM = "attachment_disguised_program"

MAX_SHOWN_NAME_CHARS = 60
FORMAT_CONTROL_CATEGORY = "Cf"


class AttachmentAnalyzer:
    name = "Attachment check"

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        detections: dict[str, Detection] = {}
        for attachment in email.request.attachments:
            for detection in _inspect(attachment):
                detections.setdefault(detection.finding_id, detection)
        return list(detections.values())


def _inspect(attachment: AttachmentInfo) -> list[Detection]:
    found = []
    shown = _shown(attachment.filename)
    if any(_reverses_text(char) for char in attachment.filename):
        found.append(
            Detection(
                ATTACHMENT_REVERSED_NAME,
                "File name with a hidden twist",
                f"The file name {shown} contains an invisible character that flips part of it around, "
                "so it can show a harmless ending while really ending differently.",
            )
        )
    extensions = _extensions(attachment.filename)
    last = extensions[-1] if extensions else ""
    if last in EXECUTABLE_EXTENSIONS:
        found.append(
            Detection(ATTACHMENT_EXECUTABLE, "Attachment that can run code",
                      f"{shown} is a program or script (.{last}); opening it can run code on your computer.")
        )
        if len(extensions) >= 2 and extensions[-2] in DECOY_EXTENSIONS:
            found.append(
                Detection(ATTACHMENT_DOUBLE_EXTENSION, "Program disguised as a document",
                          f"{shown} ends in .{last} but starts out looking like a .{extensions[-2]} file.")
            )
    elif last in MACRO_EXTENSIONS:
        found.append(
            Detection(ATTACHMENT_MACRO, "Document that can run macros",
                      f"{shown} can contain macros (small programs) that run when you enable editing.")
        )
    elif last in WEB_PAGE_EXTENSIONS:
        found.append(
            Detection(ATTACHMENT_WEB_PAGE, "Web page as an attachment",
                      f"{shown} opens as a web page and can imitate a login form without any link to inspect.")
        )
    elif last in ARCHIVE_EXTENSIONS:
        found.append(
            Detection(ATTACHMENT_ARCHIVE, "Compressed archive",
                      f"{shown} is an archive; attackers use them to hide what is inside from scanners.")
        )
    program = _program_signature(attachment.magic_hex)
    if program and last not in EXECUTABLE_EXTENSIONS:
        found.append(
            Detection(ATTACHMENT_DISGUISED_PROGRAM, "File is not what its name says",
                      f"{shown} is named like a .{last or 'plain'} file, but its contents are {program}.")
        )
    return found


def _extensions(filename: str) -> list[str]:
    # Windows ignores trailing dots and spaces, so "invoice.exe " still runs as .exe.
    visible = "".join(char for char in filename if unicodedata.category(char) != FORMAT_CONTROL_CATEGORY)
    return visible.strip().rstrip(". ").lower().split(".")[1:]


def _reverses_text(char: str) -> bool:
    # Bidirectional overrides (U+202A-202E) and isolates (U+2066-2069).
    return "‪" <= char <= "‮" or "⁦" <= char <= "⁩"


def _program_signature(magic_hex: str) -> str | None:
    for signature, kind in PROGRAM_SIGNATURES.items():
        if magic_hex.startswith(signature):
            return kind
    return None


def _shown(filename: str) -> str:
    cleaned = "".join(char for char in filename if unicodedata.category(char) != FORMAT_CONTROL_CATEGORY)
    return cleaned if len(cleaned) <= MAX_SHOWN_NAME_CHARS else cleaned[:MAX_SHOWN_NAME_CHARS] + "..."
