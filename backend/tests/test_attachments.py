from app.analyzers.attachments import (
    ATTACHMENT_DISGUISED_PROGRAM,
    ATTACHMENT_DOUBLE_EXTENSION,
    ATTACHMENT_EXECUTABLE,
    ATTACHMENT_REVERSED_NAME,
    AttachmentAnalyzer,
)
from tests.helpers import attachment, email_with


def ids_for(*files) -> set[str]:
    return {d.finding_id for d in AttachmentAnalyzer().analyze(email_with(attachments=list(files)))}


def test_program_disguised_as_a_document_is_flagged() -> None:
    assert ids_for(attachment("invoice.pdf.exe")) == {ATTACHMENT_EXECUTABLE, ATTACHMENT_DOUBLE_EXTENSION}


def test_program_with_a_harmless_name_is_caught_by_its_first_bytes() -> None:
    assert ids_for(attachment("report.pdf", magic_hex="4d5a9000")) == {ATTACHMENT_DISGUISED_PROGRAM}


def test_reversed_display_trick_is_flagged() -> None:
    assert ATTACHMENT_REVERSED_NAME in ids_for(attachment("invoice‮fdp.exe"))


def test_ordinary_documents_are_clean() -> None:
    assert ids_for(attachment("report.pdf", magic_hex="25504446"), attachment("photo.jpg")) == set()
