"""File endings and signatures used to judge attachments."""

# Programs and scripts: opening one runs code.
EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "jar", "msi", "lnk", "reg", "dll", "cpl",
})
# Office files that can carry macros (small programs inside the document).
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"})
# Pages that open in the browser and can imitate a login form, with no link for us to inspect.
WEB_PAGE_EXTENSIONS = frozenset({"html", "htm", "xhtml", "shtml", "svg"})
# Containers that hide what is inside from scanners.
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "iso", "img", "vhd", "cab", "ace"})
# Harmless-looking endings used as decoys in front of a real one ("invoice.pdf.exe").
DECOY_EXTENSIONS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "rtf", "csv"})

# The first bytes of a file, in hex, that mark it as a program whatever its name says.
PROGRAM_SIGNATURES = {
    "4d5a": "a Windows program",
    "7f454c46": "a Linux program",
}
