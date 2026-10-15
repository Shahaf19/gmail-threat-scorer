"""Hard input limits for POST /analyze.

The add-on trims every free-text field to these same caps (and sets `truncated`) before
sending, so a request that still exceeds them did not come from our add-on and is rejected.
"""

MAX_HEADERS_CHARS = 100_000
MAX_SUBJECT_CHARS = 2_000
MAX_BODY_CHARS = 200_000
MAX_ATTACHMENTS = 50
MAX_FILENAME_CHARS = 1_000
MAX_MIME_TYPE_CHARS = 255

# Worst case for ~500K capped characters: 4 UTF-8 bytes each, plus JSON escaping (up to
# 6 bytes for a control character). 4 MiB covers that with headroom for attachment metadata.
MAX_REQUEST_BYTES = 4 * 1024 * 1024
