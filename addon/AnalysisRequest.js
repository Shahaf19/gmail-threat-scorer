/**
 * Builds the POST /analyze body. Sends only what the backend analyzes: attachment
 * contents never leave Google, only their name, type, size and SHA-256 fingerprint.
 * @param {GmailApp.GmailMessage} message
 * @return {Object}
 */
function buildAnalysisRequest(message) {
  const headers = fitTo(extractHeaderBlock(message.getRawContent()), MAX_HEADERS_CHARS);
  const subject = fitTo(message.getSubject(), MAX_SUBJECT_CHARS);
  const bodyText = fitTo(message.getPlainBody(), MAX_BODY_CHARS);
  const bodyHtml = fitTo(message.getBody(), MAX_BODY_CHARS);
  const allAttachments = message.getAttachments();

  return {
    headers: headers.text,
    subject: subject.text,
    body_text: bodyText.text,
    body_html: bodyHtml.text,
    truncated:
      [headers, subject, bodyText, bodyHtml].some((field) => field.truncated) ||
      allAttachments.length > MAX_ATTACHMENTS,
    attachments: allAttachments.slice(0, MAX_ATTACHMENTS).map(describeAttachment),
    sender_history: readSenderHistory(message),
  };
}

/** The raw message is headers, a blank line, then the body; we keep only the headers. */
function extractHeaderBlock(rawContent) {
  const blankLineIndex = rawContent.search(/\r?\n\r?\n/);
  return blankLineIndex === -1 ? rawContent : rawContent.slice(0, blankLineIndex);
}

function fitTo(text, maxChars) {
  if (text.length <= maxChars) {
    return { text: text, truncated: false };
  }
  return { text: text.slice(0, maxChars), truncated: true };
}

function describeAttachment(attachment) {
  const bytes = attachment.getBytes();
  return {
    filename: keepEnd(attachment.getName(), MAX_FILENAME_CHARS),
    mime_type: fitTo(attachment.getContentType(), MAX_MIME_TYPE_CHARS).text,
    size_bytes: attachment.getSize(),
    sha256: sha256Hex(bytes),
    // The first bytes reveal what a file really is (e.g. "4d5a" = a Windows program), whatever its name says.
    magic_hex: toHex(bytes.slice(0, MAGIC_BYTES)),
  };
}

// The real extension sits at the end of a name ("invoice.pdf<padding>.exe"), so an
// over-long name is trimmed from the front, never from the back.
function keepEnd(text, maxChars) {
  return text.length <= maxChars ? text : text.slice(-maxChars);
}

function sha256Hex(bytes) {
  return toHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes));
}

function toHex(bytes) {
  // Apps Script bytes are signed (-128..127); masking maps them to 0..255 before hex encoding.
  return bytes.map((byte) => (byte & 0xff).toString(16).padStart(2, '0')).join('');
}
