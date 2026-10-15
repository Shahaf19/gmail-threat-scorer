"""Looks at how the message is built rather than what it says: hidden parts, forms, images in place of text."""

from app.analyzers.base import Detection
from app.parsed_email import ParsedEmail

TRACKING_PIXEL = "tracking_pixel"
HIDDEN_TEXT = "hidden_text"
EMAIL_FORM = "email_form"
IMAGE_ONLY_EMAIL = "image_only_email"
TRUNCATED_EMAIL = "truncated_email"

# Newsletters hide a short preview line on purpose; a long hidden block is padding to dilute the real text.
MIN_HIDDEN_CHARS = 150
# Below this much readable text, an email with images is really "an image with a link".
MIN_VISIBLE_CHARS_WITH_IMAGES = 30


class MessageStructureAnalyzer:
    name = "Message structure check"

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        content = email.content
        found = []
        if content.tracking_pixel_count:
            found.append(
                Detection(
                    TRACKING_PIXEL,
                    "Invisible tracking image",
                    "The email contains a 1-pixel image that tells the sender when and where you opened it.",
                )
            )
        if content.hidden_chars >= MIN_HIDDEN_CHARS:
            found.append(
                Detection(
                    HIDDEN_TEXT,
                    "Hidden text",
                    f"About {content.hidden_chars} characters of text are styled to be invisible; "
                    "attackers use this to pad an email with harmless words.",
                )
            )
        if content.has_form:
            found.append(
                Detection(
                    EMAIL_FORM,
                    "Form inside the email",
                    "The email contains an input form or password field. Legitimate companies link to their website instead.",
                )
            )
        if content.image_count and content.visible_chars < MIN_VISIBLE_CHARS_WITH_IMAGES:
            found.append(
                Detection(
                    IMAGE_ONLY_EMAIL,
                    "Message is mostly an image",
                    "There is almost no readable text; the message may be a picture, which text checks cannot read.",
                )
            )
        if email.request.truncated:
            found.append(
                Detection(
                    TRUNCATED_EMAIL,
                    "Email too large to check fully",
                    "Part of this email was too large to analyze; padding is a known way to hide content.",
                )
            )
        return found
