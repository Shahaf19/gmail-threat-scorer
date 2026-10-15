"""Records the user's verdict on a verdict. Today it goes to the log: the seed of labeled data for a future model."""

import json
import logging

from app.schemas import FeedbackRequest

logger = logging.getLogger(__name__)


def record_feedback(feedback: FeedbackRequest) -> None:
    # Every field is validated (fixed words, a number, ids limited to [a-z0-9_]), so nothing the caller
    # sent can add lines to the log or smuggle in message content.
    logger.info("feedback %s", json.dumps(feedback.model_dump(), sort_keys=True))
