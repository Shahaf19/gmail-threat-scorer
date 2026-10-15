"""Builds the list of analyzers the service runs."""

import logging
import os

from app.analyzers.attachments import AttachmentAnalyzer
from app.analyzers.base import Analyzer
from app.analyzers.baseline import BaselineDeviationAnalyzer
from app.analyzers.display_name import DisplayNameAnalyzer
from app.analyzers.domain_age import DomainAgeAnalyzer
from app.analyzers.known_bad import KnownBadAnalyzer
from app.analyzers.language import SensitiveInfoRequestAnalyzer, UrgentLanguageAnalyzer
from app.analyzers.links import LinkAnalyzer
from app.analyzers.lookalike_domain import LookalikeDomainAnalyzer
from app.analyzers.message_structure import MessageStructureAnalyzer
from app.analyzers.reply_to import ReplyToMismatchAnalyzer
from app.analyzers.sender_auth import SenderAuthenticationAnalyzer
from app.data.brands import BRANDS
from app.data.top_sites import load_top_sites
from app.enrichment.abusech import AbuseChClient
from app.enrichment.rdap import RdapClient

logger = logging.getLogger(__name__)

# Provided by Cloud Run from Secret Manager; never stored in the repository or the image.
ABUSECH_KEY_VARIABLE = "ABUSECH_AUTH_KEY"


def build_analyzers() -> list[Analyzer]:
    lookalike = LookalikeDomainAnalyzer(load_top_sites(), BRANDS)
    analyzers: list[Analyzer] = [
        SenderAuthenticationAnalyzer(),
        ReplyToMismatchAnalyzer(),
        DisplayNameAnalyzer(BRANDS),
        lookalike,
        LinkAnalyzer(BRANDS),
        UrgentLanguageAnalyzer(),
        SensitiveInfoRequestAnalyzer(),
        AttachmentAnalyzer(),
        MessageStructureAnalyzer(),
        BaselineDeviationAnalyzer(),
        DomainAgeAnalyzer(RdapClient(), lookalike.known_domains),
    ]
    auth_key = os.environ.get(ABUSECH_KEY_VARIABLE, "").strip()
    if auth_key:
        analyzers.append(KnownBadAnalyzer(AbuseChClient(auth_key), lookalike.known_domains))
    else:
        logger.warning("%s is not set: known-threat lookups are disabled", ABUSECH_KEY_VARIABLE)
    return analyzers
