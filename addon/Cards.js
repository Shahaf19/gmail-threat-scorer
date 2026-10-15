const VERDICT_STYLES = {
  safe: {
    label: '✅ Safe',
    advice: 'No action needed. Stay careful with unexpected requests for money or passwords.',
  },
  suspicious: {
    label: '⚠️ Suspicious',
    advice:
      "Don't click links or open attachments until you confirm the sender another way (e.g. call them).",
  },
  malicious: {
    label: '⛔ Malicious',
    advice:
      "Don't click links, open attachments or reply. Report it: Gmail's ⋮ menu → \"Report phishing\".",
  },
};

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function buildResultCard(result) {
  const style = VERDICT_STYLES[result.verdict];
  const verdictSection = CardService.newCardSection().addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText('<b>' + style.label + '</b>')
      .setBottomLabel('Risk score: ' + result.score + ' / ' + MAX_SCORE)
  );
  const adviceSection = CardService.newCardSection()
    .setHeader('What to do')
    .addWidget(CardService.newTextParagraph().setText(style.advice));

  return newAddonCard()
    .addSection(verdictSection)
    .addSection(buildFindingsSection(result.findings))
    .addSection(adviceSection)
    .build();
}

function buildFindingsSection(findings) {
  const section = CardService.newCardSection().setHeader('Why');
  if (findings.length === 0) {
    return section.addWidget(CardService.newTextParagraph().setText('No warning signs found.'));
  }
  findings.forEach((finding) => {
    section.addWidget(
      CardService.newTextParagraph().setText(
        '<b>' + escapeHtml(finding.title) + '</b><br>' + escapeHtml(finding.detail)
      )
    );
  });
  return section;
}

function buildErrorCard() {
  const message =
    "⚠️ <b>Couldn't analyze this email.</b><br>This is not a verdict: treat it with your usual caution.";
  return newAddonCard()
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(message)))
    .build();
}

function newAddonCard() {
  return CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle(ADDON_TITLE));
}

// Card text understands HTML tags. Findings can quote the email (e.g. a sender's name), so
// without escaping, an attacker could inject their own formatting or links into our verdict.
function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}
