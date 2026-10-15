const VERDICT_STYLES = {
  // Deliberately not "Safe": finding no evidence is not proof that an email is harmless.
  safe: {
    label: '✅ No warning signs found',
    advice: 'Not a guarantee: stay careful with unexpected requests for money or passwords.',
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

const VISIBLE_FINDINGS = 3;

const HTML_ESCAPES ={ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function buildResultCard(result) {
  const style = VERDICT_STYLES[result.verdict];
  const adviceSection = CardService.newCardSection()
    .setHeader('What to do')
    .addWidget(CardService.newTextParagraph().setText(style.advice));

  return newAddonCard()
    .addSection(buildVerdictSection(result, style))
    .addSection(buildFindingsSection(result.findings))
    .addSection(adviceSection)
    .addSection(buildFeedbackSection(result))
    .build();
}

function buildVerdictSection(result, style) {
  const section = CardService.newCardSection().addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText('<b>' + style.label + '</b>')
      .setBottomLabel(scoreBar(result.score) + '  ' + result.score + ' / ' + MAX_SCORE)
  );
  if (result.skipped_checks.length > 0) {
    const skipped = result.skipped_checks.map(escapeHtml).join(', ');
    section.addWidget(
      CardService.newTextParagraph().setText(
        "⚠️ Some checks couldn't run (" + skipped + '), so this verdict may be incomplete.'
      )
    );
  }
  return section;
}

// Findings arrive ranked highest-points first; the strongest reasons stay visible.
function buildFindingsSection(findings) {
  const section = CardService.newCardSection().setHeader('Why');
  if (findings.length === 0) {
    return section.addWidget(CardService.newTextParagraph().setText('None of the checks found anything.'));
  }
  findings.forEach((finding) => {
    section.addWidget(
      CardService.newTextParagraph().setText(
        '<b>+' + escapeHtml(finding.points) + ' · ' + escapeHtml(finding.title) + '</b><br>' +
          escapeHtml(finding.detail)
      )
    );
  });
  if (findings.length > VISIBLE_FINDINGS) {
    section.setCollapsible(true).setNumUncollapsibleWidgets(VISIBLE_FINDINGS);
  }
  return section;
}

function scoreBar(score) {
  const filled = Math.round((score / MAX_SCORE) * SCORE_BAR_SEGMENTS);
  return '█'.repeat(filled) + '░'.repeat(SCORE_BAR_SEGMENTS - filled);
}

// Feedback carries only the verdict, score and finding ids (never email content): the backend logs it
// as labeled examples. Action parameters must be strings.
function buildFeedbackSection(result) {
  const parameters = {
    verdict: result.verdict,
    score: String(result.score),
    finding_ids: result.findings.map((finding) => finding.id).join(','),
  };
  const feedbackAction = (rating) =>
    CardService.newAction().setFunctionName('onFeedback').setParameters(Object.assign({ rating: rating }, parameters));
  return CardService.newCardSection()
    .setHeader('Was this verdict right?')
    .addWidget(
      CardService.newButtonSet()
        .addButton(CardService.newTextButton().setText('👍 Right').setOnClickAction(feedbackAction('right')))
        .addButton(CardService.newTextButton().setText('👎 Wrong').setOnClickAction(feedbackAction('wrong')))
    );
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
