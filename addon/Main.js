/**
 * Contextual trigger: Gmail calls this every time the user opens an email.
 * @param {Object} e Event from Gmail, carrying a short-lived access token for the open message only.
 * @return {CardService.Card[]}
 */
function onGmailMessageOpen(e) {
  try {
    const message = getOpenMessage(e);
    const result = requestAnalysis(buildAnalysisRequest(message));
    return [buildResultCard(result)];
  } catch (error) {
    // Log only our own error text, never email content: logs are kept and read by people.
    console.error('Analysis failed: ' + error.message);
    return [buildErrorCard()];
  }
}

function getOpenMessage(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}
