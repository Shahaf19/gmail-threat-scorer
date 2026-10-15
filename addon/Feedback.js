/**
 * Runs when the user clicks "Right" or "Wrong" on the card. The values come from the card we built,
 * and the backend validates them again before logging anything.
 * @param {Object} e Event from Gmail carrying the button's parameters.
 * @return {CardService.ActionResponse}
 */
function onFeedback(e) {
  const parameters = e.parameters;
  let message = 'Thanks, feedback recorded.';
  try {
    postJson(FEEDBACK_PATH, {
      verdict: parameters.verdict,
      score: Number(parameters.score),
      finding_ids: parameters.finding_ids ? parameters.finding_ids.split(',') : [],
      rating: parameters.rating,
    });
  } catch (error) {
    console.error('Sending feedback failed: ' + error.message);
    message = "Couldn't send feedback.";
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(message))
    .build();
}
