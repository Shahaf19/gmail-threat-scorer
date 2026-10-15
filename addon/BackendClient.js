/**
 * Sends the request to our backend with the user's Google identity token.
 * Throws on any failure so the caller shows the error card.
 * @param {Object} analysisRequest
 * @return {{score: number, verdict: string, findings: Object[]}}
 */
function requestAnalysis(analysisRequest) {
  const response = UrlFetchApp.fetch(BACKEND_URL + ANALYZE_PATH, {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(analysisRequest),
    headers: { Authorization: 'Bearer ' + ScriptApp.getIdentityToken() },
    // Error statuses come back as values instead of exceptions, so we choose what gets logged.
    muteHttpExceptions: true,
    // A redirect would carry the identity token to whatever address it points at.
    followRedirects: false,
  });
  if (response.getResponseCode() !== HTTP_OK) {
    throw new Error('Backend returned HTTP ' + response.getResponseCode());
  }
  return parseAnalysisResult(response.getContentText());
}

/** Even our own backend's reply is checked before anything is drawn from it. */
function parseAnalysisResult(json) {
  const result = JSON.parse(json);
  const isValid =
    Number.isInteger(result.score) &&
    result.score >= 0 &&
    result.score <= MAX_SCORE &&
    Object.prototype.hasOwnProperty.call(VERDICT_STYLES, result.verdict) &&
    Array.isArray(result.findings);
  if (!isValid) {
    throw new Error('Unexpected response from backend');
  }
  return result;
}
