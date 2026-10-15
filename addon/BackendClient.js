/**
 * Sends the request to our backend with the user's Google identity token.
 * Throws on any failure so the caller shows the error card.
 * @param {Object} analysisRequest
 * @return {{score: number, verdict: string, findings: Object[]}}
 */
function requestAnalysis(analysisRequest) {
  return parseAnalysisResult(postJson(ANALYZE_PATH, analysisRequest));
}

/** Sends JSON to the backend with the user's identity token; returns the reply text or throws. */
function postJson(path, payload) {
  const response = UrlFetchApp.fetch(BACKEND_URL + path, {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    headers: { Authorization: 'Bearer ' + ScriptApp.getIdentityToken() },
    // Error statuses come back as values instead of exceptions, so we choose what gets logged.
    muteHttpExceptions: true,
    // A redirect would carry the identity token to whatever address it points at.
    followRedirects: false,
  });
  if (response.getResponseCode() !== HTTP_OK) {
    throw new Error('Backend returned HTTP ' + response.getResponseCode());
  }
  return response.getContentText();
}

/** Even our own backend's reply is checked before anything is drawn from it. */
function parseAnalysisResult(json) {
  const result = JSON.parse(json);
  const isValid =
    Number.isInteger(result.score) &&
    result.score >= 0 &&
    result.score <= MAX_SCORE &&
    Object.prototype.hasOwnProperty.call(VERDICT_STYLES, result.verdict) &&
    Array.isArray(result.findings) &&
    Array.isArray(result.skipped_checks);
  if (!isValid) {
    throw new Error('Unexpected response from backend');
  }
  return result;
}
