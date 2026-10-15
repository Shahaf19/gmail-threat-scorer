const ADDON_TITLE = 'Threat Scorer';

// Must match the urlFetchWhitelist entry in appsscript.json.
const BACKEND_URL = 'https://gmail-threat-scorer-581087277333.europe-west1.run.app';
const ANALYZE_PATH = '/analyze';
const HTTP_OK = 200;
const MAX_SCORE = 100;

// Same caps as backend/app/limits.py: trimming here means the backend never has to reject a real email.
const MAX_HEADERS_CHARS = 100000;
const MAX_SUBJECT_CHARS = 2000;
const MAX_BODY_CHARS = 200000;
const MAX_ATTACHMENTS = 50;
const MAX_FILENAME_CHARS = 1000;
const MAX_MIME_TYPE_CHARS = 255;
