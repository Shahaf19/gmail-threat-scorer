/**
 * Demo kit: sends a handful of crafted emails to YOUR OWN inbox so the add-on has something to show.
 * Run `sendDemoEmails` once from the Apps Script editor. It only ever mails the signed-in user.
 *
 * This is a separate project from the add-on on purpose: sending mail needs its own permission,
 * and the add-on itself must stay read-only.
 */
const SUBJECT_PREFIX = '[Threat Scorer demo] ';
// Cyrillic "р" and "а" inside "paypal.com" (punycode form). Nobody can register it, so the link is harmless.
const LOOKALIKE_LINK = 'https://xn--ypal-43d9g.com/login';
// A domain that is not registered, so a reply or click goes nowhere.
const UNREGISTERED_DOMAIN = 'paypal-verify-demo.com';
// A one-pixel image that is harmless to load.
const PIXEL_URL = 'https://www.gstatic.com/images/branding/product/1x/gmail_48dp.png';
const HIDDEN_FILLER_CHARS = 200;
const MZ_PROGRAM_START = [77, 90, 0, 0, 0, 0, 0, 0]; // "MZ": the first bytes of a Windows program

function sendDemoEmails() {
  const me = Session.getActiveUser().getEmail();
  buildDemoEmails().forEach((demo) => {
    try {
      MailApp.sendEmail(Object.assign({ to: me }, demo.message, { subject: SUBJECT_PREFIX + demo.subject }));
      console.log('Sent: ' + demo.subject);
    } catch (error) {
      // Gmail refuses some attachments outright; say so and carry on with the rest.
      console.error('Not sent (' + demo.subject + '): ' + error.message);
    }
  });
}

function buildDemoEmails() {
  return [
    {
      subject: '1. Control: a normal email (expect Safe, 0)',
      message: { body: 'Hi, are we still on for lunch tomorrow at noon? Let me know.' },
    },
    {
      subject: '2. Classic phishing (expect Malicious)',
      message: {
        name: 'PayPal Security',
        body: 'FINAL NOTICE: your account will be suspended. Act now and reply with your password.',
        htmlBody:
          '<p><b>FINAL NOTICE:</b> your account will be suspended. Act now and reply with your password.</p>' +
          '<p><a href="' + LOOKALIKE_LINK + '">https://paypal.com/login</a></p>',
      },
    },
    {
      subject: '3. Replies go elsewhere (expect Suspicious)',
      message: {
        name: 'Accounts Team',
        replyTo: 'refunds@' + UNREGISTERED_DOMAIN,
        body: 'Please see the updated invoice details in the portal.',
      },
    },
    {
      subject: '4. Deceptive links (expect Malicious)',
      message: {
        body: 'Open your documents.',
        htmlBody:
          '<p><a href="https://paypal.com@login-demo.example/">paypal.com</a></p>' +
          '<p><a href="http://203.0.113.7/login">Sign in</a></p>' +
          '<p><a href="javascript:void(0)">View document</a></p>',
      },
    },
    {
      subject: '5. Risky attachments (expect Suspicious)',
      message: {
        body: 'Statement attached.',
        attachments: [
          Utilities.newBlob('demo', 'application/vnd.ms-excel.sheet.macroEnabled.12', 'statement.xlsm'),
          Utilities.newBlob('<html><body>demo</body></html>', 'text/html', 'secure-login.html'),
        ],
      },
    },
    {
      subject: '6. Program disguised as a PDF (expect Suspicious)',
      message: {
        body: 'Receipt attached.',
        attachments: [Utilities.newBlob(MZ_PROGRAM_START, 'application/pdf', 'receipt.pdf')],
      },
    },
    {
      subject: '7. Hidden tricks (expect Suspicious)',
      message: {
        body: 'Newsletter.',
        htmlBody:
          '<p>Hello, here is a perfectly ordinary paragraph of readable text for you.</p>' +
          '<img src="' + PIXEL_URL + '" width="1" height="1">' +
          '<div style="display:none">' + 'padding '.repeat(HIDDEN_FILLER_CHARS / 8) + '</div>' +
          '<form><input type="password" name="pw"></form>',
      },
    },
  ];
}
