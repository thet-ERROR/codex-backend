// Preloaded into the server under test (node --require). Replaces the one outbound call the server
// makes — the Mailjet send API — with a file the tests read back, so the verification and password
// reset emails can be followed without a mail account and without anything leaving the machine.
const fs = require('node:fs');

const realFetch = global.fetch;
global.fetch = async (url, options) => {
    if (String(url).startsWith('https://api.mailjet.com/')) {
        const message = JSON.parse(options.body).Messages[0];
        fs.appendFileSync(process.env.MAIL_CAPTURE_FILE, JSON.stringify({
            to: message.To[0].Email, subject: message.Subject, text: message.TextPart,
            html: message.HTMLPart || '', replyTo: message.ReplyTo ? message.ReplyTo.Email : null
        }) + '\n');
        return new Response('{}', { status: 200 });
    }
    // Any other host is a bug in the test setup: nothing else should be called
    throw new Error(`blocked outbound request in tests: ${url}`);
};
void realFetch;
