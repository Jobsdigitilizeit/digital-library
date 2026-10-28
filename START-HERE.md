# Running AI Digital Library on your PC

## 1. Install Node.js (once)
Download the **LTS** version from https://nodejs.org and install it. Accept the defaults.

## 2. Start the system
Double-click **start.bat** (Windows). The first run installs everything, which takes a few minutes and needs internet.
Keep the black window open while you use the system. Close it to stop.

Other systems: open a terminal in this folder and run `npm install` then `npm run dev`.

## 3. Open it
Go to **http://localhost:3001**

Always use the word `localhost`. Do **not** use `127.0.0.1` or an IP address like `192.168.x.x`: the emailed sign-in links are only approved for `localhost` and will fail from other addresses. (The app redirects `127.0.0.1` to `localhost` for you.)

## 4. Signing in

1. Register, then click the **verification link** Firebase emails you (check **Spam**). Keep the registration page open: it signs you in automatically a few seconds after you click the link, even if you opened the email on your phone.
2. Every sign-in then asks for a **6-digit code** that is emailed to you. Type it in. It expires after 10 minutes.

### Setting up the code emails (whoever runs the system must do this once)
**Easiest:** double-click **setup-email.bat**, type the Gmail address and its App Password, then start the system again. The steps below do the same by hand.

Open the file `.env.local` in this folder and add the details of an email account that can send mail. Gmail example (turn on 2-Step Verification, then create an App Password at myaccount.google.com/apppasswords):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=your-address@gmail.com
SMTP_PASS=the-16-character-app-password
MAIL_FROM="AI Digital Library" <your-address@gmail.com>
```

Then restart start.bat. Gmail allows roughly 500 messages a day. Other providers (Brevo, Resend) work the same way with their own SMTP details.

**Just testing on one PC?** Add `OTP_DEV_CONSOLE=true` to `.env.local` instead. The code is then printed in the black window instead of being emailed.

**With neither**, the system falls back to Firebase's own sign-in link, which Firebase's free plan limits to **5 emails a day for everyone**. That is where the "daily limit" message comes from.

## Common problems

| What you see | Fix |
|---|---|
| "The sign-in email cannot be sent from this web address" | You opened the app from an address other than `localhost`. Use `http://localhost:3001`. |
| Console shows `ERR_QUIC_PROTOCOL_ERROR` for Firestore | Your network or antivirus blocks that protocol. The app now falls back automatically. Reload the page. If it persists, try another network. |
| No email arrives | Check Spam. Wait for the 60 second countdown and use Resend. Firebase limits how many emails one address can get per hour. |
| "Too many attempts" | Wait 10 to 15 minutes. |
| Page loads but sign-in says it cannot set up your account | The Firestore security rules in `firestore.rules` have not been published in the Firebase console. See README.md. |
| "Port 24678 is already in use" in the black window | Harmless. It only affects live reload. |

## Using your own Firebase project
This copy is configured for the project `ai-library-dee55`. To use your own, follow **README.md** (Firebase setup), then put your web config in `src/lib/firebase.ts` or in `.env.local` as `VITE_FIREBASE_*` values. In your project you must also enable **Email/Password** with **Email link (passwordless sign-in)**, create **Firestore**, publish `firestore.rules`, and keep `localhost` in **Authentication > Settings > Authorized domains**.

## AI features
AI search, study plans and the course builder use Google Gemini. Put your key in `.env.local` as `GEMINI_API_KEY=your-key`. Without a key the AI features show simple built-in results instead.
