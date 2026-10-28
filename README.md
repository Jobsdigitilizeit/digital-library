# AI Digital Library System

Four locked portals (Student, Lecturer, Librarian, System Admin) on React + Firebase (Auth, Firestore, Storage) with an Express server for the AI endpoints.

## Run locally

```
npm install
npm run dev        # http://localhost:3001
npm run lint       # type-check
npm run build && npm start
```

Set `GEMINI_API_KEY` in `.env.local` for AI features (they degrade to local fallbacks without it). Firebase web config for `ai-library-dee55` is built in (`src/lib/firebase.ts`); override with `VITE_FIREBASE_*` if needed.

## One-time Firebase setup (required before anyone can sign in)

1. **Authentication → Sign-in method**: enable *Email/Password*. Under *Settings → Authorized domains* add your deployed domain.
2. **Authentication → Templates**: customise the verification and password-reset emails (sender name, subject, language).
3. **Authentication → Settings → Password policy** (optional but recommended): enforce the same rules the app checks (10+ chars, upper, lower, number, symbol).
4. **Firestore Database**: create a database (`(default)`), then deploy the rules:
   `npx firebase-tools deploy --only firestore:rules,storage --project ai-library-dee55`
   Until the rules in `firestore.rules` are deployed, the database is **not** protected by them.
5. **Storage**: enable it (needed for lecturer file uploads; may require the Blaze plan). Lecturers can still attach https links without it.
6. **Create the first administrator** (nobody can self-register as staff):
   Firestore → collection `invites` → document ID = your email in lowercase, fields
   `email` (string, same email), `role` = `admin`, `invitedBy` = `bootstrap`, `invitedByName` = `Bootstrap`, `createdAt` = ISO date string.
   Then open `/login/admin` → *I have an invitation*, register with that email, click the verification link, sign in.
   From then on invite lecturers, librarians and more admins from **Admin → Users & invites**.

## Regulated email domains

* **Students** may only register with `@up.ac.za`, `@uj.ac.za` or `@richfield.ac.za` (subdomains such as `student.uj.ac.za` count).
* **Staff** (lecturers, librarians, admins) need an administrator invitation, and the invited address must be a university domain or one of: gmail.com, outlook.com, hotmail.com, live.com, yahoo.com, icloud.com.
* The first administrator is `monarengmarape4@gmail.com` (built-in; remove `bootstrapAdmin()` from the rules once other admins exist).
* **Duplicates:** the same email is rejected by sign-up, and the same student/staff number is rejected through the `idRegistry` collection (create-only).

The lists live in `src/config/institution.ts` (UI) **and** the `schoolEmail()` / `staffDomain()` regexes in `firestore.rules` (enforcement). Change both together, then publish the rules.

## How the portals are locked

| Layer | What it does |
|---|---|
| Firebase Auth | Passwords, email-verification link, password-reset email. Unverified emails cannot read or write anything. |
| `users/{uid}` | Holds `role` and `status`. A user can never write their own role. They become `student` (school email, verified) or take the role an admin put on an invitation for their exact email. |
| Firestore rules | Every collection is role-checked server-side (see `firestore.rules`). Suspended/removed/pending accounts are denied everywhere. Login and audit logs are append-only. |
| Portal guard | Each portal has its own login page and refuses accounts of another role (and records the attempt). Routes are guarded again by `RequireRole`. |
| Server | `/api/ai/*` needs a valid Firebase ID token from a verified, active user; the role is read from Firestore with that user's token. Rate-limited, `helmet` headers and a strict CSP in production. |
| Session | Ends when the browser closes, after 15 minutes idle, and immediately when an admin suspends the account. |
| Passwords | Regex + checklist: 10–64 chars, upper, lower, number, symbol, no spaces, not common / not your email name. |
| Bots | Human check (arithmetic + honeypot + minimum fill time) and 5-failure lockout. For real bot defence enable **App Check with reCAPTCHA v3**: set `VITE_RECAPTCHA_SITE_KEY` and enforce App Check in the console. |

## Admin: reports, activity, backups

* **Overview**: registered users, online now, logins today, active loans, and charts (logins/day, users by role, registrations/week, logins by hour, catalogue by category).
* **Users & invites**: search, change role, suspend, restore, remove, invite staff.
* **Login activity**: every sign-in, sign-out and blocked attempt, plus an audit trail of staff actions.
* **Reports**: CSV exports (users, sign-ins, loans, catalogue, audit).
* **Database backup**: one-click JSON export of every collection, restore for catalogue/loans/courses/materials/enrolments/invitations, and a history. User accounts live in Firebase Auth and are not restored from a file. For full disaster recovery also enable scheduled backups: `gcloud firestore backups schedules create --database='(default)' --recurrence=daily --retention=14d`.

## Known limits

* "Remove user" blocks all access and signs them out but keeps the Firebase Auth record (deleting Auth accounts needs the Admin SDK with a service account, which this project deliberately doesn't ship).
* Material release times are enforced in the app, not by the database rules.
* Admin charts use the latest 500 sign-in events.
