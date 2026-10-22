# Use cases

Runnable examples of `protonlite`, each a small, self-contained script. They are
also how the library is smoke-tested against a real account.

## Setup

Sign in once (this saves a session file; `protonlite` never takes a password
again afterward):

```bash
protonlite login --user you@proton.me
```

`protonlite login` is the helper for the whole first-run flow: it asks for the
password without echoing it, walks you through Proton's human-verification page
(captcha) when Proton asks for one, and prompts for your 2FA code if the account
has two-factor enabled. The examples below never see the password -- they reuse
the saved session.

Then point the examples at that session and run any of them:

```bash
export PROTONLITE_SESSION=~/you@proton.me.json
python use_cases/01_inbox_triage.py
```

Every example uses `ProtonMail.from_session()`, which reads `PROTONLITE_SESSION`.

## What each one shows

| Script | Use case | Touches the account? |
|---|---|---|
| `01_inbox_triage.py` | list unread mail, newest first | read-only |
| `02_search_and_read.py` | find a message and read it decrypted | read-only |
| `03_send_to_self.py` | send an email, then clean up both copies | sends, then trashes |
| `04_calendar_event.py` | show the agenda; add and cancel a demo event | creates + cancels |
| `05_manage_contacts.py` | add, look up and delete a demo contact | creates + deletes |
| `06_drive_backup.py` | upload a file, download it back, delete it | creates + deletes |
| `07_share_a_file.py` | make a public link for a file, then revoke it | creates + revokes |

The write examples use clearly-named `protonlite demo ...` items and clean up
after themselves, so they are safe to run on a real account. Still, prefer a
test account.
