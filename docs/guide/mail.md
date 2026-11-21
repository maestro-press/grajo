---
title: Mail
---

# Mail

Crow can hold your IMAP mailboxes in its own database and give you one reader for all of them in
Crow's Nest: one inbox across accounts, folders and labels, an open message with its whole
conversation, search, older mail fetched on demand, attachments, remote images on your terms, and the
usual actions on a message — read, unread, archive, delete and move. It is built for a phone first —
one column, every tap target big enough for a thumb — and it works the same on a desktop.

Your mail stays on your instance. The mail tables are local-only: they are never replicated to a
paired Crow, never put in a peer's outbox and never shared with a project. Each address is connected
on **one** instance; another Crow that sees the same address connected says "Mail is set up on
&lt;instance&gt;" instead of connecting it a second time.

## Turn it on

Mail is behind a flag:

```bash
CROW_MAIL=1
```

With it set, **Mail** appears in Crow's Nest under **More of Crow**. Nothing dials out until you
connect an account. With it unset, every Mail page and route answers "not found".

## Connect an account

The first time you open **Mail** with no account connected, the page offers **Connect your mail**. That
opens the settings page (`/dashboard/mail?view=settings`), where the add-account form lives. Fill in:

- a **label** you will recognise in the account chips (anything you like);
- the **address**;
- the **password** — for a provider that wants an app password, create one and paste that;
- the **IMAP** host, port and security (`ssl` or `starttls`), and the same for **SMTP**.

Only one Crow holds an address: if another of your instances already has it, the settings page names
that instance, and connecting the same address here is refused. A different address connects normally.

An account that cannot sign in shows "Sign-in failed. Update the password." with an **Update
password** button. The rest of the accounts keep working.

### Adding an account from a terminal

The same add exists as a command, for a box you reach over ssh and would rather not open a browser on:

```bash
# a file only you can read, holding the password and the address
(umask 077 && cat > ~/.crow-mail.env <<'EOF'
IMAP_PASSWORD='your app password'
MAIL_ADDRESS='alex@example.com'
EOF
)

node scripts/cli/mail-add.js \
  --label Personal --address-key MAIL_ADDRESS \
  --password-env-file ~/.crow-mail.env --password-key IMAP_PASSWORD \
  --imap imap.example.com:993:ssl --smtp smtp.example.com:465:ssl

# once the account is added, the password lives in Crow's keychain — the file need not
rm ~/.crow-mail.env
```

The env file is `KEY=VALUE` per line, and it is worth knowing exactly how it is read: `#` starts a
line; an inline `#` is part of an **unquoted** value, so a password may contain one; a value in
matching `'…'` or `"…"` quotes is taken exactly as written (`' lead '` keeps its spaces), and anything
after a closing quote that starts with `#`, with or without spaces, is a comment; an unquoted value is
trimmed of leading and trailing whitespace; nothing is escaped, so `\n` in that file is a backslash
and an `n`, not a newline. A file that is readable by other users on the box
gets a one-line warning — use the `umask 077` above.

The steps are the form's steps: the address is refused if it is already connected here or on another
of your instances, the password is checked against the mail server before anything is stored, and a
failure part-way removes what it wrote. That check is an **IMAP** connect and folder listing — the
SMTP host and port are stored for sending and are not dialled when an account is added, so an SMTP
problem does not fail the add. The password is never taken on the command line — use the env file
above, or `--password-stdin` with the password piped in (on a terminal it refuses, because it would
echo) — and it is never printed. `--dry-run` connects and stops, storing nothing.

The command writes to the instance the shell resolves, which is why it prints that instance's
`CROW_HOME` and `crow.db` path first — run it as the user whose `CROW_HOME` the gateway uses. It
refuses (`2`) instead of creating anything when that instance has no `crow.db` yet, or no usable
keychain key (missing, empty or damaged all count): an account in a fresh empty database would be
invisible to Mail, and a key minted by the command would make every password the gateway sealed under
its own key unreadable. Let the gateway create both
(start it, and seal one secret in Crow's Nest), then re-run.

Two things to know:

- With `CROW_MAIL` unset **in this shell** the command refuses, because it cannot tell whether the
gateway has the flag. The flag usually lives in the gateway's systemd unit rather than your shell, so
if Mail works in Crow's Nest, re-run with `CROW_MAIL=1` in front; `--force-flag-off` adds the account
anyway and says that the gateway will not sync it.
- The sync supervisor reads the accounts when it starts, so **restart the gateway** after adding one.

Exit codes: `0` added, `2` usage (a bad flag, the flag is off, or this shell is not the gateway's
instance), `3` refused (already connected), `4` failed and undone, `5` the mail server refused the
sign-in — in which case the password is wrong or an app password is needed, `78` the gateway's own
instance-path check refused this shell's `CROW_HOME` layout (the refusal the gateway makes at boot).

## The inbox

The inbox opens on **All**: the newest mail from every account in one list. The chips above the list
narrow it to a single account, and each row shows:

- an unread dot, or none for a message you have read;
- the sender's name (or their address, or "Unknown sender");
- the subject, or "(no subject)";
- the first line of the message;
- the time — the clock time if it arrived today, otherwise the day, and the year once it is a
  different year.

A page holds thirty messages; **Load more** brings the next thirty. **Refresh** asks each account's
server for new mail, and pulling the list down from its top does the same thing.

## Folders and labels

**Folders** opens a drawer per account, with the unread count beside each folder. Gmail labels are
folders here too, so your labels are as reachable as your inbox. The provider's own virtual views
(Gmail's "All Mail", "Flagged" and "Important") are not listed, because Crow does not keep a copy of
them.

A message that Gmail files in the inbox and in a label is one message here: it shows once, as the
inbox copy, however many labels it carries.

## Reading a message

Tap any row to open the message: subject, sender, a **to** line you can expand for the To and Cc
recipients, and the full date. Under the header is the whole conversation, oldest first; the newest
message and the one you tapped are open, the rest are collapsed until you open them. A collapsed
message loads nothing, so a thread of two hundred messages stays quick.

The message text renders in its own frame, with Crow's styling around it and no scripts from the mail
running anywhere.

## Images

Remote images in mail are **blocked** by default, so a sender learns nothing about when you opened
their message. When a message holds blocked images you get a banner with two choices:

- **Show images** — for this view only. Nothing is stored, and the next time you open the message the
  images are blocked again.
- **Always show from &lt;sender&gt;** — remembered for that sender on that account, until you remove it
  on the settings page, where every allowed sender has its own **Remove** button.

Two limits are worth knowing:

- **"Always show from &lt;sender&gt;" keys on the From address, which anyone can forge.** A sender can
  claim to be someone you have allowed, so only allow senders you would trust to be who they say they
  are.
- **Images declared 2 px or smaller on either side are removed** as tracking pixels, even when images
  are shown. A tracking pixel that declares no size at all is not recognised by that rule, so it can
  still load when you show images — blocking images, the default, is what stops every one of them.

## Search

The box at the top of the list searches the mail Crow has stored. Hits look like the inbox rows and
open the same way.

Crow keeps the last 90 days of each folder, plus whatever you have brought back by asking for older
mail. For everything else, **Search older mail on the server** asks each account's mail server and
tells you how many more it found; those messages are stored and searchable from then on.

## Older mail

At the end of a list, **Look further back** asks the server for mail older than anything Crow holds in
those folders, and adds what it finds. When there is nothing older left, it says so.

## Attachments

A message with attachments lists each one with its name and size and a **Download** link. The file is
fetched from the mail server at the moment you ask for it, not kept in Crow. That link is a plain
download, so anything over about 18 MB comes back as a failed download carrying the message "This
attachment is over about 18 MB, too large to download here."

## Acting on a message

An open message carries its own controls in the header, and each one acts on the copy you opened: a
message opened from a label is archived or moved from that label, not from the inbox.

- **Mark unread** puts the message back to unread. It appears on a message you have already read.
- **Archive** moves the message to the account's Archive folder or, on a mailbox that keeps an "All
  Mail" folder in its place, to that folder. It is not offered when the account has neither, or when
  the message is already there.
- **Delete** moves the message to Trash. Crow never erases mail from the server, and the control is
  not offered on a message that is already in Trash or on an account with no Trash folder.
- **Move…** opens a list of the account's other folders; choose one and press **Move**.

After Archive, Delete or Move the reader goes back to the list you came from, where the message has
left the folder you were reading. One action runs at a time, so a double tap cannot send the same
change twice.

Opening an unread message marks it read 1.5 seconds after the page is shown, and only while the page
is visible at that moment — leaving the page before then marks nothing read. The page itself only
reads; the mark-read is the reader's own separate request.

If the mailbox changed on the server while the page was open, Crow says so and refreshes instead of
acting on the wrong message. A mail server that cannot move messages at all refuses Archive, Delete
and Move; Mark unread still works there.

## Settings

The settings page (`/dashboard/mail?view=settings`) lists every account with its status ("Working",
"Sign-in failed. Update the password.", or "Connected on &lt;instance&gt;") and the time of its last
sync, and offers:

- **Sync now**;
- a **label** you can rename, and **Local models only** ("Applies when Crow drafts or summarises with a
  model." — the switch is stored with the account and matters when Crow drafts or summarises mail);
- **Update password** for an account that cannot sign in;
- the senders you have allowed to show images, each with **Remove**;
- **Remove this account**: "This deletes the mail Crow stored for it. Mail on the server is not
  touched."

Removing an account also removes the password Crow sealed for it. Mail passwords are not deletable
from the Passwords settings page — that page points you here instead.

## Related

- [Crow's Nest](/guide/crows-nest): Where Mail lives, and how the drawer works
- [Multi-Instance Chaining](/guide/instances): Why one address is connected on one Crow
- [Mail store and sync](/developers/mail-store-and-sync): The tables, the sync engine and the reader's
  design