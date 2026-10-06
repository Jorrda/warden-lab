Warden
======

A prototype for governing non-human identities (service accounts, API keys,
OAuth grants, webhooks, deploy keys, certificates, CI tokens and AI agents)
in a small organization. Warden stores metadata about credentials, never
credential values.

Needs Python 3.10 or newer, and access to PyPI for the one install step.
No internet is needed after that.


Install and run on Linux or macOS
---------------------------------
In a terminal:

  git clone https://github.com/Jorrda/warden-lab.git
  cd warden-lab
  python3 -m venv .venv               create a private Python environment
  . .venv/bin/activate                use it in this terminal
  pip install -r requirements.txt     install the pinned packages
  cp .env.example .env                create the settings file
  flask --app app init-db             create the database
  flask --app app seed                load the demo data, score it, PRINT THE PASSWORDS
  python app.py                       start the server

Open http://127.0.0.1:5000 and sign in as admin or as viewer.
The passwords are printed by the seed step. See "Accounts and passwords".


Install and run on Windows (PowerShell)
---------------------------------------
In PowerShell:

  git clone https://github.com/Jorrda/warden-lab.git
  cd warden-lab
  py -3 -m venv .venv
  .venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  copy .env.example .env
  flask --app app init-db
  flask --app app seed
  python app.py

If PowerShell refuses Activate.ps1, run this once and try again:
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
If "py" is not found, use: python -m venv .venv
In cmd.exe the activation line is: .venv\Scripts\activate.bat

Open http://127.0.0.1:5000 and sign in as admin or as viewer.
The passwords are printed by the seed step. See "Accounts and passwords".


Good to know
------------
The prompt shows (.venv) while the environment is active. Every new terminal
needs the activation line again. "flask: command not found" means the
environment is not active in that terminal. Stop the server with Ctrl+C.

The database is one file, instance/warden.db, inside the "warden-lab" folder.
It is not in this package: "flask --app app init-db" creates it.


Accounts and passwords
----------------------
  admin     the IT coordinator, may change data
  viewer    a manager, read only

There are two ways to get the passwords.

1. Let the seed generate them. This is what happens when the install steps
   above are followed as written, because the two password lines in .env
   are empty. Near the end of its output, "flask --app app seed" prints:

     Generated password for admin (shown once, stored only as a hash): ...
     Generated password for viewer (shown once, stored only as a hash): ...

   Copy both passwords from those lines before closing the terminal. They
   are shown once, and only their hashes are stored.

2. Choose them yourself. After the settings file .env is created and
   BEFORE the seed, open .env in a text editor and fill in these two lines:

     WARDEN_ADMIN_PASSWORD=
     WARDEN_VIEWER_PASSWORD=

   The seed then uses your values and prints no password.

Lost a password: stop the server, delete instance/warden.db, then run
init-db and seed again, and copy the two new passwords.
Five failed sign-ins lock an account for ten minutes. Restarting the server
clears the lock.


Useful commands
---------------
  python app.py                       start the server on 127.0.0.1:5000
  flask --app app recompute-risk      recompute every risk score
  flask --app app init-db             create missing tables (never alters one)
  flask --app app seed                load the demo data into an empty database

Another port, if 5000 is taken:
  Linux or macOS    WARDEN_PORT=5001 python app.py
  PowerShell        $env:WARDEN_PORT=5001; python app.py
  or set WARDEN_PORT=5001 in the .env file.

Start over: stop the server, delete instance/warden.db, then run init-db
and seed again. Seed shortly before a demo: the dates in the demo data are
offsets from the moment of seeding.

The first start warns that SECRET_KEY is not set and uses a temporary key.
For a permanent one, paste the output of this after SECRET_KEY= in .env:
  python -c "import secrets; print(secrets.token_hex(32))"


Pages
-----
  /               dashboard: indicators, charts, the riskiest identities
  /nhis           inventory: filter, register, edit, transfer, rotate, revoke
  /nhis/import    CSV import with a preview (admin)
  /people         people and owners; mark a person departed
  /systems        systems and their criticality
  /risk/report    printable posture report
  /risk/policy    the scoring weights and thresholds
  /offboarding    offboarding cases: decide every identity of a leaver
  /audit          audit log of every change
  /scanner        secrets scanner: Run scan checks sample_repo/

Looking inside the database
---------------------------
The database is the single file instance/warden.db. It exists after
"flask --app app init-db". Run these from inside the "warden-lab" folder.
Reading it is safe while the server runs.

1. With the sqlite3 tool (part of macOS and of most Linux systems). Give it
   the file name; "sqlite3" alone opens an empty database and shows nothing.

     sqlite3 -readonly instance/warden.db

     sqlite> .tables
     sqlite> .schema nhis
     sqlite> .headers on
     sqlite> .mode column
     sqlite> SELECT name, type, current_score, current_band FROM nhis
        ...> ORDER BY current_score DESC LIMIT 10;
     sqlite> SELECT action, COUNT(*) FROM audit_events GROUP BY action;
     sqlite> .quit

   A command that starts with a dot takes no semicolon. SQL ends with a
   semicolon: if the prompt turns into "...>", type ; and press Enter.

2. Without the sqlite3 tool (usual on Windows), Python 3.12 or newer has a
   small one built in. It has no .tables command, so list the tables in SQL:

     python -m sqlite3 instance/warden.db

     sqlite> SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;
     sqlite> SELECT name, current_score FROM nhis ORDER BY current_score DESC LIMIT 10;
     sqlite> .quit

3. On any Python, with the environment active, through the application:

     flask --app app shell

     >>> from warden.extensions import db
     >>> from sqlalchemy import text
     >>> db.session.execute(text("SELECT name, current_score FROM nhis ORDER BY current_score DESC LIMIT 10")).all()
     >>> exit()

Look, do not edit: a row changed by hand skips the audit log and the risk
score. The users table holds password hashes, so select its columns by
name (id, username, role) and not with SELECT *.


Data model
----------
docs/erd.pdf is the full entity relationship diagram: the thirteen tables
with every column and every relationship. Open the PDF to zoom in.
docs/erd.png is the same diagram as an image.


Sample repository
-----------------
sample_repo/ is a synthetic code base for the scanner. Every string planted
in it is fake and pattern-shaped only; none is a working credential.
