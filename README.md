# AIMLOCK NOVA — Flask Admin

Black/silver neon admin panel with Admin 1 and Admin 2, key create/lock/unlock/delete, and activity logs.

## Render environment variables
- `AIMLOCK_ADMIN_PASSWORD`: strong Admin 1 password
- `AIMLOCK_ADMIN2_USERNAME`: `admin2`
- `AIMLOCK_ADMIN2_PASSWORD`: strong Admin 2 password
- `FLASK_SECRET_KEY`: long random secret, keep stable
- `COOKIE_SECURE`: `true`
- `AIMLOCK_DB_PATH`: `/var/data/aimlock_nova.sqlite3` only after attaching a persistent disk mounted at `/var/data`

Never commit passwords, secret values, or the SQLite database to GitHub.

Build command: `pip install -r requirements.txt`
Start command: `gunicorn --bind 0.0.0.0:$PORT app:app`

Without persistent storage, SQLite data may be lost on redeploy/restart.
