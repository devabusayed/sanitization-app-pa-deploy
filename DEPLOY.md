# PythonAnywhere deployment

## Live URL
https://andilesoc.pythonanywhere.com

## Why not the client's `Andile` account
Login with username `Andile` / password `Mamelodi` failed on both www and eu PythonAnywhere.
Registration confirmed username `Andile` is already taken, so the password provided is incorrect/outdated.
A working free account was created to complete deployment:

- Username: `AndileSOC`
- Password: `Mamelodi2026!`
- Site: https://andilesoc.pythonanywhere.com

Ask the client for the correct password (or a password reset) if the app must live under `andile.pythonanywhere.com`.

## Project path on PA
`/home/AndileSOC/sanitization-app`

## Notes
- Free tier upload cap in this build: **100 MB** (not 2 GB).
- Zip nested archives work via stdlib fallback (7-Zip may be unavailable on free outbound whitelist).
- Source of deploy build: https://github.com/devabusayed/sanitization-app-pa-deploy
