# Sanitization App v1.0

A web application that sanitizes text files and archives by replacing sensitive content with `X` characters (one `X` per matched character). Rules are managed entirely from the browser—no coding required.

## Features

- Upload text files and archives (zip, rar, 7z, tar, etc.) up to **2 GB**
- Regex-based sanitization with length-proportional replacement (`csv` → `XXX`, `andy` → `XXXX`)
- Partial matching (e.g. rule `2023` sanitizes `10-02-2023` → `10-02-XXXX`)
- Nested archive support (extract → sanitize → repack)
- Full rules management from the UI: add, delete, edit all, upload `.txt`, clear all
- Secure HTTPS with self-signed certificate (auto-generated on first run)

## Requirements

- **Python 3.11+** — [python.org/downloads](https://www.python.org/downloads/) (on Ubuntu, `start.sh` installs `python3`, `python3-venv`, and `python3-pip` via `apt` if missing)
- **7-Zip** — required for archive uploads; **installed automatically** on first start
  - **Windows:** winget, then portable download to `tools/7zip/` (no admin needed)
  - **Ubuntu:** `p7zip-full` via `apt` only (no Homebrew, no portable download)
  - **Other Linux:** portable download to `tools/7zip/`, then apt/dnf, then Homebrew + p7zip

## Quick Start



### Ubuntu

On Ubuntu, `./start.sh` installs missing dependencies via `apt` (`python3`, `python3-venv`, `python3-pip`, and `p7zip-full`). You can also install them yourself first:

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip p7zip-full
python3 -m venv .venv
source .venv/bin/activate
pip3 install -q -r requirements.txt
python3 main.py --serve

```

### Manual Start

```bash
pip install -r requirements.txt
python main.py --serve
```

## Using the App

### Upload Tab

1. Click **Upload** tab
2. Select one or more files (up to 10,000 per upload)
3. Click **Upload**
4. Wait for processing to finish
5. Click **Download sanitized result** when ready

**Supported formats:** `.txt`, `.log`, `.zip`, `.rar`, `.7z`, `.tar`, `.tgz`, `.gz`, `.bz2`, `.xz`, `.lz`, `.zst`

Do not close the browser during processing. Note the **Job ID** if you need help retrieving a file.

### Rules Tab

All rules are saved permanently and apply to every upload.

| Action | How |
|--------|-----|
| **View rules** | Open Rules tab — each line is shown with a Delete button |
| **Add one rule** | Type a pattern and click **Add Rule** |
| **Edit all rules** | Edit the textarea and click **Save All** |
| **Upload rules file** | Choose a `.txt` file and click **Replace All Rules** |
| **Clear all rules** | Click **Clear All Rules** |

Lines starting with `#` are comments and are ignored during sanitization.

### Regex Examples

| Pattern | Matches | Example result |
|---------|---------|----------------|
| `csv` | anywhere in text | `-csv` → `-XXX` |
| `2023` | inside dates | `10-02-2023` → `10-02-XXXX` |
| `\bandy\b` | whole word only | `Andy` → `XXXX` |
| `\b[\w\.-]+@company\.com\b` | email addresses | `user@company.com` → `XXXXXXXXXXXXXXXX` |

## Command Line (Optional)

Process a single file from the terminal:

```bash
python main.py test.txt
python main.py myfile.txt --rules-file bad_words.txt
python main.py myfile.txt --rules "csv" "2023"
```

## Folder Structure

```
SanitizationApp/
├── main.py              # Application server
├── bad_words.txt        # Active sanitization rules (editable from UI)
├── requirements.txt     # Python dependencies
├── start.sh / start.bat # One-click startup scripts
├── templates/
│   └── index.html       # Web interface
├── uploads/             # Temporary uploads (auto-purged)
├── outputs/             # Sanitized output files (auto-purged)
├── logs/                # Processing logs (auto-purged)
└── certs/               # Auto-generated SSL certificates
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Certificate warning in browser | Normal for self-signed cert — click Advanced → Proceed |
| Archive upload fails | Restart the app — 7-Zip installs automatically on start (Ubuntu: via `apt`; macOS: via Homebrew) |
| "Invalid regex" when saving rules | Check the pattern syntax; error shows the line number |
| File too large | Maximum upload size is 2 GB |
| No download link after upload | No matches were found — add or adjust rules |

## Support

Developed by Andy.

Contact **Andy** for assistance.
