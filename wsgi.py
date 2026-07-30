"""
WSGI entrypoint for PythonAnywhere (and other WSGI hosts).

Do not call app.run() or generate SSL certs here — the platform terminates TLS.
"""
import sys
from pathlib import Path

project_home = Path(__file__).parent.resolve()
if str(project_home) not in sys.path:
    sys.path.insert(0, str(project_home))

from main import app as application  # noqa: E402

# Optional: warm 7-Zip once at worker start (safe, no sudo on PA).
try:
    from main import ensure_7zip
    ensure_7zip(verbose=False)
except Exception:
    pass
