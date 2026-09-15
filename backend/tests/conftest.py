"""Test-suite environment.

The application refuses to start on the shipped development secrets (see
app/security_posture.py). The test suite deliberately runs on them -- it is
testing the logic, not a deployment -- so it opts in explicitly here rather than
by weakening the default.

This must run before app.config is imported, which pytest guarantees by loading
conftest.py first.
"""

import os

os.environ.setdefault("AEGIS_ALLOW_DEFAULT_SECRETS", "1")
