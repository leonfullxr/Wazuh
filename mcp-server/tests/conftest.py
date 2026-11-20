"""Choose the fixture authentication mode before ASGI modules construct their singleton config."""

import os

os.environ.setdefault("AUTH_MODE", "none")
