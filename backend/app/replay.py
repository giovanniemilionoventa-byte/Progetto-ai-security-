from threading import Lock
from time import time


class ReplayStore:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = Lock()

    def consume(self, jti: str, exp: float) -> bool:
        now = time()
        with self._lock:
            self._purge(now)
            existing = self._seen.get(jti)
            if existing is not None and existing > now:
                return False
            self._seen[jti] = float(exp)
            return True

    def _purge(self, now: float) -> None:
        expired = [key for key, exp in self._seen.items() if exp <= now]
        for key in expired:
            del self._seen[key]


replay_store = ReplayStore()
