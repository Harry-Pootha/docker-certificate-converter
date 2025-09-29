from typing import Final

ENVVARNAME_DATA_DIR: Final[str] = "DATA_DIR"
ENVVARNAME_SLEEP_DELAY: Final[str] = "SLEEP_DELAY"
ENVVARNAME_MODE: Final[str] = "MODE"
ENVVARNAME_PASSPHRASE: Final[str] = "PASSPHRASE"
ENVVARNAME_GENERATE: Final[str] = "GENERATE"
ALLOWED_MODES: Final[list[str]] = ["poll", "api", "event"]