import os
from pathlib import Path

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from certificate_converter.utils.CertificateHandler import CertificateHandler
from certificate_converter.utils.CertificateHandler import generate_dummy_certificate
from certificate_converter.utils.helpers import env_or_default
import certificate_converter.utils.consts as consts

sleep_delay: int = 5
certificate_dir: str = "/openssl-certs"
mode: str = "poll"
passphrase: str = "dummy"
generate: bool = False

def get_path(path: str | Path, fail_on_nonexistence: bool = False) -> Path:
    if not type(path) is Path:
        path = Path(path)
    if fail_on_nonexistence and not path.exists():
        raise ValueError(F"File {path} does not exist")
    return path


def read_config():
    global sleep_delay
    global certificate_dir
    global mode
    global passphrase
    global generate

    try:
        certificate_dir = env_or_default(consts.ENVVARNAME_DATA_DIR, certificate_dir)
        sleep_delay = env_or_default(consts.ENVVARNAME_SLEEP_DELAY, sleep_delay)
        mode = env_or_default(consts.ENVVARNAME_MODE, mode).lower()
        passphrase = env_or_default(consts.ENVVARNAME_PASSPHRASE, passphrase)
        generate = env_or_default(consts.ENVVARNAME_GENERATE, generate)
    except TypeError as err:
        print("Invalid type for environment variable")
        raise err

def print_config():
    global sleep_delay
    global certificate_dir
    global mode
    global passphrase
    global generate

    print("###################")
    print("## CONFIGURATION ##")
    print("###################")
    print(F"{consts.ENVVARNAME_DATA_DIR}: {certificate_dir}")
    print(F"{consts.ENVVARNAME_SLEEP_DELAY}: {sleep_delay}")
    print(F"{consts.ENVVARNAME_MODE}: {mode}")
    print(F"{consts.ENVVARNAME_PASSPHRASE}: **** (length: {len(passphrase)})")
    print(F"{consts.ENVVARNAME_GENERATE}: {generate}")
    print("###################")


def check_config():
    global sleep_delay
    global certificate_dir
    global mode
    global passphrase
    global generate

    certificate_dir_path = Path(certificate_dir)

    if not certificate_dir_path.exists():
        raise ValueError(F"{certificate_dir} does not exist")
    if not certificate_dir_path.is_dir():
        raise ValueError(F"{certificate_dir} is not a path")
    if mode not in consts.ALLOWED_MODES:
        raise ValueError(F"Invalid value for mode (is: {mode}) (allowed: {"|".join(consts.ALLOWED_MODES)})")

def main():
    global sleep_delay
    global certificate_dir
    global mode
    global passphrase
    global generate

    try:
        read_config()
        check_config()
        print_config()
    except TypeError as err:
        print(err)
        exit(1)
    except ValueError as err:
        print(err)
        exit(1)

    if generate:
        generate_dummy_certificate(certificate_dir, passphrase)

    observer: Observer | PollingObserver = None
    match mode:
        case "api":
            print("API mode not implemented")
            exit(1)
        case "poll":
            observer = PollingObserver()
        case "event":
            observer = Observer()

    if observer is None:
        print("Error setting up observer")
        exit(1)

    certificate_handler = CertificateHandler()
    certificate_handler.default_passphrase = passphrase
    observer.schedule(certificate_handler, certificate_dir, recursive=True)
    observer.start()

    try:
        while observer.is_alive():
            observer.join(sleep_delay)
    finally:
        observer.stop()
        observer.join()


if __name__ == '__main__':
    main()