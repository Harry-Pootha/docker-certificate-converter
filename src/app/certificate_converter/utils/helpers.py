import os
from get_docker_secret import get_docker_secret
from pathlib import Path


def get_path(path: str | Path, fail_on_nonexistence: bool = False, fail_on_existence: bool = False) -> Path:
    if fail_on_existence and fail_on_nonexistence:
        raise ValueError("Cannot check for existence and nonexistence at the same time") # Stooooopid

    if not type(path) is Path:
        path = Path(path)
    if fail_on_nonexistence and not path.exists():
        raise ValueError(F"File {path} does not exist")
    if fail_on_existence and path.exists():
        raise ValueError(F"File {path} already exist")
    return path


def write_bytes_to_file(path: str | Path, content: bytes | str):
    if len(content) == 0:
        return # We do not write empty files here - use touch in a different way
    if content is str:
        content = content.encode()
    try:
        path = get_path(path, fail_on_existence=True)
        with path.open("wb") as writer:
            writer.write(content)
    except ValueError as err:
        print(err)


def env_or_default(key: str, default: str | int | bool) -> str | int | bool:
    try:
        value = get_docker_secret(key)
        if value == "":
            return default

        # Fuck you, python!
        # APPARENTLY bool is a subclass of int
        # DESPITE both being primitives - ok, nevermind python by definition has no primitives
        # Nevertheless if I want to perform a type match I cannot safely use int() and bool() as cases
        # Since a bool will land in the int() case before landing in its own
        # So EITHER I have to put bool() before int() as the matched type
        # Which does not make sense, since the strength of switch/match case is quick lookup without performing successive checks
        # ALTERNATIVELY I need to use int() alone and need to check isinstance(bool)
        # Because of course I cannot perform a isinstance check witch a match case statement
        # So ... which is cleaner then?
        # In the end I opted for an additional isinstance check in the int case
        # I feel this approach will be less error prone for potential update changes
        # ALTHOUGH I like the look of a separate bool() more!
        match default:
            case str():
                return value
            case int():
                if isinstance(default, bool):
                    return value.lower() == "true"
                if value.isdigit():
                    return int(value)
                return default
            case _:
                raise TypeError

    except KeyError:
        return default