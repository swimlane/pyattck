import os
from pathlib import Path
from urllib.parse import urlparse


def get_absolute_path(path: str):
    if path.startswith("http") or path.startswith("https"):
        return path
    else:
        try:
            if Path(path):
                return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
        except Exception as e:
            pass


def is_path(value: str) -> bool:
    try:
        Path(value)
        return True
    except Exception as e:
        pass
    return False


def is_url(value: str) -> bool:
    try:
        urlparse(value).scheme in ["http", "https"]
        return True
    except Exception as e:
        pass
    return False
