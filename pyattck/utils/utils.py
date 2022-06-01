import os
from urllib.parse import urlparse
from pathlib import Path


def get_absolute_path(path: str):
    if path.startswith("http") or path.startswith("https"):
        return path
    else:
        try:
            if Path(path):
                return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
        except:
            pass


def is_path(value: str) -> bool:
    try:
        Path(value)
        return True
    except:
        pass
    return False


def is_url(value: str) -> bool:
    try:
        urlparse(value).scheme in ["http", "https"]
        return True
    except:
        pass
    return False
