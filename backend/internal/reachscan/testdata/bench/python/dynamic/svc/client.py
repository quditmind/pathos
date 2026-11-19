import os

import requests


def fetch(url):
    # Dynamic dispatch: the requests function is looked up by a name from
    # the environment, so any of them (and what it calls) may run.
    method = getattr(requests, os.environ.get("HTTP_METHOD", "get"))
    return method(url, timeout=5)
