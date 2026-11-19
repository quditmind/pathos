# Deliberately vulnerable sample for the worker-sast fixture tests.
import hashlib
import pickle
import subprocess

import requests


def run(cmd, env={}):
    subprocess.run(cmd, shell=True)
    return eval(cmd)


def fetch(url):
    try:
        return requests.get(url, verify=False).text
    except:
        return None


def load(path):
    handle = open(path, "rb")
    return pickle.load(handle)


def fingerprint(data):
    return hashlib.md5(data).hexdigest()
