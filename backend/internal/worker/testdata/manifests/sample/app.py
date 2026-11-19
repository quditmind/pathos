# Deliberately vulnerable sample for the worker-sast fixture tests.
import subprocess

import yaml

PASSWORD = "hunter2"


def run(cmd):
    return subprocess.call(cmd, shell=True)


def load(text):
    return yaml.load(text)
