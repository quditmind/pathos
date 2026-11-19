"""PATHOS worker-fuzz test sample: an Atheris harness for a key=value
config parser with a planted bug (an unchecked index)."""
import sys

import atheris

with atheris.instrument_imports():
    import configparse


def test_one_input(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    configparse.parse(text)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
