"""A small key=value parser with a planted bug for the Atheris sample."""


def parse(text):
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        if value.startswith("["):
            # Bug: assumes a closing bracket follows.
            value = value[1:value.index("]")]
        out[key.strip()] = value.strip()
    return out
