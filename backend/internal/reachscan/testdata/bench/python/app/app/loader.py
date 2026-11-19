import yaml as y


def read_config(path):
    """Reachable: yaml.load (through the alias y)."""
    with open(path) as fh:
        return y.load(fh, Loader=y.Loader)
