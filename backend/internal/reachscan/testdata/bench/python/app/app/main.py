import sys

from app.loader import read_config
from .render import Page


def main():
    cfg = read_config(sys.argv[1])
    print(Page(cfg["template"]).html(name=cfg["name"]))


if __name__ == "__main__":
    main()
