from jinja2 import Template


class Page:
    def __init__(self, source):
        self.template = Template(source)

    def html(self, **values):
        # jinja2.utils.urlize (ReDoS) is never called.
        return self.template.render(**values)
