
class NetworkElement(object):
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.children = {}
        self.isEntity = False
        self.warnings = []
        self.warn_time_start = None
        self.warn_time_end = None

    def add_child_node(self, name, child_node):
        self.children[name] = child_node

    def add_warnings(self, warning):
        self.refresh_time_range(warning)
        self.warnings.append(warning)

    def refresh_time_range(self, warning):
        self.warn_time_end = warning['logTime']
        if not self.warn_time_start:
            self.warn_time_start = warning['logTime']
