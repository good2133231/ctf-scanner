"""Stage 基类：流水线的最小执行单元。"""


class Stage:
    name = "base"
    description = ""

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        raise NotImplementedError
