import tempfile


class NullMutator:
    def __init__(self):
        pass

    def mutate_trace(self, trace):
        pass


class Stat64FiletypeMutator:
    def __init__(self, filename, filetype):
        self.filename = filename
        self.filetype = filetype

    def mutate_trace(self, trace):
        with open(trace) as f:
            lines = f.readlines()
        for idx, line in enumerate(lines):
            if self.match_line(line):
                lines[idx] = self.mutate_line(line)
        hand, name = tempfile.mkstemp(suffix='.crashsimulator')
        with open(name, 'w') as f:
            for i in lines:
                f.write(i)
        return name

    def match_line(self, line):
        return 'stat64' in line and self.filename in line

    def mutate_line(self, line):
        return line.replace('st_mode=S_IFREG', 'st_mode='+self.filetype, 1)
