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


class ConnectMutator(NullMutator):
    """
    <Purpose>
      Implementation of a mutator that alters connect calls
      by overwriting the communication domain as 
      another user-specified one.
    """

    def __init__(self, orig_domain, domain):
        """
        <Purpose>
          Initialize the mutator object with an original commuication domain
          string and a target communication domain string
        
            i.e
                connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.0.2.3")}, 16) = 0
                connect(4, {sa_family=AF_UNIX, sin_port=htons(53), sin_addr=inet_addr("10.0.2.3")}, 16) = 0
        
        """
        self.orig_domain = orig_domain
        self.domain = domain


    def mutate_trace(self, trace):
        with open(trace, 'r') as f:
            lines = f.readlines()

        for idx, line in enumerate(lines):
            if self.match_line(line):
                line[idx] = self.mutate_line(line)


    def match_line(self, line):
        return 'connect' in line and self.orig_domain in line


    def mutate_line(self, line):
        return line.replace('sa_family=' + self.orig_domain, 'sa_family=' + self.domain, 1)
