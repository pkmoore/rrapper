import tempfile

class GenericMutator:
  def __init__(self):
    self.oppotunities = []

  def next_syscall(self):
    syscall = tm.next_syscall()
    if syscall is None:
      threading.wait()
    return sysycall
  
  def opportunity_identified(self, syscall, que):
    que.put(syscall)

  def find_syscall_between_indexes(self, syscalls, start, end, pred_func):
    if start < 0: raise ValueError('Starting index must be > 0')
    if end < 0: raise ValueError('Ending index must be > 0')
    if start == end: raise ValueError('starting index must not equal ending index')
    if end > len(syscalls): raise ValueError('end index must be < len(syscalls)')
    if not callable(pred_func): raise TypeError('pred_func must be callable')

    indexes = []
    for index, line in enumerate(syscalls):
      if pred_func(line):
        # We are indexing from start so if start > 0
        # we need to add it to index to get the true index into the
        # complete syscall list
        indexes.append(index + start)

    return indexes

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


class ConnectMutator(GenericMutator):
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
