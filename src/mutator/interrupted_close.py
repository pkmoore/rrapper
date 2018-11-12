from __future__ import print_function
import re

class CloseInterruptedMutator:
    def __init__(self):
       self.regex = re.compile(r"""
                      \#!(?P<file>.*)\#!\n          # Collect register file
                      .*?                           # Consume everything
                                                    # before open call
                      (?P<openline>\d+\s+open\(     # Start of open
                           "(?P=file)"              # open on <file>
                           .*                       # Everything else
                           \)                       # Closing paren
                           \s+=\s+(?P<filedesc>\d+))# Collect filedesc register
                      .*?                           # Consume until close
                      (?P<closeline>\n\d+\s+close\(   # start of close
                           (?P=filedesc)            # close on fildesc value
                           .*                       # anything else
                           \)                       # closing paren
                           \s+=\s+0)                # successful (0) return
                      (?P<remainingtrace>.*)        # Consume remaining trace
                   """,
                   re.DOTALL|re.VERBOSE)

    def mutate_trace(self, trace):
        with open(trace) as f:
            data = f.read()
        close_line_start = self.match_line(data)
        data = self.mutate_line(data, close_line_start)
        hand, name = tempfile.mkstemp(suffix='.crashsimulator')
        with open(name, 'w') as f:
            f.write(data)
        return name

    def match_line(self, data):
        return self.regex.search(data).start('closeline')+1

    def mutate_line(self, data, close_line_start):
        close_line_end = data.find('\n', close_line_start)
        close_line = data[close_line_start:close_line_end]
        mutated_close_line = close_line.replace(' = 0', ' = -1 EINTR (Interrupted)')
        return data[0:close_line_start] + mutated_close_line + data[close_line_end:]

if __name__ == '__main__':
    trace_str = """#!test.txt#!
8164  open("test.txt", O_RDONLY|O_LARGEFILE) = 3
8164  fstat64(3, {st_dev=makedev(0, 40), st_ino=54993216, st_mode=S_IFBLK|0664,
st_nlink=1, st_uid=501, st_gid=20, st_blksize=1024, st_blocks=1, st_size=5,
st_atime=2017/04/02-19:08:17, st_mtime=2017/03/23-18:03:51,
st_ctime=2017/03/23-18:03:51}) = 0
8164  mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
= 0xb7fd8000
8164  read(3, "test\n", 1024)           = 5
8164  read(3, "", 1024)                 = 0
8164  _llseek(3, 0, [5], SEEK_CUR)      = 0
8164  close(3)                          = 0
8164  munmap(0xb7fd8000, 4096)          = 0
8164  fstat64(1, {st_dev=makedev(0, 13), st_ino=4, st_mode=S_IFCHR|0620,
st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0,
st_rdev=makedev(136, 1), st_atime=2017/04/02-20:01:59,
st_mtime=2017/04/02-20:01:59, st_ctime=2017/03/30-18:12:02}) = 0
8164  mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
= 0xb7fd8000
8164  close(3)                          = 0"""

    ci = CloseInterruptedMutator()
    print(ci.match_line(trace_str))
    print(ci.mutate_line(trace_str, 537))
