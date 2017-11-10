from __future__ import print_function

import os
import sys
import subprocess
import ConfigParser

if __name__ == '__main__':
    cfg  = ConfigParser.SafeConfigParser()
    cfg.read(sys.argv[1])
    #os.environ['RR_LOG'] = 'ReplaySession'
    for i in cfg.sections():
        subprocess.call('rr replay -a -n ' + cfg.get(i, 'event'), shell=True)

