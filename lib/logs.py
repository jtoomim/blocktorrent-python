#/usr/bin/python
from __future__ import print_function
import sys

logusers = 0
logfile = None

debuglevels = []
for arg in sys.argv:
    if arg.startswith('-debug='):
        debuglevels.append(arg.split('=')[1].strip())

def log(*args, **kwargs):
    if logfile:
        return print(*args, file=logfile, **kwargs )
    else:
        return print(*args, **kwargs)

def debuglog(category, *args, **kwargs):
    if category in debuglevels:
        log(*args, **kwargs)

