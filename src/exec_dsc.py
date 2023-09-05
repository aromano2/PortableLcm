#!/usr/bin/env python
import os
import sys
import json
import inspect
cur = os.path.realpath(os.curdir)
if 'OMI_HOME' in os.environ.keys():
    prefix=os.environ['OMI_HOME']
else:
    prefix = '/opt/omi'
    os.chdir(prefix + '/lib/Scripts')
    sys.path.insert(0, '')
if sys.version < '2.6':
    os.chdir('./2.4x-2.5x')
elif sys.version < '3':
    os.chdir('./2.6x-2.7x')
else:
    os.chdir('./3.x')
from Scripts import *

the_module = globals()[sys.argv[1]]
method_name = sys.argv[2] + '_Marshall'

d = json.loads(sys.argv[3])

argspec = inspect.getargspec(the_module.__dict__[method_name])
if type(argspec) == tuple:
    args = argspec[0]
else:
    args = argspec.args

for arg in args:
    if arg not in d.keys():
        d[arg] = None
for key in d.keys():
    if key not in args:
        d.pop(key)

ret = the_module.__dict__[method_name](**d)
print('Result:' + repr(ret[0]))
