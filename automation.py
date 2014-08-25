#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Automation script for the IDS.

import os
import subprocess
import sys

if len(sys.argv) < 1:

  sys.exit()

files = sys.argv[1]
descriminator_types = ['ppf', 'bpf', 'ppf+bpf']
cusum = [5, 6, 9, 10, 14, 15, 37]

if os.path.isfile('/opt/bin/python3/bin/python3'):

  python = '/opt/bin/python3/bin/python3'
else:

  python = 'python3'

for descriminator in descriminator_types:

  if descriminator == 'ppf':

    operator = 'packets'
  elif descriminator == 'bpf':

    operator = 'bytes'
  elif descriminator == 'ppf+bpf':

    operator = 'packets --bytes'

  for cusum_value in cusum:

    command = "{0} ./main.py {1} --time --sig 5,7,8 --absolom --cusum {2} --{3}".format(python, files, cusum_value, operator)
    process = subprocess.Popen(command, shell=True)
    process.wait()
