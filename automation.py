#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
"""Automation script for the IDS.
Using the same data-set a series of cusum and descriminator types can be configured and run.
The configuration for this automation script is in 'conf/automation.conf'.

"""

import os
import subprocess
import sys

# Custom flags
import lib.flags
import lib.config
import lib.functions

if len(sys.argv) < 1:
  sys.exit()

files = sys.argv[1]
flags = lib.flags.get_flags()
config = lib.config.read_config('automation')
signatures = lib.config.read_signatures()
signatures = lib.functions.automation_signatures(signatures, config['signatures'])
descriminator_types = config['descriminator'].split(",")
cusum = config['cusum'].split(",")

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

    command = "{0} ./main.py {1} --time --sig {2} --cusum {3} --{4}".format(python, files, signatures, cusum_value, operator)
    if flags['test'] == False:
      process = subprocess.Popen(command, shell=True)
      process.wait()

    else:
      print(command)