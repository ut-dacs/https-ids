#!/usr/bin/python3
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
"""Toolie for viewing categorized result dumps created by the validation scripts.
Usage ./results_viewer.py <results-dump> <tp|tn|fp|fn> [options]

The [options] are as defined by the flags library (lib.flags).
"""
import logging
import pickle
import os
import sys

# Add the root dir to the path
sys.path.append(os.path.abspath(os.path.join(sys.path[0],'../')))

# Custom libs
import lib.config
import lib.ids
import lib.printer
import lib.flags

def load_dump(flags):
  if flags['test'] == False:
    with open(sys.argv[1], 'rb') as dump_file:
      data = pickle.load(dump_file)

  else:
    data = {sys.argv[2]: {}}
  return data

def main():
  if len(sys.argv) < 3:
    lib.flags.show_help()

    # Add support for starting in the scripts directory
  if not 'conf' in os.listdir() and 'conf'in os.listdir('../'):
    sys.argv[1] = os.path.abspath(sys.argv[1])
    os.chdir('../')

  flags = lib.flags.get_flags()
  flags['output_value'] = 'pager'
  flags['violate'] = True

  ids = lib.ids.IDS(logging.getLogger('IDS'), flags, lib.config.read_config('ids'))

  data = load_dump(flags)
  ids.data = data[sys.argv[2]]
  ids.data = ids.process_sort(ids.data)
  with lib.printer.open_pager(sys.stdout) as pager:
    lib.printer.print_data(pager, 'pager', ids.signatures, ids.data, {})

if __name__ == "__main__":
  main()