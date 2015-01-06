#!/usr/bin/python3
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Dump viewer

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

flags = lib.flags.get_flags()
flags['output_value'] = 'pager'
flags['sig'] = True
flags['sig_value'] = '1,3,5,7'
flags['violate'] = True

def load_dump():

  dump_file = open(sys.argv[1], 'rb')
  data = pickle.load(dump_file)
  dump_file.close()

  #src ip: list(data['all'].keys())[0]
  #dst ip: list(data['all'][list(data['all'].keys())[0]]['targets'])[0]
  data_length = len(data['all'][list(data['all'].keys())[0]]['targets'][list(data['all'][list(data['all'].keys())[0]]['targets'])[0]])
  if data_length == 7 or data_length == 8 or data_length == 10:

    flags['absolom'] = True
  return data

def main():

  if len(sys.argv) < 3:

    print("Usage: {0} <result-dump> <tp, tn, fp, fn>".format(sys.argv[0]))
    sys.exit()

  data = load_dump()
  ids = lib.ids.IDS(logging.getLogger('IDS'), flags, lib.config.read_config('ids'))
  ids.extended = True
  ids.flags = flags
  ids.load_signatures()
  ids.data = data[sys.argv[2]]

  ids.data = ids.process_sort(ids.data)
  with lib.printer.open_pager(sys.stdout) as pager:
    lib.printer.print_data(pager, 'pager', ids.signatures, ids.data, {})

if __name__ == "__main__":

  main()