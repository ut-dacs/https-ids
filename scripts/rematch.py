#!/usr/bin/python3
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Dump viewer

import logging
import multiprocessing
import os
import pickle
import sys

# Add the root dir to the path
sys.path.append(os.path.abspath(os.path.join(sys.path[0],'../')))

# Custom libs
from lib.ids import IDS
from lib.printer import Printer
from lib.flags import *

flags['output_value'] = 'pager'
flags['sig'] = True
flags['sig_value'] = '5,7,8'
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
  ids = IDS()
  ids.logger = logging.getLogger('IDS')
  ids.extended = True
  ids.flags = flags
  ids.load_signature()
  ids.data = data[sys.argv[2]]
  if flags['threads'] == True:

    threads = int(flags['threads_value'])
  else:

    threads = int(multiprocessing.cpu_count())
    if threads < 1:

      threads = 1
  ids.threads = threads
  ids.process_match()
  ids.process_sort()

  # Create a printing object
  printer = Printer()
  printer.logger = logging.getLogger('Printer')
  printer.ids = ids

  
  ids.process_sort()
  printer.print_results()

if __name__ == "__main__":

  main()