#!/usr/bin/python3.4

import logging
import pickle
import os
import sys

# Add the root dir to the path
sys.path.append(os.path.abspath(os.path.join(sys.path[0],'../')))

# Custom libs
from lib.ids import IDS
from lib.printer import Printer
from lib.flags import *

flags['output_value'] = 'pager'
flags['sig'] = True
flags['sig_value'] = '5,7'

logging.basicConfig(level=logging.DEBUG,
                    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[#logging.FileHandler("log/ids.log"),
                              logging.StreamHandler()])

class Comperator():

  def __init__(self):

    self.data = {}
    self.logger = logging

  def parse_files(self, file1, file2):

    with open(file1, 'rb') as file1:

      data_file1 = pickle.load(file1)
    with open(file2, 'rb') as file2:

      data_file2 = pickle.load(file2)
    return (data_file1, data_file2)

  def show_data(self):

    data_length = len(self.data[list(self.data.keys())[0]]['targets'][list(self.data[list(self.data.keys())[0]]['targets'])[0]])
    if data_length == 7 or data_length == 8 or data_length == 10:

      flags['absolom'] = True

    ids = IDS()
    ids.logger = logging.getLogger('IDS')
    ids.extended = True
    ids.flags = flags
    ids.load_signature()
    ids.data = self.data
    
    printer = Printer()
    printer.logger = logging.getLogger('Printer')
    printer.ids = ids

    ids.process_sort()
    printer.print_results()

  def compare(self, file1, file2, class_type, class_type2):

    dump1, dump2 = self.parse_files(file1, file2)
    if len(sys.argv) == 5:

      dump1 = dump1[class_type]
      dump2 = dump2[class_type2]
    elif len(sys.argv) == 4:

      dump1 = dump1[class_type]
      dump2 = dump2[class_type]

    large = dump1
    small = dump2
    for srcip in large:

      if len(sys.argv) == 4 and not srcip in small:

        self.data[srcip] = large[srcip]
      elif len(sys.argv) == 5 and srcip in small:

        self.data[srcip] = small[srcip]
    self.show_data()

file1 = sys.argv[1]
file2 = sys.argv[2]
class_type = sys.argv[3]
if len(sys.argv) == 5:

  class_type2 = sys.argv[4]
  comperator = Comperator()
  comperator.compare(file1, file2, class_type, class_type2)
else:

  comperator = Comperator()
  comperator.compare(file1, file2, class_type, 0)