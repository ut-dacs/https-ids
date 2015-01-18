#!/usr/bin/python3
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
"""Validation script, it uses the 'Validator' class in 'lib.validator' to validate a results file.
Usage: ./scripts/validate.py <path-to-result-file> [options]

The [options] are as defined by the flags library (lib.flags).
To configure the logging options see 'conf/validate.conf'.
"""

import datetime
import logging
import logging.config
import math
import multiprocessing
import os
import pickle
import queue
import re
import sys
import time
import threading
import traceback

# Add root dir to path
sys.path.append(os.path.abspath(os.path.join(sys.path[0],'../')))

# Custom libs
import lib.config
import lib.flags
import lib.ids
import lib.logsetup
import lib.printer
import lib.validator


if len(sys.argv) < 2:
  lib.flags.show_help()

# Add support for starting in the scripts directory
if not 'conf' in os.listdir() and 'conf'in os.listdir('../'):
  sys.argv[1] = os.path.abspath(sys.argv[1])
  os.chdir('../')

def main():
  results_file = sys.argv[1]
  flags = lib.flags.get_flags()
  config = lib.config.read_config('validate')

  # Override log level if debug is selected
  if flags['debug'] == True:
    config['log_level'] = "DEBUG"

  logger = lib.logsetup.log_setup(config['log_name'], config['log_file'], config['log_level'])
  logger.info("Starting validation")
  logger.debug("Init phase")

  # Read the file
  with open(results_file, 'rb') as f:
    data_bytes = f.readlines()

  file_name = re.match('.*/(.*?)-([0-9]{4}-[0-9]{2}-[0-9]{2})-(.*?)-([0-9]{1,2}).idats', results_file)
  if file_name:
    signature = file_name.group(1).split('_')
    date = file_name.group(2)
    type_scan = file_name.group(3).split('-')
    cusum = int(file_name.group(4))

  else:
    raise SystemExit("File name not understood")

  # Create the validator
  validator = lib.validator.Validator(logger, flags, config, signature)
  validator.load_attackers(cusum)
  if flags['break'] and flags['break_value'] == 'init':
    raise SystemExit("Break at init")

  logger.debug("Processing phase")
  validator.processor(data_bytes)
  if flags['break'] and flags['break_value'] == 'processing':
    logger.debug(validator.count)
    raise SystemExit("Break at processing")

  logger.debug("Calculating phase")
  validator.calculate_rates()
  validator.print_rates()
  if flags['break'] and flags['break_value'] == 'calculating':
    logger.debug((validator.tpr, validator.tnr, validator.fnr, validator.fpr, validator.acc))
    raise SystemExit("Break at calculating")

  logger.debug("Saving phase")
  validator.save_data(signature, date, type_scan, cusum)
  #validator.show_results()

if __name__ == "__main__":
  main()