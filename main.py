#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  A very simple IDS, it checks flow records agains a given signature

import logging
import logging.config
import sys
import traceback

# Custom lib
from lib.config import config
from lib.ids import IDS
from lib.worker import Worker
from lib.signature import SigWorker
from lib.printer import Printer
from lib.flags import *

# If not enough arguments are given, show the help
if len(sys.argv) == 1:

  show_help()
  sys.exit()

# This is where the magic happens
def main():

  # nfdump file is the first argument
  nfdump_file = sys.argv[1]

  # Setup logging
  log_configured = False
  try:

    # Try to load a nice log config
    import yaml
    f = open("conf/logging.conf", 'rb')
    D = yaml.load(f)
    D.setdefault('version', 1)
    if flags['debug'] == True:

      D['handlers']['console']['level'] = 'DEBUG'
    logging.config.dictConfig(D)
    log_configured = True

  except:

    if flags['debug'] == True:

      logging.basicConfig(level=logging.DEBUG,
                    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("log/ids.log"),
                              logging.StreamHandler()])
    else:

      logging.basicConfig(level=logging.INFO,
                    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("log/ids.log"),
                              logging.StreamHandler()])
    logging.info("Using basic log config")
  logging.info("Starting Intrusion Detection System")

  # Create an ids object
  ids = IDS()
  ids.flags = flags
  ids.show_help = show_help
  ids.logger = logging.getLogger('IDS')

  # Create a printing object
  printer = Printer()
  printer.logger = logging.getLogger('Printer')
  printer.ids = ids

  # Show the flags and their values
  ids.logger.debug("FLAGS: {0}".format(ids.flags))
  if ids.flags['break'] and ids.flags['break_value'] == 'init':

    sys.exit()

  # Actual ids calls
  # Load the signature
  ids.load_signature()
  if ids.flags['break'] and ids.flags['break_value'] == 'signature':

    sys.exit()

  # Process the filenames into a long list
  ids.process_filenames(nfdump_file)
  if ids.flags['break'] and ids.flags['break_value'] == 'files':

    sys.exit()

  # Process the files
  ids.logger.info("Processing files")
  ids.process_files()
  logging.debug("{0} sources found".format(len(ids.data)))
  if ids.flags['break'] and ids.flags['break_value'] == 'process':

    sys.exit()

  # Find the closest match
  ids.logger.info("Matching signatures")
  ids.process_match()

  # Hack to get the data for everything through
  if ids.flags['absolom'] == True and 'everything' in ids.signature.keys():

    # Store the actual data somewhere
    temp = ids.data.copy()

    # Replace the data with everything
    ids.data = ids.everything.copy()

    # Match signatures
    ids.process_match()

    # And put the data back where they belong
    ids.everything = ids.data.copy()
    ids.data = temp.copy()

    # Delete traces
    del temp

  # Little status message
  logging.debug("{0} sources found".format(len(ids.data)))
  if ids.flags['break'] and ids.flags['break_value'] == 'match':

    sys.exit()

  # Count signatures
  ids.logger.info("Counting signatures")
  ids.process_count()

  # Do sources dissapear?
  logging.debug("{0} sources found".format(len(ids.data)))
  if ids.flags['break'] and ids.flags['break_value'] == 'count':

    sys.exit()

  # Sort the data
  ids.logger.info("Sorting data")
  ids.process_sort()

  # Do sources dissapear?
  logging.debug("{0} sources found".format(len(ids.data)))
  if ids.flags['break'] and ids.flags['break_value'] == 'sort':

    sys.exit()

  # Calculate the time statistics if requested
  if ids.flags['time'] == True:

    ids.calculate_time()

  # Print the output in someway
  if 'pipe' in ids.flags['output_value']:

    printer.save_data()
    if ids.flags['break'] and ids.flags['break_value'] == 'save':

      sys.exit()

  if 'pager' in ids.flags['output_value'] or 'disk' in ids.flags['output_value']:

    printer.print_results()
    if ids.flags['break'] and ids.flags['break_value'] == 'print':

      sys.exit()

if __name__ == "__main__":

  main()
