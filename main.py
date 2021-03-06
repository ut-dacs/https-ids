#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
"""A rather simple IDS, it checks flow records against a given signature.
If a cusum rate, or flow record threshols, is exceeded it is marked as an attack.

Usage: ./main.py <path-to-result-file> [options]

The [options] are as defined by the flags library (lib.flags).
Configuration of this IDS is in 'conf/ids.conf'.
#Signature definitions are in 'conf/signature.conf'.
"""

# TODO: github documentation

import logging
import logging.config
import sys
import traceback
import time
import datetime

# Custom lib
import lib.config
import lib.flags
import lib.functions
import lib.logsetup
import lib.ids
import lib.printer
import lib.signature

def main():
  # Init phase
  begin_time = time.time()
  path = sys.argv[1]
  flags = lib.flags.get_flags()
  config = lib.config.read_config('ids')
  if flags['debug'] == True:
    config['log_level'] = "DEBUG"

  logger = lib.logsetup.log_setup(config['log_name'], config['log_file'], config['log_level'])
  logger.info("Starting Intrusion Detection System")
  logger.debug("Init phase")
  ids = lib.ids.IDS(logger, flags, config)
  init_time = time.time()
  if flags['break'] and flags['break_value'] == 'init':
    logger.debug(config)
    logger.debug(flags)
    raise SystemExit("Break at init")

  # Signature phase
  logger.debug("Signature phase")
  ids.load_signatures()
  #ids.filter_signatures(['1','5'])
  #ids.coordinates_signatures()
  signature_time = time.time()
  if flags['break'] and flags['break_value'] == 'signatures':
    logger.debug(ids.signatures)
    logger.debug(ids.coordinates)
    raise SystemExit("Break at signatures")

  # Files phase
  logger.debug("Files phase")
  nfdump_files = ids.process_filenames(path)
  files_time = time.time()
  if flags['break'] and flags['break_value'] == 'files':
    logger.debug(nfdump_files)
    raise SystemExit("Break at files")

  # File processing phase
  logger.debug("File processing phase")
  data, counting, attack, everything = ids.process_files(nfdump_files)
  processing_time = time.time()
  if flags['break'] and flags['break_value'] == 'processing':
    logger.debug(attack)
    raise SystemExit("Break at processing")

  # Signature matching phase
  logger.debug("Signature matching phase")
  if len(attack) > 0:
    attack = ids.process_match(attack)

  if len(everything) > 0:
    everything = lib.absolom.match_everything(everything)

  matching_time = time.time()
  if flags['break'] and flags['break_value'] == 'matching':
    #logger.debug(attack)
    raise SystemExit("Break at matching")

  # Counting phase
  logger.debug("Signature counting phase")
  sig_count = {}
  if len(attack) > 0:
    sig_count = ids.process_count(sig_count, attack)

  if 'everything' in ids.signatures and len(everything) > 0:
    sig_count = ids.process_count(sig_count, everything)

  counting_time = time.time()
  if flags['break'] and flags['break_value'] == 'counting':
    logger.debug(sig_count)
    raise SystemExit("Break at counting")

  # Sorting phase
  logger.debug("Sorting phase")
  attack = ids.process_sort(attack)
  if 'everything' in ids.signatures:
    everything = ids.process_sort(everything)

  sorting_time = time.time()
  if flags['break'] and flags['break_value'] == 'sorting':
    logger.debug(sig_count)
    raise SystemExit("Break at sorting")

  if flags['time'] == True:
    line = lib.functions.time_statistics(begin_time, init_time, signature_time, files_time,
                                  processing_time, matching_time, sorting_time)
    line = line.format('init', 'signature', 'files', 'processing', 'matching', 'sorting')
    logger.info(line)

  # Printing phase
  logger.debug("Printing/saving phase")
  output_modules = flags['output_value'].split(',')
  date = str(datetime.datetime.fromtimestamp(time.time())).split(" ")[0]
  if 'pipe' in output_modules:
    with lib.printer.open_parsable_file(ids.outputdir, ids.signatures, date) as pipe:
      lib.printer.print_parsable_data(pipe, attack)
      if 'everything' in ids.signatures:
        lib.printer.print_parsable_data(pipe, everything)

  if 'pager' in output_modules:
    with lib.printer.open_pager(sys.stdout) as pager:
      if 'everything' in ids.signatures:
        attack = lib.absolom.merge_everything(attack, everything)

      lib.printer.print_data(pager, 'pager', ids.signatures, attack, sig_count)

  if 'disk' in output_modules:
    with lib.printer.open_file(ids.outputdir, ids.signatures, date) as disk:
      if 'everything' in ids.signatures:
        attack = lib.absolom.merge_everything(attack, everything)

      lib.printer.print_data(disk, 'disk', ids.signatures, attack, sig_count)
  if flags['break'] and flags['break_value'] == 'printing':
    raise SystemExit("Break at printing")

if __name__ == "__main__":
  if len(sys.argv) == 1:
    lib.flags.show_help()

  main()