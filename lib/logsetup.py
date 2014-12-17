#!/usr/bin/python3

import logging
import os
import sys

def log_setup(name, log_file, log_level):
  """Function to setup a logger, based on the given configuration.

  :param name: name used in logging
  :type name: str
  :param log_file: specifies the log file
  :type log_file: str
  :param log_level: specifies the log level
  :type log_level: str
  :return: logger object
  """
  if not (isinstance(name, str) and (isinstance(log_file, str) or log_file == None) and isinstance(log_level, str)):
    raise TypeError("Arguments not all strings")

  logger = logging.getLogger(name)
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  log_level = log_level.upper()
  if log_level == 'DEBUG':
    logger.setLevel(logging.DEBUG)

  elif log_level == 'INFO':
    logger.setLevel(logging.INFO)

  elif log_level == 'WARNING':
    logger.setLevel(logging.WARNING)

  elif log_level == 'ERROR':
    logger.setLevel(logging.ERROR)

  elif log_level == 'CRITICAL':
    logger.setLevel(logging.CRITICAL)

  # Log to a file
  if not (log_file == None or (sys.platform == 'win32' and name != 'sparc-II-client')):
    path, file_name = os.path.split(log_file)
    if os.path.isdir(path) == False:
      try:
        os.makedirs(path)

      except IOError:
        logger.error("Log dir doesn't exist and cannot be made")
        raise
    fileHandler = logging.FileHandler(log_file)
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

  # Log to the console
  consoleHandler = logging.StreamHandler()
  consoleHandler.setFormatter(formatter)
  logger.addHandler(consoleHandler)
  logger.propagate = False
  return logger