#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  This parses config files

import configparser
import os
import sys

def get_conf_file(conf_name):
  """Function for converting a config name to a path to the actual config file.
  
  :param conf_name: specifies the config name
  :type conf_name: str
  :return: path to the file as a string
  """
  if not isinstance(conf_name, str):
    raise TypeError("Argument not a string")

  if 'conf' in os.listdir(os.curdir):
    target_dir = os.path.abspath(os.path.curdir)

  elif os.path.split(sys.argv[0])[0] != "":
    target_dir = os.path.split(sys.argv[0])[0]

  else:
    raise FileNotFoundError("Conf dir not found")

  file_path = os.path.join(target_dir, 'conf', "{0}.conf".format(conf_name))
  if not os.path.isfile(file_path):
    raise FileNotFoundError("Config file {0} does not exist".format(conf_name))
  return file_path

def get_parser(conf_file):
  if not isinstance(conf_file, str):
    raise TypeError("Argument not a string")

  if not os.path.isfile(conf_file):
    raise FileNotFoundError("File {0} does not exist".format(conf_file))
  config_parser = configparser.ConfigParser()
  config_parser.read(conf_file)
  return config_parser

def get_all_options(conf_name, config_parser):
  """Function for translating a config parser config file to a Python dictionary
  :param conf_name: specifies the config file name
  :type conf_name: string
  :param config_parser: the config parser used for reading the config file
  :type config_parser: configparser object
  :return: dictionary of the options
  """
  if not (isinstance(conf_name, str) and isinstance(config_parser, configparser.ConfigParser)):
    raise TypeError("Wrong arguments given")

  if not conf_name in config_parser.sections():
     raise LookupError("Section {0} not found in given config file".format(conf_name))

  options = config_parser.options(conf_name)
  return_dict = {}
  for option in options:
    return_dict[option] = config_parser.get(conf_name, option)

  return return_dict

def read_config(conf_name):
  """Function for parsing config files.
  :param conf_name: specifies the config file to be read
  :type conf_name: str
  """
  conf_file = get_conf_file(conf_name)
  config_parser = get_parser(conf_file)
  config = get_all_options(conf_name, config_parser)
  return config

def get_signatures(config_parser):
  """Lists the configured signatures
  :return: list of signatures
  """
  if not isinstance(config_parser, configparser.ConfigParser):
    raise TypeError("Wrong arguments given")
  options = config_parser.sections()
  return options

def read_signatures():
  """Similair to read_config, however it is specified to the signatures.
  :return: dictionary of signatures with their options
  """
  conf_file = get_conf_file('signatures')
  config_parser = get_parser(conf_file)
  signatures = get_signatures(config_parser)
  signature_details = {}
  for signature in signatures:
    options = get_all_options(signature, config_parser)
    if signature in signature_details:
      raise KeyError("Duplicate signature detected")
    signature_details[signature] = options
  return signature_details