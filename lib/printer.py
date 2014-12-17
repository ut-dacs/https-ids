#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  The printing module

import datetime
import os
import re
import subprocess
import sys
import time
import io

try:
  from termcolor import colored

except ImportError:
  print("Import failed")
  pass

import lib.flags

header_order = ['src','dst',

          'packet_mean', 'packet_stdev',
          'bytes_mean', 'bytes_stdev',
          'duration_mean', 'duration_stdev',

          'flows', 'flow_duration',
          'cusum',
          'reset', 'attack',

          'activity', 'total_duration',
          'first_seen', 'last_seen',
          'start_time', 'end_time',
          'signature',
          ]
header_dict = { 'src': '{:>20}','dst':'{:>20}',

                'start_time':'{:>26}', 'end_time':'{:>26}',
                'first_seen':'{:>26}', 'last_seen':'{:>26}',
                'activity':'{:>10}', 'total_duration':'{:>20}',

                'packet_mean':'{:>12}', 'packet_stdev':'{:>14}',
                'bytes_mean':'{:>11}', 'bytes_stdev':'{:>13}',
                'duration_mean':'{:>14}', 'duration_stdev':'{:>16}',
                'flows':'{:>10}', 'flow_duration':'{:>14}',
                'signature':'{:>15}',

                'attack': '{:>10}',
                'reset': '{:>10}',
                'cusum': '{:>10}',
              }

def get_options():
  """Returns a string based on the given flags.
  Usefull for filenames.

  :return: string with options
  """
  flags = lib.flags.get_flags()
  if flags['bytes'] and flags['packets']:
    options = "ppf-bpf"

  elif flags['bytes']:
    options = "bpf"

  else:
    options = "ppf"

  options = "{0}-{1}".format(options, flags['cusum_value'])
  return options

def get_action(action):
  """Returns the appropriate function for the given action.

  :param action: action to take
  :type action: string
  """
  if action in ['disk']:
    print_message = write_to_file

  elif action in ['pager']:
    print_message = write_to_pager
  return print_message

def open_file(output_dir, signatures, date):
  """Open a file descriptor.

  :param signatures: dictionary of used signatures
  :type signatures: dictionary
  :param output_dir: specifies the output directory
  :type output_dir: string
  :return: file descriptor
  """
  if not (isinstance(signatures, dict) and isinstance(date, str) and isinstance(output_dir, str)):
    raise TypeError("Arguments are of wrong type")
  signatures = "_".join(sorted(signatures))
  options = get_options()
  file_name = "{0}-{1}-{2}.ids".format(signatures, date, options)
  file_path = os.path.join(output_dir, file_name)
  path, file_name = os.path.split(file_path)
  if os.path.isdir(path) == False:
    try:
      os.makedirs(path)

    except IOError:
      raise
  return open(file_path, 'wb')

def open_pager(output):
  """Opens a pager with to the given output (usually sys.stdout).

  :param output: specifies to where the output should go
  """
  pager = subprocess.Popen(['less', '-F', '-R', '-S', '-X', '-K'],
                           stdin=subprocess.PIPE, stdout=output)
  return pager

def open_parsable_file(output_dir, signatures, date):
  """Function for opening a file for parsable output.

  :param output_dir: specifies the output directory
  :type output_dir: string
  :param signatures: a list of the used signatures
  :type signatures: list
  :param date: a date string
  :type date: string
  :return: a filedescriptor
  """
  if not (isinstance(signatures, dict) and isinstance(date, str) and isinstance(output_dir, str)):
    raise TypeError("Arguments are of wrong type")
  signatures = "_".join(sorted(signatures))
  options = get_options()
  file_name = "{0}-{1}-{2}.idats".format(signatures, date, options)
  file_path = os.path.join(output_dir, file_name)
  path, file_name = os.path.split(file_path)
  if os.path.isdir(path) == False:
    try:
      os.makedirs(path)

    except IOError:
      raise
  return open(file_path, 'wb')

def write_to_file(fd, message, color=None):
  """Writes a message to the given file descriptor. It takes care of line endings and encoding for you.

  :param fd: the filedescriptor
  :type fd: io.BufferedWriter
  :param message: the message to be written
  :type message: string
  :param color: dummy variable, not used
  """
  if not (isinstance(fd, io.BufferedWriter) and isinstance(message, str)):
    raise TypeError("Arguments of wrong type")

  if 'colored' in dir():
    message = colored(message,color)

  if not message.endswith("\n"):
    message += "\n"

  message_bytes = bytes(message, 'utf-8')
  fd.write(message_bytes)

def write_to_pager(pager, message, color):
  """Writes a message to the given pager. If termcolor is available it will even be written in the given color.

  :param pager: the pager to write to
  :type pager: subprocess.Popen
  :param message: the message to write
  :type message: string
  :param color: the color to write the message in
  :type color: string
  """
  if not (isinstance(pager, subprocess.Popen)
          and isinstance(message, str)
          and (isinstance(color, str) or color == None)):
    raise TypeError("Arguments are of wrong type")
  if not message.endswith("\n"):

    message += "\n"

  if 'termcolor' in sys.modules.keys() and color != None:
    message = colored(message,color)

  message = bytes(message, 'utf-8')
  pager.stdin.write(message)

def legenda(fd, action, count):
  """Prints a legenda to the given file descriptor.

  :param fd: filedescriptor, can be an actual filedescriptor or a pager
  :type fd: io.BufferedWriter or subprocess.Popen
  :param action: specifies where the output should go
  :type action: string
  :param count: dictionary containing signature hit counters
  :type count: dictionary
  """
  if not isinstance(action, str):
    raise TypeError("Arguments of the wrong type")

  print_message = get_action(action)
  if 'colored' in dir():
    message = "\nLegenda: [Red: packet-stdev && bytes-stdev && duration-stdev == 0], [Magenta: two of <- are equal to 0], [White: one is equal to 0]"
    print_message(fd, message, None)

  for signature in count:
    message = "{0} ips match signature '{1}'".format(count[signature], signature)
    print_message(fd, message, None)

  print_message(fd, "", None)

def header(fd, action, data):
  """Prints a header for a given data set.

  :param fd: filedescriptor, can be an actual filedescriptor or a pager
  :type fd: io.BufferedWriter or subprocess.Popen
  :param action: specifies where the output should go
  :type action: string
  :param data: the data set
  :type data: dictionary
  :return: list of used items
  """
  print_message = get_action(action)
  line = []
  used = []

  srcip = list(data.keys())[0]
  dstip = list(data[srcip]['targets'].keys())[0]
  keys = list(data[srcip]['targets'][dstip].keys())
  for item in ['targets', 'url']:
    if item in keys:
      keys.remove(item)
  keys.insert(0, 'src')
  keys.insert(1, 'dst')
  dictionary = {}
  for item in keys:
    dictionary[item] = header_dict[item].format(item)

  for item in header_order:
    if item in dictionary.keys():
      line.append(dictionary[item])
      used.append(item)

  line = "".join(line)
  line = line.replace("_","-").replace("   src","src ->")
  length = len(line)
  print_message(fd, line, None)
  sub = '{:=^'+str(length)+'}'
  line = sub.format('')
  print_message(fd, line, None)
  return used

def format_value(item, value):
  """Formats values according to some set rules.

  :param item: identifier, what kind of value is given
  :type item: string
  :param value: value of the item
  :return: formatted string
  """
  if not isinstance(item, str):
    raise TypeError("Arguments of wrong type")

  if item in ['start_time','end_time',
              'first_seen', 'last_seen',
              'total_duration', 'duration_mean',
              'duration_stdev', 'flow_duration']:
    value = value/1000

  if item in ['start_time','end_time', 'first_seen', 'last_seen']:
    value = str(datetime.datetime.fromtimestamp(value))
    value = "{0}".format(value[:-4])

  if item == 'total_duration':
    value = str(datetime.timedelta(seconds=int(value)))

  if item in ['packet_mean','packet_stdev','bytes_mean','bytes_stdev']:
    value = float(value)

  if item in ['packet_mean','packet_stdev',
                'bytes_mean','bytes_stdev',
                'duration_mean','duration_stdev',
                'flow_duration', 'flows',
                'cusum', 'activity']:
    value = "{0:.2f}".format(value)
  return value

def print_urls(fd, action, color, urls):
  """Function for nicely printing a dictionary of urls.
  The dictionary is expected to hold a hit count.

  :param fd: filedescriptor, can be an actual filedescriptor or a pager
  :type fd: io.BufferedWriter or subprocess.Popen
  :param action: specifies where the output should go
  :type action: string
  :param color: denotes the color
  :type color: string or None
  :param urls: dictionary of urls
  :type urls: dictionary
  """
  if not (isinstance(action, str)
          and (isinstance(color, str) or color == None)
          and isinstance(urls, dict)):
    raise TypeError("Arguments are of the wrong type")

  print_message = get_action(action)
  for item in sorted(urls.keys()):
    if item != "":
      count = "{:>44}".format("[{0}]".format(urls[item]))
      url = re.sub('^([^/]*)/',"", item)
      line = "{0}: {1}".format(count, url)
      print_message(fd, line ,color)

def print_parsable_urls(urls):
  """Converts a urls dictionary into a single line.

  :param urls: dictionary of urls and their hitcount
  :type: urls: dictionary
  :return: string of urls
  """
  url_line = []
  for url in urls:
    if url != "":
      count = urls[url]
      line = "{0}\\{1}".format(url,count)
      url_line.append(line)
  url_line = "\\".join(url_line)
  return url_line

def print_srcip(data, srcip, used):
  """Formats the data fields belonging to the source in a nice line.

  :param data: data dictionary
  :type data: dictionary
  :param srcip: the source ip
  :type srcip: string
  :param used: list of used data fields (the header function returns this)
  :type used: list
  :return: formatted string
  """
  if not (isinstance(data, dict) and isinstance(srcip, str) and isinstance(used, list)):
    raise TypeError("Arguments of wrong type")

  line = []
  keys = list(data[srcip].keys())
  keys.remove('targets')
  for item in used:
    if item == 'first_seen':
      item = 'start_time'

    if item == 'last_seen':
      item = 'end_time'

    if item in keys:
      value = data[srcip][item]
      value = format_value(item, value)
      value = header_dict[item].format(value)
    elif item == 'src':
      value = header_dict[item].format(srcip)

    elif item == 'dst':
      value = header_dict[item].format('\U000021B4')

    else:
      value = header_dict[item].format(' ')

    line.append(value)
  line = "".join(line)
  return line

def print_dstip(signatures, data, srcip, dstip, used):
  """Formats the data fields belonging to the destination in a nice line.

  :param data: data dictionary
  :type data: dictionary
  :param srcip: the source ip
  :type srcip: string
  :param dstip: the destination ip
  :type dstip: string
  :param used: list of used data fields (the header function returns this)
  :type used: list
  :return: formatted string
  """
  flags = lib.flags.get_flags()
  line = []
  color = signatures[data[srcip]['targets'][dstip]['signature']]['color']
  if flags['flows'] == False or data[srcip]['targets'][dstip]['flows'] >= flags['flows_value']:
    keys = list(data[srcip]['targets'][dstip].keys())
    if 'url' in keys:
      keys.remove('url')

    for item in used:
      if item in keys:
        value = data[srcip]['targets'][dstip][item]
        value = format_value(item, value)
        value = header_dict[item].format(value)

      elif item == 'src':
        value = header_dict[item].format('\U000021D2')

      elif item == 'dst':
        value = header_dict[item].format(dstip)

      else:
        value = header_dict[item].format(' ')

      line.append(value)
  line = "".join(line)
  return line, color

def print_parsable_dstip(data, srcip, dstip):
  """Returns a parsable data line for the destination data.

  :param data: the data source
  :type data: dictionary
  :param scrip: the source ip
  :type srcip: string
  :param dstip: the destination ip
  :type dstip: string
  :return: a line of urls and their hitcount
  """
  line = []
  for item in header_order:
    if item in data[srcip]['targets'][dstip]:
      value = data[srcip]['targets'][dstip][item]

    elif item == "src":
      value = srcip

    elif item == "dst":
      value = dstip.replace(":", "|")

    else:
      value = ""

    if value != "":
      line.append(str(value))

  if 'url' in data[srcip]['targets'][dstip]:
    line.append(print_parsable_urls(data[srcip]['targets'][dstip]['url']))

  line = "|".join(line)
  return line

def print_data(fd, action, signatures, data, count):
  """Prints data to the given filedescriptor

  :param fd: filedescriptor
  :type fd: io.BufferedWriter or subprocess.Popen
  :param action: the action to take
  :type action: string
  :param data: the data dictionary to print
  :type data: dictionary
  :param count: signature hit count dictionary
  :type count: dictionary
  """
  if len(data) == 0:
    return

  print_message = get_action(action)
  legenda(fd, action, count)
  used = header(fd, action, data)
  for srcip in data:
    line = print_srcip(data,srcip, used)
    print_message(fd, line, None)
    for dstip in data[srcip]['targets']:
      line, color = print_dstip(signatures, data, srcip, dstip, used)
      print_message(fd, line, color)
      if 'url' in data[srcip]['targets'][dstip] and len(data[srcip]['targets'][dstip]['url']) > 0:
        urls = data[srcip]['targets'][dstip]['url']
        print_urls(fd, action, None, urls)
    print_message(fd, '', None)

def print_parsable_data(fd, data):
  """Prints the data in a parsable manner to the filedescriptor.

  :param fd: file descriptor
  :type fd: io.BufferedWriter
  :param data: dictionary to print
  :type data: dictionary
  """
  if len(data) == 0:
    return

  for srcip in data:
    for dstip in data[srcip]['targets']:
      line = print_parsable_dstip(data, srcip, dstip)
      write_to_file(fd, line)