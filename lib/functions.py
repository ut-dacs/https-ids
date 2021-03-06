#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Miscellaneous functions

import statistics
import math
import os

def convert_ipaddress(ipint):
  """Function for converting a 32 bit integer to a human readable ip address
  https://geekdeck.wordpress.com/2010/01/19/converting-a-decimal-number-to-ip-address-in-python/

  :param ipint: 32 bit int ip address
  :type ipint: integer
  :return: human readable ip address
  """
  ipint = int(ipint)
  ip=""
  for i in range(4):
    ip1 = ""
    for j in range(8):
      ip1=str(ipint % 2)+ip1
      ipint = ipint >> 1
    ip = str(int(ip1,2)) + "." + ip
  ip = ip.strip(".")
  return ip

def filter(line):
  """Function to filter bytes from a given line.

  :param line: a given string
  :type line: bytes
  """
  line = line.replace(b'\xff',bytes('','utf-8')).replace(b'\xfe',bytes('','utf-8'))
  return line

def data_statistics(data):
  """Calculates mean and stdev for the given data.

  :param data: data dictionary
  :type data: dictionary
  """
  mean = statistics.mean(data)
  if len(data) >= 2:
    stdev = statistics.stdev(data)

  else:
    stdev = 0
  return mean, stdev

def pythagoras(x1, y1, x2, y2):
  """Calculates the distance between two points.

  :param x1: x coordinate
  :type x1: integer
  :param y1: y coordinate
  :type y1: integer
  :param x2: x coordinate
  :type x2: integer
  :param y2: y coordinate
  :type y2: integer
  :return: distance between the two points
  """
  x_diff = x1 - x2
  y_diff = y1 - y2
  distance = math.pow(x_diff,2) + math.pow(y_diff, 2)
  distance = math.sqrt(distance)
  return distance

def check_accept(flags, signatures, signature, x, y):
    """Function to check if the given x and y falls inside of the given signature.
    :param signatures: dictionary of signatures
    :type signatures: dictionary
    :param signature: selected signature
    :type signature: string
    :param x: x coordinate
    :type x: int
    :param y: y coordinate
    :type y: int
    :return: accepted boolean
    """
    accepted = False
    if flags['packets'] == True and flags['bytes'] == True and\
        (x >= float(signatures[signature]['packets_low']) and x <= float(signatures[signature]['packets_high'])) and\
        (y >= float(signatures[signature]['bytes_low']) and y <= float(signatures[signature]['bytes_high'])):
      accepted = True

    elif flags['packets'] == True and flags['bytes'] == False and\
        (x >= float(signatures[signature]['packets_low']) and x <= float(signatures[signature]['packets_high'])):
      accepted = True

    elif flags['packets'] == False and flags['bytes'] == True and\
        (y >= float(signatures[signature]['bytes_low']) and y <= float(signatures[signature]['bytes_high'])):
      accepted = True

    elif flags['packets'] == False and flags['bytes'] == False and\
        (x >= float(signatures[signature]['packets_low']) and x <= float(signatures[signature]['packets_high'])):
      accepted = True
    return accepted

def nfdump_file_notation(nfdump_files):
  """Converts our file notation to nfdump file notation.

  :param nfdump_files: specifies either a single file or a range of files in a directory
  :type nfdump_files: string
  :return: nfdump file notation
  """
  nfdump_files = sorted(nfdump_files)
  if len(nfdump_files) > 1:
    begin = nfdump_files[0]
    end = nfdump_files[-1]

    begin = os.path.split(begin)
    basedir = begin[0]
    begin = begin[1]
    end = os.path.split(end)[1]
    nfdump_notation = "-R {0}/{1}:{2}".format(basedir, begin, end)

  else:
    nfdump_notation = "-r {0}".format(nfdump_files[0])
  return nfdump_notation

def time_statistics(*time):
  """Calculates time statistics. Time is a list of variable length of unix timestamps.
  This function calculates the total duration (first value is assumed beginning, last value is assumed end).
  And from there it calculates the time spent in each phase.

  :param *time: unit time stamps
  :type *time: int
  :return: pre-formatted line
  """
  diff = []
  percentages = []
  total_time = time[-1] - time[0]
  for i, item in enumerate(time):
    if i > 0:
      diff_time = item - time[i-1]
      diff.append(diff_time)

      percent = (diff_time / total_time)*100
      percentages.append(percent)

  total = "Total run time: {0} seconds.".format(total_time)
  percentage = ""
  for i, item in enumerate(percentages):
    if percentage == "":
      percentage = "{0:.3f}% of the time was in phase {{{1}}}".format(item, i)

    else:
      percentage = "{0}, {1:.3f}% of the time was in {{{2}}} phase".format(percentage, item, i)

  line = "\n".join([total, percentage])
  return line

def automation_signatures(signatures, config):
  """Function for converting configured signatures into numbers 'main.py' understands.

  :param signatures: dictionary of available signatures
  :type signatures: dictionary
  :param config: configured signatures
  :type config: string
  :return: a string of signatures main.py understands
  """
  config = config.replace(" ", "").split(",")
  numbers = []
  for i,signature in enumerate(sorted(signatures)):
    if signature in config:
      numbers.append(str(i+1))
  numbers = ",".join(numbers)
  return numbers