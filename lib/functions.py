#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Miscellaneous functions

import statistics
import math

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