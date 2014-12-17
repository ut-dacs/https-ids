#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Worker class for ids.py

import threading
import queue
import math
import traceback
import sys

import lib.absolom
import lib.functions

class Worker(threading.Thread):
  """Signature worker class
  """
  def __init__(self, logger, flags, signatures, coordinates, data):
    threading.Thread.__init__(self)
    self.logger = logger.getChild('sigworker')
    self.flags = flags
    self.signatures = signatures
    self.coordinates = coordinates
    self.data = data

  def match_signature(self, data, signatures, srcip, dstip):
    """Function for matching a signature

    :param data: data dictionary
    :type data: dictionary
    :param signatures: signatures dictionary
    :type signatures: dictionary
    :param srcip: source ip
    :type srcip: string
    :param dstip: destination ip
    :type dstip: string
    :return: matched signature
    """
    x = float(data[srcip]['targets'][dstip]['packet_mean'])
    y = float(data[srcip]['targets'][dstip]['bytes_mean'])
    port = int(dstip.split(":")[1])
    distances = {}
    for signature in signatures:
      if port == int(signatures[signature]['port']) and not (signature == 'everything' or signature == 'everything-ssl'):
        accepted = lib.functions.check_accept(self.flags, signatures, signature, x, y)
        if accepted == True:
          d = lib.functions.pythagoras(x, y, self.coordinates[signature]['x'], self.coordinates[signature]['y'])
          distances[signature] = d

    if len(distances) == 0:
      signature = None

    else:
      min_value = min(distances.values())
      match = []
      for item in distances:
        if distances[item] == min_value:
          match.append(item)
      if len(match) > 0:
        signature = match[0]

      else:
        signature = None
    return signature

  def run(self):
    """Main function of the signature worker. Matches signatures in the given data.
    """
    filtered_data = {}
    cusum_threshold = int(self.flags['cusum_value'])
    for srcip in self.data.keys():
      for dstip in self.data[srcip]['targets'].keys():
        if self.data[srcip]['targets'][dstip]['cusum'] >= cusum_threshold:
          signature = self.match_signature(self.data, self.signatures, srcip, dstip)
          signature_absolom = lib.absolom.match_signature(self.data, srcip, dstip)
          if self.flags['break'] and self.flags['break_value'] == 'matching':
            self.logger.debug((signature, signature_absolom))

          if signature != signature_absolom and signature != None:
            self.logger.error("Signature does not match with Absolom signature!\n{0} -- {1}".format(signature, signature_absolom))
            #signature = signature_absolom
          self.data[srcip]['targets'][dstip]['signature'] = signature
          if signature != None:
            if not srcip in filtered_data:
              filtered_data[srcip] = self.data[srcip].copy()
              filtered_data[srcip]['targets'] = {}
              filtered_data[srcip]['targets'][dstip] = self.data[srcip]['targets'][dstip]

            else:
              filtered_data[srcip]['targets'][dstip] = self.data[srcip]['targets'][dstip]
    self.result = filtered_data

  def get_result(self):
    """Returns the result.

    :return: data dictionary
    """
    return self.result
