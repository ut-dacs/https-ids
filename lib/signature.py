#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Worker class for ids.py

import threading
import queue
import math
import traceback
import sys

class SigWorker(threading.Thread):

  def __init__(self):

    threading.Thread.__init__(self)
    import lib.absolom
    self.absolom = lib.absolom

  # Main control function
  def run(self):

    filtered_data = {}
    flow_threshold = int(self.ids.flags['flows_value'])
    for srcip in self.data.keys():

      for dstip in self.data[srcip]['targets'].keys():

        if self.data[srcip]['targets'][dstip]['flows'] >= flow_threshold:

          signature = self.match_signature(srcip, dstip)
          if self.ids.flags['absolom'] == True:

            signature_absolom = self.absolom.match_signature(self,self.data,srcip,dstip)
            if signature != signature_absolom and signature_absolom == 'everything':

              #self.logger.error("Signature does not match with Absolom signature!\n{0} -- {1}: ({2}, {3}, P:{4}, B:{5})".format(signature, signature_absolom, srcip, dstip,
              #self.ids.data[srcip]['targets'][dstip]['packet_mean'],
              #self.ids.data[srcip]['targets'][dstip]['bytes_mean']))
              signature = signature_absolom
          self.data[srcip]['targets'][dstip]['signature'] = signature
          if signature != None:

            if not srcip in filtered_data:

              filtered_data[srcip] = self.data[srcip].copy()
              filtered_data[srcip]['targets'] = {}
              filtered_data[srcip]['targets'][dstip] = self.data[srcip]['targets'][dstip]
            else:

              filtered_data[srcip]['targets'][dstip] = self.data[srcip]['targets'][dstip]
    self.result = filtered_data 

  def match_signature(self, srcip, dstip):

    # Coordinates of the target: X,Y and Z
    x = float(self.ids.data[srcip]['targets'][dstip]['packet_mean'])
    y = float(self.ids.data[srcip]['targets'][dstip]['bytes_mean'])
    #z = float(self.ids.data[srcip]['targets'][dstip]['duration_mean'])
    port = int(dstip.split(":")[1])

    # Calculate the differences and the distance
    distances = {}

    for signature in self.ids.signature:

      if port == int(self.ids.signature[signature]['port']):

        # The point still needs to fall within the signature
        accepted = False
        if self.ids.flags['packets'] == True and self.ids.flags['bytes'] == True and\
            (x >= float(self.ids.signature[signature]['packets_low']) and x <= float(self.ids.signature[signature]['packets_high'])) and\
            (y >= float(self.ids.signature[signature]['bytes_low']) and y <= float(self.ids.signature[signature]['bytes_high'])):

          accepted = True

        elif self.ids.flags['packets'] == True and self.ids.flags['bytes'] == False and\
            (x >= float(self.ids.signature[signature]['packets_low']) and x <= float(self.ids.signature[signature]['packets_high'])):

          accepted = True

        elif self.ids.flags['packets'] == False and self.ids.flags['bytes'] == True and\
            (y >= float(self.ids.signature[signature]['bytes_low']) and y <= float(self.ids.signature[signature]['bytes_high'])):

          accepted = True
        elif self.ids.flags['packets'] == False and self.ids.flags['bytes'] == False and\
            (x >= float(self.ids.signature[signature]['packets_low']) and x <= float(self.ids.signature[signature]['packets_high'])):

          accepted = True
        #if signature == "everything" and accepted == False:

          #self.logger.error("{0} -- {1}".format(self.ids.data[srcip]['targets'][dstip]['packet_mean'],self.ids.data[srcip]['targets'][dstip]['bytes_mean']))
        if accepted == True:

          x_diff = self.coordinates[signature]['x'] - x
          y_diff = self.coordinates[signature]['y'] - y
          #z_diff = self.coordinates[signature]['z'] - z

          # Pythagoras
          d = math.pow(x_diff,2) + math.pow(y_diff, 2) # + math.pow(z_diff, 2)
          d = math.sqrt(d)
          distances[signature] = d

    try:

      min_value = min(distances.values())
      match = []
      for item in distances:

        if distances[item] == min_value:

          match.append(item)
      signature = match[0]
    except:

      signature = None
    return signature

  # Returns the data to the host process
  def get_result(self):

    return self.result
