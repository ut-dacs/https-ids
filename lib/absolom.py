#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Implementation of the 'absolute' algorithm.

import statistics
import sys
import threading

# Logs a few debug statistics
def debug(self):

  for srcip in self.attack:

    for dstip in self.attack[srcip]['targets']:

      packet_mean = self.attack[srcip]['targets'][dstip]['packet_mean']
      if packet_mean > 9:

        self.logger.debug((srcip, dstip, packet_mean))

def add_srcip(self, srcdict, dstdict, srcip, root_keys):

  for i,key in enumerate(root_keys):

    if key == 'start_time':

      if srcip in dstdict:

        if key in dstdict[srcip]:

          value = min(int(srcdict[srcip][key]),int(dstdict[srcip][key]))
        else:

          value = int(srcdict[srcip][key])
        dstdict[srcip][key] = value
      else:

        value = int(srcdict[srcip][key])
        dstdict[srcip] = {key: value}
    elif key == 'end_time':

      if srcip in dstdict:

        if key in dstdict[srcip]:

          value = max(int(srcdict[srcip][key]),int(dstdict[srcip][key]))
        else:

          value = int(srcdict[srcip][key])
        dstdict[srcip][key] = value
      else:

        value = int(srcdict[srcip][key])
        dstdict[srcip] = {key: value}
    elif key == 'targets':

      if srcip in dstdict:

        if not key in dstdict[srcip]:

          dstdict[srcip]['targets'] = {}
      else:

        dstdict[srcip] = {key: {}}


def add_dstip(self, srcdict, dstdict, srcip, dstip, keys):

  for i,key in enumerate(keys):

    if key == 'signature':

      if srcip in dstdict:

        if dstip in dstdict[srcip]['targets']:

          if key in dstdict[srcip]['targets'][dstip]:

            for signature in srcdict[srcip]['targets'][dstip][key]:

              if signature in dstdict[srcip]['targets'][dstip][key]:

                dstdict[srcip]['targets'][dstip][key][signature] += srcdict[srcip]['targets'][dstip][key][signature]
              else:

                dstdict[srcip]['targets'][dstip][key][signature] = srcdict[srcip]['targets'][dstip][key][signature]
          else:

            dstdict[srcip]['targets'][dstip][key] = srcdict[srcip]['targets'][dstip][key]
        else:

          dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      else:

        dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}
    elif key in ['packet_mean', 'bytes_mean', 'cusum']:

      self.absolom.add_dst_mean(self, srcdict, dstdict, srcip, dstip, key)
    elif key in ['flows']:

      self.absolom.add_dst_add(self, srcdict, dstdict, srcip, dstip, key)
    elif key == 'first_seen':

      if srcip in dstdict:

        if dstip in dstdict[srcip]['targets']:

          if key in dstdict[srcip]['targets'][dstip]:

            value = min([srcdict[srcip]['targets'][dstip][key],dstdict[srcip]['targets'][dstip][key]])
          else:

            value = srcdict[srcip]['targets'][dstip][key]
          dstdict[srcip]['targets'][dstip][key] = value
        else:

          dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      else:

        dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}
    elif key == 'last_seen':

      if srcip in dstdict:

        if dstip in dstdict[srcip]['targets']:

          if key in dstdict[srcip]['targets'][dstip]:

            value = min([srcdict[srcip]['targets'][dstip][key],dstdict[srcip]['targets'][dstip][key]])
          else:

            value = srcdict[srcip]['targets'][dstip][key]
          dstdict[srcip]['targets'][dstip][key] = value
        else:

          dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      else:

        dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}
    elif key == 'url':

      if srcip in dstdict:

        if dstip in dstdict[srcip]['targets']:

          if key in dstdict[srcip]['targets'][dstip]:

            for url in srcdict[srcip]['targets'][dstip][key]:

              if url in dstdict[srcip]['targets'][dstip][key]:

                dstdict[srcip]['targets'][dstip][key][url] += srcdict[srcip]['targets'][dstip][key][url]
              else:

                dstdict[srcip]['targets'][dstip][key][url] = srcdict[srcip]['targets'][dstip][key][url]
          else:

            dstdict[srcip]['targets'][dstip][key] = srcdict[srcip]['targets'][dstip][key]
        else:

          dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      else:

        dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}

def add_dst_mean(self, srcdict, dstdict, srcip, dstip, key):

  if srcip in dstdict:

    if dstip in dstdict[srcip]['targets']:

      if key in dstdict[srcip]['targets'][dstip]:

        value = statistics.mean([srcdict[srcip]['targets'][dstip][key],dstdict[srcip]['targets'][dstip][key]])
      else:

        value = srcdict[srcip]['targets'][dstip][key]
      dstdict[srcip]['targets'][dstip][key] = value
    else:

      dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
  else:

    dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}

def add_dst_add(self, srcdict, dstdict, srcip, dstip, key):

  if srcip in dstdict:

    if dstip in dstdict[srcip]['targets']:

      if key in dstdict[srcip]['targets'][dstip]:

        value = srcdict[srcip]['targets'][dstip][key] + dstdict[srcip]['targets'][dstip][key]
      else:

        value = srcdict[srcip]['targets'][dstip][key]
      dstdict[srcip]['targets'][dstip][key] = value
    else:

      dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
  else:

    dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}

def add_merge(self, srcdict, dstdict, srcip, dstip):

  root_keys = srcdict[srcip].keys()
  keys = srcdict[srcip]['targets'][dstip]

  self.absolom.add_srcip(self,srcdict, dstdict, srcip, root_keys)
  self.absolom.add_dstip(self,srcdict, dstdict, srcip, dstip, keys)

def add_counting(self, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets):

  first_seen = int("{0}{1}".format(first,first_msec.zfill(3)))
  last_seen = int("{0}{1}".format(last,last_msec.zfill(3)))
  if srcip in self.counting:

    if dstip in self.counting[srcip]['targets']:

      for key in self.counting[srcip]['targets'][dstip]:

        if key == "first_seen":

          self.counting[srcip]['start_time'] = min([first_seen, self.counting[srcip]['start_time']])
          self.counting[srcip]['targets'][dstip][key] = min([first_seen, self.counting[srcip]['targets'][dstip][key]])
        elif key == "last_seen":

          self.counting[srcip]['end_time'] = min([last_seen, self.counting[srcip]['end_time']])
          self.counting[srcip]['targets'][dstip][key] = max([last_seen, self.counting[srcip]['targets'][dstip][key]])
        elif key in ['packet_mean', 'bytes_mean']:

          if key == 'packet_mean':

            value = int(no_pkts)
          elif key == 'bytes_mean':

            value = int(no_octets)
          self.counting[srcip]['targets'][dstip][key] = statistics.mean([value, self.counting[srcip]['targets'][dstip][key]])
        elif key in ['flows', 'cusum']:

          self.counting[srcip]['targets'][dstip][key] += 1
        elif key == 'signature':

          if signature in self.counting[srcip]['targets'][dstip]['signature']:

            self.counting[srcip]['targets'][dstip]['signature'][signature] += 1
          else:

            self.counting[srcip]['targets'][dstip]['signature'][signature] = 1
        elif key == 'url':

          url = '{0}{1}'.format(host,page)
          if url in self.counting[srcip]['targets'][dstip][key]:

            self.counting[srcip]['targets'][dstip][key][url] += 1
          else:

            self.counting[srcip]['targets'][dstip][key][url] = 1
    else:

      self.counting[srcip]['targets'][dstip] = {'signature':      {signature:1},
                                                'packet_mean':    int(no_pkts),
                                                'bytes_mean':     int(no_octets),
                                                'cusum':          1,
                                                'flows':          1,
                                                'first_seen':     int(first_seen),
                                                'last_seen':      int(last_seen),
                                                'url':            {"{0}{1}".format(host,page):1},
                                                }
      self.counting[srcip]['start_time'] = min([first_seen, self.counting[srcip]['start_time']])
      self.counting[srcip]['end_time'] = min([last_seen, self.counting[srcip]['end_time']])
  else:

    self.counting[srcip] = {'start_time':         int(first_seen),
                            'end_time':           int(last_seen),
                            'targets':            {
                              dstip:              {
                                'signature':      {signature:1},
                                'packet_mean':    int(no_pkts),
                                'bytes_mean':     int(no_octets),
                                'cusum':          1,
                                'flows':          1,
                                'first_seen':     first_seen,
                                'last_seen':      last_seen,
                                'url':            {"{0}{1}".format(host,page):1},
                                }
                              }
                            }

# Move an attack from the counting dictionary to the attack dictionary
def add_attack(self, srcip, dstip):

  if self.counting[srcip]['targets'][dstip]['cusum'] >= self.ids.flags['cusum_value']:

    self.absolom.add_merge(self, self.counting, self.attack, srcip, dstip)
  else:

    self.counting[srcip]['targets'][dstip]['signature'] = {'everything': 1}
    self.absolom.add_merge(self, self.counting, self.everything, srcip, dstip)
  self.absolom.del_counting(self, srcip, dstip)

def add_everything(self, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets):

  if srcip in self.counting:

    if dstip in self.counting[srcip]['targets']:

      self.absolom.add_attack(self, srcip,dstip)

  self.absolom.add_counting(self, srcip, dstip, first, first_msec, last, last_msec, 'everything', host, page, no_pkts, no_octets)
  self.absolom.add_merge(self, self.counting, self.everything, srcip, dstip)
  self.absolom.del_counting(self, srcip, dstip)

def del_counting(self, srcip, dstip):

  if len(self.counting[srcip]['targets']) <= 1:

    del self.counting[srcip]
  else:

    del self.counting[srcip]['targets'][dstip]

# Flushes data from the counting dictionary
def flush_attack(self, srcip, dstip):

  flushed = False
  if srcip in self.counting:

    if dstip in self.counting[srcip]['targets']:

      try:

        self.absolom.add_attack(self, srcip, dstip)
        flushed = True
      except:

        self.logger.exception("Pardon me for breathing, which I never do anyway so I don't know why I bother to say it, oh God, I'm so depressed.")
        sys.exit()
  return flushed

# Flushes all the remaining traffic in the counting dictionary
def flush(self):

  while len(self.counting) > 0:

    srcip_list = list(self.counting.keys())
    count = 0
    tuples = {}
    for srcip in srcip_list:

      count += len(self.counting[srcip]['targets'])
      tuples[srcip] = list(self.counting[srcip]['targets'].keys())
    self.logger.debug("{0} left in counting".format(count))
    i = 0
    for srcip in tuples:

      for dstip in tuples[srcip]:

        if self.ids.flags['verbose'] == True:

          if i%1000 == 0:

            self.logger.debug("{0} - Flush: {1}/{2}".format(threading.current_thread().name,i+1, count))
        self.absolom.flush_attack(self,srcip,dstip)
        i += 1

# Processes a data line
def data_line(self, line):

  try:

    line = line.replace(b'\xff',bytes('','utf-8')).replace(b'\xfe',bytes('','utf-8'))
    data = str(line, 'utf-8').replace("\n","").split("|")
    length = len(data)
    if length == 24:

      af, first, first_msec, last, last_msec, prot,\
        sa_0, sa_1, sa_2, sa_3, src_port,\
        da_0, da_1, da_2, da_3, dst_port,\
        src_as, dst_as, r_input, r_output,\
        flags, tos, no_pkts, no_octets = data
      host = ''
      page = ''

    elif length == 28 or length == 49:

      af, first, first_msec, last, last_msec, prot,\
          sa_0, sa_1, sa_2, sa_3, src_port,\
          da_0, da_1, da_2, da_3, dst_port,\
          src_as, dst_as, r_input, r_output,\
          flags, tos, no_pkts, no_octets,\
          something, http_port, host, page = data[0:28]
      self.ids.extended = True
    else:

      return

    # Grab a signature
    srcip = self.convert_ipaddress(sa_3)
    dstip = "{0}:{1}".format(self.convert_ipaddress(da_3),dst_port)
    signature, no_pkts, no_octets = self.absolom.descriminator(self,float(no_pkts), float(no_octets), int(dst_port), flags, srcip, dstip)

    # Based on the signature and flags perform any of these actions
    # TCP flag filter: 26: .AP.S., 27: .AP.SF
    flag_filter = 27
    if int(flags) >= flag_filter and signature != 'reset' and signature != 'everything':

      self.absolom.add_counting(self,srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets)
    elif int(flags) >= flag_filter and signature == 'everything':

      self.absolom.add_everything(self,srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets)
    else:

      flushed = self.absolom.flush_attack(self,srcip, dstip)
      if flushed == False:

        self.absolom.add_everything(self,srcip, dstip, first, first_msec, last, last_msec, 'everything', host, page, no_pkts, no_octets)

  except:

    self.logger.exception("Funny, how just when you think life can't possibly get any worse it suddenly does.\n{0}".format(line))

def mod_accept(self, x, y, srcip, dstip):

  times = 1
  if self.ids.flags['nmod'] == False and srcip in self.counting:

    if dstip in self.counting[srcip]['targets']:

      try:

        packet_mean = int(round(self.counting[srcip]['targets'][dstip]['packet_mean'],0))
        if self.ids.flags['pmod'] == True:

          if x%packet_mean == 0:

            times = int(round(x/packet_mean,0))
        else:

          if x%packet_mean in [packet_mean-1, 0 , 1]:

            times = int(round(x/packet_mean,0))
      except:

        self.logger.exception(self.attack[srcip]['targets'][dstip].keys())

      if times == 0:

        times = 1
      x = float(x)/times
      y = float(y)/times
  return x,y

def descriminator(self, packets, bytes, port, flags, srcip, dstip):

  x,y = self.absolom.mod_accept(self, packets, bytes, srcip, dstip)
  return_signature = 'reset'
  signatures = list(sorted(self.ids.signature.keys()))

  # Make sure everything is checked last
  if "everything" in signatures:

    signatures.remove("everything")
    signatures.append("everything")

  # Select the first signature that matches
  for signature in signatures:

    if port == int(self.ids.signature[signature]['port']):

      # The point still needs to fall within the signature
      if self.ids.flags['packets'] == True and self.ids.flags['bytes'] == True:

        if ((x >= float(self.ids.signature[signature]['packets_low']) and x <= float(self.ids.signature[signature]['packets_high'])) and\
            (y >= float(self.ids.signature[signature]['bytes_low']) and y <= float(self.ids.signature[signature]['bytes_high']))):

          if self.ids.flags['tcp_flags'] == False or int(self.ids.signature[signature]['flags']) == 0 or int(self.ids.signature[signature]['flags']) == int(flags):

            return_signature = signature
            break
      elif self.ids.flags['packets'] == True and self.ids.flags['bytes'] == False:

        if (x >= float(self.ids.signature[signature]['packets_low']) and x <= float(self.ids.signature[signature]['packets_high'])):

          if self.ids.flags['tcp_flags'] == False or int(self.ids.signature[signature]['flags']) == 0 or int(self.ids.signature[signature]['flags']) == int(flags):

            return_signature = signature
            break
      elif self.ids.flags['packets'] == False and self.ids.flags['bytes'] == True:

        if (y >= float(self.ids.signature[signature]['bytes_low']) and y <= float(self.ids.signature[signature]['bytes_high'])):

          if self.ids.flags['tcp_flags'] == False or int(self.ids.signature[signature]['flags']) == 0 or int(self.ids.signature[signature]['flags']) == int(flags):

            return_signature = signature
            break
      elif self.ids.flags['packets'] == False and self.ids.flags['bytes'] == False:

        if (x >= float(self.ids.signature[signature]['packets_low']) and x <= float(self.ids.signature[signature]['packets_high'])):

          if self.ids.flags['tcp_flags'] == False or int(self.ids.signature[signature]['flags']) == 0 or int(self.ids.signature[signature]['flags']) == int(flags):

            return_signature = signature
            break
  return (return_signature, x, y)

# Merges data with result, child function
def process_merger(self, data, result, srcip, dstip):

  data[srcip]['targets'][dstip]['packet_mean'] = statistics.mean([result[srcip]['targets'][dstip]['packet_mean'],data[srcip]['targets'][dstip]['packet_mean']])
  data[srcip]['targets'][dstip]['bytes_mean'] = statistics.mean([result[srcip]['targets'][dstip]['bytes_mean'],data[srcip]['targets'][dstip]['bytes_mean']])
  data[srcip]['targets'][dstip]['flows'] += result[srcip]['targets'][dstip]['flows']
  for signature in result[srcip]['targets'][dstip]['signature']:

    if signature in data[srcip]['targets'][dstip]['signature']:

      data[srcip]['targets'][dstip]['signature'][signature] += result[srcip]['targets'][dstip]['signature'][signature]
    else:

      data[srcip]['targets'][dstip]['signature'][signature] = result[srcip]['targets'][dstip]['signature'][signature]
  if result[srcip]['targets'][dstip]['first_seen'] < data[srcip]['targets'][dstip]['first_seen']:

    data[srcip]['targets'][dstip]['first_seen'] = result[srcip]['targets'][dstip]['first_seen']
  if result[srcip]['targets'][dstip]['last_seen'] < data[srcip]['targets'][dstip]['last_seen']:

    data[srcip]['targets'][dstip]['last_seen'] = result[srcip]['targets'][dstip]['last_seen']

  if 'cusum' in data[srcip]['targets'][dstip]:

    data[srcip]['targets'][dstip]['cusum'] = statistics.mean([result[srcip]['targets'][dstip]['cusum'],data[srcip]['targets'][dstip]['cusum']])

# Master merger
def merge(self, data, everything, result):

  attack = result['attack'].copy()
  everything = result['everything'].copy()

  # Merge attacks
  for srcip in attack:

    for dstip in attack[srcip]['targets']:

      if not srcip in data:

        data.update(attack)
      else:

        first_seen = attack[srcip]['targets'][dstip]['first_seen']
        last_seen = attack[srcip]['targets'][dstip]['last_seen']
        if not dstip in data[srcip]['targets']:

          data[srcip]['targets'].update(attack[srcip]['targets'])

        else:

          self.absolom.process_merger(self,data,attack,srcip,dstip)

        if data[srcip]['start_time'] > first_seen:

          data[srcip]['start_time'] = first_seen
        if data[srcip]['end_time'] < last_seen:

          data[srcip]['end_time'] = last_seen
        data[srcip]['total_duration'] = data[srcip]['end_time'] - data[srcip]['start_time']

  # Merge everything dictionary
  for srcip in everything:

    for dstip in everything[srcip]['targets'].copy():

      if not srcip in self.everything:

        self.everything.update(everything)
      else:

        first_seen = everything[srcip]['targets'][dstip]['first_seen']
        last_seen = everything[srcip]['targets'][dstip]['last_seen']
        if not dstip in self.everything[srcip]['targets']:

          self.everything[srcip]['targets'].update(everything[srcip]['targets'])

        else:

          self.absolom.process_merger(self,self.everything,everything,srcip,dstip)

        if self.everything[srcip]['start_time'] > first_seen:

          self.everything[srcip]['start_time'] = first_seen
        if self.everything[srcip]['end_time'] < last_seen:

          self.everything[srcip]['end_time'] = last_seen
        self.everything[srcip]['total_duration'] = self.everything[srcip]['end_time'] - self.everything[srcip]['start_time']

# Removes entries from the everything dictionary if they are in the attack dictionary
def purge_everything(self):

  purged_everything = {}
  for srcip in self.everything:

    for dstip in self.everything[srcip]['targets']:

      accept = True
      if srcip in self.data:

        if dstip in self.data[srcip]['targets']:

          accept = False
          if self.extended == True and self.flags['merge']:

            urls = self.everything[srcip]['targets'][dstip]['url']
            for url in urls:

              if url in self.data[srcip]['targets'][dstip]['url'].keys():

                self.data[srcip]['targets'][dstip]['url'][url] += self.everything[srcip]['targets'][dstip]['url'][url]
              else:

                self.data[srcip]['targets'][dstip]['url'][url] = self.everything[srcip]['targets'][dstip]['url'][url]
      if accept == True:

        if srcip in purged_everything:

          purged_everything[srcip]['targets'][dstip] = self.everything[srcip]['targets'][dstip]
        else:

          purged_everything[srcip] = self.everything[srcip].copy()
          purged_everything[srcip]['targets'] = {dstip: self.everything[srcip]['targets'][dstip].copy()}
  self.everything = purged_everything

# See which signature was matched most of the time
def match_signature(self, data, srcip, dstip):

  signatures = data[srcip]['targets'][dstip]['signature']
  try:
    max_value = max(signatures.values())
    match = []
    for signature in signatures:

      if signatures[signature] == max_value:

        match.append(signature)

    signature = match[0]
  except:

    if not type(data[srcip]['targets'][dstip]['signature']) == type(''):

      signature = 'everything'
    else:

      signature = data[srcip]['targets'][dstip]['signature']
  return signature
