#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Implementation of the 'absolute' algorithm.

import statistics
import sys

# Custom libs
import lib.functions

def mod_accept(flags, counting, pkts, bts, srcip, dstip):
  """Modulus accept to allow a bit of variance in flows.
  When a flow is doubled it is still accepted.

  :param flags: flags dictionary
  :type flags: dictionary
  :param counting: counting dictionary
  :type counting: dictionary
  """
  times = 1
  x = pkts
  y = bts
  if srcip in counting:
    if dstip in counting[srcip]['targets']:
      packet_mean = int(round(counting[srcip]['targets'][dstip]['packet_mean'],0))
      if x%packet_mean == 0:
        times = int(round(x/packet_mean,0))

      else:
        if x%packet_mean in [packet_mean-1, 0 , 1]:
          times = int(round(x/packet_mean,0))

      if times == 0:
        times = 1

      x = float(x)/times
      y = float(y)/times
  return x,y

def descriminator(flags, signatures, counting, srcip, dstip, pkts, bts, port, tcp_flags):
  """Descriminator function, does something... I think.

  :param flags: flags dictionary
  :type flags: dictionary
  :param signatures: signatures dictionary
  :type signatures: dictionary
  :param counting: counting dictionary
  :type counting: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :param pkts: number of packets
  :type pkts: int
  :param bts: amount of bytes
  :type bts: int
  :param port: TCP port number
  :type port: int
  :return: tuple of (signature, pkts, bts)
  """

  x,y = mod_accept(flags, counting, pkts, bts, srcip, dstip)
  return_signature = 'reset'
  signatures_list = list(sorted(signatures.keys()))

  # Make sure everything is checked last
  if "everything" in signatures_list:
    signatures_list.remove("everything")
    signatures_list.append("everything")

  for signature in signatures_list:
    if port == int(signatures[signature]['port']):
      if lib.functions.check_accept(flags, signatures, signature, x, y) == True:
         if flags['tcp_flags'] == False or int(signatures[signature]['flags']) == 0 or int(signatures[signature]['flags']) == int(tcp_flags):
            return_signature = signature
            break
  return (return_signature, x, y)

def merge_move_target(src_dict, dst_dict, srcip, dstip):
  """Merges an entry from source dictionary to destination dictionary.
  It is assumed here that both the source ip and destination ip exist in the destination dictionary.

  :param src_dict: source dictionary
  :type src_dict: dictionary
  :param dst_dict: destination dictionary
  :type dst_dict: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :return: dst_dict
  """
  for key in src_dict[srcip]['targets'][dstip]:
    if key == "first_seen":
      dst_dict[srcip]['start_time'] = min([src_dict[srcip]['start_time'], dst_dict[srcip]['start_time']])
      dst_dict[srcip]['targets'][dstip][key] = min([src_dict[srcip]['targets'][dstip][key], dst_dict[srcip]['targets'][dstip][key]])

    elif key == "last_seen":
      dst_dict[srcip]['end_time'] = max([src_dict[srcip]['end_time'], dst_dict[srcip]['end_time']])
      dst_dict[srcip]['targets'][dstip][key] = max([src_dict[srcip]['targets'][dstip][key], dst_dict[srcip]['targets'][dstip][key]])

    elif key in ['packet_mean', 'bytes_mean']:
      dst_dict[srcip]['targets'][dstip][key] = statistics.mean([src_dict[srcip]['targets'][dstip][key], dst_dict[srcip]['targets'][dstip][key]])

    elif key in ['flows', 'cusum']:
      dst_dict[srcip]['targets'][dstip][key] += src_dict[srcip]['targets'][dstip][key]

    elif key in ['signature', 'url']:
      for item in src_dict[srcip]['targets'][dstip][key]:
        if item in dst_dict[srcip]['targets'][dstip][key]:
          dst_dict[srcip]['targets'][dstip][key][item] += src_dict[srcip]['targets'][dstip][key][item]

        else:
          dst_dict[srcip]['targets'][dstip][key][item] = src_dict[srcip]['targets'][dstip][key][item]
  return dst_dict

def del_from_dict(dictionary, srcip, dstip):
  """Removes an entry from the given dictionary.
  Assumed is that srcip and dstip exist in the dictionary.
  :param dictionary: dictionary to remove an entry from
  :type dictionary: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :return: dictionary
  """
  if len(dictionary[srcip]['targets']) <= 1:
    del dictionary[srcip]

  else:
    del dictionary[srcip]['targets'][dstip]
  return dictionary

def add_counting(counting, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets):
  """Function to add an entry to the counting dictionary.

  :param counting: counting dictionary
  :type counting: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :param first: first seen time
  :type first: int
  :param first_msec: first seen time
  :type first_msec: int
  :param last: last seen time
  :type last: int
  :param last_msec: last seen time
  :type last_msec: int
  :param signature: given signature
  :type signature: string
  :param host: host visited
  :type host: string
  :param page: page visited
  :type page: string
  :param no_pkts: number of packets
  :type no_pkts: int
  :param no_octets: number of bytes
  :type no_octets: int
  :return: counting dictionary
  """
  first_seen = int("{0}{1}".format(first,first_msec.zfill(3)))
  last_seen = int("{0}{1}".format(last,last_msec.zfill(3)))
  src_dict = {
    srcip: {
      'start_time':         first_seen,
      'end_time':           last_seen,
      'total_duration':     last_seen - first_seen,
      'targets':{
        dstip:{
          'packet_mean':  int(no_pkts),
          'bytes_mean':   int(no_octets),
          'flows':        1,
          'cusum':        1,
          'first_seen':   first_seen,
          'last_seen':    last_seen,
          'signature':    {signature: 1},
          'url':          {"{0}{1}".format(host,page): 1}
        }
      }
    }
  }
  if srcip in counting:
    if dstip in counting[srcip]['targets']:
      counting = merge_move_target(src_dict, counting, srcip, dstip)

    else:
      counting[srcip]['targets'][dstip] = src_dict[srcip]['targets'][dstip].copy()
      counting[srcip]['start_time'] = min([first_seen, counting[srcip]['start_time']])
      counting[srcip]['end_time'] = min([last_seen, counting[srcip]['end_time']])
  else:
    counting[srcip] = src_dict[srcip].copy()
  return counting

def add_attack(flags, counting, attack, everything, srcip, dstip):
  """Function to move an entry from the counting dictionary to the attack dictionary.

  :param flags: flag dictionary
  :type flags: dictionary
  :param counting: counting dictionary
  :type counting: dictionary
  :param attack: attack dictionary
  :type attack: dictionary
  :param everything: everything dictionary
  :type everything: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :return: tuple of changed dictionaries (counting, attack, everything)
  """
  if counting[srcip]['targets'][dstip]['cusum'] >= flags['cusum_value']:
    if srcip in attack:
      if dstip in attack[srcip]['targets']:
        attack = merge_move_target(counting, attack, srcip, dstip)

      else:
        attack[srcip]['targets'][dstip] = counting[srcip]['targets'][dstip].copy()
        attack[srcip]['start_time'] = min([counting[srcip]['start_time'], attack[srcip]['start_time']])
        attack[srcip]['end_time'] = max([counting[srcip]['end_time'], attack[srcip]['end_time']])

    else:
      attack[srcip] = {
        'start_time':    counting[srcip]['start_time'],
        'end_time':      counting[srcip]['end_time'],
        'total_duration':counting[srcip]['total_duration'],
        'targets':{
          dstip: counting[srcip]['targets'][dstip]
        },
      }

  else:
    #counting[srcip]['targets'][dstip]['signature'] = {'everything': 1}
    if srcip in everything:
      if dstip in everything[srcip]['targets']:
        everything = merge_move_target(counting, everything, srcip, dstip)

      else:
        everything[srcip]['targets'][dstip] = counting[srcip]['targets'][dstip].copy()
        everything[srcip]['start_time'] = min([counting[srcip]['start_time'], everything[srcip]['start_time']])
        everything[srcip]['end_time'] = max([counting[srcip]['end_time'], everything[srcip]['end_time']])

    else:
      everything[srcip] = counting[srcip].copy()
  counting = del_from_dict(counting, srcip, dstip)
  return (counting, attack, everything)

def add_everything(flags, counting, attack, everything, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets):
  """Adds an entry to the everything dictionary.

  :param flags: flag dictionary
  :type flags: dictionary
  :param counting: counting dictionary
  :type counting: dictionary
  :param attack: attack dictionary
  :type attack: dictionary
  :param everything: everything dictionary
  :type everything: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :param first: first seen time
  :type first: int
  :param first_msec: first seen time
  :type first_msec: int
  :param last: last seen time
  :type last: int
  :param last_msec: last seen time
  :type last_msec: int
  :param signature: given signature
  :type signature: string
  :param host: host visited
  :type host: string
  :param page: page visited
  :type page: string
  :param no_pkts: number of packets
  :type no_pkts: int
  :param no_octets: number of bytes
  :type no_octets: int
  :return: tuple of (counting, attack, everything)
  """
  if srcip in counting:
    if dstip in counting[srcip]['targets']:
      counting, attack, everything = add_attack(flags, counting, attack, everything, srcip,dstip)
      return (counting, attack, everything)

  if srcip in attack:
    if dstip in attack[srcip]['targets']:
      return (counting, attack, everything)

  first_seen = int("{0}{1}".format(first,first_msec.zfill(3)))
  last_seen = int("{0}{1}".format(last,last_msec.zfill(3)))
  src_dict = {

    srcip: {
      'start_time':         first_seen,
      'end_time':           last_seen,
      'total_duration':     last_seen - first_seen,
      'targets':{
        dstip:{
          'packet_mean':  int(no_pkts),
          'bytes_mean':   int(no_octets),
          'flows':        1,
          'cusum':        1,
          'first_seen':   first_seen,
          'last_seen':    last_seen,
          'signature':    {'everything': 1},
          'url':          {"{0}{1}".format(host,page): 1}
        }
      }
    }
  }
  if srcip in everything:
    if dstip in everything[srcip]['targets']:
      everything = merge_move_target(src_dict, everything, srcip, dstip)

    else:
      everything[srcip]['targets'][dstip] = src_dict[srcip]['targets'][dstip].copy()
      everything[srcip]['start_time'] = min([first_seen, everything[srcip]['start_time']])
      everything[srcip]['end_time'] = min([last_seen, everything[srcip]['end_time']])

  else:
    everything[srcip] = src_dict[srcip].copy()
  return (counting, attack, everything)

def flush_everything(attack, everything):
  for srcip in everything.copy():
    if srcip in attack:
      for dstip in everything[srcip]['targets'].copy():
        if dstip in attack[srcip]['targets']:
          everything = del_from_dict(everything, srcip, dstip)
  return everything

def merge_everything(attack, everything):
  for srcip in everything:
    if srcip in attack:
      for dstip in everything[srcip]['targets']:
        if not dstip in attack[srcip]['targets']:
          attack[srcip]['targets'][dstip] = everything[srcip]['targets'][dstip]

    else:
      attack[srcip] = everything[srcip]
  return attack

def flush(flags, counting, attack, everything):
  """Flushes all the remaining traffic in the counting dictionary

  :param flags: flag dictionary
  :type flags: dictionary
  :param counting: counting dictionary
  :type counting: dictionary
  :param attack: attack dictionary
  :type attack: dictionary
  :param everything: everything dictionary
  :type everything: dictionary
  """

  while len(counting) > 0:
    srcip = list(counting.keys())[0]
    dstip = list(counting[srcip]['targets'].keys())[0]
    counting, attack, everything = add_attack(flags, counting, attack, everything, srcip, dstip)
  return (counting, attack, everything)

def data_line(flags, signatures, counting, attack, everything, line):
  """Processes a data line


  :param flags: flag dictionary
  :type flags: dictionary
  :param signatures: signatures dictionary
  :type signatures: dictionary
  :param counting: counting dictionary
  :type counting: dictionary
  :param attack: attack dictionary
  :type attack: dictionary
  :param everything: everything dictionary
  :type everything: dictionary
  :return: counting, attack, everything
  """
  try:
    line = line.replace(b'\xff',bytes('','utf-8')).replace(b'\xfe',bytes('','utf-8'))
    data = str(line, 'utf-8').replace("\n","")
    if "PANIC!" in data:
      return (counting, attack, everything)

    data = data.split("|")

  except ValueError as e:
    raise

  length = len(data)
  if length == 24:
    af, first, first_msec, last, last_msec, prot,\
      sa_0, sa_1, sa_2, sa_3, src_port,\
      da_0, da_1, da_2, da_3, dst_port,\
      src_as, dst_as, r_input, r_output,\
      tcp_flags, tos, no_pkts, no_octets = data
    host = ''
    page = ''
    extended = False

  elif length == 28 or length == 49:
    af, first, first_msec, last, last_msec, prot,\
        sa_0, sa_1, sa_2, sa_3, src_port,\
        da_0, da_1, da_2, da_3, dst_port,\
        src_as, dst_as, r_input, r_output,\
        tcp_flags, tos, no_pkts, no_octets,\
        something, http_port, host, page = data[0:28]
    extended = True
  else:
    raise OverflowError("Odd length line")

  # Grab a signature
  srcip = lib.functions.convert_ipaddress(sa_3)
  dstip = "{0}:{1}".format(lib.functions.convert_ipaddress(da_3),dst_port)
  signature, no_pkts, no_octets = descriminator(flags, signatures, counting, srcip, dstip, float(no_pkts), float(no_octets), int(dst_port), int(tcp_flags))

  # Based on the signature and flags perform any of these actions
  # TCP flag filter: 26: .AP.S., 27: .AP.SF
  flag_filter = 27
  if int(tcp_flags) >= flag_filter and signature != 'reset' and signature != 'everything':
    counting = add_counting(counting, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets)

  elif int(tcp_flags) >= flag_filter and signature == 'everything':
    counting, attack, everything = add_everything(flags, counting, attack, everything, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets)

  else:
    counting, attack, everything = add_everything(flags, counting, attack , everything, srcip, dstip, first, first_msec, last, last_msec, 'everything', host, page, no_pkts, no_octets)

  return (counting, attack, everything)

def match_signature(data, srcip, dstip):
  """Check which signature was matched most of the time

  :param data: data dictionary
  :type data: dictionary
  :param srcip: source ip
  :type srcip: string
  :param dstip: destination ip
  :type dstip: string
  :return: signature
  """
  signatures = data[srcip]['targets'][dstip]['signature']
  max_value = max(signatures.values())
  match = []
  for signature in signatures:
    if signatures[signature] == max_value:
        match.append(signature)
  if len(match) > 0:
    signature = match[0]

  else:
    signature = "everything"

  return signature

def match_everything(data):
  for srcip in data:
    for dstip in data[srcip]['targets']:
      data[srcip]['targets'][dstip]['signature'] = 'everything'
  return data
#====================================

#def add_srcip(self, srcdict, dstdict, srcip, root_keys):

  #for i,key in enumerate(root_keys):

    #if key == 'start_time':

      #if srcip in dstdict:

        #if key in dstdict[srcip]:

          #value = min(int(srcdict[srcip][key]),int(dstdict[srcip][key]))
        #else:

          #value = int(srcdict[srcip][key])
        #dstdict[srcip][key] = value
      #else:

        #value = int(srcdict[srcip][key])
        #dstdict[srcip] = {key: value}
    #elif key == 'end_time':

      #if srcip in dstdict:

        #if key in dstdict[srcip]:

          #value = max(int(srcdict[srcip][key]),int(dstdict[srcip][key]))
        #else:

          #value = int(srcdict[srcip][key])
        #dstdict[srcip][key] = value
      #else:

        #value = int(srcdict[srcip][key])
        #dstdict[srcip] = {key: value}
    #elif key == 'targets':

      #if srcip in dstdict:

        #if not key in dstdict[srcip]:

          #dstdict[srcip]['targets'] = {}
      #else:

        #dstdict[srcip] = {key: {}}


#def add_dstip(self, srcdict, dstdict, srcip, dstip, keys):

  #for i,key in enumerate(keys):

    #if key == 'signature':

      #if srcip in dstdict:

        #if dstip in dstdict[srcip]['targets']:

          #if key in dstdict[srcip]['targets'][dstip]:

            #for signature in srcdict[srcip]['targets'][dstip][key]:

              #if signature in dstdict[srcip]['targets'][dstip][key]:

                #dstdict[srcip]['targets'][dstip][key][signature] += srcdict[srcip]['targets'][dstip][key][signature]
              #else:

                #dstdict[srcip]['targets'][dstip][key][signature] = srcdict[srcip]['targets'][dstip][key][signature]
          #else:

            #dstdict[srcip]['targets'][dstip][key] = srcdict[srcip]['targets'][dstip][key]
        #else:

          #dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      #else:

        #dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}
    #elif key in ['packet_mean', 'bytes_mean', 'cusum']:

      #self.absolom.add_dst_mean(self, srcdict, dstdict, srcip, dstip, key)
    #elif key in ['flows']:

      #self.absolom.add_dst_add(self, srcdict, dstdict, srcip, dstip, key)
    #elif key == 'first_seen':

      #if srcip in dstdict:

        #if dstip in dstdict[srcip]['targets']:

          #if key in dstdict[srcip]['targets'][dstip]:

            #value = min([srcdict[srcip]['targets'][dstip][key],dstdict[srcip]['targets'][dstip][key]])
          #else:

            #value = srcdict[srcip]['targets'][dstip][key]
          #dstdict[srcip]['targets'][dstip][key] = value
        #else:

          #dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      #else:

        #dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}
    #elif key == 'last_seen':

      #if srcip in dstdict:

        #if dstip in dstdict[srcip]['targets']:

          #if key in dstdict[srcip]['targets'][dstip]:

            #value = min([srcdict[srcip]['targets'][dstip][key],dstdict[srcip]['targets'][dstip][key]])
          #else:

            #value = srcdict[srcip]['targets'][dstip][key]
          #dstdict[srcip]['targets'][dstip][key] = value
        #else:

          #dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      #else:

        #dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}
    #elif key == 'url':

      #if srcip in dstdict:

        #if dstip in dstdict[srcip]['targets']:

          #if key in dstdict[srcip]['targets'][dstip]:

            #for url in srcdict[srcip]['targets'][dstip][key]:

              #if url in dstdict[srcip]['targets'][dstip][key]:

                #dstdict[srcip]['targets'][dstip][key][url] += srcdict[srcip]['targets'][dstip][key][url]
              #else:

                #dstdict[srcip]['targets'][dstip][key][url] = srcdict[srcip]['targets'][dstip][key][url]
          #else:

            #dstdict[srcip]['targets'][dstip][key] = srcdict[srcip]['targets'][dstip][key]
        #else:

          #dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
      #else:

        #dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}

#def add_dst_mean(self, srcdict, dstdict, srcip, dstip, key):

  #if srcip in dstdict:

    #if dstip in dstdict[srcip]['targets']:

      #if key in dstdict[srcip]['targets'][dstip]:

        #value = statistics.mean([srcdict[srcip]['targets'][dstip][key],dstdict[srcip]['targets'][dstip][key]])
      #else:

        #value = srcdict[srcip]['targets'][dstip][key]
      #dstdict[srcip]['targets'][dstip][key] = value
    #else:

      #dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
  #else:

    #dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}

#def add_dst_add(self, srcdict, dstdict, srcip, dstip, key):

  #if srcip in dstdict:

    #if dstip in dstdict[srcip]['targets']:

      #if key in dstdict[srcip]['targets'][dstip]:

        #value = srcdict[srcip]['targets'][dstip][key] + dstdict[srcip]['targets'][dstip][key]
      #else:

        #value = srcdict[srcip]['targets'][dstip][key]
      #dstdict[srcip]['targets'][dstip][key] = value
    #else:

      #dstdict[srcip]['targets'][dstip] = {key: srcdict[srcip]['targets'][dstip][key]}
  #else:

    #dstdict[srcip] = {'targets': {dstip: {key: srcdict[srcip]['targets'][dstip][key]}}}

#def add_merge(self, srcdict, dstdict, srcip, dstip):

  #root_keys = srcdict[srcip].keys()
  #keys = srcdict[srcip]['targets'][dstip]

  #self.absolom.add_srcip(self,srcdict, dstdict, srcip, root_keys)
  #self.absolom.add_dstip(self,srcdict, dstdict, srcip, dstip, keys)













## Merges data with result, child function
#def process_merger(self, data, result, srcip, dstip):

  #data[srcip]['targets'][dstip]['packet_mean'] = statistics.mean([result[srcip]['targets'][dstip]['packet_mean'],data[srcip]['targets'][dstip]['packet_mean']])
  #data[srcip]['targets'][dstip]['bytes_mean'] = statistics.mean([result[srcip]['targets'][dstip]['bytes_mean'],data[srcip]['targets'][dstip]['bytes_mean']])
  #data[srcip]['targets'][dstip]['flows'] += result[srcip]['targets'][dstip]['flows']
  #for signature in result[srcip]['targets'][dstip]['signature']:

    #if signature in data[srcip]['targets'][dstip]['signature']:

      #data[srcip]['targets'][dstip]['signature'][signature] += result[srcip]['targets'][dstip]['signature'][signature]
    #else:

      #data[srcip]['targets'][dstip]['signature'][signature] = result[srcip]['targets'][dstip]['signature'][signature]
  #if result[srcip]['targets'][dstip]['first_seen'] < data[srcip]['targets'][dstip]['first_seen']:

    #data[srcip]['targets'][dstip]['first_seen'] = result[srcip]['targets'][dstip]['first_seen']
  #if result[srcip]['targets'][dstip]['last_seen'] < data[srcip]['targets'][dstip]['last_seen']:

    #data[srcip]['targets'][dstip]['last_seen'] = result[srcip]['targets'][dstip]['last_seen']

  #if 'cusum' in data[srcip]['targets'][dstip]:

    #data[srcip]['targets'][dstip]['cusum'] = statistics.mean([result[srcip]['targets'][dstip]['cusum'],data[srcip]['targets'][dstip]['cusum']])

## Master merger
#def merge(self, data, everything, result):

  #attack = result['attack'].copy()
  #everything = result['everything'].copy()

  ## Merge attacks
  #for srcip in attack:

    #for dstip in attack[srcip]['targets']:

      #if not srcip in data:

        #data.update(attack)
      #else:

        #first_seen = attack[srcip]['targets'][dstip]['first_seen']
        #last_seen = attack[srcip]['targets'][dstip]['last_seen']
        #if not dstip in data[srcip]['targets']:

          #data[srcip]['targets'].update(attack[srcip]['targets'])

        #else:

          #self.absolom.process_merger(self,data,attack,srcip,dstip)

        #if data[srcip]['start_time'] > first_seen:

          #data[srcip]['start_time'] = first_seen
        #if data[srcip]['end_time'] < last_seen:

          #data[srcip]['end_time'] = last_seen
        #data[srcip]['total_duration'] = data[srcip]['end_time'] - data[srcip]['start_time']

  ## Merge everything dictionary
  #for srcip in everything:

    #for dstip in everything[srcip]['targets'].copy():

      #if not srcip in self.everything:

        #self.everything.update(everything)
      #else:

        #first_seen = everything[srcip]['targets'][dstip]['first_seen']
        #last_seen = everything[srcip]['targets'][dstip]['last_seen']
        #if not dstip in self.everything[srcip]['targets']:

          #self.everything[srcip]['targets'].update(everything[srcip]['targets'])

        #else:

          #self.absolom.process_merger(self,self.everything,everything,srcip,dstip)

        #if self.everything[srcip]['start_time'] > first_seen:

          #self.everything[srcip]['start_time'] = first_seen
        #if self.everything[srcip]['end_time'] < last_seen:

          #self.everything[srcip]['end_time'] = last_seen
        #self.everything[srcip]['total_duration'] = self.everything[srcip]['end_time'] - self.everything[srcip]['start_time']

## Removes entries from the everything dictionary if they are in the attack dictionary
#def purge_everything(self):

  #purged_everything = {}
  #for srcip in self.everything:

    #for dstip in self.everything[srcip]['targets']:

      #accept = True
      #if srcip in self.data:

        #if dstip in self.data[srcip]['targets']:

          #accept = False
          #if self.extended == True and self.flags['merge']:

            #urls = self.everything[srcip]['targets'][dstip]['url']
            #for url in urls:

              #if url in self.data[srcip]['targets'][dstip]['url'].keys():

                #self.data[srcip]['targets'][dstip]['url'][url] += self.everything[srcip]['targets'][dstip]['url'][url]
              #else:

                #self.data[srcip]['targets'][dstip]['url'][url] = self.everything[srcip]['targets'][dstip]['url'][url]
      #if accept == True:

        #if srcip in purged_everything:

          #purged_everything[srcip]['targets'][dstip] = self.everything[srcip]['targets'][dstip]
        #else:

          #purged_everything[srcip] = self.everything[srcip].copy()
          #purged_everything[srcip]['targets'] = {dstip: self.everything[srcip]['targets'][dstip].copy()}
  #self.everything = purged_everything
