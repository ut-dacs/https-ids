#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Worker class for ids.py

import threading
import time
import queue
import sys
import os
import logging
import subprocess
import statistics
import traceback
import math

# Custom libs
import lib.absolom
import lib.functions
import lib.flags

class Worker(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.attack = {}
    self.counting = {}
    self.everything = {}
    self.flags = lib.flags.get_flags()

  def write_filter(self, filter):
    """Function for writing nfdump filters to file, so the stdin limit doesn't affect us.

    :param filter: filter to write
    :type filter: string
    :return: path to filter file
    """
    filter_file = os.path.abspath("tmp/nfdump-filter.ids")
    filter = bytes(filter, 'utf-8')
    with open(filter_file, 'wb') as f:
      f.write(filter)
    return filter_file

  def preselect_filter(self, signatures):
    """Function to build a preselection filter

    :param signatures: signature filter_dictionary
    :type signatures: dictionary
    :return: path to the filter file
    """
    flags = lib.flags.get_flags()
    filter_list = []
    for signature in signatures:
      if flags['ip'] == True:
        filter = 'ip {0} and dst port {1}'.format(flags['ip_value'], signature[signature]['port'])

      else:
        if flags['packets'] == True and flags['bytes'] == True:

          filter = "dst port {0} and packets > {1} and packets < {2} and bytes > {3} and bytes < {4}".format(
            signatures[signature]['port'],
            signatures[signature]['packets_low'],
            int(signatures[signature]['packets_high'])+1,
            signatures[signature]['bytes_low'],
            signatures[signature]['bytes_high'],
          )
        elif flags['bytes'] == True:
          filter = "dst port {0} and bytes > {1} and bytes < {2}".format(
            signatures[signature]['port'],
            signatures[signature]['bytes_low'],
            signatures[signature]['bytes_high'],
            )

        else:
          filter = "dst port {0} and packets > {1} and packets < {2}".format(
            signatures[signature]['port'],
            signatures[signature]['packets_low'],
            int(signatures[signature]['packets_high'])+1,
          )

      if not filter in filter_list:
        filter_list.append(filter)

    filter = ") or (".join(filter_list)
    filter = "({0})".format(filter)
    filter_file = self.write_filter(filter)
    return filter_file

  def preselect_line(self, ip, line):
    """Processes a line for the preselector

    :param ip: list of preselected ip addresses (src, dst, dpt)
    :type ip: list
    :param line: line to check
    :type line: bytes
    """
    # Split the line and throw it in a bunch of variables
    try:
      data = str(line, 'utf-8').split("|")

    except ValueError:
      raise

    ip_version = data[0]
    src = data[9]
    dst = data[14]
    dpt = data[15]

    if int(ip_version) == 2 and (src,dst,dpt) not in ip:
        ip.append((src,dst,dpt))
    return ip

  def preselect_file(self, nfdump_file, signatures):
    """Preselects ips from the nfcapd file

    :param nfdump_file: path to the nfdump/nfcapd file
    :type nfdump_file: string
    :param signatures: dictionary containing signature details
    :type signatures: dictionary
    :return: list of preselected ip tuples
    """
    ip = []

    # Generate a filter
    filter = self.preselect_filter(signatures)
    if self.flags['break_value'] == 'pfilter':
      raise SystemExit("Break at preselect filter")

    command = "nfdump -qN -r {0} -f {1} -o pipe".format(nfdump_file, filter)
    process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)

    # While the line is not empty continue reading
    for line in iter(process.stdout.readline, b''):

      ip = self.preselect_line(ip, line)
    process.communicate()
    return ip

  def data_filter(self, ip_list):
    """Function to build a nfdump filter

    :param ip_list: an (preselected) list of ip tuples
    :type ip_list: list
    :return: path to a filter
    """
    filter_dictionary = {}
    filter_list = []
    for ip in ip_list:
      srcip = lib.functions.convert_ipaddress(ip[0])
      dstip = lib.functions.convert_ipaddress(ip[1])
      dstport = ip[2]
      filter = "src ip {0} and dst ip {1}".format(srcip, dstip)
      if dstport in filter_dictionary.keys():
        if not filter in filter_dictionary[dstport]:
          filter_dictionary[dstport].append(filter)

      else:
        filter_dictionary[dstport] = [filter]

    for port in filter_dictionary:
      filter = ") or (".join(filter_dictionary[port])
      filter = "({0}) and dst port {1}".format(filter, port)
      if not filter in filter_list:
        filter_list.append(filter)

    filter = ") or (".join(filter_list)
    filter = "({0})".format(filter)
    filter_path = self.write_filter(filter)
    ports = list(filter_dictionary.keys())
    if self.flags['break_value'] == 'dfilter':
      raise SystemExit("Break at preselect filter")
    return filter_path, ports

  def data_line(self, data, ports, line):
    """Function for processing data lines

    :param data: data dictionary
    :type data: dictionary
    :param line: line to be processed
    :type line: bytes
    :return: data dictionary
    """
    try:
      data = str(line, 'utf-8').replace("\n","").split("|")

    except ValueError as e:
      raise

    length = len(data)
    if length == 24:
      af, first, first_msec, last, last_msec, prot,\
        sa_0, sa_1, sa_2, sa_3, src_port,\
        da_0, da_1, da_2, da_3, dst_port,\
        src_as, dst_as, r_input, r_output,\
        flags, tos, no_pkts, no_octets = data
      self.extended = False

    elif length == 28 or length == 49:
      af, first, first_msec, last, last_msec, prot,\
          sa_0, sa_1, sa_2, sa_3, src_port,\
          da_0, da_1, da_2, da_3, dst_port,\
          src_as, dst_as, r_input, r_output,\
          flags, tos, no_pkts, no_octets,\
          something, http_port, host, page = data[0:28]
      self.extended = True
    else:
      raise OverflowError("Odd length line")

    # Add the port to the destination (typically 80, 443)
    if int(dst_port) in ports:

      sa_3 = lib.functions.convert_ipaddress(sa_3)
      da_3 = "{0}:{1}".format(lib.functions.convert_ipaddress(da_3), dst_port)

      # Set the id and calculate needed information
      id = ((sa_3, da_3))
      begin = float(first+first_msec.zfill(3))
      end = float(last+last_msec.zfill(3))
      duration = (end - begin)*1000

      # Note the [first,last]_seen if it is zero
      if not id in data.keys():

        data[id] = {'packets':[],'bytes':[],'duration':[],
                        'first_seen':0,'last_seen':0, 'url':[]}

      # Note begin and end times
      if data[id]['first_seen'] == 0 or begin < data[id]['first_seen']:

        data[id]['first_seen'] = begin

      # And not the end if it is larger
      if end > data[id]['last_seen']:

        data[id]['last_seen'] = end

      # Throw the data in the right container
      # data: no_pkts, no_octets, duration
      data[id]['packets'].append(float(no_pkts))
      data[id]['bytes'].append(float(no_octets))
      data[id]['duration'].append(float(duration))

      # Add the url
      if self.extended == True:

        url = "{0}{1}".format(host,page)
        data[id]['url'].append(url)
    return data

  def data_file(self, nfdump_file, signatures, ip_list):
    """Function for reading data files

    """
    filter, ports = self.data_filter(ip_list)
    port = []
    data = {}
    for signature in signatures:
      port.append(int(signatures[signature]['port']))

    command = "nfdump -qN -r {0} -f {1} -o pipe".format(nfdump_file, filter)
    process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,  bufsize=1)

    for line in iter(process.stdout.readline, b''):
        data = self.data_line(data, ports, line)
    #data = process.communicate()
    process.communicate()

    #self.absolom.flush(self)
    #self.processed_data = self.attack
    #self.absolom.debug(self)
    return data

  def grab_data(self, data, id):
    """Calculates things about the given data and id

    :param data: data dictionary
    :type data: dictionary
    :param id: tuple identifier
    :type id: tuple
    :return: lots of things
    """
    packet_mean, packet_stdev = lib.functions.data_statistics(data[id]['packets'])
    bytes_mean, bytes_stdev = lib.functions.data_statistics(data[id]['bytes'])
    duration_mean, duration_stdev = lib.functions.data_statistics(data[id]['duration'])
    flows = len(data[id]['packets'])
    start_time = data[id]['first_seen']
    stop_time = data[id]['last_seen']
    total_duration = stop_time - start_time
    flow_duration = sum(data[id]['duration'])
    if total_duration == 0:
      activity = 0

    else:
      activity = (flow_duration / total_duration)* 100
    return (packet_mean, packet_stdev,
            bytes_mean, bytes_stdev,
            duration_mean, duration_stdev,
            flows, start_time,
            stop_time, total_duration,
            flow_duration, activity)

  def data_processor(self, data):
    """Function for processing the gathered data.

    """
    processed_data = {}
    for id in data:
      srcip = id[0]
      dstip = id[1]

      (packet_mean, packet_stdev,
       bytes_mean, bytes_stdev,
       duration_mean, duration_stdev,
       flows, start_time,
       stop_time, total_duration,
       flow_duration, activity) = self.grab_data(data, id)

      if not srcip in processed_data.keys():
        processed_data[srcip] = {
          'start_time':             start_time,
          'end_time':               stop_time,
          'total_duration':         total_duration,
          'targets': {
            dstip: {
              'packet_mean':        packet_mean,
              'packet_stdev':       packet_stdev,
              'bytes_mean':         bytes_mean,
              'bytes_stdev':        bytes_stdev,
              'duration_mean':      duration_mean,
              'duration_stdev':     duration_stdev,
              'flows':              flows,
              'activity':           activity,
              'flow_duration':      flow_duration,
              'total_duration':     total_duration,
              'first_seen':         start_time,
              'last_seen':          stop_time,
              'url':                {}
            }
          }
        }

      else:
        processed_data[srcip]['targets'][dstip] = {
          'packet_mean':            packet_mean,
          'packet_stdev':           packet_stdev,
          'bytes_mean':             bytes_mean,
          'bytes_stdev':            bytes_stdev,
          'duration_mean':          duration_mean,
          'duration_stdev':         duration_stdev,
          'flows':                  flows,
          'activity':               activity,
          'flow_duration':          flow_duration,
          'total_duration':         total_duration,
          'first_seen':             start_time,
          'last_seen':              stop_time,
          'url':                    {}
        }

      for url in data[id]['url']:
        if url in processed_data[srcip]['targets'][dstip]['url'].keys():
          processed_data[srcip]['targets'][dstip]['url'][url] += 1

        else:
          processed_data[srcip]['targets'][dstip]['url'][url] = 1
    return processed_data

  def match_signature(self, data, signatures, srcip, dstip):
    """Matches a signature to the source destination tuple

    :param data: data dictionary
    :type data: dictionary
    :param signatures: signature dictionary
    :type signature: dictionary
    :param srcip: source ip
    :type srcip: string
    :param dstip: destination ip
    :type dstip: string
    :return: matching signature
    """

    # Coordinates of the target: X,Y and Z
    x = float(data[srcip]['targets'][dstip]['packet_mean'])
    y = float(data[srcip]['targets'][dstip]['bytes_mean'])
    port = int(dstip.split(":")[1])

    # Calculate the differences and the distance
    distances = {}
    for signature in signatures:
      if port == int(signatures[signature]['port']):
        accepted = self.check_accept(signatures, signature, x, y)
        if accepted == True:
          distances[signature] = lib.functions.pythagoras(self.coordinates[signature]['x'],
                                                          self.coordinates[signature]['y'],
                                                          x,
                                                          y)

      if len(distances) > 0 :
        min_value = min(distances.values())
        match = []
        for item in distances:
          if distances[item] == min_value:
            match.append(item)
        signature = match[0]
      else:
        signature = None
      return signature

  def data_descriminator(self, data):
    """Data should match the signature and a flow record threshold should be met.

    :param data: data dictionary
    :type data: dictionary
    :param signatures: signatures dictionary
    :type signatures: dictionary
    :param srcip: source ip
    :type srcip: string
    :param dstip: destination ip
    :type dstip: string
    :return: processed data dictionary
    """
    flow_threshold = int(self.flags['flows_value'])
    processed_data = {}
    for srcip in data.keys():
      for dstip in data[srcip]['targets'].keys():
        if data[srcip]['targets'][dstip]['flows'] >= flow_threshold:
          signature = self.match_signature(data, srcip ,dstip)
          if signature != None:
            if srcip in processed_data.keys():
              processed_data[srcip]['targets'][dstip] = data[srcip]['targets'][dstip].copy()
            else:

              processed_data[srcip] = data[srcip].copy()
              processed_data[srcip]['targets'] = {dstip: data[srcip]['targets'][dstip].copy()}
            processed_data[srcip]['targets'][dstip]['signature'] = signature
    return processed_data

  def time_statistics(self, begin_time, preselect_time, data_gathering_time):
    time_statistics = {
      'total_duration':             time.time() - begin_time,
      'preselect_duration':         preselect_time - begin_time,
      'data_gathering_duration':    data_gathering_time - preselect_time,
    }
    return time_statistics

  def run(self):
    """Main function. The variables self.nfdump_files, self.signatures, self.logger should be set before running this.

    """
    begin_time = time.time()
    ip_list = []
    data = {}
    for nfdump_file in self.nfdump_files:

      # Preselection
      ip_list.extend(self.preselect_file(nfdump_file, self.signatures))
      preselect_time = time.time()
      if self.flags['break_value'] == 'preselect':
        raise SystemExit('Break at preselect')

      new_data = self.data_file(nfdump_file, self.signatures, ip_list)
      print(new_data)
      # TODO: make a data merger
      data_gathering_time = time.time()
      if self.flags['break_value'] == 'dfile':
        raise SystemExit("Break at data file")

      #if self.ids.flags['absolom'] == False:
        #self.data_processor()
      #data_processing_time = time.time()
      #if self.ids.flags['break_value'] == 'dprocessor':
        #sys.exit()
      ## Descriminate the data
      #if self.ids.flags['absolom'] == False:
        #self.data_descriminator()
      #data_filtering_time = time.time()
      #if self.ids.flags['break_value'] == 'descriminator':
        #sys.exit()

      time_statistics = self.time_statistics(begin_time, preselect_time, data_gathering_time)
      self.logger.info(time_statistics)
    # TODO: set return data

  def get_result(self):
    """Returns the result.

    :return: data dictionary
    """
    return self.result
