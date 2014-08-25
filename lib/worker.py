#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Worker class for ids.py

import threading
import time
import queue
import sys
import logging
import subprocess
import statistics
import traceback
import math

class Worker(threading.Thread):

  def __init__(self):

    threading.Thread.__init__(self)
    import lib.absolom
    self.absolom = lib.absolom
    self.attack = {}
    self.counting = {}
    self.everything = {}
    self.i = 0
    self.mod = 0

  # Converts an 32bit integer into an ip address
  def convert_ipaddress(self, ipint):

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

  # Writes the filter to file
  def write_filter(self, filter):

    filter_file = "tmp/filter-{0}".format(threading.current_thread().name)
    filter = bytes(filter, 'utf-8')
    f = open(filter_file, 'wb')
    f.write(filter)
    f.close()
    return filter_file

  # Function to build a preselection filter
  def preselect_filter(self):

    filter_list = []
    signatures = list(self.ids.signature.keys())
    for signature in signatures:

      if self.ids.flags['ip'] == True:

        filter = 'ip {0} and dst port {1}'.format(self.ids.flags['ip_value'], self.ids.signature[signature]['port'])
      else:

        if self.ids.flags['packets'] == True and self.ids.flags['bytes'] == True:

          filter  = "dst port {0} and packets > {1} and packets < {2} \
  and bytes > {3} and bytes < {4}".format(self.ids.signature[signature]['port'],
                                                                                self.ids.signature[signature]['packets_low'],
                                                                                int(self.ids.signature[signature]['packets_high'])+1,
                                                                                self.ids.signature[signature]['bytes_low'],
                                                                                self.ids.signature[signature]['bytes_high'], 
                                                                                )
        elif self.ids.flags['packets'] == False and self.ids.flags['bytes'] == True:

          filter  = "dst port {0} and bytes > {1} and bytes < {2}".format(self.ids.signature[signature]['port'],
                                                                                self.ids.signature[signature]['bytes_low'],
                                                                                self.ids.signature[signature]['bytes_high'], 
                                                                                )
        else:

          filter  = "dst port {0} and packets > {1} and packets < {2}".format(self.ids.signature[signature]['port'],
                                                                                self.ids.signature[signature]['packets_low'],
                                                                                int(self.ids.signature[signature]['packets_high'])+1, 
                                                                                )
      if not filter in filter_list:

        filter_list.append(filter)
    filter = ") or (".join(filter_list)
    filter = "({0})".format(filter)
    if self.ids.flags['verbose'] == True:

      self.logger.debug("pFILTER: {0}".format(filter))
    filter = self.write_filter(filter)
    return filter

  # Processes a line for the preselector
  def preselect_line(self, line):

    # Split the line and throw it in a bunch of variables
    try:

      data = str(line, 'utf-8').split("|")
      if int(data[0]) == 2 and (data[9],data[14],data[15]) not in self.ip:

          if self.ids.flags['verbose'] == True and self.i%1000 == 0:

              self.logger.debug("{0} - Preselected {1} IPs ({2} lines processed)".format(threading.current_thread().name, self.i, self.j))
          self.ip.append((data[9],data[14],data[15]))
          self.i += 1
    except:

      pass

  # Preselects ips from the nfcapd file
  def preselect_file(self, nfdump_file):

    self.logger.debug("Preselect")
    self.i = 0

    # Use nfdump to grab the data
    self.ip = []

    # Generate a filter
    filter = self.preselect_filter()
    if self.ids.flags['break_value'] == 'pfilter':

      sys.exit()

    # Build command
    command = "nfdump -qN -r {0} -f {1} -o pipe".format(nfdump_file, filter)
    self.logger.debug("pCOMMAND: {0}".format(command))

    # Run the command
    process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)

    # While the line is not empty continue reading
    for self.j, line in enumerate(iter(process.stdout.readline, b'')):

      self.preselect_line(line)
    process.communicate()
    self.logger.debug("{0} IPs preselected".format(self.i))

  # Function to build a nfdump filter
  def data_filter(self):

    filter_dictionary = {}
    filter_list = []
    ip_list = []
    for ip in self.ip:

      srcip = self.convert_ipaddress(ip[0])
      dstip = self.convert_ipaddress(ip[1])
      dstport = ip[2]
      filter = "src ip {0} and dst ip {1}".format(srcip, dstip)
      if dstport in filter_dictionary.keys():

        if not filter in filter_dictionary[dstport]:

          filter_dictionary[dstport].append(filter)
      else:

        filter_dictionary[dstport] = [filter]
    for port in filter_dictionary:

      filter = ") or (".join(filter_dictionary[port])
      if self.ids.flags['absolom'] == True:

        filter = "({0}) and dst port {1}".format(filter, port)
      else:

        filter = "({0}) and dst port {1} and flags APSF and not flags UR".format(filter, port)
      if not filter in filter_list:

        filter_list.append(filter)
    filter = ") or (".join(filter_list)
    if self.ids.flags['absolom'] == True:

      filter = "({0})".format(filter)
    else:

      filter = "({0})".format(filter)
    filter = self.write_filter(filter)
    if self.ids.flags['break_value'] == 'dfilter':

      sys.exit()
    return filter

  # Function for processing data lines
  def data_line(self,line):

    try:

      data = str(line, 'utf-8').replace("\n","").split("|")
      length = len(data)
      if length == 24:

        af, first, first_msec, last, last_msec, prot,\
          sa_0, sa_1, sa_2, sa_3, src_port,\
          da_0, da_1, da_2, da_3, dst_port,\
          src_as, dst_as, r_input, r_output,\
          flags, tos, no_pkts, no_octets = data

      elif length == 28 or length == 49:

        af, first, first_msec, last, last_msec, prot,\
            sa_0, sa_1, sa_2, sa_3, src_port,\
            da_0, da_1, da_2, da_3, dst_port,\
            src_as, dst_as, r_input, r_output,\
            flags, tos, no_pkts, no_octets,\
            something, http_port, host, page = data[0:28]
        self.ids.extended = True
      else:

        self.logger.debug("Found odd length: {0}".format(length))
        return

      # Add the port to the destination (typically 80, 443)
      if int(dst_port) in self.port:

        sa_3 = self.convert_ipaddress(sa_3)
        da_3 = "{0}:{1}".format(self.convert_ipaddress(da_3), dst_port)

        # Set the id and calculate needed information
        id = ((sa_3, da_3))
        begin = float(first+first_msec.zfill(3))
        end = float(last+last_msec.zfill(3))
        duration = (end - begin)*1000

        # Note the [first,last]_seen if it is zero
        if not id in self.data.keys():

          self.data[id] = {'packets':[],'bytes':[],'duration':[],
                          'first_seen':0,'last_seen':0, 'url':[]}

        # Note begin and end times
        if self.data[id]['first_seen'] == 0 or begin < self.data[id]['first_seen']:

          self.data[id]['first_seen'] = begin

        # And not the end if it is larger
        if end > self.data[id]['last_seen']:

          self.data[id]['last_seen'] = end

        # Throw the data in the right container
        # data: no_pkts, no_octets, duration
        self.data[id]['packets'].append(float(no_pkts))
        self.data[id]['bytes'].append(float(no_octets))
        self.data[id]['duration'].append(float(duration))

        # Add the url
        if self.ids.extended == True:

          url = "{0}{1}".format(host,page)
          self.data[id]['url'].append(url)
    except:

      pass

  # Function for reading data files
  def data_file(self):

    self.logger.debug("Data gathering")
    filter = self.data_filter()
    self.port = []
    self.data = {}
    for signature in self.ids.signature:

      self.port.append(int(self.ids.signature[signature]['port']))
    # Build command
    command = "nfdump -qN -r {0} -f {1} -o pipe".format(self.nfdump_file, filter)
    self.logger.debug("dCOMMAND: {0}".format(command))

    # Run the command
    process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,  bufsize=1)

    # While the line is not empty continue reading
    for self.i, line in enumerate(iter(process.stdout.readline, b'')):

      if self.ids.flags['absolom'] == True:

        self.absolom.data_line(self,line)
      else:

        self.data_line(line)
      if self.ids.flags['verbose'] == True and self.i % 10000 == 0:

        self.logger.debug('{0} - Processed {1} lines'.format(threading.current_thread().name, self.i))
    data = process.communicate()
    del self.ip
    if self.ids.flags['absolom'] == True:

      self.logger.debug("Flushing...")
      self.absolom.flush(self)
      self.processed_data = self.attack
      self.absolom.debug(self)

  # Function for calculating statistics
  def data_statistics(self, data):

    mean = statistics.mean(data)
    if len(data) >= 2:

      stdev = statistics.stdev(data)
    else:

      stdev = 0
    return mean, stdev

  # Function for processing the gathered data
  def data_processor(self):

    self.logger.debug("Processing data")
    self.processed_data = {}
    for id in self.data:

      srcip = id[0]
      dstip = id[1]

      # Packets
      packet_mean, packet_stdev = self.data_statistics(self.data[id]['packets'])

      # Bytes
      bytes_mean, bytes_stdev = self.data_statistics(self.data[id]['bytes'])


      # Duration
      duration_mean, duration_stdev = self.data_statistics(self.data[id]['duration'])

      # Flows
      flows = len(self.data[id]['packets'])

      # Start/Stop
      start_time = self.data[id]['first_seen']
      stop_time = self.data[id]['last_seen']

      # Total duration
      total_duration = stop_time - start_time

      # Activity
      flow_duration = sum(self.data[id]['duration'])
      if total_duration == 0:

        activity = 0
      else:

        activity = (flow_duration / total_duration)* 100

      if not srcip in self.processed_data.keys():

        self.processed_data[srcip] = {'start_time': start_time,
                                      'end_time': stop_time,
                                      'total_duration': total_duration,
                                      'targets': 
                                        {dstip: 
                                           {'packet_mean': packet_mean,
                                            'packet_stdev': packet_stdev,
                                            'bytes_mean': bytes_mean,
                                            'bytes_stdev': bytes_stdev,
                                            'duration_mean': duration_mean,
                                            'duration_stdev': duration_stdev,
                                            'flows': flows,
                                            'activity': activity,
                                            'flow_duration': flow_duration,
                                            'total_duration': total_duration,
                                            'first_seen': start_time,
                                            'last_seen': stop_time,
                                            'url':{}
                                          }
                                        }
                                      }
      else:

        self.processed_data[srcip]['targets'][dstip] = {'packet_mean': packet_mean,
                                                        'packet_stdev': packet_stdev,
                                                        'bytes_mean': bytes_mean,
                                                        'bytes_stdev': bytes_stdev,
                                                        'duration_mean': duration_mean,
                                                        'duration_stdev': duration_stdev,
                                                        'flows': flows,
                                                        'activity': activity,
                                                        'flow_duration': flow_duration,
                                                        'total_duration': total_duration,
                                                        'first_seen': start_time,
                                                        'last_seen': stop_time,
                                                        'url':{}
                                                        }

      # Urls
      for url in self.data[id]['url']:

        if url in self.processed_data[srcip]['targets'][dstip]['url'].keys():

          self.processed_data[srcip]['targets'][dstip]['url'][url] += 1
        else:

          self.processed_data[srcip]['targets'][dstip]['url'][url] = 1

    #self.ids.print_output("done!",'normal')
    del self.data

  def match_signature(self, srcip, dstip):

    # Coordinates of the target: X,Y and Z
    x = float(self.processed_data[srcip]['targets'][dstip]['packet_mean'])
    y = float(self.processed_data[srcip]['targets'][dstip]['bytes_mean'])
    #z = float(self.processed_data[srcip]['targets'][dstip]['duration_mean'])
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
        if accepted == True:

          x_diff = self.coordinates[signature]['x'] - x
          y_diff = self.coordinates[signature]['y'] - y
          #z_diff = self.coordinates[signature]['z'] - z

          # Pythagoras
          d = math.pow(x_diff,2) + math.pow(y_diff, 2) # + math.pow(z_diff, 2)
          d = math.sqrt(d)
          distances[signature] = d
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

  # Data should match the signature
  def data_descriminator(self):

    self.logger.debug("Filtering data")
    flow_threshold = int(self.ids.flags['flows_value'])
    data = {}
    for srcip in self.processed_data.keys():

      for dstip in self.processed_data[srcip]['targets'].keys():

        if self.processed_data[srcip]['targets'][dstip]['flows'] >= flow_threshold:

          signature = self.match_signature(srcip,dstip)
          if signature != None:

            if srcip in data.keys():

              data[srcip]['targets'][dstip] = self.processed_data[srcip]['targets'][dstip].copy()
            else:

              data[srcip] = self.processed_data[srcip].copy()
              data[srcip]['targets'] = {dstip: self.processed_data[srcip]['targets'][dstip].copy()}
            data[srcip]['targets'][dstip]['signature'] = signature
    self.processed_data = data

  # Main control function
  def run(self):

    begin_time = time.time()

    for i,self.nfdump_file in enumerate(self.nfdump_files):

      # Preselection
      self.logger.info("{0} - file {1}/{2}".format(threading.current_thread().name, i+1, len(self.nfdump_files)))
      self.preselect_file(self.nfdump_file)
      preselect_time = time.time()
      if self.ids.flags['break_value'] == 'preselect':

        sys.exit()

      # Time to call nfdump
      self.data_file()
      data_gathering_time = time.time()
      if self.ids.flags['break_value'] == 'dfile':

        sys.exit()


      # Process the data
      if self.ids.flags['absolom'] == False:

        self.data_processor()
      data_processing_time = time.time()
      if self.ids.flags['break_value'] == 'dprocessor':

        sys.exit()

      # Descriminate the data
      if self.ids.flags['absolom'] == False:

        self.data_descriminator()
      data_filtering_time = time.time()
      if self.ids.flags['break_value'] == 'descriminator':

        sys.exit()
      total_duration = time.time() - begin_time
      preselect_duration = preselect_time - begin_time
      data_gathering_duration = data_gathering_time - preselect_time 
      data_processing_duration = data_processing_time - data_gathering_time
      data_filtering_duration = data_filtering_time - data_processing_time
      self.ids.time['worker'].append(total_duration)
      self.ids.time['preselection'].append(preselect_duration)
      self.ids.time['data_gathering'].append(data_gathering_duration)
      self.ids.time['data_processing'].append(data_processing_duration)
      self.ids.time['data_filtering'].append(data_filtering_duration)
    self.logger.info("{0} - done".format(threading.current_thread().name))

  # Returns the data to the host process
  def get_result(self):

    if self.ids.flags['absolom'] == True and 'everything' in self.ids.signature.keys():

      self.result = {'attack': self.processed_data, 'everything': self.everything}
    else:

      self.result = self.processed_data
    return self.result
