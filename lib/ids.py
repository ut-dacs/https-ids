#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  A very simple IDS, it checks flow records agains a given signature

import collections
import logging
import logging.config
import math
import multiprocessing
import os
import statistics
import subprocess
import sys
import time
import threading
import traceback
import queue
import re

import lib.config
import lib.worker
import lib.signature
import lib.flags

class IDS():
  """IDS class, main management class.

  """
  #coordinates = {}
  #count = {}
  #data = {}
  #everything = {}
  #extended = False
  #time = {'creation': time.time(),
          #'worker':[],
          #'preselection':[],
          #'data_gathering':[],
          #'data_processing':[],
          #'data_filtering':[]}
  #sig_count = {}

  def DEPRICATED_calculate_time(self):
    # IDS times
    self.time['demolition'] = time.time()
    total_duration = self.time['demolition'] - self.time['creation']
    process_duration = ((self.time['processing'] - self.time['creation'])/total_duration)*100
    matching_duration = ((self.time['matching'] - self.time['processing'])/total_duration)*100
    sorting_duration = ((self.time['sorting'] - self.time['matching'])/total_duration)*100

    # Worker times
    worker_duration = statistics.mean(self.time['worker'])
    preselection_duration = ((statistics.mean(self.time['preselection']))/worker_duration)*100
    data_gathering_duration = ((statistics.mean(self.time['data_gathering']))/worker_duration)*100
    data_processing_duration = ((statistics.mean(self.time['data_processing']))/worker_duration)*100
    data_filtering_duration = ((statistics.mean(self.time['data_filtering']))/worker_duration)*100

    self.logger.info("This program ran for {0:.1f}s.".format(total_duration))
    self.logger.info("{0:.2f}% of the time it was processing datafiles, \
{1:.2f}% of the time it was matching signatures and {2:.2f}% of the time was spent on sorting data.".format(
        process_duration,matching_duration,sorting_duration))
    self.logger.info("On average {0:.1f}s was spent on the worker thread, of this time {1:.2f}% was pre-selecting, \
{2:.2f}% was data gathering, {3:.2f}% was data processing and {4:.2f}% was data filtering.".format(
  worker_duration,preselection_duration,data_gathering_duration,data_processing_duration,data_filtering_duration))


  def DEPRICATED_process_merger_mean(self, result, srcip, dstip):
    """DEPRICATED: Merges the result with already exisiting data (in case of the mean algorithm)

    DEPRICATED: use the absolom algorithm and functions instead.
    """

    # Data mining
    packet_mean = statistics.mean([self.data[srcip]['targets'][dstip]['packet_mean'],
                                    result[srcip]['targets'][dstip]['packet_mean']])
    packet_stdev = statistics.mean([self.data[srcip]['targets'][dstip]['packet_stdev'],
                                    result[srcip]['targets'][dstip]['packet_stdev']])
    bytes_mean = statistics.mean([self.data[srcip]['targets'][dstip]['bytes_mean'],
                                    result[srcip]['targets'][dstip]['bytes_mean']])
    bytes_stdev = statistics.mean([self.data[srcip]['targets'][dstip]['bytes_stdev'],
                                    result[srcip]['targets'][dstip]['bytes_stdev']])
    duration_mean = statistics.mean([self.data[srcip]['targets'][dstip]['duration_mean'],
                                    result[srcip]['targets'][dstip]['duration_mean']])
    duration_stdev = statistics.mean([self.data[srcip]['targets'][dstip]['duration_stdev'],
                                    result[srcip]['targets'][dstip]['duration_stdev']])
    flows = self.data[srcip]['targets'][dstip]['flows'] + result[srcip]['targets'][dstip]['flows']
    flow_duration = self.data[srcip]['targets'][dstip]['flow_duration'] + result[srcip]['targets'][dstip]['flow_duration']
    if self.data[srcip]['targets'][dstip]['first_seen'] > result[srcip]['targets'][dstip]['first_seen']:

      first_seen = result[srcip]['targets'][dstip]['first_seen']
    else:

      first_seen = self.data[srcip]['targets'][dstip]['first_seen']
    if self.data[srcip]['targets'][dstip]['last_seen'] < result[srcip]['targets'][dstip]['last_seen']:

      last_seen = result[srcip]['targets'][dstip]['last_seen']
    else:

      last_seen = self.data[srcip]['targets'][dstip]['last_seen']
    total_duration = self.data[srcip]['targets'][dstip]['last_seen'] - self.data[srcip]['targets'][dstip]['first_seen']
    activity = ( flow_duration /  total_duration)* 100

    # Data placing
    self.data[srcip]['targets'][dstip]['packet_mean'] = packet_mean
    self.data[srcip]['targets'][dstip]['packet_stdev'] = packet_stdev
    self.data[srcip]['targets'][dstip]['bytes_mean'] = bytes_mean
    self.data[srcip]['targets'][dstip]['bytes_stdev'] = bytes_stdev
    self.data[srcip]['targets'][dstip]['duration_mean'] = duration_mean
    self.data[srcip]['targets'][dstip]['duration_stdev'] = duration_stdev
    self.data[srcip]['targets'][dstip]['flows'] = flows
    self.data[srcip]['targets'][dstip]['activity'] = activity
    self.data[srcip]['targets'][dstip]['flow_duration'] = flow_duration
    self.data[srcip]['targets'][dstip]['total_duration'] = total_duration
    self.data[srcip]['targets'][dstip]['first_seen'] = first_seen
    self.data[srcip]['targets'][dstip]['last_seen'] = last_seen

    # URLs :D only for analysis
    for url in result[srcip]['targets'][dstip]['url']:

      if url in self.data[srcip]['targets'][dstip]['url']:

        self.data[srcip]['targets'][dstip]['url'][url] += result[srcip]['targets'][dstip]['url'][url]
      else:

        self.data[srcip]['targets'][dstip]['url'][url] = result[srcip]['targets'][dstip]['url'][url]

  def DEPRICATED_process_merger(self, result):
    """DEPRICATED: The main merge function, merges the result into existing data

    This is likely also depricated.
    """

    # Call the Absolom merger if the algorithm is used and an everything signature is detected
    if self.flags['absolom'] == True and 'everything' in self.signature.keys():

      self.absolom.merge(self, self.data, self.everything, result)
    else:

      for srcip in result:

        # Srcip doesn't exist, take a shortcut
        if not srcip in self.data:

          self.data.update(result)
        else:

          for dstip in result[srcip]['targets']:

            # Dstip doesn't exist, take a shortcut
            if not dstip in self.data[srcip]['targets']:

              self.data[srcip]['targets'][dstip] = result[srcip]['targets'][dstip]
            else:

              first_seen = result[srcip]['targets'][dstip]['first_seen']
              last_seen = result[srcip]['targets'][dstip]['last_seen']
              if not dstip in self.data[srcip]['targets']:

                self.data[srcip]['targets'][dstip] = result[srcip]['targets'][dstip]

              else:

                # Call the correct merger
                if self.flags['absolom'] == True:

                  self.absolom.process_merger(self,self.data,result,srcip,dstip)
                else:

                  self.process_merger_mean(result, srcip, dstip)

              # Update times if needed
              changed = False
              if self.data[srcip]['start_time'] > first_seen:

                self.data[srcip]['start_time'] = first_seen
                changed = True
              if self.data[srcip]['end_time'] < last_seen:

                self.data[srcip]['end_time'] = last_seen
                changed = True
              if changed == True:

                self.data[srcip]['total_duration'] = self.data[srcip]['end_time'] - self.data[srcip]['start_time']

  def __init__(self, logger, flags, config):
    self.logger = logger.getChild("ids")
    self.flags = flags
    self.options = config
    self.signatures = lib.config.read_signatures()
    self.basedir = self.options['basedir']
    self.outputdir = "{0}{1}".format(self.basedir,self.options['outputdir'])
    self.datadir = "{0}{1}".format(self.basedir,self.options['datadir'])

  def filter_signatures(self, number):
    """Function for filtering out unrequested signatures.

    :param number: list created by splitting user input ( "1,2,3".split(',') )
    :type number: list
    """
    signature_keys = sorted(self.signatures.keys())
    for i, sig  in enumerate(signature_keys):
      if not str(i+1) in number:
        del self.signatures[sig]

  def coordinates_signatures(self):
    """Generate a coordinate dictionary for the signatures.

    """
    self.coordinates = {}
    for signature in self.signatures:

      x = int(self.signatures[signature]['packets_low']) + (int(self.signatures[signature]['packets_high']) - int(self.signatures[signature]['packets_low']))/2
      y = int(self.signatures[signature]['bytes_low']) + (int(self.signatures[signature]['bytes_high']) - int(self.signatures[signature]['bytes_low']))/2
      z = int(self.signatures[signature]['duration_low']) + (int(self.signatures[signature]['duration_high']) - int(self.signatures[signature]['duration_low']))/2
      self.coordinates[signature] = {'x':x, 'y':y, 'z':z}

  def load_signatures(self):
    """Prints available signatures and asks which one to look for.

    """
    self.count = {}
    if self.flags['sig'] == True:
      number = self.flags['sig_value']

    else:
      for i, signature in enumerate(sorted(self.signatures)):
        print("{0}: {1}".format(i+1, signature))
      number = input('What to look for? (1-{0}) (comma separated for multiple)\n'.format(len(self.signatures)))
    number = number.split(",")
    self.filter_signatures(number)
    self.coordinates_signatures()

  def expander(self, basedir, bottom, top):
    """Finds all the nfcapd files within the specified range.

    :param basedir: specifies what directory to look in
    :type basedir: string
    :param bottom: bottom limit
    :type bottom: string
    :param top: top limit
    :type top: string
    :return: nfdump_files, a list of nfdump files
    """
    nfdump_files = []
    if len(top) == 8:

      # top specifies a day (yyyymmdd)
      top = int("{0}2355".format(top))
    else:

      # likely yyyyMMddhhmm
      top = int("{:0<12}".format(top))
    bottom = int("{:0<12}".format(bottom))

    for item in os.listdir(basedir):
      os.path.join(basedir,item)
      match = re.match(".*([0-9]{12})$", item)
      if match:
        time_code = int(match.group(1))
        if time_code >= bottom and time_code <= top:
          nfdump_files.append(os.path.join(basedir, item))

    nfdump_files = sorted(nfdump_files)
    return nfdump_files

  def process_filenames(self, path):
    """Function to translate a range into a nfdump range

    :param path: denotes the path (might be a range of file)
    :type path: string
    :return: a list of nfdump files
    """
    nfdump_files = []
    colon = path.count(":")
    if colon != 0 and colon != 2:
      lib.flags.show_help()

    # Single file
    elif colon == 0:
      nfdump_files = [path]

    # Multiple files
    elif colon == 2:
      path = path.split(":")
      basedir = str(path[0])
      bottom = str(path[1])
      top = str(path[2])
      nfdump_files = self.expander(basedir, bottom, top)

    return nfdump_files

  def process_files(self, nfdump_files):
    """Creates a worker and processes files.

    :param nfdump_files: nfdump files to process
    :type nfdump_files: list
    :return: data dictiionary
    """
    worker = lib.worker.Worker(self.logger, self.flags, self.signatures, nfdump_files)
    worker.run()
    return worker.get_result()

  def process_match(self, data):
    """Calculate the closest match and add it to the data
    """
    def worker(q, data):
      """Spawns signature worker.
      """
      thread = lib.signature.Worker(self.logger, self.flags, self.signatures, self.coordinates, data)
      thread.start()
      q.put(thread, True)

    def getter(q, num):
      """Gets the result from the workers.
      """
      data = {}
      for i in range(num):
        thread = q.get(True)
        thread.join()

        # Grab the result
        result = thread.get_result()
        if not (self.flags['break'] and self.flags['break_value'] == 'matching'):
          self.logger.info("Progress signature: {0}/{1}".format(i+1, num))

        data.update(result)
      return data

    threads = int(multiprocessing.cpu_count())
    q = queue.Queue(threads)
    length = len(data)
    step = math.ceil(length/threads)
    if step == 0:

      step = 1
    num = 0
    for num,i in enumerate(range(0,length,step)):

      data_part = {}
      if i+step <= length:

        keys = list(data.keys())
        keys = keys[i:i+step]
      else:

        keys = list(data.keys())
        keys = keys[i:length]
      for key in keys:

        data_part[key] = data[key]
      threading._start_new_thread(worker, ((q, data_part)))
    data = getter(q,num+1)
    return data

  def process_count(self, sig_count, data):
    """Counts the number of occuring signatures

    :param data: data dictionary
    :type data: dictionary
    :return: counting dictionary
    """
    count = 0
    for srcip in data.keys():
      for dstip in data[srcip]['targets'].keys():
        if not 'signature' in data[srcip]['targets'][dstip]:
          count += 1
        signature = data[srcip]['targets'][dstip]['signature']
        if signature in sig_count:
          sig_count[signature] += 1

        else:
          sig_count[signature] = 1
    if count > 0:
      self.logger.error('{0} missing signatures'.format(count))
    return sig_count

  def process_sort(self, data):
    """Sorts the data based on source ip

    :param data: data to be sorted
    :type data: dictionary
    """
    for srcip in data:\
      data[srcip]['targets'] = collections.OrderedDict(sorted(data[srcip]['targets'].items()))
    data = collections.OrderedDict(sorted(data.items()))
    return data
