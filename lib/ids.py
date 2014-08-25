#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  A very simple IDS, it checks flow records agains a given signature

import collections
import fnmatch
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

# Custom libs
from lib.config import config
from lib.worker import Worker
from lib.signature import SigWorker

class IDS():

  # Base variables
  coordinates = {}
  count = {}
  data = {}
  everything = {}
  extended = False
  time = {'creation': time.time(),
          'worker':[],
          'preselection':[],
          'data_gathering':[],
          'data_processing':[],
          'data_filtering':[]}
  sig_count = {}

  def __init__(self):

    # Extend the functionality with Absolom
    import lib.absolom

    # Make it more accessible
    self.absolom = lib.absolom

    # Load general options
    self.options = config.read_all('','general')
    self.basedir = self.options['basedir']
    self.outputdir = "{0}{1}".format(self.basedir,self.options['outputdir'])
    self.datadir = "{0}{1}".format(self.basedir,self.options['datadir'])

  # Loads the signature
  def load_signature(self):

    # Print available signatures
    self.count = {}
    signatures = config.get_signatures()
    if self.flags['sig'] == False:

      for i, signature in enumerate(signatures):

        print("{0}: {1}".format(i+1, signature))
      number = input('What to look for? (1-{0}) (comma separated for multiple)\n'.format(len(signatures)))
    else:

      number = self.flags['sig_value']
    number = number.split(",")
    for i, num  in enumerate(number):

      number[i] = int(num)

    # Create a dictionary structure
    self.signature = {}
    for item in number:

      self.signature[signatures[item-1]] = {'duration_high':  0,
                                            'duration_low':   0,
                                            'duration_stdev': 0,
                                            'bytes_high':     0,
                                            'bytes_low':      0,
                                            'bytes_stdev':    0,
                                            'packets_high':   0,
                                            'packets_low':    0,
                                            'packets_stdev':  0,
                                            'port':           0,
                                            'flags':          0,
                                            }

    # Load the signature
    for item in self.signature:

      self.count[item] = 0
      self.options  = config.read_all('signature',item)
      for option in self.signature[item]:

        self.signature[item][option] = self.options[option]
      self.signature[item]['flags'] = int(self.signature[item]['flags'])
    self.logger.debug("SIGNATURE: {0}".format(self.signature))

    for signature in self.signature:

      x = int(self.signature[signature]['packets_low']) + (int(self.signature[signature]['packets_high']) - int(self.signature[signature]['packets_low']))/2
      y = int(self.signature[signature]['bytes_low']) + (int(self.signature[signature]['bytes_high']) - int(self.signature[signature]['bytes_low']))/2 
      z = int(self.signature[signature]['duration_low']) + (int(self.signature[signature]['duration_high']) - int(self.signature[signature]['duration_low']))/2
      self.coordinates[signature] = {'x':x, 'y':y, 'z':z}
      self.sig_count[signature] = 0

  # Finds all the nfcapd files within the specified range
  def expander(self, basedir, bottom, top):

    # Base variables
    nfdump_files = []

    # If length is 8 it is a day
    if len(top) == 8:

      top = "{0}2355".format(top)
    else:

      top = "{:0<12}".format(top)
    bottom = "{:0<12}".format(bottom)

    # Find all the (nfcapd) files
    for path, subdirs, files in os.walk(basedir):

      for filename in fnmatch.filter(files, 'nfcapd.*'):

        # If their timecode falls between the limits add to list
        timecode = str(filename.split(".")[1])
        if timecode >= bottom and timecode <= top:

          nfdump_files.append(os.path.join(path, filename))

    # Sort list and make available
    nfdump_files = sorted(nfdump_files)
    self.nfdump_files = nfdump_files
    self.logger.debug("Files: {0}".format(self.nfdump_files))

  # Function to translate a range into a nfdump range
  def process_filenames(self, path):

    # If argument is not according to specification show help
    # Single file support, yayy
    if path.count(":") == 0:

      self.path = path
      nfdump_files = [path]
      self.nfdump_files = nfdump_files

    # Multiple file support, more yayy
    elif path.count(":") == 2:

      self.path = path
      basedir = str(path.split(":")[0])
      bottom = str(path.split(":")[1])
      top = str(path.split(":")[2])
      self.expander(basedir, bottom, top)
    else:

      self.show_help()
      sys.exit()

  # Merges the result with already exisiting data (in case of the mean algorithm)
  def process_merger_mean(self, result, srcip, dstip):

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

  # The main merge function, merges the result into existing data
  def process_merger(self, result):

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

  # Process the nfcapd files
  def process_files(self):

    # Function to spawn worker threads
    def worker(q, process):

      ## Every file gets his own thread
      #for item in process:

      # Create the worker object
      thread = Worker()
      thread.logger = logging.getLogger('Worker')

      # Set some of it's base variables
      thread.ids = self
      thread.nfdump_files = process
      thread.coordinates = self.coordinates

      # Start the thread and put on the queue
      thread.start()
      q.put(thread, True)

    # Function to get results
    def getter(q, num):

      for i in range(num):

        # Join the thread
        thread = q.get(True)
        thread.join()

        # Grab the result
        result = thread.get_result()
        self.logger.info("Progress files: {0}/{1}".format(i+1, num))
        if len(result) != 0:

          self.process_merger(result)
        self.logger.info("Done merging the result of: {0}/{1}".format(i+1,num))

    # Set base variables
    length = len(self.nfdump_files)
    if self.flags['threads'] == True:

      threads = int(self.flags['threads_value'])
    else:

      threads = int(multiprocessing.cpu_count())
      if threads < 1:

        threads = 1
    self.threads = threads
    if self.flags['break_value'] == 'threads':

      sys.exit()

    # Coordinates of the signature
    coordinates = {}

    self.logger.debug("COORDINATES: {0}".format(self.coordinates))

    # Create a queue and start the threads
    q = queue.Queue(threads)
    step = math.ceil(length/threads)
    if step == 0:

      step = 1
    self.logger.debug("Files: {0}".format(self.nfdump_files))
    for num,i in enumerate(range(0,length,step)):

      if i+step <= length:

        process = self.nfdump_files[i:i+step]
      else:

        process = self.nfdump_files[i:length]
      threading._start_new_thread(worker, ((q, process)))
      self.logger.info("Starting thread: {0}".format(num+1))
    getter(q, num+1)
    self.time['processing'] = time.time()

  # Calculate the closest match and add it to the data
  def process_match(self):

    # Function to spawn worker threads
    def worker(q, data):

      # Create the worker object
      thread = SigWorker()
      thread.logger = logging.getLogger('SigWorker')

      # Set some of it's base variables
      thread.ids = self
      thread.data = data
      thread.coordinates = self.coordinates

      # Start the thread and put on the queue
      thread.start()
      q.put(thread, True)

    # Function to get results
    def getter(q, num):

      data = {}
      for i in range(num):

        # Join the thread
        thread = q.get(True)
        thread.join()

        # Grab the result
        result = thread.get_result()
        self.logger.info("Progress signature: {0}/{1}".format(i+1, num))
        data.update(result)
      self.data = data.copy()

    if self.flags['absolom'] == True:

      self.absolom.purge_everything(self)

    q = queue.Queue(self.threads)
    length = len(self.data)
    step = math.ceil(length/self.threads)
    if step == 0:

      step = 1
    num = 0
    for num,i in enumerate(range(0,length,step)):

      data = {}
      if i+step <= length:

        keys = list(self.data.keys())
        keys = keys[i:i+step]
      else:

        keys = list(self.data.keys())
        keys = keys[i:length]
      for key in keys:

        data[key] = self.data[key]
      threading._start_new_thread(worker, ((q, data)))
    getter(q,num+1)
    self.time['matching'] = time.time()

  def process_count(self):

    count = 0
    for srcip in self.data.keys():

      for dstip in self.data[srcip]['targets'].keys():

        if not 'signature' in self.data[srcip]['targets'][dstip]:

          count += 1
          self.logger.error(self.data[srcip]['targets'][dstip])
        try:

          signature = self.data[srcip]['targets'][dstip]['signature'] 
          self.sig_count[signature] += 1
        except:

          self.logger.exception("COUNT: {0} --> {1}".format(srcip, dstip))
    if count > 0:

      self.logger.error('{0} missing signatures'.format(count))
    self.time['counting'] = time.time()

  # Sorts the data based on source ip
  def process_sort(self):

    for srcip in self.data:

      self.data[srcip]['targets'] = collections.OrderedDict(sorted(self.data[srcip]['targets'].items()))
    self.data = collections.OrderedDict(sorted(self.data.items()))
    self.time['sorting'] = time.time()

  def calculate_time(self):

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
