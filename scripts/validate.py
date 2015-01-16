#!/usr/bin/python3
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Calculates the accuracy of a given results file from ids.py

import datetime
import logging
import logging.config
import math
import multiprocessing
import os
import pickle
import queue
import re
import sys
import time
import threading
import traceback

# Add the root dir to the path
sys.path.append(os.path.abspath(os.path.join(sys.path[0],'../')))

# Custom libs
import lib.config
import lib.printer
import lib.flags
from lib.validator import Validator
from lib.ids import IDS

class Validation():

  # Setup logging
  root_logger = logging.getLogger()
  fallback_handler = logging.StreamHandler(stream=sys.stdout)
  root_logger.addHandler(fallback_handler)

  try:

    import yaml
    f = open("conf/logging.conf", 'rb')
    D = yaml.load(f)
    D.setdefault('version', 1)
    if lib.flags.get_flags()['debug'] == True:

      D['handlers']['console']['level'] = 'DEBUG'
      D['handlers']['file']['level'] = 'DEBUG'
      D['root']['level'] = 'DEBUG'
      D['loggers']['simpleExample']['level'] = 'DEBUG'
    logging.config.dictConfig(D)

  except:

    print("Using basic log config")
    print(traceback.format_exc())
    logging.basicConfig(filename='log/ids.conf', level=logging.DEBUG)
  logging.info("Starting Validation script")

  # Base variables
  sig = ['ba', 'fa-v2', 'xmlrpc', 'xmlrpc-v2']
  count = { 'tp':0,
            'tn':0,
            'fp':0,
            'fn':0,
            'total':0}
  data = {'all': {},
          'tp':  {},
          'tn':  {},
          'fp':  {},
          'fn':  {},
          }

  # Might be usefull later
  def __init__(self):

      self.flags = lib.flags.get_flags()
      self.flags['output_value'] = 'none'
      self.flags['sig'] = True
      self.flags['sig_value'] = '1,5,7'
      self.flags['violate'] = True
      logging.debug(self.flags)

  def load_attackers(self):

    with open('includes/attackers.dump', 'rb') as attackers:

      attackers = pickle.load(attackers)
    self.attackers = []
    for attacker in attackers:

      srcip = attacker[0]
      dstip = attacker[1]
      count = attacker[2]
      if int(count) >= int(self.flags['cusum_value']) and (srcip,dstip) not in self.attackers:

        self.attackers.append((srcip,dstip))
    with open('includes/attackers_ba.dump', 'rb') as attackers:

      attackers = pickle.load(attackers)
    self.attackers_ba = []
    for attacker in attackers:

      srcip = attacker[0]
      dstip = attacker[1]
      count = attacker[2]
      if int(count) >= int(self.flags['cusum_value']) and (srcip,dstip) not in self.attackers:

        self.attackers_ba.append((srcip, dstip))
    logging.debug("BA-attackers: {0}, FA-attackers: {1}".format(len(self.attackers_ba),len(self.attackers)))

  # Merges data
  def data_merger(self,data):

    for item in self.data.keys():
      for srcip in data[item]:
        if srcip in self.data[item].keys():
          for dstip in data[item][srcip]['targets']:
            self.data[item][srcip]['targets'].update(data[item][srcip]['targets'])

        else:
          self.data[item].update(data[item])

  def result_counter(self, data):

    # Keeping counters is a good thing
    count, data = data
    for item in count:

      self.count[item] += count[item]

    # Parsing data for later use is too
    self.data_merger(data)

  # Processes the data from the IDS
  def processor(self, data):

    def worker(q, data):

      # Create the Validator and give it what it needs
      thread = Validator(q)
      thread.logger = logging.getLogger('Validator')
      thread.orig_data = data.copy()
      thread.parent = self
      thread.attackers = self.attackers.copy()
      thread.attackers_ba = self.attackers_ba.copy()

      # Lets start the Validator
      thread.start()
      #q.put(thread, True)

    def getter(q, num):

      for i in range(num):

        start = time.time()
        #thread = q.get(True)
        #thread.join()
        #result = thread.get_result()

        result = q.get(True)

        # Every 1000 items print where we are
        logging.info("Progress records: {0}/{1}".format(i+1, num))
        self.result_counter(result)

    # Parallel processing!
    threads = int(multiprocessing.cpu_count())
    if threads < 1:

      threads = 1

    self.threads = threads
    q = queue.Queue()
    step = math.ceil(len(data)/threads)
    for num,i in enumerate(range(0,len(data),step)):

      if i+step <= len(data):

        data_tmp = data[i:i+step]
      else:

        data_tmp = data[i:len(data)]
      threading._start_new_thread(worker, ((q,data_tmp)))
      logging.debug("Thread {0} started".format(num))
    getter(q, num+1)

  #def missing(self):

    #attacks = []
    #for item in ['tp', 'fn']:

      #for srcip in self.data[item]:

        #for dstip in self.data[item][srcip]['targets']:

          #dstip = str(dstip.split(":")[0])
          #attacks.append((srcip,dstip))
    #difference = len(self.attackers) - len(attacks)
    #logging.info("{0} missing attacks".format(difference))
    #with open('debug/missing.txt', 'wb') as missing:

      #for item in self.attackers:

        #if not item in attacks:

          #line = bytes("{0}\n".format(item),'utf-8')
          #missing.write(line)
    #if difference > 0:

      #self.count['fn'] += difference
      #self.count['total'] += difference

  def calculate_rates(self):

    if (self.count['tp'] + self.count['fn']) != 0:

      self.tpr = self.count['tp']/(self.count['tp'] + self.count['fn'])
      self.fnr = self.count['fn']/(self.count['tp'] + self.count['fn'])
    else:

      self.tpr = 0
      self.fnr = 0
    if (self.count['tn'] + self.count['fp']) != 0:

      self.fpr = self.count['fp']/(self.count['tn'] + self.count['fp'])
      self.tnr = self.count['tn']/(self.count['tn'] + self.count['fp'])
    else:

      self.fpr = 0
      self.tnr = 0
    self.acc = (self.count['tp'] + self.count['tn'])/(self.count['tp'] + self.count['tn'] + self.count['fp'] + self.count['fn'])

  def save_data(self, signature, date, type_scan, cusum):

    logging.info("Saving data...")
    signature = "_".join(signature)
    type_scan = "-".join(type_scan)
    filename = "results/{0}-{1}-{2}-{3}.txt".format(signature, date, type_scan, cusum)
    #if self.flags['automate'] == True:

      #filename = "{0}-{1}".format(filename, self.flags['automate_value'])
    #if self.flags['packets'] == True:

      #filename = "{0}-ppf".format(filename)
    #if self.flags['bytes'] == True:

      #filename = "{0}-bpf".format(filename)
    #filename = "{0}.txt".format(filename)
    with open(filename, 'wb') as results_file:

      # Actually lets write it to a file
      def write_file(message):

        results_file.write(bytes(message+"\n", 'utf-8'))
      write_file("RESULTS:")
      write_file("TP: {0}".format(self.count['tp']))
      write_file("FP: {0}".format(self.count['fp']))
      write_file("TN: {0}".format(self.count['tn']))
      write_file("FN: {0}".format(self.count['fn']))
      write_file("TOT: {0}".format(self.count['total']))
      write_file("")
      write_file("TPr: {0}".format(self.tpr))
      write_file("TNr: {0}".format(self.tnr))
      write_file("FPr: {0}".format(self.fpr))
      write_file("FNr: {0}".format(self.fnr))
      write_file("Acc: {0}".format(self.acc))
      write_file("")
      write_file("{0} {1} {2} {3} {4}".format(self.tpr, self.tnr, self.fpr, self.fnr, self.acc))
    filename = filename.replace(".txt",".dump")
    with open(filename, 'wb') as results_dump:
      pickle.dump(self.data, results_dump)
    logging.info("TP: {0}, TN: {1}, FP: {2}, FN: {3}, TOT: {4}".format(self.count['tp'], self.count['tn'], self.count['fp'], self.count['fn'], self.count['total']))
    logging.info("TPr: {0}, TNr: {1}, FPr: {2}, FNr: {3}, ACC: {4}".format(self.tpr, self.tnr, self.fpr, self.fnr, self.acc))

  # Shows the counters and if needed it kicks the IDS to show the data
  def show_results(self):

    # Lets not invent the wheel twice, just call the IDS to display stuff
    self.ids = IDS(logging.getLogger('ids'), self.flags, lib.config.read_config('ids'))
    #self.ids.logger = logging.getLogger('IDS')
    self.ids.extended = True
    self.ids.flags = self.flags
    self.ids.threads = self.threads
    self.ids.load_signatures()

    # Create a printing object
    if 'pager' in self.flags['output_value']:
      with lib.printer.open_pager(sys.stdout) as pager:
        #answer = input("Show what data?\n")
        answer = 'tp'
        if not answer == "":
          lib.printer.print_data(pager, 'pager', self.ids.signatures, self.data[answer], {})
    logging.info("TP: {0}, TN: {1}, FP: {2}, FN: {3}, TOT: {4}".format(self.count['tp'], self.count['tn'], self.count['fp'], self.count['fn'], self.count['total']))
    logging.info("TPr: {0}, TNr: {1}, FPr: {2}, FNr: {3}, ACC: {4}".format(self.tpr, self.tnr, self.fpr, self.fnr, self.acc))

def main():

  # Read the file
  file = sys.argv[1]
  with open(file, 'rb') as f:

    data_bytes = f.readlines()

  "ba_everything_fa_xmlrpc-2014-12-25-ppf-5.idats"
  #signature = re.match('.*/([0-9]{4}-[0-9]{2}-[0-9]{2})-(.*?)-',file.replace('fa-v2','fa_v2').replace('xmlrpc-v2','xmlrpc_v2'))
  file_name = re.match('.*/(.*?)-([0-9]{4}-[0-9]{2}-[0-9]{2})-(.*?)-([0-9]{1,2}).idats', file)
  if file_name:
    signature = file_name.group(1).split('_')
    date = file_name.group(2)
    type_scan = file_name.group(3).split('-')
    cusum = file_name.group(4)

  else:
    raise SystemExit("File name not understood")

  # Create the validator
  validator = Validation()
  validator.sig = signature
  validator.load_attackers()
  validator.processor(data_bytes)
  validator.calculate_rates()
  #validator.missing()
  validator.save_data(signature, date, type_scan, cusum)
  #validator.show_results()

if __name__ == "__main__":

  main()