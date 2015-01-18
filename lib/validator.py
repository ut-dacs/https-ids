#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Validation class definition

import math
import multiprocessing
import os
import pickle
import queue
import threading
import time

import lib.validator_worker

class Validator():
  """Class used for validation purposes.
  """

  # Base variables
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

  def __init__(self, logger, flags, config, signature):
      self.flags = flags
      self.flags['output_value'] = 'none'
      self.flags['sig'] = True
      self.flags['sig_value'] = '1,5,7'
      self.flags['violate'] = True
      self.logger = logger.getChild('validator')
      self.config = config
      self.signature = signature

  def no_dump(self, attack):
    if self.flags['test'] == False:
      answer = input("The {0} attackers dump was not found, read the manual on how to\
 create this dump. \n The validation process can continue, but the results are likely\
 to be incorrect.\n Would you like to continue? (y/n)\n".format(attack))
      if answer.lower() != 'y':
        raise SystemExit
    return []

  def filter_attackers(self, attackers, cusum):
    """Filters the attackers list for a given cusum (flow record threshold).

    :param attackers: attackers list
    :type attackers: list
    :param cusum: the minimum cusum rate (flow record threshold)
    :type cusum: int
    :return: a filtered attackers list
    """
    filtered_list = []
    for attacker in attackers:
      srcip = attacker[0]
      dstip = attacker[1]
      count = attacker[2]
      if int(count) >= cusum and (srcip,dstip) not in filtered_list:
        filtered_list.append((srcip,dstip))
    return filtered_list

  def load_attackers(self, cusum):
    """Function for loading the attacker lists. These lists should be in the 'includes' folder, named as 'attackers_fa.dump'
    and 'attackers_ba.dump'.

    :param cusum: the minimum cusum rate (flow record threshold)
    :type cusum: int
    """
    try:
      with open('includes/attackers_fa.dump', 'rb') as attackers:
        attackers = pickle.load(attackers)

      self.attackers_fa = self.filter_attackers(attackers, cusum)

    except FileNotFoundError:
      self.attackers_fa = self.no_dump("FA")

    try:
      with open('includes/attackers_ba.dump', 'rb') as attackers:
        attackers = pickle.load(attackers)

      self.attackers_ba = self.filter_attackers(attackers, cusum)

    except FileNotFoundError:
      self.attackers_ba = self.no_dump("BA")
    self.logger.debug("BA-attackers: {0}, FA-attackers: {1}".format(len(self.attackers_ba),len(self.attackers_fa)))

  def data_merger(self,data):
    """Merges data into self.data.

    :param data: a data dictionary to be merged into self.data
    :type data: dictionary
    """
    for item in self.data.keys():
      for srcip in data[item]:
        if srcip in self.data[item].keys():
          for dstip in data[item][srcip]['targets']:
            self.data[item][srcip]['targets'].update(data[item][srcip]['targets'])

        else:
          self.data[item].update(data[item])

  def result_counter(self, data):
    """Keeps a count of the TP, TN, FP and FN statistics.

    :param data: a tuple of a count dictionary and a data dictionary
    :type data: tuple
    """
    count, data = data
    for item in count:
      self.count[item] += count[item]

    # Parsing data for later use is too
    self.data_merger(data)

  def processor(self, data):
    """The actual validation process, i.e. grab a worker and tell him to do it.

    :param data: data to be processed
    :type data: dictionary
    """
    def worker(q, data):
      # Create the Validator and give it what it needs
      thread = lib.validator_worker.Worker(q, self.logger, self.signature, data.copy(), self.flags, self.attackers_fa.copy(), self.attackers_ba.copy())
      thread.start()

    def getter(q, num):
      for i in range(num):
        start = time.time()
        result = q.get(True)

        # Every 1000 items print where we are
        self.logger.info("Progress records: {0}/{1}".format(i+1, num))
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
      self.logger.debug("Thread {0} started".format(num))
    getter(q, num+1)

  def calculate_rates(self):
    """Calculates the TPR, TNR, FPR and FNR rates.
    """
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

  def print_rates(self):
    """Prints the rates to the logger.
    """
    self.logger.info("TP: {0}, TN: {1}, FP: {2}, FN: {3}, TOT: {4}".format(self.count['tp'], self.count['tn'], self.count['fp'], self.count['fn'], self.count['total']))
    self.logger.info("TPr: {0}, TNr: {1}, FPr: {2}, FNr: {3}, ACC: {4}".format(self.tpr, self.tnr, self.fpr, self.fnr, self.acc))

  def save_data(self, signature, date, type_scan, cusum):
    """This function saves two files, one containing the rates. The other is a categorized dump of the data. This dump can be viewed with the 'results_viewer' in the 'scripts' folder.

    :param signature: a list of used signatures in the scan
    :type signature: list
    :param date: a date string of when the scan was performed
    :type data: string
    :param type_scan: ppf, bpf or ppf+bpf
    :type type_scan: list
    :param cusum: the cusum rate (flow record threshold
    :type cusum: string
    """
    self.logger.info("Saving data...")
    signature = "_".join(signature)
    type_scan = "-".join(type_scan)
    filename = "results/{0}-{1}-{2}-{3}.txt".format(signature, date, type_scan, cusum)
    if not 'results' in os.listdir():
      os.mkdir('results')

    with open(filename, 'wb') as results_file:
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