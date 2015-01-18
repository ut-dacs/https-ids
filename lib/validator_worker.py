#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Worker class for validate.py

import threading
import queue
import traceback
import re
import sys

class Worker(threading.Thread):
  """The worker class for the validator.
  """
  def __init__(self, queue, logger, signature, data, flags, fa, ba):
    threading.Thread.__init__(self)
    self.data = {'all': {},
                 'tp':  {},
                 'tn':  {},
                 'fp':  {},
                 'fn':  {}
                 }
    self.count = {'tp': 0,
                  'fp': 0,
                  'tn': 0,
                  'fn': 0,
                  'total': 0,
                  }
    self.queue = queue
    self.logger = logger.getChild('worker')
    self.signature = signature
    self.process_data = data
    self.flags = flags
    self.attackers_fa = fa
    self.attackers_ba = ba

  def grab_data(self, line):
    """Transforms a ids line into a dictionary.

    :param line: a line from a result file
    :type line: string
    :return: data dictionary
    """
    data ={ 'packet_mean':             float(line[3]),
            'bytes_mean':              float(line[4]),
            'flows':                   int(line[5]),
            'cusum':                   float(line[6]),
            'first_seen':              float(line[7]),
            'last_seen':               float(line[8]),
            'signature':               line[9],
            'url':                     {},
          }
    return data

  def check(self, srcip, dstip, signature):
    """Checks if the src <-> dst tuple is a TP, FN, FP or TN.

    :param srcip: the source ip
    :type srcip: string
    :param dstip: the destination ip
    :type dstip: string
    :param signature: the matched signature
    :type signature: string
    :return: result ('tp', 'fn', 'fp', 'tn')
    """
    real_attack = False
    sig_attack = False
    if (srcip, dstip) in self.attackers_ba or (srcip, dstip) in self.attackers_fa:
        real_attack = True

    if signature in ['ba', 'fa', 'xmlrpc']:
      sig_attack = True

    if real_attack == True and sig_attack == True:
      result = 'tp'

    elif real_attack == True and sig_attack == False:
      result = 'fn'

    elif real_attack == False and sig_attack == True:
      result = 'fp'

    elif real_attack == False and sig_attack == False:
      result = 'tn'

    return result

  def split_url(self, url):
    """Splits a URL from their hit count

    :param url: a string of a URL and its hit count
    :type url: string
    :return: a tuple of the count and URL
    """
    url = re.match(r"(.*)\\([0-9]+)$",url)
    count = int(url.group(2))
    url = url.group(1)
    return (count, url)

  def parse_data(self, line, id):
    """Function for parsing the data for later analysis.

    :param line: a data line from the results file
    :type line: string
    :param id: defines it to be a TP, TN, FP or FN
    :type id: string
    """
    srcip = line[0]
    dstip = "{0}:{1}".format(line[1],line[2])
    urls = line[10]
    urls = re.sub(r"\.nlhttp",".nl/http",urls)
    urls = re.sub(r"(\\)([0-9]+)([\\\n])",r"\\\2\n",urls).split("\n")

    data = self.grab_data(line)

    # All
    if srcip in self.data['all'].keys():
      if dstip in self.data['all'][srcip]['targets']:
        self.logger.error("I should not be here, ALL")

      else:
        self.data['all'][srcip]['targets'][dstip] = data

    else:
      self.data['all'][srcip] = {  'start_time':        0,
                                   'end_time':          0,
                                   'total_duration':    0,
                                   'targets':           {dstip: data},
                                  }

    if srcip in self.data[id].keys():
      if dstip in self.data[id][srcip]['targets']:
        self.logger.error("Data corruption detected!")
        self.logger.debug("{0}\n{1}\n{2}".format(id,data,self.data[id][srcip]['targets'][dstip]))
        self.logger.info("To continue please hit enter")
        input()

      self.data[id][srcip]['targets'][dstip] = data

    else:
      self.data[id][srcip] = {  'start_time':        0,
                                   'end_time':          0,
                                   'total_duration':    0,
                                   'targets':           {dstip: data},
                                  }

    # Urls
    for url in urls:
      if url != "":
        count, url = self.split_url(url)
        if not url in self.data['all'][srcip]['targets'][dstip]['url'].keys():
          self.data['all'][srcip]['targets'][dstip]['url'][url] = count

        if not url in self.data[id][srcip]['targets'][dstip]['url'].keys():
          self.data[id][srcip]['targets'][dstip]['url'][url] = count

  def stats(self, line):
    """Determines the type and parses the data

    :param line: a line from the results file
    :type line: bytes
    """
    line = str(line, 'utf-8').split("|")
    srcip = line[0]
    dstip = line[1].replace(":*","")
    signature = line[9]
    result = self.check(srcip, dstip, signature)

    self.parse_data(line, result)
    self.count[result] += 1
    self.count['total'] += 1

  def run(self):
    """Main function that runs trough the all the lines in the results file and calls 'stats' on the line.
    """
    length = len(self.process_data)
    for i, line in enumerate(self.process_data):
      self.stats(line)

    self.queue.put((self.count, self.data))

  def get_result(self):
   """Returns the achieved result.

   :return: the resulting dictionary
   """
   self.result = (self.count, self.data)
   return self.result