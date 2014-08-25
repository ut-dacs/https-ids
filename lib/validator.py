#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Worker class for validate.py

import threading
import queue
import traceback
import re
import sys

class Validator(threading.Thread):

  def __init__(self):

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

  def grab_data(self, line):

    if self.parent.flags['absolom'] == True:

      data ={ 'packet_mean':             float(line[3]),
              'bytes_mean':              float(line[4]),
              'flows':                   int(line[5]),
              'cusum':                   float(line[6]),
              'first_seen':              float(line[7]),
              'last_seen':               float(line[8]),
              'signature':               line[9],
              'url':                     {},
            }

    # Mean algorithm stuff
    else:

      data ={   'packet_mean':             float(line[3]),
                'packet_stdev':            float(line[4]),
                'bytes_mean':              float(line[5]),
                'bytes_stdev':             float(line[6]),
                'duration_mean':           float(line[7]),
                'duration_stdev':          float(line[8]),
                'flows':                   int(line[9]),
                'activity':                float(line[11]),
                'flow_duration':           float(line[10]),
                'total_duration':          float(line[12]),
                'first_seen':              float(line[13]),
                'last_seen':               float(line[14]),
                'signature':               line[15],
                'url':                     {},
              }
    return data

  def split_url(self, url):

    url = re.match(r"(.*)\\([0-9]+)$",url)
    count = int(url.group(2))
    url = url.group(1)
    return (count, url)

  # Parse the data for later analysis
  def parse_data(self, line, urls, id):

    srcip = line[0]
    dstip = "{0}:{1}".format(line[1],line[2])
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

    # ID
    if srcip in self.data[id].keys():

      if dstip in self.data[id][srcip]['targets']:

        self.logger.error("I should not be here {0}\n{1}\n{2}".format(id,data,self.data[id][srcip]['targets'][dstip]))
      else:

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

  # See if the url contains a login page
  def match(self,url):

    accept = False
    if 'fa' in self.parent.sig:

      try:

        url_match = re.match(r"(.*)({0})(\\)(.*)".format(self.parent.fa_pages),url)
      except:

        self.logger.exception("Bummer")
    elif 'ba' in self.parent.sig:

      self.parent.ba_pages = self.parent.ba_pages.replace("(","\(")
      try:

        url_match = re.match(r"(.*)({0})(\\)(.*)".format(self.parent.ba_pages),url)
      except:

        self.logger.error(pages)

    if url_match:

      accept = True
    return accept

  def ba(self, signature, srcip, dstip):

    attack = False
    if (srcip,dstip) in self.attackers_ba:

      attack = True
    if attack == True and signature in self.parent.sig:

      result = 'tp'

    elif attack == False and signature in self.parent.sig:

      result = 'fp'
    elif attack == True and not signature in self.parent.sig:

      result = 'fn'

    elif attack == False and not signature in self.parent.sig:

      result = 'tn'
    return result

  def fa(self, signature, srcip, dstip):

    attack = False
    if (srcip, dstip) in self.attackers:

      attack = True
    if attack == True and signature in self.parent.sig:

      result = 'tp'

    elif attack == False and signature in self.parent.sig:

      result = 'fp'
    elif attack == True and not signature in self.parent.sig:

      result = 'fn'

    elif attack == False and not signature in self.parent.sig:

      result = 'tn'
    return result

  # Determines what the line is (tp, tn, fn, fp)
  def stats(self,line):

    try:

      line = str(line, 'utf-8').split("|")
      if len(line) == 11:

        self.parent.flags['absolom'] = True
        self.new = 1

      # Grab the urls
      if self.parent.flags['absolom'] == True and self.new == 1:

        urls = line[10]
        signature = line[9]

      else:

        urls = line[16]
        signature = line[15]

      # One line per url
      urls = re.sub(r"\.nlhttp",".nl/http",urls)
      urls = re.sub(r"(\\)([0-9]+)([\\\n])",r"\\\2\n",urls).split("\n")

      srcip = line[0]
      dstip = line[1].replace(":*","")

      if 'ba' in self.parent.sig:

        result = self.ba(signature, srcip, dstip)
      if 'fa-v2' in self.parent.sig or 'xmlrpc' in self.parent.sig or 'xmlrpc-v2' in self.parent.sig:

        result = self.fa(signature, srcip, dstip)
      self.parse_data(line, urls, result)
      self.count[result] += 1
      self.count['total'] += 1
    except:

      self.logger.exception("Marvin was humming ironically because he hated humans so much.")

  def run(self):

    # Go through all the lines and see what they are
    for line in self.orig_data:

      self.stats(line)

  def get_result(self):

   self.result = (self.count, self.data)
   return self.result
