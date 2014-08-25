#!/usr/bin/python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Generates a list of fa attacks

import fnmatch
import os
import re
import pickle
import subprocess
import sys
import traceback

from collections import defaultdict

class CDF():

  def __init__(self):

    self.threshold = 5
    self.attackers = []
    self.data = {}
    self.fa_pages = [ 'wp-login.php(.*)',
                      'xmlrpc.php',
                      'administrator/index.php',
                      'administrator/index.php?option=com_login',
                      '\?q=user',
                      '\?q=user/login(.*)',
                    ]
    self.count = {  'fa': [],
                    'xmlrpc': [],
                  }

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
        if timecode >= bottom and timecode < top:

          nfdump_files.append(os.path.join(path, filename))

    # Sort list and make available
    nfdump_files = sorted(nfdump_files)
    self.nfdump_files = nfdump_files

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

  # See if the url contains a login page
  def match(self,url):

    accept = False
    for page in self.fa_pages:

      url_match = re.match(r"(.*)({0})".format(page),url)
      if url_match:

        accept = True
        break
    return (accept, page)

  def write_to_file(self, message):

    if not message.endswith("\n"):

      message += "\n"
    message = bytes(message, 'utf-8')
    self.attack_file.write(message)

  def write_to_cdf(self, message):

    if not message.endswith("\n"):

      message += "\n"
    message = bytes(message, 'utf-8')
    self.cdf_file.write(message)


  def add_item(self, id, cur_type, cur_host, cur_page):

    #item = (id[0], id[1], self.data[id][cur_host]['count'])
    #if item not in self.attackers:

      #self.attackers.append(item)
    ##message = "{0} {1} {2} {3} {4} {5}".format(self.data[id][cur_host]['count'],id[0],id[1], cur_type, cur_host, cur_page)
    #message = "{0} {1}".format(self.data[id][cur_host]['first'], cur_type)
    #if self.data[id][cur_host]['count'] >= 5 and cur_type == 'xmlrpc.php':

      #pass
    #print(message)
    #self.write_to_file(message)
    #if self.data[id][cur_host]['count'] >= 5:

      #self.write_to_cdf(message)

    if self.data[id][cur_host]['count'] >= 5:

      if cur_type == 'xmlrpc.php':

        cur_type = 'xmlrpc'
      else:

        cur_type = 'fa'
      count  = self.count[cur_type]
      if len(count) > 0:

        count = count[-1]
      else:

        count = 0
      count += 1
      self.count[cur_type].append(int(self.data[id][cur_host]['first']) - 1405408518)

  def process_line(self, line):

    try:

      line = line.replace(b'\xff',bytes('','utf-8')).replace(b'\xfe',bytes('','utf-8')).replace(b'\xe9',bytes('','utf-8'))
      data = str(line, 'utf-8').replace("\n","").split("|")
      if len(data) >= 28:

        af, first, first_msec, last, last_msec, prot,\
            sa_0, sa_1, sa_2, sa_3, src_port,\
            da_0, da_1, da_2, da_3, dst_port,\
            src_as, dst_as, r_input, r_output,\
            flags, tos, no_pkts, no_octets,\
            something, http_port, host, page = data[0:28]
        #if int(flags) in [2,3,4]:

          #srcip = self.convert_ipaddress(sa_3)
          #dstip = self.convert_ipaddress(da_3)
          #id = (srcip,dstip)
          #self.flush_src(id)
        if host != "" or page != "":

          #url = "".join([host,page])
          url_match = self.match(page)
          if url_match[0] == True:

            srcip = self.convert_ipaddress(sa_3)
            dstip = self.convert_ipaddress(da_3)
            id = (srcip,dstip)
            if id in self.data:

              if host in self.data[id]:

                cur_type = url_match[1]
                cur_host = host
                cur_page = page
                prev_type = self.data[id][host]['type']
                prev_host = self.data[id][host]['host']
                prev_page = self.data[id][host]['page']
                if cur_type == prev_type and cur_page == prev_page:

                  self.data[id][host]['count'] += 1
                else:

                  if self.data[id][host]['count'] >= self.threshold:

                    self.add_item(id, cur_type, cur_host, cur_page)
                  del self.data[id][host]
              else:

                self.data[id][host] = {'type':  url_match[1],
                                       'page':  page,
                                       'host':  host,
                                       'count': 1,
                                       'first': first,
                                       }
            else:

              self.data[id] = {host: {'type':  url_match[1],
                                      'page':  page,
                                      'host':  host,
                                      'count': 1,
                                      'first': first,}}
    except:

      print(len(line))
      print(traceback.format_exc())

  def process_files(self, fa_graph, xml_graph):

    for nfdump_file in self.nfdump_files:

      command = "nfdump -qN -r {0} -o pipe".format(nfdump_file)
      print("pCOMMAND: {0}".format(command))

      # Run the command
      process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)

      for self.j, line in enumerate(iter(process.stdout.readline, b'')):

        self.process_line(line)
      self.flush()
    self.save_fa(fa_graph)
    self.save_xml(xml_graph)

  def flush_src(self, id):

    if id in self.data:

      for host in self.data[id]:

        if self.data[id][host]['count'] >= self.threshold:

          cur_type = self.data[id][host]['type']
          cur_host = self.data[id][host]['host']
          cur_page = self.data[id][host]['page']
          self.add_item(id, cur_type, cur_host, cur_page)
      del self.data[id]

  def flush(self):

    print("Flushing remaining")
    for id in self.data:

      for host in self.data[id]:

        if self.data[id][host]['count'] >= self.threshold:

          cur_type = self.data[id][host]['type']
          cur_host = self.data[id][host]['host']
          cur_page = self.data[id][host]['page']
          self.add_item(id, cur_type, cur_host, cur_page)
    self.data = {}

  def save_fa(self, fa_graph):

    count = defaultdict(int)
    for timecode in self.count['fa']:

      count[timecode] += 1
    for timecode in sorted(count.keys()):

      message = bytes("{0} {1}\n".format(timecode, count[timecode]), 'utf-8')
      fa_graph.write(message)
    pass
    #for i,timecode in enumerate(sorted(self.count['fa'].values())):

      #print(timecode, i)
      #message = bytes("{0} {1}\n".format(timecode, i+1), 'utf-8')
      #fa_graph.write(message)

  def save_xml(self, xml_graph):

    count = defaultdict(int)
    for timecode in self.count['xmlrpc']:

      count[timecode] += 1
    for timecode in sorted(count.keys()):

      message = bytes("{0} {1}\n".format(timecode, count[timecode]), 'utf-8')
      xml_graph.write(message)
    pass
    #for i,timecode in enumerate(sorted(self.count['xmlrpc'].values())):

      #print(timecode, i)
      #message = bytes("{0} {1}\n".format(timecode, i+1), 'utf-8')
      #xml_graph.write(message)

def main():

  # nfdump file is the first argument
  nfdump_file = sys.argv[1]
  
  cdf = CDF()
  cdf.process_filenames(nfdump_file)
  with open('debug/fa_graph.txt','wb') as fa_graph:
    
    with open('debug/xmlrpc_graph.txt','wb') as xml_graph:

      cdf.process_files(fa_graph, xml_graph)
  cdf.flush()

if __name__ == "__main__":

  main()