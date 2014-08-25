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

class CDF():

  def __init__(self):

    self.threshold = 0
    self.attackers = []
    self.data = {}
    with open('includes/401.dump', 'rb') as f:

      ba_pages = pickle.load(f)
    self.ba_pages = ba_pages
    #self.find_folders()

  def find_folders(self):

    for i,page in enumerate(self.ba_pages):

      page = re.sub("(.*)/(.*)$",'\g<1>',page)
      self.ba_pages[i] = page

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
  def match(self,host,page):

    accept = False
    test = "{0}{1}".format(host,page)
    if not test.startswith("http://"):

      test = "http://{0}".format(test)
    for url in self.ba_pages:

      #print((test,url))
      if url in test:

        accept = True
        break
    return accept

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


  def add_item(self, id, cur_host, cur_page):

    item = (id[0], id[1], self.data[id][cur_host]['count'])
    if item not in self.attackers:

      self.attackers.append(item)
    message = "{0} {1} {2} {3} {4}".format(self.data[id][cur_host]['count'],id[0],id[1], cur_host, cur_page)
    if self.data[id][cur_host]['count'] >= 3:

      print(message)
      pass
    self.write_to_file(message)
    if self.data[id][cur_host]['count'] >= 5:

      self.write_to_cdf(message)

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
          url_match = self.match(host,page)
          if url_match == True:

            srcip = self.convert_ipaddress(sa_3)
            dstip = self.convert_ipaddress(da_3)
            id = (srcip,dstip)
            if id in self.data:

              if host in self.data[id]:

                cur_host = host
                cur_page = page
                prev_host = self.data[id][host]['host']
                prev_page = self.data[id][host]['page']
                if cur_page == prev_page:

                  self.data[id][host]['count'] += 1
                else:

                  if self.data[id][host]['count'] >= self.threshold:

                    self.add_item(id, cur_host, cur_page)
                  del self.data[id][host]
              else:

                self.data[id][host] = {
                                       'page':  page,
                                       'host':  host,
                                       'count': 1}
            else:

              self.data[id] = {host: {
                                      'page':  page,
                                      'host':  host,
                                      'count': 1}}
    except:

      print(len(line))
      print(traceback.format_exc())

  def process_files(self, attack_file, cdf_file):

    self.attack_file = attack_file
    self.cdf_file = cdf_file
    for nfdump_file in self.nfdump_files:

      command = "nfdump -qN -r {0} -o pipe".format(nfdump_file)
      print("pCOMMAND: {0}".format(command))

      # Run the command
      process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)

      for self.j, line in enumerate(iter(process.stdout.readline, b'')):

        self.process_line(line)
      self.flush()

  def flush_src(self, id):

    if id in self.data:

      for host in self.data[id]:

        if self.data[id][host]['count'] >= self.threshold:

          cur_host = self.data[id][host]['host']
          cur_page = self.data[id][host]['page']
          self.add_item(id, cur_host, cur_page)
      del self.data[id]

  def flush(self):

    print("Flushing remaining")
    for id in self.data:

      for host in self.data[id]:

        if self.data[id][host]['count'] >= self.threshold:

          cur_host = self.data[id][host]['host']
          cur_page = self.data[id][host]['page']
          self.add_item(id, cur_host, cur_page)
    self.data = {}

def main():

  # nfdump file is the first argument
  nfdump_file = sys.argv[1]

  cdf = CDF()
  cdf.process_filenames(nfdump_file)
  with open('debug/attackers_data_ba.txt', 'wb') as attack_file:
    
    with open('debug/cdf_data_ba.txt', 'wb') as cdf_file:

      cdf.process_files(attack_file, cdf_file)
      cdf.flush()
  with open('includes/attackers_ba.dump', 'wb') as attackers_data:

    pickle.dump(cdf.attackers, attackers_data)

if __name__ == "__main__":

  main()