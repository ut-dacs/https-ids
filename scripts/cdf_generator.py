#!/usr/bin/python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Generates a cdf from flow data

import fnmatch
import os
import re
import subprocess
import sys
import traceback

class CDF():

  def __init__(self):

    self.threshold = 5
    self.data = {}
    self.fa_pages = [ 'wp-login.php',
                      'administrator/index.php(.*)',
                      'administrator/index.php?option=com_login',
                      'wp-login.php\?redirect_to=(.*)',
                      '\?q=user',
                      '\?q=user/login',
                    ]

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

      url_match = re.match(r"(.*)({0})(.*)".format(page),url)
      if url_match:

        accept = True
        break
    return (accept, page)

  def write_to_file(self, message):

    if not message.endswith("\n"):

      message += "\n"
    message = bytes(message, 'utf-8')
    self.cdf_file.write(message)

  def process_line(self, line):

    try:

      line = line.replace(b'\xff',bytes('','utf-8')).replace(b'\xfe',bytes('','utf-8'))
      data = str(line, 'utf-8').replace("\n","").split("|")
      if len(data) >= 28:

        af, first, first_msec, last, last_msec, prot,\
            sa_0, sa_1, sa_2, sa_3, src_port,\
            da_0, da_1, da_2, da_3, dst_port,\
            src_as, dst_as, r_input, r_output,\
            flags, tos, no_pkts, no_octets,\
            something, http_port, host, page = data[0:28]
        if host != "" or page != "":

          url = "".join([host,page])
          url_match = self.match(url)
          if url_match[0] == True:

            srcip = self.convert_ipaddress(sa_3)
            dstip = self.convert_ipaddress(da_3)
            id = (srcip,dstip)
            if id in self.data:

              cur_type = url_match[1]
              prev_type = self.data[id]['type']
              prev_host = self.data[id]['host']
              if cur_type == prev_type and prev_host:

                self.data[id]['count'] += 1
              else:

                if self.data[id]['count'] >= self.threshold:

                  print((self.data[id]['count'],self.data[id]['type'], id))
                  message = "{0} {1} {2}".format(self.data[id]['count'],self.data[id]['type'], id)
                  self.write_to_file(message)
                del self.data[id]
            else:

              self.data[id] = {'type':  url_match[1],
                               'page':  page,
                               'host':  host,
                               'count': 1}
    except:

      print(len(line))
      print(traceback.format_exc())

  def process_files(self, cdf_file):

    self.cdf_file = cdf_file
    for nfdump_file in self.nfdump_files:

      command = "nfdump -qN -r {0} -o pipe".format(nfdump_file)
      print("pCOMMAND: {0}".format(command))

      # Run the command
      process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)

      for self.j, line in enumerate(iter(process.stdout.readline, b'')):

        if self.j % 100000 == 0:

          #print("Processed {0} lines".format(self.j))
          #print(self.data)
          pass
        self.process_line(line)

def main():

  # nfdump file is the first argument
  nfdump_file = sys.argv[1]
  
  cdf = CDF()
  cdf.process_filenames(nfdump_file)
  with open('cdf_data.txt', 'wb') as cdf_file:

    cdf.process_files(cdf_file)

if __name__ == "__main__":

  main()