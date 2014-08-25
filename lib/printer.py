#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  The printing module

import datetime
import os
import re
import subprocess
import sys
import time

# Try to import termcolor for fancy output, set a variable if it is available
try:

  from termcolor import colored
  color_text = True
except:

  color_text = False

class Printer():

  available_colors = ['magenta', 'white', 'blue', 'red',  'green', 'yellow']
  header = ['src','dst',

            'packet_mean', 'packet_stdev',
            'bytes_mean', 'bytes_stdev',
            'duration_mean', 'duration_stdev',

            'flows', 'flow_duration',
            'cusum',
            'reset', 'attack', 

            'activity', 'total_duration',
            'first_seen', 'last_seen',
            'start_time', 'end_time',
            'signature',
            ]
  header_dict = { 'src': '{:>20}','dst':'{:>20}',

                  'start_time':'{:>26}', 'end_time':'{:>26}',
                  'first_seen':'{:>26}', 'last_seen':'{:>26}',
                  'activity':'{:>10}', 'total_duration':'{:>20}',

                  'packet_mean':'{:>12}', 'packet_stdev':'{:>14}',
                  'bytes_mean':'{:>11}', 'bytes_stdev':'{:>13}',
                  'duration_mean':'{:>14}', 'duration_stdev':'{:>16}',
                  'flows':'{:>10}', 'flow_duration':'{:>14}', 
                  'signature':'{:>15}',

                  'attack': '{:>10}',
                  'reset': '{:>10}',
                  'cusum': '{:>10}',
                }
  sig_colors = {}

  def __init__(self):

    pass

  # Opens a file to print to (if output is set to disk)
  def print_open_file(self):

    signature = "_".join(sorted(self.ids.signature.keys()))
    filename = "{0}{1}-{2}.ids".format(self.ids.outputdir,str(self.ids.path.split("/")[-1]), signature)
    if not os.path.isdir(self.ids.outputdir):

      self.logger.debug("Creating an output dir")
      os.mkdir(self.ids.outputdir)
    if not os.path.isdir(self.ids.outputdir):

      self.logger.error("'I am at a rough estimate thirty billion times more intelligent than you. Let me give you an example. Think of a number, any number.'\n\
There is something wrong with your filesystem, please fix this.")
      sys.exit()
    self.output_file = open(filename, 'wb')

  # Closes the print file
  def print_close_file(self):

    self.output_file.close()

  # Writes a line to the print file
  def print_file(self, message):

    if not message.endswith("\n"):

      message += "\n"
    message = bytes(message, 'utf-8')
    self.output_file.write(message)

  # Writes a line to the pager
  def print_less(self, message, color):

    if not message.endswith("\n"):

      message += "\n"

    # If the termcolor is loaded add color information
    if color_text and color != None:

      message = colored(message,color)
    message = bytes(message, 'utf-8')
    self.pager.stdin.write(message)

  def print_message(self, message, color):

    if 'disk' in self.ids.flags['output_value']:

      self.print_file(message)

    if 'pager' in self.ids.flags['output_value']:

      self.print_less(message, color)

  # Prints a legenda and a few statistics
  def print_legenda(self):

    if color_text == True:

      message = "\nLegenda: [Red: packet-stdev && bytes-stdev && duration-stdev == 0], [Magenta: two of <- are equal to 0], [White: one is equal to 0]"
      self.print_message(message, None)
    try:

      for signature in self.ids.count:

        message = "{0} ips match signature '{1}'".format(self.ids.count[signature], signature)
        self.print_message(message, None)
    except:

      self.logger.exception("'I have a million ideas. They all point to certain death.'\n{0}".format(self.ids.count))
    self.print_message("", None)

  # This function prints a fancy header
  def print_header(self):

    # Print the legenda
    if self.ids.flags['absolom'] == False:

      self.print_legenda()

    line = []
    self.used = []

    srcip = list(self.ids.data.keys())[0]
    dstip = list(self.ids.data[srcip]['targets'].keys())[0]
    keys = list(self.ids.data[srcip]['targets'][dstip].keys())
    if 'targets' in keys:

      keys.remove('targets')
    if 'url' in keys:

      keys.remove('url')
    keys.insert(0, 'src')
    keys.insert(1, 'dst')
    dictionary = {}
    for item in keys:

      try:

        header = self.header_dict[item].format(item)
        dictionary[item] = header
      except:

        self.logger.exception("'I could calculate your chance of survival, but you won't like it.'")
    for item in self.header:

      if item in dictionary.keys():

        line.append(dictionary[item])
        self.used.append(item)
    line = "".join(line)
    line = line.replace("_","-").replace("   src","src ->")
    length = len(line)
    self.print_message(line, None)

    # Print a nice line
    sub = '{:=^'+str(length)+'}'
    line = sub.format('')
    self.print_message(line, None)

  # Prints urls in a nice fashion
  def print_urls(self, srcip, dstip, color):

    for url in self.ids.data[srcip]['targets'][dstip]['url']:

      if url != "":

        count = "[{0}]".format(self.ids.data[srcip]['targets'][dstip]['url'][url])
        count = "{:>44}".format(count)
        key = url
        if self.ids.flags['violate'] == False:

          url = re.sub('^([^/]*)/',"",url)
        if int(self.ids.data[srcip]['targets'][dstip]['url'][key]) >= int(self.ids.flags['url_value']):

          line = "{0}: {1}".format(count, url)
          self.print_message(line,color)

  def print_format_value(self, item, value):

    if item in ['start_time','end_time', 'first_seen', 'last_seen']:

      value = value/1000
      value = str(datetime.datetime.fromtimestamp(value))
      value = "{0}".format(value[:-4])
    elif item == 'total_duration':

      value = value/1000
      value = str(datetime.timedelta(seconds=int(value)))
    elif item in ['packet_mean','packet_stdev','bytes_mean','bytes_stdev']:

      value = float(value)
      value = "{0:.2f}".format(value)
    elif item in ['duration_mean','duration_stdev']:

      value = value/1000
      value = "{0:.2f}".format(value)
    elif item in ['flow_duration']:

            value = value/1000
            value = "{0:.2f}".format(value)
    elif item == 'activity':

      #value = str(value)
      #before = re.sub('\..*$','',value)
      #after = re.sub('^.*\.','',value).zfill(2)
      #value = "{0}.{1}%".format(before,after[0:2])
      value = ''
    elif item in ['signature', 'flows', 'reset', 'attack']:

      pass
    elif item in ['cusum']:

      value = "{0:.2f}".format(value)
    else:

      value = ''
    return value

  def print_srcip(self, srcip):

    line = []
    keys = list(self.ids.data[srcip].keys())
    keys.remove('targets')
    for item in self.used:

      if item == 'first_seen':

        item = 'start_time'
      if item == 'last_seen':

        item = 'end_time'

      if item in keys:

        value = self.ids.data[srcip][item]
        value = self.print_format_value(item, value)
        data = self.header_dict[item].format(value)
      elif item == 'src':

        data = self.header_dict[item].format(srcip)
      elif item == 'dst':

        data = self.header_dict[item].format('\U000021B4')
      else:

        data = self.header_dict[item].format(' ')
      line.append(data)
    line = "".join(line)
    return line

  def print_dstip(self, srcip, dstip):

    line = []
    if self.ids.flags['flows'] == False or self.ids.data[srcip]['targets'][dstip]['flows'] >= self.ids.flags['flows_value']:

      keys = list(self.ids.data[srcip]['targets'][dstip].keys())
      if 'url' in keys:

        keys.remove('url')
      for item in self.used:

        if item in keys:

          value = self.ids.data[srcip]['targets'][dstip][item]
          value = self.print_format_value(item, value)
          data = self.header_dict[item].format(value)
        elif item == 'src':

          data = self.header_dict[item].format('\U000021D2')
        elif item == 'dst':

          data = self.header_dict[item].format(dstip)
        else:

          data = self.header_dict[item].format(' ')
        line.append(data)
    line = "".join(line)
    return line

  def print_color(self, srcip, dstip):

    color = None
    signature = self.ids.data[srcip]['targets'][dstip]['signature']
    if self.ids.flags['absolom'] == True:

      if signature in self.sig_colors:

        color = self.sig_colors[signature]
      else:

        color = self.available_colors.pop(0)
        self.sig_colors[signature] = color

    else:

      if float(self.ids.data[srcip]['targets'][dstip]['packet_stdev']) <= float(self.ids.signature[signature]['packets_stdev'])\
          and float(self.ids.data[srcip]['targets'][dstip]['bytes_stdev']) <= float(self.ids.signature[signature]['bytes_stdev'])\
          and float(self.ids.data[srcip]['targets'][dstip]['duration_stdev']) <= float(self.ids.signature[signature]['duration_stdev']):

        color = 'red'
      elif (float(self.ids.data[srcip]['targets'][dstip]['packet_stdev']) <= float(self.ids.signature[signature]['packets_stdev'])\
            and float(self.ids.data[srcip]['targets'][dstip]['bytes_stdev']) <= float(self.ids.signature[signature]['bytes_stdev'])) or\
            (float(self.ids.data[srcip]['targets'][dstip]['packet_stdev']) <= float(self.ids.signature[signature]['packets_stdev'])\
            and float(self.ids.data[srcip]['targets'][dstip]['duration_stdev']) <= float(self.ids.signature[signature]['duration_stdev'])) or\
            (float(self.ids.data[srcip]['targets'][dstip]['bytes_stdev']) <= float(self.ids.signature[signature]['bytes_stdev'])\
            and float(self.ids.data[srcip]['targets'][dstip]['duration_stdev']) <= float(self.ids.signature[signature]['duration_stdev'])):

        color = 'magenta'
      elif float(self.ids.data[srcip]['targets'][dstip]['packet_stdev']) <= float(self.ids.signature[signature]['packets_stdev']) or\
            float(self.ids.data[srcip]['targets'][dstip]['bytes_stdev']) <= float(self.ids.signature[signature]['bytes_stdev']) or\
            float(self.ids.data[srcip]['targets'][dstip]['duration_stdev']) <= float(self.ids.signature[signature]['duration_stdev']):

        color = 'white'

    return color

  # Print all the data
  def print_data(self):

    # Go through all the sources in the data
    for srcip in self.ids.data:

      # Print the source
      line = self.print_srcip(srcip)
      self.print_message(line, None)

      # Print the targets
      for dstip in self.ids.data[srcip]['targets']:

        line = self.print_dstip(srcip, dstip)
        color = self.print_color(srcip, dstip)
        self.print_message(line, color)

        if self.ids.extended == True and line != "":

          self.print_urls(srcip, dstip, color)
      self.print_message('', None)

  # This functions prints the results
  def print_results(self):

    self.logger.debug("{0} srcips in data".format(len(self.ids.data)))
    if self.ids.flags['absolom'] == True:

          self.ids.data.update(self.ids.everything)
    if len(self.ids.data) > 0:

      try:

        if 'disk' in self.ids.flags['output_value']:

          self.print_open_file()

        # Create a pager
        if 'pager' in self.ids.flags['output_value']:

          self.pager = subprocess.Popen(['less', '-F', '-R', '-S', '-X', '-K'], stdin=subprocess.PIPE, stdout=sys.stdout)

        # Print a nice header
        self.print_header()

        # Print the data
        self.print_data()

        # Close the pager
        if 'pager' in self.ids.flags['output_value']:

          self.pager.stdin.close()
          self.pager.wait()
        if 'disk' in self.ids.flags['output_value']:

          self.print_close_file()
      except:

        self.logger.exception("Incredible... it's even worse than I thought it would be.")

  # Open a file for parsable data
  def save_open_file(self):

    signature = "_".join(sorted(self.ids.signature.keys()))
    if self.ids.flags['absolom'] == True:

      date = str(str(datetime.datetime.fromtimestamp(time.time())).split(" ")[0])
      cusum = self.ids.flags['cusum_value']
      filename = "{0}{1}-{2}-{3}".format(self.ids.datadir,date,signature,cusum)
      if self.ids.flags['packets'] == True:

        filename = "{0}-ppf".format(filename)
      if self.ids.flags['bytes'] == True:

        filename = "{0}-bpf".format(filename)
      filename = "{0}.idats".format(filename)
    else:

      filename = "{0}{1}-{2}.idats".format(self.ids.datadir,str(self.ids.path.split("/")[-1]),signature)
    if not os.path.isdir(self.ids.datadir):

      self.logging.debug("Creating an output dir")
      os.mkdir(self.ids.datadir)
    if not os.path.isdir(self.ids.datadir):

      self.logger.error("'I am at a rough estimate thirty billion times more intelligent than you. Let me give you an example. Think of a number, any number.'\n\
There is something wrong with your filesystem, please fix this.")
      sys.exit()
    self.data_file = open(filename, 'wb')

  # Close the save file
  def save_close_file(self):

    self.data_file.close()

  # Writes the URLs to the save file
  def save_urls(self, srcip, dstip):

    url_line = []
    for url in self.ids.data[srcip]['targets'][dstip]['url']:

      if url != "":

        count = self.ids.data[srcip]['targets'][dstip]['url'][url]
        line = "{0}\\{1}".format(url,count)
        url_line.append(line)
    url_line = "\\".join(url_line)
    return url_line

  # Write a line to the save file
  def save_write_line(self, line):

    if not line.endswith("\n"):

      line += "\n"
    #self.logger.debug(line)
    line = bytes(line, 'utf-8')
    self.data_file.write(line)

  def save_data(self):

    # Open a file
    self.save_open_file()

    # Go through all the sources
    for srcip in self.ids.data:

      # Go through all the destinations
      for dstip in self.ids.data[srcip]['targets']:

        line = []
        for item in self.header:

          if item in self.ids.data[srcip]['targets'][dstip]:

            data = self.ids.data[srcip]['targets'][dstip][item]
          elif item == 'src':

            data = srcip
          elif item == 'dst':

            data = dstip.replace(":","|")
          else:

            data = ''
          if data != '':

            line.append(str(data))
        line.append(self.save_urls(srcip,dstip))
        line = "|".join(line)
        self.save_write_line(line)

    if self.ids.flags['absolom'] == True and 'everything' in self.ids.signature.keys():

      self.ids.data_temp = self.ids.data.copy()
      self.ids.data = self.ids.everything.copy()
      for srcip in self.ids.everything:

        # Go through all the destinations
        for dstip in self.ids.everything[srcip]['targets']:

          line = []
          for item in self.header:

            if item in self.ids.everything[srcip]['targets'][dstip]:

              data = self.ids.everything[srcip]['targets'][dstip][item]
            elif item == 'src':

              data = srcip
            elif item == 'dst':

              data = dstip.replace(":","|")
            else:

              data = ''
            if data != '':

              line.append(str(data))
          line.append(self.save_urls(srcip,dstip))
          line = "|".join(line)
          self.save_write_line(line)
      self.ids.data = self.ids.data_temp.copy()
      del self.ids.data_temp

    # Close the save file
    self.save_close_file()
