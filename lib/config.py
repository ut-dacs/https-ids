#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <oliviervdtoorn@gmail.com>
# Description:  This parses config files

import configparser
import traceback
import sys

class Config():

  def __init__(self):

    # Setup the config, and the conf path
    self.config = configparser.ConfigParser()
    self.config.read("conf/ids.conf")
    self.signature = configparser.ConfigParser()
    self.signature.read("conf/signatures.conf")

  def get_signatures(self):

    return self.signature.sections()

  def read_item(self, section, item):

    # Try to read the item, if this fails return an error
    try:

      request = self.config.get(section, item)
      return request
    except:

      print(traceback.format_exc())

  def read_all(self, item, section):

    # This reads the entire config into a dictionary
    return_dict = {}
    if item == "signature":

      if section in self.signature.sections():

        options = self.signature.options(section)
        for option in options:

          return_dict[option] = self.signature.get(section, option)
    else:

      if section in self.config.sections():

        options = self.config.options(section)
        for option in options:

          return_dict[option] = self.config.get(section, option)
    return return_dict
config = Config()
