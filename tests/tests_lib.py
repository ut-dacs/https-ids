import unittest
import sys
import os
import configparser
sys.path.append(os.path.abspath(os.path.curdir))

import lib.config

class Test_lib_config(unittest.TestCase):
  def setUp(self):

    self.conf_files = ['ids']
  def test_get_conf_file(self):

    # No argument, should error
    self.assertRaises(TypeError, lib.config.get_conf_file)

    # Non string argument should error
    self.assertRaises(TypeError, lib.config.get_conf_file, 1)

    # File doesn't exist, should raise an IOError
    self.assertRaises(FileNotFoundError, lib.config.get_conf_file, 'Bogus_File')

    # Returns existing file string
    for item in self.conf_files:
      target_dir = os.path.abspath(os.path.curdir)
      path =  os.path.join(target_dir, 'conf', "{0}.conf".format(item))
      self.assertEqual(lib.config.get_conf_file(item), path.format(item))

  def test_get_parser(self):

    # No argument, should error
    self.assertRaises(TypeError,lib.config.get_parser)

    # Non string argument should error
    self.assertRaises(TypeError,lib.config.get_parser, 1)

    # File doesn't exist
    self.assertRaises(FileNotFoundError,lib.config.get_parser, 'Bogus')

    # Should return configparser object
    for item in self.conf_files:

      conf_file = lib.config.get_conf_file(item)
      self.assertIsInstance(lib.config.get_parser(conf_file), configparser.ConfigParser)

  def test_get_all_options(self):

    # No argument, should error
    self.assertRaises(TypeError,lib.config.get_all_options)

    # Non string argument should error
    self.assertRaises(TypeError,lib.config.get_all_options, 1, 1)

    # Non existing section
    conf_file = lib.config.get_conf_file("signatures")
    config_parser = lib.config.get_parser(conf_file)
    self.assertRaises(LookupError, lib.config.get_all_options, "ids",config_parser)

    # Options dictionaries
    for item in self.conf_files:

      conf_file = lib.config.get_conf_file(item)
      config_parser = lib.config.get_parser(conf_file)
      options = lib.config.get_all_options(item, config_parser)
      self.assertIsInstance(options,dict)
      self.assertGreater(len(options),0)

  def test_read_config(self):

    # No argument, should error
    self.assertRaises(TypeError,lib.config.read_config)

    # Non string argument should error
    self.assertRaises(TypeError,lib.config.read_config, 1)

    # Bogus conf_name
    self.assertRaises(FileNotFoundError, lib.config.read_config, 'Bogus')

    # All conf files should work
    for item in self.conf_files:

      conf_file = lib.config.get_conf_file(item)
      config_parser = lib.config.get_parser(conf_file)
      options = lib.config.get_all_options(item, config_parser)
      config = lib.config.read_config(item)
      self.assertDictEqual(options, config)

  def test_get_signatures(self):
    conf_file = lib.config.get_conf_file('signatures')
    config_parser = lib.config.get_parser(conf_file)
    signatures = lib.config.get_signatures(config_parser)
    self.assertIsInstance(signatures, list)
    self.assertGreater(len(signatures), 0)

  def test_read_signatures(self):
    signatures = lib.config.read_signatures()
    self.assertIsInstance(signatures, dict)
    self.assertGreater(len(signatures), 0)
    for signature in signatures:
      self.assertIsInstance(signatures[signature], dict)
      self.assertGreater(len(signatures[signature]), 0)

if __name__ == '__main__':
  if not '--verbose' in sys.argv:
    sys.argv.append('--verbose')
  unittest.main(buffer=True, failfast=True)