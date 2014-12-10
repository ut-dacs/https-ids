import unittest
import sys
import os
import configparser
import subprocess
sys.path.append(os.path.abspath(os.path.curdir))

import lib.config
import lib.flags
import lib.printer

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

class Test_lib_flags(unittest.TestCase):
  def test_get_default(self):
    flags = lib.flags.get_default()
    self.assertIsInstance(flags, dict)
    self.assertGreater(len(flags), 0)

  def test_show_help(self):
    self.assertRaises(SystemExit, lib.flags.show_help)

  def test_get_flags(self):
    flags = lib.flags.get_flags()
    self.assertIsInstance(flags, dict)
    self.assertGreater(len(flags), 0)

  def test_flip_flag(self):
    state = lib.flags.get_default()['debug']
    sys.argv.append("--debug")
    self.assertIsNot(lib.flags.get_flags()['debug'], state)
    sys.argv.remove("--debug")

  def test_set_value(self):
    # No value specified
    sys.argv.append("--threads")
    self.assertRaises(IndexError, lib.flags.get_flags)

    # Wrong argument
    sys.argv.append("y")
    self.assertRaises(ValueError, lib.flags.get_flags)
    sys.argv.remove("y")

    # Correct argument
    sys.argv.append("10")
    self.assertEqual(lib.flags.get_flags()['threads_value'], 10)

class Test_lib_printer(unittest.TestCase):
  def setUp(self):
    self.printer = lib.printer.Printer()
    self.signatures = {
      'test': {},
      'ba': {},
      'fa': {},
    }
    self.date = '2014-12-12'
    self.output_dir = './tests/printer'
    self.clear_directory(self.output_dir)
    self.count = {
      'fa': 10,
      'ba': 66,
    }
    self.data = {
      '0.0.0.0':
      {
        'start_time':           0,
        'end_time':             0,
        'total_duration':       0,
        'targets':
        {
          '1.1.1.1:80':
          {
            'packet_mean':      0,
            'packet_stdev':     0,
            'bytes_mean':       0,
            'bytes_stdev':      0,
            'duration_mean':    0,
            'duration_stdev':   0,
            'flows':            0,
            'activity':         0,
            'flow_duration':    0,
            'total_duration':   0,
            'first_seen':       0,
            'last_seen':        0,
            'signature':        'fa',
            'url':
            {
              'google.com/index.php':     10,
              'www.mini.true/now-playing.php':  100,
              'dev.mini.true/wallpaper.php':  50,
            }
          }
        }
      }
    }

  def clear_directory(self, output_dir):
    files = os.listdir(output_dir)
    for item in files:
      os.remove(os.path.join(output_dir,item))

  def test_open_file(self):
    self.clear_directory(self.output_dir)
    with lib.printer.open_file(self.output_dir, self.signatures, self.date) as output_file:
      output_file.write(bytes("hi\n", 'utf-8'))
    self.assertListEqual(os.listdir(self.output_dir),['ba_fa_test-2014-12-12-ppf-5.ids'])

  def test_open_pager(self):
    self.assertIsInstance(lib.printer.open_pager(None), subprocess.Popen)

  def test_open_parsable_file(self):
    self.clear_directory(self.output_dir)
    with lib.printer.open_parsable_file(self.output_dir, self.signatures, self.date) as output_file:
      output_file.write(bytes("hi\n", 'utf-8'))
    self.assertListEqual(os.listdir(self.output_dir),['ba_fa_test-2014-12-12-ppf-5.idats'])

  def test_write_to_file(self):
    message = 'Hello'
    with lib.printer.open_file(self.output_dir, self.signatures, self.date) as output_file:
      lib.printer.write_to_file(output_file, message)
    files = os.listdir(self.output_dir)
    with open(os.path.join(self.output_dir, files[0]), 'rb') as fd:
      line_bytes = fd.read(1024)
    line = str(line_bytes, 'utf-8').replace("\n","")
    self.assertEqual(line, message)

  def test_write_to_pager(self):
    with lib.printer.open_pager(None) as pager:
      lib.printer.write_to_pager(pager, "Hello", "red")

  def test_legenda(self):
    with lib.printer.open_file(self.output_dir, self.signatures, self.date) as output_file:
      lib.printer.legenda(output_file, 'disk', self.count)
    with lib.printer.open_pager(None) as pager:
      lib.printer.legenda(pager, 'pager', self.count)

  def test_header(self):
    with lib.printer.open_file(self.output_dir, self.signatures, self.date) as output_file:
      lib.printer.header(output_file, 'disk', self.data)
    with lib.printer.open_pager(None) as pager:
      lib.printer.header(pager, 'pager', self.data)

  def test_print_urls(self):
    urls = self.data['0.0.0.0']['targets']['1.1.1.1:80']['url']
    with lib.printer.open_file(self.output_dir,self.signatures,self.date) as fd:
      lib.printer.print_urls(fd,'disk',None,urls)
    with open(os.path.join(self.output_dir, 'ba_fa_test-2014-12-12-ppf-5.ids'), 'rb') as fd:
      lines = fd.readlines()
    self.assertGreater(len(lines), 0)
    with lib.printer.open_pager(None) as fd:
      lib.printer.print_urls(fd,'pager',None,urls)

  def test_print_parsable_urls(self):
    urls = self.data['0.0.0.0']['targets']['1.1.1.1:80']['url']
    self.assertIsInstance(lib.printer.print_parsable_urls(urls), str)

  def test_format_value(self):
    data = self.data['0.0.0.0']['targets']['1.1.1.1:80']
    for item in data:
      if item != 'url':
        self.assertIsInstance(lib.printer.format_value(item, data[item]), str)

  def test_print_srcip(self):
    with lib.printer.open_pager(None) as pager:
      used = lib.printer.header(pager, 'pager', self.data)
    self.assertIsInstance(lib.printer.print_srcip(self.data, '0.0.0.0', used), str)

  def test_print_dstip(self):
    with lib.printer.open_pager(None) as pager:
      used = lib.printer.header(pager, 'pager', self.data)
    self.assertIsInstance(lib.printer.print_dstip(self.data, '0.0.0.0', '1.1.1.1:80', used), str)

  def test_print_data(self):
    with lib.printer.open_pager(None) as pager:
      lib.printer.print_data(pager, 'pager', self.data, self.count)

  def test_print_parsable_data(self):
    with lib.printer.open_parsable_file(self.output_dir, self.signatures, self.date) as output_file:
      lib.printer.print_parsable_data(output_file, self.data)

if __name__ == '__main__':
  if not '--verbose' in sys.argv:
    sys.argv.append('--verbose')
  unittest.main(buffer=True, failfast=True)
