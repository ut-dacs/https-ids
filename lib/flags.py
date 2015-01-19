#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Loads arguments

""" "Do you have a flag …?'
'What? We don't need a flag, this is our home, you bastards'
'No flag, No Country, You can't have one!
Those are the rules... that I just made up!...and I'm backing it up with this gun.' --Eddie Izzard

These flags are available:

:break:             Break the script at a certain point. (Requires an argument)
:bytes:              Descriminate on bytes (BPF)
:cusum:              Cusum streak value for the Absolom algorithm
:debug:              Enable debug output
:flows:              Set a minimum flow count. (Requires an argument) (DEPRECATED)
:help:               Shows this help
:ip:                 Only look at one ip. (Requires an argument)
:packets:            Descriminate on packets (PPF)
:output:             Sets the output method (pipe, pager, disk, none), Default: pipe
:sig:                Selects a signature
:tcp_flags:          Treats a TCP RST flags as a reset
:threads:            By default it uses all available cores, here you can specify otherwise
:time:               Shows time statistics in the end (BROKEN)
:test:               Test mode, skips certain questions/code
:url:                Set a threshold for urls to be shown
"""

import sys

def get_default():
  """Sets the default flags, add new flags here

  :return: a dictionary of flags
  """
  flags = {
    'break':              False,
    'break_value':        'flags',
    'bytes':              False,
    'cusum':              False,
    'cusum_value':        5,
    'debug':              False,
    'flows':              False,
    'flows_value':        2,
    'help':               False,
    'ip':                 False,
    'ip_value':           '0.0.0.0',
    'packets':            False,
    'output':             False,
    'output_value':       'pipe',
    'sig':                False,
    'sig_value':          '',
    'tcp_flags':          False,
    'threads':            False,
    'threads_value':      1,
    'time':               False,
    'test':               False,
    'violate':            False,
    'url':                False,
    'url_value':          0,
  }
  return flags

def show_help():
  """Function for showing usage/help output
  """
  flags = get_default()
  help = {'break':              'Break the script at a certain point. (Requires an argument)',
          'bytes':              'Descriminate on bytes (BPF)',
          'cusum':              'Cusum streak value for the Absolom algorithm',
          'debug':              'Enable debug output',
          'flows':              'Set a minimum flow count. (Requires an argument) (DEPRECATED)',
          'help':               'Shows this help.',
          'ip':                 'Only look at one ip. (Requires an argument)',
          'packets':            'Descriminate on packets (PPF)',
          'output':             'Sets the output method (pipe, pager, disk, none), Default: pipe',
          'sig':                'Selects a signature.',
          'tcp_flags':          'Treats a TCP RST flags as a reset',
          'threads':            'By default it uses all available cores, here you can specify otherwise',
          'time':               'Shows time statistics in the end',
          'test':               'Test mode, skips certain questions/code',
          'url':                'Set a threshold for urls to be shown'
          }

  if "main" in sys.argv[0] or "automation" in sys.argv[0]:
    type_file = "<nfdump-files>"

  elif "validate" in sys.argv[0]:
    type_file = "<results-file>"

  elif "results_viewer" in sys.argv[0]:
    type_file = "<results-dump> <tp|tn|fp|fn>"

  else:
    type_file = "<files>"
  print("Usage {0} {1} [options]".format(sys.argv[0], type_file))
  if "main" in sys.argv[0] or "automation" in sys.argv[0]:
    print()
    print("<nfdump-files> can point to a single file. Or it can be used to select a range of files within a directory,\n\
the syntax is for this is: <path-to-directory>:<lower-boundary>:<upper-boundary>")
    print("For example 'flows/:201407150910:201407150945' selects all the files in 'flows' that fall between '201407150910' and '201407150945'.")

  print()
  print("Optional flags:")
  for item in sorted(flags.keys()):
    if ("main" in sys.argv[0] or "automation" in sys.argv[0]) and item in ['threads', 'test']:
      pass

    elif 'validate' in sys.argv[0] and item in ['bytes', 'cusum', 'flow', 'ip', 'packets', 'output', 'sig', 'tcp_flags', 'time', 'url']:
      pass

    elif 'results_viewer' in sys.argv[0] and item in ['break', 'bytes', 'cusum', 'flows', 'ip', 'packets',
                  'output', 'sig', 'tcp_flags', 'threads', 'time', 'url']:
      pass

    elif item in help.keys():
      line = "--{0}".format(item)
      line = "{:<20}".format(line)
      line = "{0}{1}".format(line, help[item])
      print(line)
      if item == 'break':
        if 'main' in sys.argv[0]:
          print("{:<22}".format("")+"possible breakpoints include: init, signatures, files, processing, matching, counting")

        elif 'validate' in sys.argv[0]:
          print("{:<22}".format("")+"possible breakpoints include: init, processing, calculating")


  print()
  raise SystemExit()

def get_flags():
  """Function for going through the system arguments and setting options in the default flags.

  :return: dictionary of flags
  """
  flags = get_default()

  # Go through the flags for the arguments
  for i, arg in enumerate(sys.argv):
    stripped_arg = arg.replace("--","")
    if stripped_arg in flags.keys():

      # Toggle flag
      flags[stripped_arg] = not flags[stripped_arg]

      # Additional arguments
      if stripped_arg in ['automate','break','ip','output','sig']:
        item = "{0}_value".format(stripped_arg)
        flags[item] = sys.argv[i+1]

      elif stripped_arg in ['cusum', 'flows', 'url', 'threads']:
        item = "{0}_value".format(stripped_arg)
        try:
          flags[item] = int(sys.argv[i+1])

        except IndexError:
          print("Option {0} requires an argument".format(stripped_arg))
          raise

        except ValueError:
          print("Option {0} requires an interger as argument")
          raise

      elif stripped_arg == 'violate':
        answer = input("\n\n!!!!\tThis is a serious violation of privacy, you are recommended to run this program without the '--violate' flag\t!!!!\n\n\
  Are you sure you want to continue (y/n)?\n")
        if answer == "n":
          flags['violate'] = False

      elif stripped_arg == 'help':
        show_help()
  return flags