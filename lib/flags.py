#!/usr/bin/env python3.4
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Loads arguments

""" "Do you have a flag …?'
'What? We don't need a flag, this is our home, you bastards'
'No flag, No Country, You can't have one!
Those are the rules... that I just made up!...and I'm backing it up with this gun.' --Eddie Izzard"""

import sys

def get_default():
  """Sets the default flags, add new flags here
  :return: a dictionary of flags
  """
  flags = {
    'absolom':            False,
    'automate':           False,
    'automate_value':     '',
    'break':              False,
    'break_value':        'flags',
    'bytes':              False,
    'cusum':              False,
    'cusum_value':        5,
    'debug':              False,
    'duration':           False,
    'flows':              False,
    'flows_value':        2,
    'help':               False,
    'ip':                 False,
    'ip_value':           '0.0.0.0',
    'kick':               False,
    'kill_output':        False,
    'merge':              False,
    'pmod':               False,
    'nmod':               False,
    'packets':            False,
    'output':             False,
    'output_value':       'pipe',
    'sig':                False,
    'sig_value':          '',
    'tcp_flags':          False,
    'threads':            False,
    'threads_value':      1,
    'time':               False,
    'verbose':            False,
    'violate':            False,
    'url':                False,
    'url_value':          0,
  }
  return flags

def show_help():
  """Function for showing usage/help output
  """
  flags = get_default()
  help = {'absolom':            'Enables the absolute detection algorithm',
          'break':              'Break the script at a certain point. (Requires an argument)',
          'bytes':              'Descriminate on bytes',
          'cusum':              'Cusum streak value for the Absolom algorithm',
          'debug':              'Enable debug output',
          'duration':           'Descriminate on duration too.',
          'flows':              'Set a minimum flow count. (Requires an argument)',
          'help':               'Shows this help.',
          'ip':                 'Only look at one ip. (Requires an argument)',
          'kill_output':        'Show no output during the processing, debug output is not affected by this option (DEPRECATED)',
          'packets':            'Descriminate on packets',
          'output':             'Sets the output method (pipe, pager, disk, none), Default: pipe',
          'sig':                'Selects a signature.',
          'tcp_flags':          'Treats a TCP RST flags as a reset',
          'threads':            'By default it uses all available cores, here you can specify otherwise',
          'time':               'Shows time statistics in the end',
          'verbose':            'A more verbose debug',
          'url':                'Set a threshold for urls to be shown'
          }

  print("Usage {0} <nfdump-file> [options]".format(sys.argv[0]))
  print()
  print("Optional flags:")
  for item in sorted(flags.keys()):
    if item in help.keys():
        line = "--{0}".format(item)
        line = "{:<20}".format(line)
        line = "{0}{1}".format(line, help[item])
        print(line)

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