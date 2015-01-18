
====
main
====

A rather simple IDS, it checks flow records against a given signature.
If a cusum rate, or flow record threshols, is exceeded it is marked as
an attack.

Usage: ./main.py <path-to-result-file> [options]

The [options] are as defined by the flags library (lib.flags).
Configuration of this IDS is in 'conf/ids.conf'. #Signature
definitions are in 'conf/signature.conf'.

===========
lib/absolom
===========

Yes, this library is named after the Alice in Wonderland character.

lib.absolom.add_attack(flags, counting, attack, everything, srcip, dstip)

   Function to move an entry from the counting dictionary to the
   attack dictionary.

   Parameters:
      * **flags** (*dictionary*) -- flag dictionary

      * **counting** (*dictionary*) -- counting dictionary

      * **attack** (*dictionary*) -- attack dictionary

      * **everything** (*dictionary*) -- everything dictionary

      * **srcip** (*string*) -- source ip

      * **dstip** (*string*) -- destination ip

   Returns:
      tuple of changed dictionaries (counting, attack, everything)

lib.absolom.add_counting(counting, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets)

   Function to add an entry to the counting dictionary.

   Parameters:
      * **counting** (*dictionary*) -- counting dictionary

      * **srcip** (*string*) -- source ip

      * **dstip** (*string*) -- destination ip

      * **first** (*int*) -- first seen time

      * **first_msec** (*int*) -- first seen time

      * **last** (*int*) -- last seen time

      * **last_msec** (*int*) -- last seen time

      * **signature** (*string*) -- given signature

      * **host** (*string*) -- host visited

      * **page** (*string*) -- page visited

      * **no_pkts** (*int*) -- number of packets

      * **no_octets** (*int*) -- number of bytes

   Returns:
      counting dictionary

lib.absolom.add_everything(flags, counting, attack, everything, srcip, dstip, first, first_msec, last, last_msec, signature, host, page, no_pkts, no_octets)

   Adds an entry to the everything dictionary.

   Parameters:
      * **flags** (*dictionary*) -- flag dictionary

      * **counting** (*dictionary*) -- counting dictionary

      * **attack** (*dictionary*) -- attack dictionary

      * **everything** (*dictionary*) -- everything dictionary

      * **srcip** (*string*) -- source ip

      * **dstip** (*string*) -- destination ip

      * **first** (*int*) -- first seen time

      * **first_msec** (*int*) -- first seen time

      * **last** (*int*) -- last seen time

      * **last_msec** (*int*) -- last seen time

      * **signature** (*string*) -- given signature

      * **host** (*string*) -- host visited

      * **page** (*string*) -- page visited

      * **no_pkts** (*int*) -- number of packets

      * **no_octets** (*int*) -- number of bytes

   Returns:
      tuple of (counting, attack, everything)

lib.absolom.data_line(flags, signatures, counting, attack, everything, line)

   Processes a data line

   Parameters:
      * **flags** (*dictionary*) -- flag dictionary

      * **signatures** (*dictionary*) -- signatures dictionary

      * **counting** (*dictionary*) -- counting dictionary

      * **attack** (*dictionary*) -- attack dictionary

      * **everything** (*dictionary*) -- everything dictionary

   Returns:
      counting, attack, everything

lib.absolom.del_from_dict(dictionary, srcip, dstip)

   Removes an entry from the given dictionary. Assumed is that srcip
   and dstip exist in the dictionary. :param dictionary: dictionary to
   remove an entry from :type dictionary: dictionary :param srcip:
   source ip :type srcip: string :param dstip: destination ip :type
   dstip: string :return: dictionary

lib.absolom.descriminator(flags, signatures, counting, srcip, dstip, pkts, bts, port, tcp_flags)

   Descriminator function, does something... I think.

   Parameters:
      * **flags** (*dictionary*) -- flags dictionary

      * **signatures** (*dictionary*) -- signatures dictionary

      * **counting** (*dictionary*) -- counting dictionary

      * **srcip** (*string*) -- source ip

      * **dstip** (*string*) -- destination ip

      * **pkts** (*int*) -- number of packets

      * **bts** (*int*) -- amount of bytes

      * **port** (*int*) -- TCP port number

   Returns:
      tuple of (signature, pkts, bts)

lib.absolom.flush(flags, counting, attack, everything)

   Flushes all the remaining traffic in the counting dictionary

   Parameters:
      * **flags** (*dictionary*) -- flag dictionary

      * **counting** (*dictionary*) -- counting dictionary

      * **attack** (*dictionary*) -- attack dictionary

      * **everything** (*dictionary*) -- everything dictionary

lib.absolom.match_signature(data, srcip, dstip)

   Check which signature was matched most of the time

   Parameters:
      * **data** (*dictionary*) -- data dictionary

      * **srcip** (*string*) -- source ip

      * **dstip** (*string*) -- destination ip

   Returns:
      signature

lib.absolom.merge_move_target(src_dict, dst_dict, srcip, dstip)

   Merges an entry from source dictionary to destination dictionary.
   It is assumed here that both the source ip and destination ip exist
   in the destination dictionary.

   Parameters:
      * **src_dict** (*dictionary*) -- source dictionary

      * **dst_dict** (*dictionary*) -- destination dictionary

      * **srcip** (*string*) -- source ip

      * **dstip** (*string*) -- destination ip

   Returns:
      dst_dict

lib.absolom.mod_accept(flags, counting, pkts, bts, srcip, dstip)

   Modulus accept to allow a bit of variance in flows. When a flow is
   doubled it is still accepted.

   Parameters:
      * **flags** (*dictionary*) -- flags dictionary

      * **counting** (*dictionary*) -- counting dictionary

==========
lib/config
==========

lib.config.get_all_options(conf_name, config_parser)

   Function for translating a config parser config file to a Python
   dictionary

   Parameters:
      * **conf_name** (*string*) -- specifies the config file name

      * **config_parser** (*configparser object*) -- the config
        parser used for reading the config file

   Returns:
      dictionary of the options

lib.config.get_conf_file(conf_name)

   Function for converting a config name to a path to the actual
   config file.

   Parameters:
      **conf_name** (*str*) -- specifies the config name

   Returns:
      path to the file as a string

lib.config.get_signatures(config_parser)

   Lists the configured signatures

   Returns:
      list of signatures

lib.config.read_config(conf_name)

   Function for parsing config files.

   Parameters:
      **conf_name** (*str*) -- specifies the config file to be read

lib.config.read_signatures()

   Similair to read_config, however it is specified to the signatures.

   Returns:
      dictionary of signatures with their options

=========
lib/flags
=========

"Do you have a flag …?' 'What? We don't need a flag, this is our home,
you bastards' 'No flag, No Country, You can't have one! Those are the
rules... that I just made up!...and I'm backing it up with this gun.'
--Eddie Izzard

These flags are available:

break:
   Break the script at a certain point. (Requires an argument)

bytes:
   Descriminate on bytes (BPF)

cusum:
   Cusum streak value for the Absolom algorithm

debug:
   Enable debug output

flows:
   Set a minimum flow count. (Requires an argument) (DEPRECATED)

help:
   Shows this help

ip:
   Only look at one ip. (Requires an argument)

packets:
   Descriminate on packets (PPF)

output:
   Sets the output method (pipe, pager, disk, none), Default: pipe

sig:
   Selects a signature

tcp_flags:
   Treats a TCP RST flags as a reset

threads:
   By default it uses all available cores, here you can specify
   otherwise

time:
   Shows time statistics in the end (BROKEN)

test:
   Test mode, skips certain questions/code

url:
   Set a threshold for urls to be shown

lib.flags.get_default()

   Sets the default flags, add new flags here

   Returns:
      a dictionary of flags

lib.flags.get_flags()

   Function for going through the system arguments and setting options
   in the default flags.

   Returns:
      dictionary of flags

lib.flags.show_help()

   Function for showing usage/help output

=============
lib/functions
=============

lib.functions.check_accept(flags, signatures, signature, x, y)

   Function to check if the given x and y falls inside of the given
   signature. :param signatures: dictionary of signatures :type
   signatures: dictionary :param signature: selected signature :type
   signature: string :param x: x coordinate :type x: int :param y: y
   coordinate :type y: int :return: accepted boolean

lib.functions.convert_ipaddress(ipint)

   Function for converting a 32 bit integer to a human readable ip
   address https://geekdeck.wordpress.com/2010/01/19/converting-a
   -decimal-number-to-ip-address-in-python/

   Parameters:
      **ipint** (*integer*) -- 32 bit int ip address

   Returns:
      human readable ip address

lib.functions.data_statistics(data)

   Calculates mean and stdev for the given data.

   Parameters:
      **data** (*dictionary*) -- data dictionary

lib.functions.filter(line)

   Function to filter bytes from a given line.

   Parameters:
      **line** (*bytes*) -- a given string

lib.functions.pythagoras(x1, y1, x2, y2)

   Calculates the distance between two points.

   Parameters:
      * **x1** (*integer*) -- x coordinate

      * **y1** (*integer*) -- y coordinate

      * **x2** (*integer*) -- x coordinate

      * **y2** (*integer*) -- y coordinate

   Returns:
      distance between the two points

=======
lib/ids
=======

class class lib.ids.IDS(logger, flags, config)

   IDS class, main management class.

   coordinates_signatures()

      Generate a coordinate dictionary for the signatures.

   expander(basedir, bottom, top)

      Finds all the nfcapd files within the specified range.

      Parameters:
         * **basedir** (*string*) -- specifies what directory to
           look in

         * **bottom** (*string*) -- bottom limit

         * **top** (*string*) -- top limit

      Returns:
         nfdump_files, a list of nfdump files

   filter_signatures(number)

      Function for filtering out unrequested signatures.

      Parameters:
         **number** (*list*) -- list created by splitting user input (
         "1,2,3".split(',') )

   load_signatures()

      Prints available signatures and asks which one to look for.

   process_count(sig_count, data)

      Counts the number of occuring signatures

      Parameters:
         **data** (*dictionary*) -- data dictionary

      Returns:
         counting dictionary

   process_filenames(path)

      Function to translate a range into a nfdump range

      Parameters:
         **path** (*string*) -- denotes the path (might be a range of
         file)

      Returns:
         a list of nfdump files

   process_files(nfdump_files)

      Creates a worker and processes files.

      Parameters:
         **nfdump_files** (*list*) -- nfdump files to process

      Returns:
         data dictiionary

   process_match(data)

      Calculate the closest match and add it to the data

   process_sort(data)

      Sorts the data based on source ip

      Parameters:
         **data** (*dictionary*) -- data to be sorted

============
lib/logsetup
============

Yes, this library is named after the Alice in Wonderland character.

lib.logsetup.log_setup(name, log_file, log_level)

   Function to setup a logger, based on the given configuration.

   Parameters:
      * **name** (*str*) -- name used in logging

      * **log_file** (*str*) -- specifies the log file

      * **log_level** (*str*) -- specifies the log level

   Returns:
      logger object

===========
lib/printer
===========

lib.printer.format_value(item, value)

   Formats values according to some set rules.

   Parameters:
      * **item** (*string*) -- identifier, what kind of value is
        given

      * **value** -- value of the item

   Returns:
      formatted string

lib.printer.get_action(action)

   Returns the appropriate function for the given action.

   Parameters:
      **action** (*string*) -- action to take

lib.printer.get_options()

   Returns a string based on the given flags. Usefull for filenames.

   Returns:
      string with options

lib.printer.header(fd, action, data)

   Prints a header for a given data set.

   Parameters:
      * **fd** (*io.BufferedWriter or subprocess.Popen*) --
        filedescriptor, can be an actual filedescriptor or a pager

      * **action** (*string*) -- specifies where the output should
        go

      * **data** (*dictionary*) -- the data set

   Returns:
      list of used items

lib.printer.legenda(fd, action, count)

   Prints a legenda to the given file descriptor.

   Parameters:
      * **fd** (*io.BufferedWriter or subprocess.Popen*) --
        filedescriptor, can be an actual filedescriptor or a pager

      * **action** (*string*) -- specifies where the output should
        go

      * **count** (*dictionary*) -- dictionary containing signature
        hit counters

lib.printer.open_file(output_dir, signatures, date)

   Open a file descriptor.

   Parameters:
      * **signatures** (*dictionary*) -- dictionary of used
        signatures

      * **output_dir** (*string*) -- specifies the output directory

   Returns:
      file descriptor

lib.printer.open_pager(output)

   Opens a pager with to the given output (usually sys.stdout).

   Parameters:
      **output** -- specifies to where the output should go

lib.printer.open_parsable_file(output_dir, signatures, date)

   Function for opening a file for parsable output.

   Parameters:
      * **output_dir** (*string*) -- specifies the output directory

      * **signatures** (*list*) -- a list of the used signatures

      * **date** (*string*) -- a date string

   Returns:
      a filedescriptor

lib.printer.print_data(fd, action, signatures, data, count)

   Prints data to the given filedescriptor

   Parameters:
      * **fd** (*io.BufferedWriter or subprocess.Popen*) --
        filedescriptor

      * **action** (*string*) -- the action to take

      * **data** (*dictionary*) -- the data dictionary to print

      * **count** (*dictionary*) -- signature hit count dictionary

lib.printer.print_dstip(signatures, data, srcip, dstip, used)

   Formats the data fields belonging to the destination in a nice
   line.

   Parameters:
      * **data** (*dictionary*) -- data dictionary

      * **srcip** (*string*) -- the source ip

      * **dstip** (*string*) -- the destination ip

      * **used** (*list*) -- list of used data fields (the header
        function returns this)

   Returns:
      formatted string

lib.printer.print_parsable_data(fd, data)

   Prints the data in a parsable manner to the filedescriptor.

   Parameters:
      * **fd** (*io.BufferedWriter*) -- file descriptor

      * **data** (*dictionary*) -- dictionary to print

lib.printer.print_parsable_dstip(data, srcip, dstip)

   Returns a parsable data line for the destination data.

   Parameters:
      * **data** (*dictionary*) -- the data source

      * **scrip** -- the source ip

      * **dstip** (*string*) -- the destination ip

   Returns:
      a line of urls and their hitcount

lib.printer.print_parsable_urls(urls)

   Converts a urls dictionary into a single line.

   Parameters:
      **urls** -- dictionary of urls and their hitcount

   Type:
      urls: dictionary

   Returns:
      string of urls

lib.printer.print_srcip(data, srcip, used)

   Formats the data fields belonging to the source in a nice line.

   Parameters:
      * **data** (*dictionary*) -- data dictionary

      * **srcip** (*string*) -- the source ip

      * **used** (*list*) -- list of used data fields (the header
        function returns this)

   Returns:
      formatted string

lib.printer.print_urls(fd, action, color, urls)

   Function for nicely printing a dictionary of urls. The dictionary
   is expected to hold a hit count.

   Parameters:
      * **fd** (*io.BufferedWriter or subprocess.Popen*) --
        filedescriptor, can be an actual filedescriptor or a pager

      * **action** (*string*) -- specifies where the output should
        go

      * **color** (*string or None*) -- denotes the color

      * **urls** (*dictionary*) -- dictionary of urls

lib.printer.write_to_file(fd, message, color=None)

   Writes a message to the given file descriptor. It takes care of
   line endings and encoding for you.

   Parameters:
      * **fd** (*io.BufferedWriter*) -- the filedescriptor

      * **message** (*string*) -- the message to be written

      * **color** -- dummy variable, not used

lib.printer.write_to_pager(pager, message, color)

   Writes a message to the given pager. If termcolor is available it
   will even be written in the given color.

   Parameters:
      * **pager** (*subprocess.Popen*) -- the pager to write to

      * **message** (*string*) -- the message to write

      * **color** (*string*) -- the color to write the message in

=============
lib/signature
=============

class class lib.signature.Worker(logger, flags, signatures, coordinates, data)

   Signature worker class

   get_result()

      Returns the result.

      Returns:
         data dictionary

   match_signature(data, signatures, srcip, dstip)

      Function for matching a signature

      Parameters:
         * **data** (*dictionary*) -- data dictionary

         * **signatures** (*dictionary*) -- signatures dictionary

         * **srcip** (*string*) -- source ip

         * **dstip** (*string*) -- destination ip

      Returns:
         matched signature

   run()

      Main function of the signature worker. Matches signatures in the
      given data.

=============
lib/validator
=============

class class lib.validator.Validator(logger, flags, config, signature)

   Class used for validation purposes.

   calculate_rates()

      Calculates the TPR, TNR, FPR and FNR rates.

   data_merger(data)

      Merges data into self.data.

      Parameters:
         **data** (*dictionary*) -- a data dictionary to be merged
         into self.data

   filter_attackers(attackers, cusum)

      Filters the attackers list for a given cusum (flow record
      threshold).

      Parameters:
         * **attackers** (*list*) -- attackers list

         * **cusum** (*int*) -- the minimum cusum rate (flow record
           threshold)

      Returns:
         a filtered attackers list

   load_attackers(cusum)

      Function for loading the attacker lists. These lists should be
      in the 'includes' folder, named as 'attackers_fa.dump' and
      'attackers_ba.dump'.

      Parameters:
         **cusum** (*int*) -- the minimum cusum rate (flow record
         threshold)

   print_rates()

      Prints the rates to the logger.

   processor(data)

      The actual validation process, i.e. grab a worker and tell him
      to do it.

      Parameters:
         **data** (*dictionary*) -- data to be processed

   result_counter(data)

      Keeps a count of the TP, TN, FP and FN statistics.

      Parameters:
         **data** (*tuple*) -- a tuple of a count dictionary and a
         data dictionary

   save_data(signature, date, type_scan, cusum)

      This function saves two files, one containing the rates. The
      other is a categorized dump of the data. This dump can be viewed
      with the 'results_viewer' in the 'scripts' folder.

      Parameters:
         * **signature** (*list*) -- a list of used signatures in
           the scan

         * **date** -- a date string of when the scan was performed

         * **type_scan** (*list*) -- ppf, bpf or ppf+bpf

         * **cusum** (*string*) -- the cusum rate (flow record
           threshold

====================
lib/validator_worker
====================

class class lib.validator_worker.Worker(queue, logger, signature, data, flags, fa, ba)

   The worker class for the validator.

   check(srcip, dstip, signature)

      Checks if the src <-> dst tuple is a TP, FN, FP or TN.

      Parameters:
         * **srcip** (*string*) -- the source ip

         * **dstip** (*string*) -- the destination ip

         * **signature** (*string*) -- the matched signature

      Returns:
         result ('tp', 'fn', 'fp', 'tn')

   get_result()

      Returns the achieved result.

      Returns:
         the resulting dictionary

   grab_data(line)

      Transforms a ids line into a dictionary.

      Parameters:
         **line** (*string*) -- a line from a result file

      Returns:
         data dictionary

   parse_data(line, id)

      Function for parsing the data for later analysis.

      Parameters:
         * **line** (*string*) -- a data line from the results file

         * **id** (*string*) -- defines it to be a TP, TN, FP or FN

   run()

      Main function that runs trough the all the lines in the results
      file and calls 'stats' on the line.

   split_url(url)

      Splits a URL from their hit count

      Parameters:
         **url** (*string*) -- a string of a URL and its hit count

      Returns:
         a tuple of the count and URL

   stats(line)

      Determines the type and parses the data

      Parameters:
         **line** (*bytes*) -- a line from the results file

==========
lib/worker
==========

================
scripts/validate
================

Validation script, it uses the 'Validator' class in 'lib.validator' to
validate a results file. Usage: ./scripts/validate.py <path-to-result-
file> [options]

The [options] are as defined by the flags library (lib.flags). To
configure the logging options see 'conf/validate.conf'.
