### Navigation

-   [https-ids 0.8 documentation](index.html#document-index) »

Welcome to https-ids’s documentation![¶](#welcome-to-https-ids-s-documentation "Permalink to this headline")
============================================================================================================

Contents:

main[¶](#module-main "Permalink to this headline")
--------------------------------------------------

A rather simple IDS, it checks flow records against a given signature. If a cusum rate, or flow record threshols, is exceeded it is marked as an attack.

Usage: ./main.py \<path-to-result-file\> [options]

The [options] are as defined by the flags library (lib.flags). Configuration of this IDS is in ‘conf/ids.conf’. \#Signature definitions are in ‘conf/signature.conf’.

lib/absolom[¶](#lib-absolom "Permalink to this headline")
---------------------------------------------------------

Yes, this library is named after the Alice in Wonderland character.

 `lib.absolom.``add_attack`(*flags*, *counting*, *attack*, *everything*, *srcip*, *dstip*)[¶](#lib.absolom.add_attack "Permalink to this definition")  
Function to move an entry from the counting dictionary to the attack dictionary.

Parameters:

-   **flags** (*dictionary*) – flag dictionary
-   **counting** (*dictionary*) – counting dictionary
-   **attack** (*dictionary*) – attack dictionary
-   **everything** (*dictionary*) – everything dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip

Returns:

tuple of changed dictionaries (counting, attack, everything)

 `lib.absolom.``add_counting`(*counting*, *srcip*, *dstip*, *first*, *first\_msec*, *last*, *last\_msec*, *signature*, *host*, *page*, *no\_pkts*, *no\_octets*)[¶](#lib.absolom.add_counting "Permalink to this definition")  
Function to add an entry to the counting dictionary.

Parameters:

-   **counting** (*dictionary*) – counting dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip
-   **first** (*int*) – first seen time
-   **first\_msec** (*int*) – first seen time
-   **last** (*int*) – last seen time
-   **last\_msec** (*int*) – last seen time
-   **signature** (*string*) – given signature
-   **host** (*string*) – host visited
-   **page** (*string*) – page visited
-   **no\_pkts** (*int*) – number of packets
-   **no\_octets** (*int*) – number of bytes

Returns:

counting dictionary

 `lib.absolom.``add_everything`(*flags*, *counting*, *attack*, *everything*, *srcip*, *dstip*, *first*, *first\_msec*, *last*, *last\_msec*, *signature*, *host*, *page*, *no\_pkts*, *no\_octets*)[¶](#lib.absolom.add_everything "Permalink to this definition")  
Adds an entry to the everything dictionary.

Parameters:

-   **flags** (*dictionary*) – flag dictionary
-   **counting** (*dictionary*) – counting dictionary
-   **attack** (*dictionary*) – attack dictionary
-   **everything** (*dictionary*) – everything dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip
-   **first** (*int*) – first seen time
-   **first\_msec** (*int*) – first seen time
-   **last** (*int*) – last seen time
-   **last\_msec** (*int*) – last seen time
-   **signature** (*string*) – given signature
-   **host** (*string*) – host visited
-   **page** (*string*) – page visited
-   **no\_pkts** (*int*) – number of packets
-   **no\_octets** (*int*) – number of bytes

Returns:

tuple of (counting, attack, everything)

 `lib.absolom.``data_line`(*flags*, *signatures*, *counting*, *attack*, *everything*, *line*)[¶](#lib.absolom.data_line "Permalink to this definition")  
Processes a data line

Parameters:

-   **flags** (*dictionary*) – flag dictionary
-   **signatures** (*dictionary*) – signatures dictionary
-   **counting** (*dictionary*) – counting dictionary
-   **attack** (*dictionary*) – attack dictionary
-   **everything** (*dictionary*) – everything dictionary

Returns:

counting, attack, everything

 `lib.absolom.``del_from_dict`(*dictionary*, *srcip*, *dstip*)[¶](#lib.absolom.del_from_dict "Permalink to this definition")  
Removes an entry from the given dictionary. Assumed is that srcip and dstip exist in the dictionary. :param dictionary: dictionary to remove an entry from :type dictionary: dictionary :param srcip: source ip :type srcip: string :param dstip: destination ip :type dstip: string :return: dictionary

 `lib.absolom.``descriminator`(*flags*, *signatures*, *counting*, *srcip*, *dstip*, *pkts*, *bts*, *port*, *tcp\_flags*)[¶](#lib.absolom.descriminator "Permalink to this definition")  
Descriminator function, does something... I think.

Parameters:

-   **flags** (*dictionary*) – flags dictionary
-   **signatures** (*dictionary*) – signatures dictionary
-   **counting** (*dictionary*) – counting dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip
-   **pkts** (*int*) – number of packets
-   **bts** (*int*) – amount of bytes
-   **port** (*int*) – TCP port number

Returns:

tuple of (signature, pkts, bts)

 `lib.absolom.``flush`(*flags*, *counting*, *attack*, *everything*)[¶](#lib.absolom.flush "Permalink to this definition")  
Flushes all the remaining traffic in the counting dictionary

Parameters:

-   **flags** (*dictionary*) – flag dictionary
-   **counting** (*dictionary*) – counting dictionary
-   **attack** (*dictionary*) – attack dictionary
-   **everything** (*dictionary*) – everything dictionary

 `lib.absolom.``match_signature`(*data*, *srcip*, *dstip*)[¶](#lib.absolom.match_signature "Permalink to this definition")  
Check which signature was matched most of the time

Parameters:

-   **data** (*dictionary*) – data dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip

Returns:

signature

 `lib.absolom.``merge_move_target`(*src\_dict*, *dst\_dict*, *srcip*, *dstip*)[¶](#lib.absolom.merge_move_target "Permalink to this definition")  
Merges an entry from source dictionary to destination dictionary. It is assumed here that both the source ip and destination ip exist in the destination dictionary.

Parameters:

-   **src\_dict** (*dictionary*) – source dictionary
-   **dst\_dict** (*dictionary*) – destination dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip

Returns:

dst\_dict

 `lib.absolom.``mod_accept`(*flags*, *counting*, *pkts*, *bts*, *srcip*, *dstip*)[¶](#lib.absolom.mod_accept "Permalink to this definition")  
Modulus accept to allow a bit of variance in flows. When a flow is doubled it is still accepted.

Parameters:

-   **flags** (*dictionary*) – flags dictionary
-   **counting** (*dictionary*) – counting dictionary

lib/config[¶](#module-lib.config "Permalink to this headline")
--------------------------------------------------------------

 `lib.config.``get_all_options`(*conf\_name*, *config\_parser*)[¶](#lib.config.get_all_options "Permalink to this definition")  
Function for translating a config parser config file to a Python dictionary

Parameters:

-   **conf\_name** (*string*) – specifies the config file name
-   **config\_parser** (*configparser object*) – the config parser used for reading the config file

Returns:

dictionary of the options

 `lib.config.``get_conf_file`(*conf\_name*)[¶](#lib.config.get_conf_file "Permalink to this definition")  
Function for converting a config name to a path to the actual config file.

Parameters:

**conf\_name** (*str*) – specifies the config name

Returns:

path to the file as a string

 `lib.config.``get_signatures`(*config\_parser*)[¶](#lib.config.get_signatures "Permalink to this definition")  
Lists the configured signatures

Returns:

list of signatures

 `lib.config.``read_config`(*conf\_name*)[¶](#lib.config.read_config "Permalink to this definition")  
Function for parsing config files.

Parameters:

**conf\_name** (*str*) – specifies the config file to be read

 `lib.config.``read_signatures`()[¶](#lib.config.read_signatures "Permalink to this definition")  
Similair to read\_config, however it is specified to the signatures.

Returns:

dictionary of signatures with their options

lib/flags[¶](#module-lib.flags "Permalink to this headline")
------------------------------------------------------------

“Do you have a flag …?’ ‘What? We don’t need a flag, this is our home, you bastards’ ‘No flag, No Country, You can’t have one! Those are the rules... that I just made up!...and I’m backing it up with this gun.’ –Eddie Izzard

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

tcp\_flags:

Treats a TCP RST flags as a reset

threads:

By default it uses all available cores, here you can specify otherwise

time:

Shows time statistics in the end (BROKEN)

test:

Test mode, skips certain questions/code

url:

Set a threshold for urls to be shown

 `lib.flags.``get_default`()[¶](#lib.flags.get_default "Permalink to this definition")  
Sets the default flags, add new flags here

Returns:

a dictionary of flags

 `lib.flags.``get_flags`()[¶](#lib.flags.get_flags "Permalink to this definition")  
Function for going through the system arguments and setting options in the default flags.

Returns:

dictionary of flags

 `lib.flags.``show_help`()[¶](#lib.flags.show_help "Permalink to this definition")  
Function for showing usage/help output

lib/functions[¶](#module-lib.functions "Permalink to this headline")
--------------------------------------------------------------------

 `lib.functions.``automation_signatures`(*signatures*, *config*)[¶](#lib.functions.automation_signatures "Permalink to this definition")  
Function for converting configured signatures into numbers ‘main.py’ understands.

Parameters:

-   **signatures** (*dictionary*) – dictionary of available signatures
-   **config** (*string*) – configured signatures

Returns:

a string of signatures main.py understands

 `lib.functions.``check_accept`(*flags*, *signatures*, *signature*, *x*, *y*)[¶](#lib.functions.check_accept "Permalink to this definition")  
Function to check if the given x and y falls inside of the given signature. :param signatures: dictionary of signatures :type signatures: dictionary :param signature: selected signature :type signature: string :param x: x coordinate :type x: int :param y: y coordinate :type y: int :return: accepted boolean

 `lib.functions.``convert_ipaddress`(*ipint*)[¶](#lib.functions.convert_ipaddress "Permalink to this definition")  
Function for converting a 32 bit integer to a human readable ip address [https://geekdeck.wordpress.com/2010/01/19/converting-a-decimal-number-to-ip-address-in-python/](https://geekdeck.wordpress.com/2010/01/19/converting-a-decimal-number-to-ip-address-in-python/)

Parameters:

**ipint** (*integer*) – 32 bit int ip address

Returns:

human readable ip address

 `lib.functions.``data_statistics`(*data*)[¶](#lib.functions.data_statistics "Permalink to this definition")  
Calculates mean and stdev for the given data.

Parameters:

**data** (*dictionary*) – data dictionary

 `lib.functions.``filter`(*line*)[¶](#lib.functions.filter "Permalink to this definition")  
Function to filter bytes from a given line.

Parameters:

**line** (*bytes*) – a given string

 `lib.functions.``nfdump_file_notation`(*nfdump\_files*)[¶](#lib.functions.nfdump_file_notation "Permalink to this definition")  
Converts our file notation to nfdump file notation.

Parameters:

**nfdump\_files** (*string*) – specifies either a single file or a range of files in a directory

Returns:

nfdump file notation

 `lib.functions.``pythagoras`(*x1*, *y1*, *x2*, *y2*)[¶](#lib.functions.pythagoras "Permalink to this definition")  
Calculates the distance between two points.

Parameters:

-   **x1** (*integer*) – x coordinate
-   **y1** (*integer*) – y coordinate
-   **x2** (*integer*) – x coordinate
-   **y2** (*integer*) – y coordinate

Returns:

distance between the two points

 `lib.functions.``time_statistics`(*\*time*)[¶](#lib.functions.time_statistics "Permalink to this definition")  
Calculates time statistics. Time is a list of variable length of unix timestamps. This function calculates the total duration (first value is assumed beginning, last value is assumed end). And from there it calculates the time spent in each phase.

Parameters:

**\*time** –

unit time stamps

Returns:

pre-formatted line

lib/ids[¶](#module-lib.ids "Permalink to this headline")
--------------------------------------------------------

 *class*`lib.ids.``IDS`(*logger*, *flags*, *config*)[¶](#lib.ids.IDS "Permalink to this definition")  
IDS class, main management class.

 `coordinates_signatures`()[¶](#lib.ids.IDS.coordinates_signatures "Permalink to this definition")  
Generate a coordinate dictionary for the signatures.

 `expander`(*basedir*, *bottom*, *top*)[¶](#lib.ids.IDS.expander "Permalink to this definition")  
Finds all the nfcapd files within the specified range.

Parameters:

-   **basedir** (*string*) – specifies what directory to look in
-   **bottom** (*string*) – bottom limit
-   **top** (*string*) – top limit

Returns:

nfdump\_files, a list of nfdump files

 `filter_signatures`(*number*)[¶](#lib.ids.IDS.filter_signatures "Permalink to this definition")  
Function for filtering out unrequested signatures.

Parameters:

**number** (*list*) – list created by splitting user input ( “1,2,3”.split(‘,’) )

 `load_signatures`()[¶](#lib.ids.IDS.load_signatures "Permalink to this definition")  
Prints available signatures and asks which one to look for.

 `process_count`(*sig\_count*, *data*)[¶](#lib.ids.IDS.process_count "Permalink to this definition")  
Counts the number of occuring signatures

Parameters:

**data** (*dictionary*) – data dictionary

Returns:

counting dictionary

 `process_filenames`(*path*)[¶](#lib.ids.IDS.process_filenames "Permalink to this definition")  
Function to translate a range into a nfdump range

Parameters:

**path** (*string*) – denotes the path (might be a range of file)

Returns:

a list of nfdump files

 `process_files`(*nfdump\_files*)[¶](#lib.ids.IDS.process_files "Permalink to this definition")  
Creates a worker and processes files.

Parameters:

**nfdump\_files** (*list*) – nfdump files to process

Returns:

data dictiionary

 `process_match`(*data*)[¶](#lib.ids.IDS.process_match "Permalink to this definition")  
Calculate the closest match and add it to the data

 `process_sort`(*data*)[¶](#lib.ids.IDS.process_sort "Permalink to this definition")  
Sorts the data based on source ip

Parameters:

**data** (*dictionary*) – data to be sorted

lib/logsetup[¶](#lib-logsetup "Permalink to this headline")
-----------------------------------------------------------

Yes, this library is named after the Alice in Wonderland character.

 `lib.logsetup.``log_setup`(*name*, *log\_file*, *log\_level*)[¶](#lib.logsetup.log_setup "Permalink to this definition")  
Function to setup a logger, based on the given configuration.

Parameters:

-   **name** (*str*) – name used in logging
-   **log\_file** (*str*) – specifies the log file
-   **log\_level** (*str*) – specifies the log level

Returns:

logger object

lib/printer[¶](#module-lib.printer "Permalink to this headline")
----------------------------------------------------------------

 `lib.printer.``format_value`(*item*, *value*)[¶](#lib.printer.format_value "Permalink to this definition")  
Formats values according to some set rules.

Parameters:

-   **item** (*string*) – identifier, what kind of value is given
-   **value** – value of the item

Returns:

formatted string

 `lib.printer.``get_action`(*action*)[¶](#lib.printer.get_action "Permalink to this definition")  
Returns the appropriate function for the given action.

Parameters:

**action** (*string*) – action to take

 `lib.printer.``get_options`()[¶](#lib.printer.get_options "Permalink to this definition")  
Returns a string based on the given flags. Usefull for filenames.

Returns:

string with options

 `lib.printer.``header`(*fd*, *action*, *data*)[¶](#lib.printer.header "Permalink to this definition")  
Prints a header for a given data set.

Parameters:

-   **fd** (*io.BufferedWriter or subprocess.Popen*) – filedescriptor, can be an actual filedescriptor or a pager
-   **action** (*string*) – specifies where the output should go
-   **data** (*dictionary*) – the data set

Returns:

list of used items

 `lib.printer.``legenda`(*fd*, *action*, *count*)[¶](#lib.printer.legenda "Permalink to this definition")  
Prints a legenda to the given file descriptor.

Parameters:

-   **fd** (*io.BufferedWriter or subprocess.Popen*) – filedescriptor, can be an actual filedescriptor or a pager
-   **action** (*string*) – specifies where the output should go
-   **count** (*dictionary*) – dictionary containing signature hit counters

 `lib.printer.``open_file`(*output\_dir*, *signatures*, *date*)[¶](#lib.printer.open_file "Permalink to this definition")  
Open a file descriptor.

Parameters:

-   **signatures** (*dictionary*) – dictionary of used signatures
-   **output\_dir** (*string*) – specifies the output directory

Returns:

file descriptor

 `lib.printer.``open_pager`(*output*)[¶](#lib.printer.open_pager "Permalink to this definition")  
Opens a pager with to the given output (usually sys.stdout).

Parameters:

**output** – specifies to where the output should go

 `lib.printer.``open_parsable_file`(*output\_dir*, *signatures*, *date*)[¶](#lib.printer.open_parsable_file "Permalink to this definition")  
Function for opening a file for parsable output.

Parameters:

-   **output\_dir** (*string*) – specifies the output directory
-   **signatures** (*list*) – a list of the used signatures
-   **date** (*string*) – a date string

Returns:

a filedescriptor

 `lib.printer.``print_data`(*fd*, *action*, *signatures*, *data*, *count*)[¶](#lib.printer.print_data "Permalink to this definition")  
Prints data to the given filedescriptor

Parameters:

-   **fd** (*io.BufferedWriter or subprocess.Popen*) – filedescriptor
-   **action** (*string*) – the action to take
-   **data** (*dictionary*) – the data dictionary to print
-   **count** (*dictionary*) – signature hit count dictionary

 `lib.printer.``print_dstip`(*signatures*, *data*, *srcip*, *dstip*, *used*)[¶](#lib.printer.print_dstip "Permalink to this definition")  
Formats the data fields belonging to the destination in a nice line.

Parameters:

-   **data** (*dictionary*) – data dictionary
-   **srcip** (*string*) – the source ip
-   **dstip** (*string*) – the destination ip
-   **used** (*list*) – list of used data fields (the header function returns this)

Returns:

formatted string

 `lib.printer.``print_parsable_data`(*fd*, *data*)[¶](#lib.printer.print_parsable_data "Permalink to this definition")  
Prints the data in a parsable manner to the filedescriptor.

Parameters:

-   **fd** (*io.BufferedWriter*) – file descriptor
-   **data** (*dictionary*) – dictionary to print

 `lib.printer.``print_parsable_dstip`(*data*, *srcip*, *dstip*)[¶](#lib.printer.print_parsable_dstip "Permalink to this definition")  
Returns a parsable data line for the destination data.

Parameters:

-   **data** (*dictionary*) – the data source
-   **scrip** – the source ip
-   **dstip** (*string*) – the destination ip

Returns:

a line of urls and their hitcount

 `lib.printer.``print_parsable_urls`(*urls*)[¶](#lib.printer.print_parsable_urls "Permalink to this definition")  
Converts a urls dictionary into a single line.

Parameters:

**urls** – dictionary of urls and their hitcount

Type:

urls: dictionary

Returns:

string of urls

 `lib.printer.``print_srcip`(*data*, *srcip*, *used*)[¶](#lib.printer.print_srcip "Permalink to this definition")  
Formats the data fields belonging to the source in a nice line.

Parameters:

-   **data** (*dictionary*) – data dictionary
-   **srcip** (*string*) – the source ip
-   **used** (*list*) – list of used data fields (the header function returns this)

Returns:

formatted string

 `lib.printer.``print_urls`(*fd*, *action*, *color*, *urls*)[¶](#lib.printer.print_urls "Permalink to this definition")  
Function for nicely printing a dictionary of urls. The dictionary is expected to hold a hit count.

Parameters:

-   **fd** (*io.BufferedWriter or subprocess.Popen*) – filedescriptor, can be an actual filedescriptor or a pager
-   **action** (*string*) – specifies where the output should go
-   **color** (*string or None*) – denotes the color
-   **urls** (*dictionary*) – dictionary of urls

 `lib.printer.``write_to_file`(*fd*, *message*, *color=None*)[¶](#lib.printer.write_to_file "Permalink to this definition")  
Writes a message to the given file descriptor. It takes care of line endings and encoding for you.

Parameters:

-   **fd** (*io.BufferedWriter*) – the filedescriptor
-   **message** (*string*) – the message to be written
-   **color** – dummy variable, not used

 `lib.printer.``write_to_pager`(*pager*, *message*, *color*)[¶](#lib.printer.write_to_pager "Permalink to this definition")  
Writes a message to the given pager. If termcolor is available it will even be written in the given color.

Parameters:

-   **pager** (*subprocess.Popen*) – the pager to write to
-   **message** (*string*) – the message to write
-   **color** (*string*) – the color to write the message in

lib/signature[¶](#module-lib.signature "Permalink to this headline")
--------------------------------------------------------------------

 *class*`lib.signature.``Worker`(*logger*, *flags*, *signatures*, *coordinates*, *data*)[¶](#lib.signature.Worker "Permalink to this definition")  
Signature worker class

 `get_result`()[¶](#lib.signature.Worker.get_result "Permalink to this definition")  
Returns the result.

Returns:

data dictionary

 `match_signature`(*data*, *signatures*, *srcip*, *dstip*)[¶](#lib.signature.Worker.match_signature "Permalink to this definition")  
Function for matching a signature

Parameters:

-   **data** (*dictionary*) – data dictionary
-   **signatures** (*dictionary*) – signatures dictionary
-   **srcip** (*string*) – source ip
-   **dstip** (*string*) – destination ip

Returns:

matched signature

 `run`()[¶](#lib.signature.Worker.run "Permalink to this definition")  
Main function of the signature worker. Matches signatures in the given data.

lib/validator[¶](#module-lib.validator "Permalink to this headline")
--------------------------------------------------------------------

 *class*`lib.validator.``Validator`(*logger*, *flags*, *config*, *signature*)[¶](#lib.validator.Validator "Permalink to this definition")  
Class used for validation purposes.

 `calculate_rates`()[¶](#lib.validator.Validator.calculate_rates "Permalink to this definition")  
Calculates the TPR, TNR, FPR and FNR rates.

 `data_merger`(*data*)[¶](#lib.validator.Validator.data_merger "Permalink to this definition")  
Merges data into self.data.

Parameters:

**data** (*dictionary*) – a data dictionary to be merged into self.data

 `filter_attackers`(*attackers*, *cusum*)[¶](#lib.validator.Validator.filter_attackers "Permalink to this definition")  
Filters the attackers list for a given cusum (flow record threshold).

Parameters:

-   **attackers** (*list*) – attackers list
-   **cusum** (*int*) – the minimum cusum rate (flow record threshold)

Returns:

a filtered attackers list

 `load_attackers`(*cusum*)[¶](#lib.validator.Validator.load_attackers "Permalink to this definition")  
Function for loading the attacker lists. These lists should be in the ‘includes’ folder, named as ‘attackers\_fa.dump’ and ‘attackers\_ba.dump’.

Parameters:

**cusum** (*int*) – the minimum cusum rate (flow record threshold)

 `print_rates`()[¶](#lib.validator.Validator.print_rates "Permalink to this definition")  
Prints the rates to the logger.

 `processor`(*data*)[¶](#lib.validator.Validator.processor "Permalink to this definition")  
The actual validation process, i.e. grab a worker and tell him to do it.

Parameters:

**data** (*dictionary*) – data to be processed

 `result_counter`(*data*)[¶](#lib.validator.Validator.result_counter "Permalink to this definition")  
Keeps a count of the TP, TN, FP and FN statistics.

Parameters:

**data** (*tuple*) – a tuple of a count dictionary and a data dictionary

 `save_data`(*signature*, *date*, *type\_scan*, *cusum*)[¶](#lib.validator.Validator.save_data "Permalink to this definition")  
This function saves two files, one containing the rates. The other is a categorized dump of the data. This dump can be viewed with the ‘results\_viewer’ in the ‘scripts’ folder.

Parameters:

-   **signature** (*list*) – a list of used signatures in the scan
-   **date** – a date string of when the scan was performed
-   **type\_scan** (*list*) – ppf, bpf or ppf+bpf
-   **cusum** (*string*) – the cusum rate (flow record threshold

lib/validator\_worker[¶](#module-lib.validator_worker "Permalink to this headline")
-----------------------------------------------------------------------------------

 *class*`lib.validator_worker.``Worker`(*queue*, *logger*, *signature*, *data*, *flags*, *fa*, *ba*)[¶](#lib.validator_worker.Worker "Permalink to this definition")  
The worker class for the validator.

 `check`(*srcip*, *dstip*, *signature*)[¶](#lib.validator_worker.Worker.check "Permalink to this definition")  
Checks if the src \<-\> dst tuple is a TP, FN, FP or TN.

Parameters:

-   **srcip** (*string*) – the source ip
-   **dstip** (*string*) – the destination ip
-   **signature** (*string*) – the matched signature

Returns:

result (‘tp’, ‘fn’, ‘fp’, ‘tn’)

 `get_result`()[¶](#lib.validator_worker.Worker.get_result "Permalink to this definition")  
Returns the achieved result.

Returns:

the resulting dictionary

 `grab_data`(*line*)[¶](#lib.validator_worker.Worker.grab_data "Permalink to this definition")  
Transforms a ids line into a dictionary.

Parameters:

**line** (*string*) – a line from a result file

Returns:

data dictionary

 `parse_data`(*line*, *id*)[¶](#lib.validator_worker.Worker.parse_data "Permalink to this definition")  
Function for parsing the data for later analysis.

Parameters:

-   **line** (*string*) – a data line from the results file
-   **id** (*string*) – defines it to be a TP, TN, FP or FN

 `run`()[¶](#lib.validator_worker.Worker.run "Permalink to this definition")  
Main function that runs trough the all the lines in the results file and calls ‘stats’ on the line.

 `split_url`(*url*)[¶](#lib.validator_worker.Worker.split_url "Permalink to this definition")  
Splits a URL from their hit count

Parameters:

**url** (*string*) – a string of a URL and its hit count

Returns:

a tuple of the count and URL

 `stats`(*line*)[¶](#lib.validator_worker.Worker.stats "Permalink to this definition")  
Determines the type and parses the data

Parameters:

**line** (*bytes*) – a line from the results file

lib/worker[¶](#module-lib.worker "Permalink to this headline")
--------------------------------------------------------------

scripts/validate[¶](#module-scripts.validate "Permalink to this headline")
--------------------------------------------------------------------------

Validation script, it uses the ‘Validator’ class in ‘lib.validator’ to validate a results file. Usage: ./scripts/validate.py \<path-to-result-file\> [options]

The [options] are as defined by the flags library (lib.flags). To configure the logging options see ‘conf/validate.conf’.

Indices and tables[¶](#indices-and-tables "Permalink to this headline")
=======================================================================

-   [*Index*](genindex.html)
-   [*Module Index*](py-modindex.html)
-   [*Search Page*](search.html)

### [Table Of Contents](index.html#document-index)

-   [main](index.html#document-main)
-   [lib/absolom](index.html#document-lib/absolom)
-   [lib/config](index.html#document-lib/config)
-   [lib/flags](index.html#document-lib/flags)
-   [lib/functions](index.html#document-lib/functions)
-   [lib/ids](index.html#document-lib/ids)
-   [lib/logsetup](index.html#document-lib/logsetup)
-   [lib/printer](index.html#document-lib/printer)
-   [lib/signature](index.html#document-lib/signature)
-   [lib/validator](index.html#document-lib/validator)
-   [lib/validator\_worker](index.html#document-lib/validator_worker)
-   [lib/worker](index.html#document-lib/worker)
-   [scripts/validate](index.html#document-scripts/validate)

### Navigation

-   [https-ids 0.8 documentation](index.html#document-index) »

© Copyright 2014, Olivier van der Toorn. Created using [Sphinx](http://sphinx-doc.org/) 1.2.2.
