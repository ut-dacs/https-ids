#!/usr/bin/python3

import datetime
import os
import re
import time
import subprocess
import sys

if len(sys.argv) < 1:

  sys.exit()

def format_line(line):

  if not line.endswith("\n"):

    line = "{0}\n".format(line)
  line = bytes(line, 'utf-8')
  return line

descriminator_types = ['ppf', 'bpf', 'ppf-bpf']
cusum = [6, 9, 14, 37]
data_folder = sys.argv[1]
date_report = sys.argv[2]
date_report = datetime.datetime.strptime(date_report, '%Y-%m-%d')
date_report = time.mktime(date_report.timetuple())


data_files = {}

# Go over all of the folders in root
for path, subdirs, files in os.walk(data_folder):
  for name in files:
    name_edit = name.replace("fa-v2", "fa_v2").replace("xmlrpc-v2","xmlrpc_v2")
    item = re.match('(.*?)-([0-9]{4}-[0-9]{2}-[0-9]{2})-(.*?)-([0-9]{1,2}).idats', name_edit)
    if item:
      signature = item.group(1).replace("fa_v2","fa-v2").replace("xmlrpc_v2","xmlrpc-v2")
      date = item.group(2)
      descriminator = item.group(3)
      cusum_value = int(item.group(4))
      date = datetime.datetime.strptime(date, '%Y-%m-%d')
      date = time.mktime(date.timetuple())
      if date == date_report and date in data_files:
        if descriminator in data_files[date]:
          data_files[date][descriminator][cusum_value] = (os.path.join(path, name),signature)

        else:
          data_files[date][descriminator] = {cusum_value: (os.path.join(path, name),signature)}

      else:
        data_files[date] = {descriminator: {cusum_value: (os.path.join(path, name),signature)}}

for date in sorted(data_files.keys()):
  print("{0}:".format(date))
  for descriminator in sorted(data_files[date].keys()):
    print("\t{0}:".format(descriminator))
    for cusum_value in sorted(data_files[date][descriminator].keys()):
      print("\t\t{0}".format(cusum_value))

    print()

  print()

if os.path.isfile('/opt/bin/python3/bin/python3'):
  python = '/opt/bin/python3/bin/python3'

else:
  python = 'python3'

for descriminator in descriminator_types:
  if descriminator == 'ppf':
    operator = 'packets'

  elif descriminator == 'bpf':
    operator = 'bytes'

  elif descriminator == 'ppf-bpf':
    operator = 'packets --bytes'

  for cusum_value in data_files[date_report][descriminator]:
    command = "{0} ./scripts/validate.py {1} --automate {2} --cusum {3} --{4}".format(python, data_files[date_report][descriminator][cusum_value][0], data_files[date_report][descriminator][cusum_value][1], cusum_value, operator)
    print(command)
    #process = subprocess.Popen(command, shell=True)
    #process.wait()

def header(descriminator):
  header_list = []
  header_list.append("Cusum value")
  for cusum_value in sorted(result_files[descriminator].keys()):

    header_list.append("{:>26}".format(cusum_value))
  header_line = " ".join(header_list)
  sub = '{:=^'+str(len(header_line))+'}'
  line = sub.format('')
  header_line = "\n".join([header_line,line])
  return header_line

result_files = {}
for path, subdirs, files in os.walk('results/'):
  for name in files:
    if '.txt' in name:
      name_edit = name.replace("fa-v2", "fa_v2").replace("xmlrpc-v2","xmlrpc_v2")
      #item = re.search("([0-9]{4}-[0-9]{2}-[0-9]{2})-([0-9]+?)-.*?-(.*)\.(.*)",name_edit)
      item = re.search('(.*?)-([0-9]{4}-[0-9]{2}-[0-9]{2})-(.*?)-([0-9]{1,2}).txt', name_edit)
      if item:
        date_result = item.group(2)
        date_result = datetime.datetime.strptime(date_result, '%Y-%m-%d')
        date_result = time.mktime(date_result.timetuple())
        if date_result == date_report:
          cusum_value = int(item.group(4))
          descriminator = item.group(3)
          if descriminator in result_files:
            result_files[descriminator][cusum_value] = os.path.join(path, name)

          else:
            result_files[descriminator] = {cusum_value: os.path.join(path, name)}

latex_data = {}
for descriminator in sorted(result_files.keys()):
  filename = "results/report-{0}-{1}.txt".format(sys.argv[2],descriminator)
  tp = []
  fp = []
  tn = []
  fn = []
  tpr = []
  fpr = []
  tnr = []
  fnr = []
  rates = []
  for cusum_value in sorted(result_files[descriminator].keys()):
    with open(result_files[descriminator][cusum_value], 'rb') as data_file:
      data = data_file.readlines()

    for i,line in enumerate(data):
      line = str(line, 'utf-8')
      value = re.search(".*\ (.*)$", line)

      # Numbers
      if line.startswith("TP:"):

        tp.append("{:>26}".format(value.group(1)))
      elif line.startswith("FP:"):

        fp.append("{:>26}".format(value.group(1)))
      elif line.startswith("TN:"):

        tn.append("{:>26}".format(value.group(1)))
      elif line.startswith("FN:"):

        fn.append("{:>26}".format(value.group(1)))

      # Rates
      elif line.startswith("TPr:"):

        tpr.append("{:>26}".format(str(round(float(value.group(1)),2))))
      elif line.startswith("FPr:"):

        fpr.append("{:>26}".format(str(round(float(value.group(1)),2))))
      elif line.startswith("TNr:"):

        tnr.append("{:>26}".format(str(round(float(value.group(1)),2))))
      elif line.startswith("FNr:"):

        fnr.append("{:>26}".format(str(round(float(value.group(1)),2))))
      if i+1 == len(data):

        line = "{0} {1}".format(cusum_value, line)
        rates.append(line)
  with open(filename, 'wb') as report:

    with open(filename.replace("report","plot"), 'wb') as plot:

      data = [('tp',tp), ('tn',tn), ('fp',fp), ('fn',fn),('',''), ('tpr',tpr), ('tnr',tnr), ('fpr',fpr), ('fnr',fnr)]
      header_line = header(descriminator)
      report.write(format_line(header_line))
      for item in data:

        if item[0] != '':

          ident = "{0}:".format(item[0].upper())
        else:

          ident = ''
        ident = "{:<11}".format(ident)
        line = "{0} {1}".format(ident, " ".join(item[1]))
        report.write(format_line(line))
      report.write(format_line(''))
      report.write(format_line('# Cusum TPR TNR FPR FNR ACC'))
      plot.write(format_line('# Cusum TPR TNR FPR FNR ACC'))
      rates = "".join(rates)
      report.write(format_line(rates))
      plot.write(format_line(rates))

  with open(filename.replace('report','plot'), 'rb') as plot_data:

    data = plot_data.readlines()

  for line in data:

    line = str(line,'utf-8')
    match = re.search("^([0-9]+)\ (.*?)\ (.*?)\ (.*?)\ (.*?)\ (.*?)$",line)
    if match:

      cusum_value = int(match.group(1))
      if cusum_value in cusum:

        tpr = round(float(match.group(2)),3)
        tnr = round(float(match.group(3)),3)
        fpr = round(float(match.group(4)),3)
        fnr = round(float(match.group(5)),3)
        acc = round(float(match.group(6)),3)
        if cusum_value in latex_data:

          latex_data[cusum_value][descriminator] = {'tpr': tpr,
                                                    'tnr': tnr,
                                                    'fpr': fpr,
                                                    'fnr': fnr,
                                                    'acc': acc,
                                                    }
        else:

          latex_data[cusum_value] = {descriminator: {'tpr': tpr,
                                                      'tnr': tnr,
                                                      'fpr': fpr,
                                                      'fnr': fnr,
                                                      'acc': acc,
                                                    }}

# Define latex file content
latex = [ "\\begin{tabular}{c | >{\\centering\\arraybackslash}m{1.8cm} | c | c | c | c || c } \\cline{2-7}",
          "\t& \\textbf{Flow record threshold} & \\textbf{TPR} & \\textbf{TNR} & \\textbf{FPR} & \\textbf{FNR} & \\textbf{\\textit{Acc}} \\\\ \\hline",
          "\t\\multirow{{4}}{{*}}{{\\rotatebox[origin=c]{{90}}{{\\textbf{{PPF}}}}}} & 6 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[6]['ppf']['tpr'],latex_data[6]['ppf']['tnr'],
                                                                                                                 latex_data[6]['ppf']['fpr'],latex_data[6]['ppf']['fnr'],
                                                                                                                 latex_data[6]['ppf']['acc']),
          "\t& 9 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[9]['ppf']['tpr'],latex_data[9]['ppf']['tnr'],
                                                           latex_data[9]['ppf']['fpr'],latex_data[9]['ppf']['fnr'],
                                                           latex_data[9]['ppf']['acc']),
          "\t& 14 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[14]['ppf']['tpr'],latex_data[14]['ppf']['tnr'],
                                                             latex_data[14]['ppf']['fpr'],latex_data[14]['ppf']['fnr'],
                                                             latex_data[14]['ppf']['acc']),
          "\t& 37 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\hline \\hline".format(latex_data[37]['ppf']['tpr'],latex_data[37]['ppf']['tnr'],
                                                             latex_data[37]['ppf']['fpr'],latex_data[37]['ppf']['fnr'],
                                                             latex_data[37]['ppf']['acc']),
          "\t\\multirow{{4}}{{*}}{{\\rotatebox[origin=c]{{90}}{{\\textbf{{BPF}}}}}} & 6 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[6]['bpf']['tpr'],latex_data[6]['bpf']['tnr'],
                                                                                                                                  latex_data[6]['bpf']['fpr'],latex_data[6]['bpf']['fnr'],
                                                                                                                                  latex_data[6]['bpf']['acc']),
          "\t& 9 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[9]['bpf']['tpr'],latex_data[9]['bpf']['tnr'],
                                                           latex_data[9]['bpf']['fpr'],latex_data[9]['bpf']['fnr'],
                                                           latex_data[9]['bpf']['acc']),
          "\t& 14 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[14]['bpf']['tpr'],latex_data[14]['bpf']['tnr'],
                                                             latex_data[14]['bpf']['fpr'],latex_data[14]['bpf']['fnr'],
                                                             latex_data[14]['bpf']['acc']),
          "\t& 37 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\hline \\hline".format(latex_data[37]['bpf']['tpr'],latex_data[37]['bpf']['tnr'],
                                                             latex_data[37]['bpf']['fpr'],latex_data[37]['bpf']['fnr'],
                                                             latex_data[37]['bpf']['acc']),
          "\t\\multirow{{4}}{{*}}{{\\rotatebox[origin=c]{{90}}{{\\textbf{{PPF+BPF}}}}}} & 6 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[6]['ppf-bpf']['tpr'],latex_data[6]['ppf-bpf']['tnr'],
                                                                                                                                       latex_data[6]['ppf-bpf']['fpr'],latex_data[6]['ppf-bpf']['fnr'],
                                                                                                                                       latex_data[6]['ppf-bpf']['acc']),
          "\t& 9 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[9]['ppf-bpf']['tpr'],latex_data[9]['ppf-bpf']['tnr'],
                                                            latex_data[9]['ppf-bpf']['fpr'],latex_data[9]['ppf-bpf']['fnr'],
                                                            latex_data[9]['ppf-bpf']['acc']),
          "\t& 14 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\cline{{2-7}}".format(latex_data[14]['ppf-bpf']['tpr'],latex_data[14]['ppf-bpf']['tnr'],
                                                             latex_data[14]['ppf-bpf']['fpr'],latex_data[14]['ppf-bpf']['fnr'],
                                                             latex_data[14]['ppf-bpf']['acc']),
          "\t& 37 & {0:.3f} & {1:.3f} & {2:.3f} & {3:.3f} & {4:.3f} \\\\ \\hline".format(latex_data[37]['ppf-bpf']['tpr'],latex_data[37]['ppf-bpf']['tnr'],
                                                             latex_data[37]['ppf-bpf']['fpr'],latex_data[37]['ppf-bpf']['fnr'],
                                                             latex_data[37]['ppf-bpf']['acc']),
          "\\end{tabular}",]
with open(re.sub("/.*\.","/latex.",filename), 'wb') as latex_file:

  latex_contents = bytes("\n".join(latex),'utf-8')
  latex_file.write(latex_contents)
