#!/usr/bin/python3
# Author:       Olivier van der Toorn <o.i.vandertoorn@student.utwente.nl>
# Description:  Extracts urls from IDS results file and checks headers

import sys
import re
import urllib.request

def extract_urls(data_bytes):


  # Open a file for writing status codes to
  f = open('statuscodes.txt','wb')

  # Setup progress metering
  length = len(data_bytes)
  i = 0
  for line in data_bytes:

    print("Progress: {0}/{1}".format(i+1, length))

    # Split line
    line = str(line,'utf-8').split("|")

    # Grab the urls
    urls = line[16]

    # One line per url
    urls = re.sub(r"\.nlhttp",".nl/http",urls)
    urls = re.sub(r"(\\)([0-9]+)([\\\n])",r"\\\2\n",urls).split("\n")
    for url in urls:

      # We need something to visit ;)
      if url != '':

        # Split the url from the access count
        url = re.match(r"(.*)\\([0-9]+)$",url)
        count = int(url.group(2))
        url = url.group(1)

        # Urls usually start with http
        if not  "http://" in url:

          url = "http://{0}".format(url)
        
        # Try and request the page, write down the status code, error status codes are status codes too
        try:

          request = urllib.request.urlopen(url)
          message = "{0} {1}\n".format(request.status, url)
          f.write((bytes(message, 'utf-8')))
        except urllib.error.HTTPError as e:

          print(e.code)
          message = "{0} {1}\n".format(e.code, url)
          f.write((bytes(message, 'utf-8')))
    i += 1

  # Close the file descriptor
  f.close()

def main():

  # Read the file from the IDS
  file = sys.argv[1]
  f = open(file, 'rb')
  data_bytes = f.readlines()
  f.close()

  extract_urls(data_bytes)

if __name__ == "__main__":

  main()