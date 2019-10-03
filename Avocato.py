import time
import requests
import json
import csv
import sys
import os

#Enter your API key here
apikey = "fc0bffbf1a792d2b6d97f06456c19a4d451029e91318ac05ff671fa529efc769"
fcount = 1

print("""
    ___   _____   ___   _ _____ ___  
   /_\ \ / / _ \ / __| /_\_   _/ _ \ 
  / _ \ V / (_) | (__ / _ \| || (_) |
 /_/ \_\_/ \___/ \___/_/ \_\_| \___/ 
                                     """)

while True:
    outfile = f"outputhashes{fcount}.csv"
    
    #Get Input file location from user, assign hashes to variable
    while True:
        try:
            hashfile = input("\nEnter filename for input hashes: ")
            with open(hashfile, mode='r') as f:
                inputhashes = f.readlines()
                numhashes = len(inputhashes)
                print(f"\n{numhashes} hashes found in {hashfile}\n")
            break
        except FileNotFoundError:
            print("\nERROR: Cannot find specified file, please try again.")
            
    #Wait time dictated by VT rate limiting (4/minute)
    wait_time = 15
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    #Initialises an output .csv file
    with open(outfile, mode='w') as hashoutput:
        hashwriter=csv.writer(hashoutput, delimiter=',', lineterminator="\n",)
        hashwriter.writerow(['md5','sha1','sha256','Notes'])

        #Performs VT lookups and writes hashes to .csv
        for count, hash in enumerate(inputhashes):
            j = (count+1)/numhashes
            sys.stdout.write("\r[%-20s] %d%%  " % ('='*int(20*j), 100*j) + f"{count+1} of {numhashes} hashes scanned")

            #Sends request to VT
            params = {'apikey': apikey, 'resource': hash}
            response = requests.get(url, params=params)
            dictresponse = response.json()
                                 
            if dictresponse['response_code'] == 1:
                hashwriter.writerow([dictresponse['md5'],dictresponse['sha1'],dictresponse['sha256']])
            else:
                hashwriter.writerow(['-','-','-',f"VT response [{dictresponse['response_code']}] - {dictresponse['verbose_msg']}"])

            if (count+1) < numhashes:
                time.sleep(wait_time)
                sys.stdout.flush()
            else:
                print(f"\n\nOutput hashes written to {outfile}")
                break
            
    #Open outputfile and allow user to continue or exit        
    while True:
        os.startfile(outfile)
        repeat = input("\nScan another file? Y/N: ")
        if repeat.lower() == "y":
            fcount = fcount+1
            break
        elif repeat.lower() == "n":
            exit()
        else:
            print("\nAhem, Y/N please.\n")
            continue
            

    

    
