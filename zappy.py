#!/usr/bin/env python3
import time
from pprint import pprint
from zapv2 import ZAPv2
import sys

class Zappy:
    def __init__(self, target):
        self.target = target
        self.apikey = 'changeme'
        self.zap = ZAPv2(apikey=self.apikey)
        
    def access_target(self):
        print('[+] Accessing target {}'.format(self.target))
        self.zap.urlopen(self.target)
        # Give the sites tree a chance to get updated
        time.sleep(2)        

    def spider_target(self):
        print('[+] Spidering target {}'.format(self.target))
        self.zap.spider.set_option_max_depth(400)
        scanid = self.zap.spider.scan(self.target)
        time.sleep(2)
        
        # Wait for Spider
        while (int(self.zap.spider.status(scanid)) < 100):
           print('| Spider progress %: {}'.format(self.zap.spider.status(scanid)))
           time.sleep(2)
        print ('[+] Spider completed')

    def active_scan_target(self):
        print ('[+] Active Scanning target {}'.format(self.target))
        scanid = self.zap.ascan.scan(self.target)
        while (int(self.zap.ascan.status(scanid)) < 100):
            # Loop until the scanner has finished
            print ('| Scan progress %: {}'.format(self.zap.ascan.status(scanid)))
            time.sleep(60)
        print ('[+] Active Scan completed')


    def report_results(self):
        st = 0
        pg = 5000
        alert_dict = {}
        alert_count = 0
        alerts = self.zap.core.alerts()
        
        if not alerts:
            print("[-] Could not detect any vulnerabilities")
        for alert in alerts:
            with open("Zappy_{}.txt".format(""),"a+") as output:
                plugin_id = alert.get('pluginId')
                if alert.get('risk') == 'High':
                    print("""
                 
Vulnerability: {}
Risk: {}
URL: {}
                 
                 """.format(alert.get('name'),alert.get('risk'),alert.get('url')))
                    output.write("""
                     
Vulnerability: {}
Risk: {}
URL: {}
                     
                     """.format(alert.get('name'),alert.get('risk'),alert.get('url')))



    def run(self):
        self.access_target()
        self.spider_target()
        self.active_scan_target()
        self.report_results()
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Don't forget to add a target list!")
        print("[-] Usage: python3 zappy.py target_list.txt")
        sys.exit()
    with open(sys.argv[1]) as target_list:
        for target_url in target_list:
            try:
                target_url = target_url.rstrip()
                print("""
=======================================================================================

Initiating Scan for target: {}

=======================================================================================        
                
                """.format(target_url))
                scanner = Zappy(target_url)
                scanner.run()
            except:
                pass
