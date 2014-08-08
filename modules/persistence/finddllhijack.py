"""

Uploads Mandiant's finddllhijack.exe tool, runs it
and downloads the results.

All credit to Mandiant:
    https://www.mandiant.com/blog/malware-persistence-windows-registry/

Module built by @harmj0y

"""

import settings

from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "FindDllHijack"
        self.description = ("Uploads/executes Mandiant's finddllhijack.exe tool "
                            "and downloads the results.")

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

        # command to invoke finddllhijack and output it to a temporary file
        exePath = settings.VEIL_PILLAGE_PATH+"/data/misc/finddllhijack.exe"
        cmd = "C:\\Windows\\Temp\\finddllhijack.exe"

        for target in self.targets:
 
            # upload the binary to the host at C:\Windows\Temp\
            smb.uploadFile(target, username, password, "C$", "\\Windows\\Temp\\", exePath)
            
            # execute finddllhijack and get the results
            out = command_methods.executeResult(target, username, password, cmd, triggerMethod, pause=5)
        
            # cleanup 
            command_methods.executeCommand(target, username, password, "del C:\\Windows\\Temp\\finddllhijack.exe", triggerMethod)

            # save the file off to the appropriate location
            saveFile = helpers.saveModuleFile(self, target, "finddllhijack.txt", out)

            if out != "":
                self.output += "[*] FindDllHijack results for "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] FindDllHijack failed for "+target+" : no result file\n"

        
