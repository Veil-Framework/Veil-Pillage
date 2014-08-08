"""

Runs a set of common host-enumeration commands
and returns the result.

For domain commands, see enumeration/domain/enum_domain.py

Module built by @harmj0y

"""

import time
from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Enum Host"
        self.description = "Runs a set of common host-enumeration commands (no /domain commands)."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                    "out_file"          :   ["enum.txt", "temporary output filename used"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        outFile = self.required_options["out_file"][0]

        if "\\" not in outFile:
            # otherwise assume it's an absolute path
            outFile = "C:\\Windows\\Temp\\" + outFile 

        for target in self.targets:

            targetUsernames = []

            command = "echo IPCONFIG:>>%(p)s&ipconfig /all>>%(p)s&echo ARP:>>%(p)s&arp -a>>%(p)s&echo NET USERS:>>%(p)s&net users>>%(p)s&echo NET SESSIONS:>>%(p)s&net sessions>>%(p)s&echo QWINSTA:>>%(p)s&qwinsta>>%(p)s&echo NETSTAT:>>%(p)s&netstat -nao>>%(p)s&echo TASKLIST:>>%(p)s&tasklist /v>>%(p)s&echo SYSTEMINFO:>>%(p)s&systeminfo>>%(p)s" %{"p":outFile}

            # execute the command
            result = command_methods.executeCommand(target, username, password, command, triggerMethod)

            # wait 20 seconds for "systeminfo" to run
            print helpers.color("\n [*] Waiting 20 seconds for enumeration commands to run on '"+target+"'", status=True)
            time.sleep(20)

            # # grab the output file and delete it
            out = smb.getFile(target, username, password, outFile, delete=True)

            if out != "":
                # save the file off to the appropriate location
                saveFile = helpers.saveModuleFile(self, target, "enum_host.txt", out)
                self.output += "[*] enum_host results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] enum_host failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"
