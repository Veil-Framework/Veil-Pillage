"""

Runs a set of common domain-enumeration commands
and returns the result.

For host commands, see enumeration/host/enum_host.py

Module built by @harmj0y

"""

import time
from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Enum Domain"
        self.description = "Runs a set of common domain-enumeration commands."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {  "out_file"   :   ["enum.txt", "temporary output filename used"]}


    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        outFile = self.required_options["out_file"][0]

        # wmis doesn't like net * /domain commands >_<
        triggerMethod = "winexe"

        if "\\" not in outFile:
            # otherwise assume it's an absolute path
            outFile = "C:\\Windows\\Temp\\" + outFile 

        for target in self.targets:

            targetUsernames = []

            command = "echo NET VIEW:>>%(p)s&net view /domain>>%(p)s&echo NET USERS:>>%(p)s&net users /domain>>%(p)s&echo NET GROUPS:>>%(p)s&net groups /domain>>%(p)s&echo NET ACCOUNTS:>>%(p)s&net accounts /domain>>%(p)s"%{"p":outFile}

            # execute the command
            result = command_methods.executeCommand(target, username, password, command, triggerMethod)

            # wait 20 seconds for commands to run
            print helpers.color("\n [*] Waiting 20 seconds for enumeration commands to run on '"+target+"'", status=True)
            time.sleep(20)

            # # grab the output file and delete it
            out = smb.getFile(target, username, password, outFile, delete=True)

            if out != "":
                # save the file off to the appropriate location
                saveFile = helpers.saveModuleFile(self, target, "enum_domain.txt", out)
                self.output += "[*] enum_domain results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
            else:
                self.output += "[!] enum_domain failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"
