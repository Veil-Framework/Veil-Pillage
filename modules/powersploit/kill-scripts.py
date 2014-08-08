"""

Kill all Powershell processes on a host,
ending the execution of any PowerSploit modules.

"""

import settings
from lib import command_methods
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Kill-Scripts"
        self.description = ("Kill all Powershell processes on a host, ending the "
                            "execution of any PowerSploit modules.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        # user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis] or [winexe] for triggering"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        # kill all powershell processes
        killCMD = "taskkill /f /im powershell.exe"

        for target in self.targets:

            # execute the command on the host and get the output
            out = command_methods.executeResult(target, username, password, killCMD, triggerMethod=triggerMethod)

            if "SUCCESS" in out:
                self.output += "[*] Powershell processes terminated using creds '"+username+":"+password+"' on "+target+"\n"
            else:
                self.output += "[*] Powershell processes failed to terminate using creds '"+username+":"+password+"' on "+target+"\n"
