"""

Run an arbitrary command on a target or targets
and return the result.

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Run Command"
        self.description = "Run a command on a target(s) and return the result."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"   : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                    "command"          : ["dir C:\\", "command to run on target(s)"]}

    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        command = self.required_options["command"][0]

        for target in self.targets:
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result != "":
                self.output += "[*] Results for '%s' using creds '"+username+":"+password+"' on %s : " %(command, target) + "\n"
                self.output += result
                self.output += "\n\n"


