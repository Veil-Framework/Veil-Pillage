"""

Queries the domain controller for a system for the current
domain user list.

Note:   for some reason, pth-wmis doesn't play nicely for 
        doing net /domain query commands, so we only
        allow pth-winexe here

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Query Domain Users"
        self.description = "Queries the domain controller for a system for the current domain user list."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = "winexe"

        for target in self.targets:
            
            # net command to query the domain group
            command = "net users /domain"
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result == "":
                self.output += "[!] No result file, query for domain user failed using creds '"+username+":"+password+"' on " + target + "\n"
            else:
                self.output += "[!] Query for domain users sucessful on " + target + ":\n"
                self.output += result + "\n"

