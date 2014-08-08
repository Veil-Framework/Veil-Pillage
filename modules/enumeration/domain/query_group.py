"""

Queries the domain controller for a system for the users
of a particular group (default="Domain Admins")


Note:   for some reason, pth-wmis doesn't play nicely for 
        doing net /domain query commands, so we only
        allow pth-winexe here
        

Module built by @harmj0y
"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Query Domain Group"
        self.description = "Queries the domain controller for a system for the users in a particular domain group."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = { "group" : ["Domain Admins", "group to query for"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        group = self.required_options["group"][0]
        
        triggerMethod = "winexe"

        for target in self.targets:
            
            # net command to query the domain group
            command = "net group \"%s\" /domain" %( group )
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result == "":
                self.output += "[!] No result file, query for domain group '"+group+"'' failed using creds '"+username+":"+password+"' on " + target + "\n"
            else:
                self.output += "[*] Query for domain group '"+group+"'' sucessful using creds '"+username+":"+password+"' on " + target + ":\n"
                self.output += result + "\n"

