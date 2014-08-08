"""

Hunts for a particular user on a set of hosts by querying 
tasklist and qwinsta for users with sessions/tokens. 

Module built by @harmj0y

"""

import os
from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "User Hunter"
        self.description = "Hunts for a particular user on a set of hosts."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method"   : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                 "user"             : ["Administrator", "[domain\\]user to hunt for, or filepath to userlist"]}
        
    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        targetUsernames = []

        # if we're passed a file, read in the usernames
        if os.path.exists(self.required_options["user"][0]):
            f = open(self.required_options["user"][0])
            lines = f.readlines()
            f.close()

            for line in lines:
                targetUsernames.append(line.strip())

        # if we have just a single name, use just that
        else:
            targetUsernames.append(self.required_options["user"][0])

        for target in self.targets:
            
            # check the task list on the host
            taskListResult = command_methods.executeResult(target, username, password, "tasklist /V /FO CSV", triggerMethod)
            
            # check the sessions list on the host
            sessionsResult = command_methods.executeResult(target, username, password, "qwinsta", triggerMethod)

            # for each username in our target list, see if they show up in the queried results
            for u in targetUsernames:
                if u.lower() in taskListResult.lower():
                    self.output += "[*] User '%s' has process on %s\n" %(u, target)
                if u.lower() in sessionsResult.lower():
                    self.output += "[*] User '%s' has session on %s\n" %(u, target)

        # if we have no results, add message to the output
        if self.output == "":
            self.output = "[!] No users found\n"
