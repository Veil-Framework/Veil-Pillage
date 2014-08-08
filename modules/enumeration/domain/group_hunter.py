"""

Queries the first host for members of a particular group
(i.e. Domain Admins) and then checks each target to
see if any of those users are loged in or has a process
running using tasklist and qwinsta.


Note:   for some reason, pth-wmis doesn't play nicely for 
        doing net /domain query commands, so we only
        allow pth-winexe here


Module built by @harmj0y

"""

import time

from lib import command_methods
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Group Hunter"
        self.description = ("Queries the users of a particular group and then "
                            "hunts for members of that group on a set of hosts.")

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "group"            : ["Domain Admins", "domain group to query"]}
        
    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        group = self.required_options["group"][0]

        triggerMethod = "winexe"

        for target in self.targets:
            
            targetUsernames = []

            # reg.exe command to query the domain group
            # we want to do this on each box so we can operate across domains!
            command = "net group \"%s\" /domain" %( group )
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            # TODO: sanity check that we get a correct file back?

            # find the ---------- marker, get the bottom half, split by newline
            # and extract just the name fields
            nameParts = result[result.find("-----"):].split("\r\n")[1:-3]
            for part in nameParts:
                targetUsernames.extend(part.lower().split())

            # check the task list on the host
            taskListResult = command_methods.executeResult(target, username, password, "tasklist /V /FO CSV", triggerMethod)
            
            # check the sessions list on the host
            sessionsResult = command_methods.executeResult(target, username, password, "qwinsta", triggerMethod)

            print ""

            # for each username in our target list, see if they show up in the queried results
            for u in targetUsernames:
                if u.lower() in taskListResult.lower():
                    self.output += "[*] User '%s\\%s' has a process on %s\n" %(group, u, target)
                    print helpers.color("\n [*] User '%s\\%s' has a process on %s!" %(group, u, target))
                    time.sleep(1)
                if u.lower() in sessionsResult.lower():
                    self.output += "[*] User '%s\\%s' has a session on %s\n" %(group, u, target)
                    print helpers.color(" [*] User '%s\\%s' has a session on %s!" %(group, u, target))
                    time.sleep(1)

        # if we have no results, add message to the output
        if self.output == "":
            self.output = "[!] No users found\n"