"""

Gets the domain SID for the domain the current user
is attached to.


Module built by @harmj0y
"""

import time

from lib import command_methods
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Query Domain Sid"
        self.description = "Gets the domain SID for the crurrent domain"

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

        trigger_method = "wmis"

        for target in self.targets:
            
            # reg.exe command to query the domain group
            command = "whoami /user"
            result = command_methods.executeResult(target, username, password, command, trigger_method)

            if result == "":
                self.output += "[!] No result file, query for domain sid '"+group+"'' failed on " + target + "\n"
            else:
                sid = ""
                for line in result.split("\n"):
                    if "S-" in line:
                        user,sid_full = line.split()
                        # extract the domain sid from the results
                        sid = "-".join(sid_full.split("-")[:-1])
                        print helpers.color("\n\n [*] Domain sid: "+sid)
                        time.sleep(2)
                        self.output += "[*] Domain sid extracted using creds '"+username+":"+password+"' on " + target + ": "+sid+"\n"
                if sid == "":
                    self.output += "[!] Couldn't extract domain sid from results using creds '"+username+":"+password+"' on " + target + "\n"
