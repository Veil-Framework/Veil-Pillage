"""

Module to check if UAC is enabled on a host or host list.

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Check UAC"
        self.description = "Check whether User Access Control (UAC) is enabled on a host or host list."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        # user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}
        
    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:
            
            # reg.exe command to disable UAC
            command = "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA"
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result == "":
                self.output += "[!] No result file, check UAC failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "0x1" in result:
                self.output += "[*] UAC enabled using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "0x0" in result:
                self.output += "[*] UAC disabled using creds '"+username+":"+password+"' on : " + target + "\n"
            else:
                self.output += "[!] Error in checking UAC using creds '"+username+":"+password+"' on : " + target + "\n"

