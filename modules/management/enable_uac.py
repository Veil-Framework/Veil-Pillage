"""

Module to enable UAC on a host or host list.

Module built by @harmj0y

"""

from lib import command_methods

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Enable UAC"
        self.description = "Enables User Access Control (UAC) on a host or host list."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}
        
    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:
            
            # reg.exe command to enable UAC
            command = "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f"
            result = command_methods.executeResult(target, username, password, command, triggerMethod)

            if result == "":
                self.output += "[!] No result file, UAC enable failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in result:
                self.output += "[*] UAC successfully enabled using creds '"+username+":"+password+"' on : " + target + "\n"
            else:
                self.output += "[!] Error in enabling UAC using creds '"+username+":"+password+"' on : " + target + "\n"

