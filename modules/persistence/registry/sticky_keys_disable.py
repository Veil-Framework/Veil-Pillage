"""

Remove a sticky keys backdoor to a system.

Module built by @harmj0y

"""

from lib import command_methods


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Stickykeys Backdoor Disable"
        self.description = "Removes the sethc stickykeys backdoor on a host or host list."

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

        # assume single set of credentials (take the first one)
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:

            # the registry command to disable the sethc stickkeys backdoor
            disableSethcCommand = "REG DELETE \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /f"

            # execute the sethc command and get the result
            disableResult = command_methods.executeResult(target, username, password, disableSethcCommand, triggerMethod)

            if disableResult == "":
                self.output += "[!] No result file, SETHC backdoor disable failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in disableResult:
                self.output += "[*] SETHC backdoor successfully disabled using creds '"+username+":"+password+"' on : " + target + "\n"
