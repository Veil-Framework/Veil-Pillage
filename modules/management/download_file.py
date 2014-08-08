"""

Retrieve a specified file from a host or host list.

Module built by @harmj0y

"""

import os

import settings
from lib import smb
from lib import helpers

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Get File"
        self.description = "Download a specific file from a host."

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "fileName"  : ["C:\\Windows\\win.ini", "file to download"],
                                    "delete"    : ["false", "delete the file after download"]}

    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        fileName = self.required_options["fileName"][0]
        deleteFile = self.required_options["delete"][0]

        for target in self.targets:

            print "\n [*] downloading '"+fileName+"' from "+target

            # check if the user wants to delete the file after download
            if deleteFile.lower() == "true":
                out = smb.getFile(target, username, password, fileName, delete=True)
            else:
                out = smb.getFile(target, username, password, fileName, delete=False)

            if out == "":
                self.output += "[!] File '"+fileName+"' from "+target+" using creds '"+username+":"+password+"' empty or doesn't exist\n"
                # TODO: keep this "" or change to None if nothing is returned?

            else:

                # write the module out to the appropriate output location
                saveName = helpers.saveModuleFile(self, target, fileName.split("\\")[-1], out)

                self.output += "[*] File '"+fileName+"' from "+target+" using creds '"+username+":"+password+"' saved to "+saveName+"\n"
