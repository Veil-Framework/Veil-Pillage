"""

Hosts a file on a temporary SMB server which any
network user can connect to.

All cred to the the awesome Impacket project !
    https://code.google.com/p/impacket/


Module built by @harmj0y

"""

import settings, os, time

# pillage imports
from lib import helpers
from lib import smb

class Module:
    
    def __init__(self, targets=None, creds=None, args=None):

        self.name = "SMB Host file"
        self.description = ("Use a temporary Impacket SMB server to host "
                            "a specified file. Type Ctrl+C to kill the server.")

        # any relevant text to echo to the output file
        self.output = ""

        #   user interaction for- format is {Option : [Value, Description]]}
        self.required_options = { "file_path"    : ["", "path of file to host"]}


    def run(self):

        try:
            file_path = self.required_options["file_path"][0]

            # make the tmp hosting directory if it doesn't already exist
            if not os.path.exists(settings.TEMP_DIR + "shared/"): 
                os.makedirs(settings.TEMP_DIR + "shared/")

            # grab just the file name to hsot
            hostedFileName = file_path.split("/")[-1]

            # copy the payload to the random hostedFileName in the temp directory
            os.system("cp "+file_path+" /"+settings.TEMP_DIR+"/shared/" + hostedFileName)

            # spin up the SMB server 
            server = smb.ThreadedSMBServer()
            server.start()
            time.sleep(.5)

            print helpers.color("\n [*] Hosting file "+file_path+" at "+helpers.lhost()+"\\system\\"+hostedFileName)
            print helpers.color(" [*] Press Ctrl+C to kill the server")

            # sleep until Ctrl + C
            while 1==1:
                time.sleep(1)

        # catch any ctrl + c interrupts
        except KeyboardInterrupt:

            print helpers.color("\n\n [!] Killing SMB server...\n", warning=True)

            # shut the smb server down
            server.shutdown()

            # remove the temporarily hosted files
            os.system("rm -rf " + settings.TEMP_DIR+"/shared/")

            self.output += "[*] SMB server hosted "+file_path+"\n"

