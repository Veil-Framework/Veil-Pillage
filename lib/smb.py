
"""

SMB-related methods.

Includes: 

    ThreadedSMBServer()     - for local smb file hosting
    smbConn()               - establish an SMB connection to a target
    getFile()               - download a particular file from a target    
    uploadFileConn()        - upload a file to a host using an established SMB connection
    uploadFile()            - upload a file to a host over smb using specified credentials 
    checkAdminShare()       - see if the ADMIN$ share is writeable on a target
    verifyLogin()           - verify specific SMB credentials for a target

"""


import threading, StringIO, ConfigParser
import re, signal, sys

# our impacket imports
from impacket import smbserver
from impacket.smbconnection import *
from impacket.dcerpc import transport, svcctl, srvsvc

from lib import helpers


def smbConn(target, username, password, timeout=5):
    """
    Try to establish an smb connection to 'target' using the
    supplied credentials.

    Returns a valid smb connection object, or None if the connection fails.
    """

    conn = None
    domain = ''

    try:
        # see if we need to extract a domain from "domain\username"
        if "/" in username:
            domain,username = username.split("/")

        # create the SMB connection object
        conn = SMBConnection('*SMBSERVER', target, timeout=timeout)
        # check if we have a LM:NTLM credential passed
        if re.match(r'[0-9A-Za-z]{32}:[0-9A-Za-z]{32}', password):
            lm,nt = password.split(":")
            conn.login(username, '', lmhash=lm, nthash=nt, domain=domain)
        # otherwise default to juse username:password
        else:
            conn.login(username, password, domain=domain)

        # print an error and return None if we only got a guest session
        if conn.isGuestSession() > 0:
            print helpers.color(" [!] GUEST session granted on "+target, warning=True)
            return None

        return conn

    # error handling
    except Exception as e:

        # try to handle as many error cases as we can
        if "timed out" in str(e).lower():
            print helpers.color(" [!] Target "+target+" not reachable", warning=True)
        elif "connection refused" in str(e).lower():
            print helpers.color(" [!] Target "+target+" reachable but connection refused", warning=True)
        elif "STATUS_LOGON_FAILURE" in str(e):
            print helpers.color(" [!] SMB logon failure on "+target+" (likely bad credentials)", warning=True)
        elif "STATUS_PASSWORD_EXPIRED" in str(e):
            print helpers.color(" [!] Password has expired for '"+username+"' on "+target, warning=True)
        else:
            print "error:",e
            print helpers.color(" [!] Misc error logging into "+target, warning=True)

        return None


def getFile(target, username, password, fileName, delete=False):
    """
    Get a specified fileName from a target with the supplied credentials
    and then optionally delete it.

    delete = True will delete the file from the server after download
    """

    # establish our smb connection
    conn = smbConn(target, username, password)
    out = ""

    # make sure we have a valid smb connection
    if conn:
        
        try:
            # if we're passed a full path filename with C:\Path\blah
            # strip out the preceeding "C:"
            if fileName.lower()[:2] == "c:":
                fileName = "\\".join(fileName.split("\\")[1:])

            # use StringIO so we don't have to write temporarily to disk
            output = StringIO.StringIO()
            conn.getFile("C$", fileName, output.write)
            
            # delete the file from the host if 'delete' is set to True
            if delete:
                conn.deleteFile("C$", fileName)

            # get the text of the file and close the StringIO object off
            out = output.getvalue()
            output.close()

        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                print helpers.color(" [!] Error: file '"+fileName+"' not found on " + target, warning=True)
            else:
                print helpers.color(" [!] Error in execution: " + str(e), warning=True)

        # close off the smb connection
        conn.logoff()

    return out


def checkAdminShare(smbConn):
    """
    Check if the admin share for a host is writeable using the specified
    smb connection.

    smbConn = established SMB connection object

    Returns True if ADMIN$ is writable, False otherwise
    """

    name = helpers.randomString()
    try:
        # create a random directory and then delete it immedately
        smbConn.createDirectory('ADMIN$',name)
        smbConn.deleteDirectory('ADMIN$',name)
        return True
    except:
        return False


def verifyLogin(target, username, password):
    """
    Verify a specific set of credentials for a specified target

    Returns True if ADMIN$ writable on the target, False otherwise
    """

    # establish and SMB connection
    conn = smbConn(target, username, password)

    # make sure we got a valid connection back
    if conn:

        # see if the admin share is writeable
        s = checkAdminShare(conn)
        conn.logoff()

        if not s: return False
        else:return True

    else:
        return False


def uploadFileConn(smbConn, share, uploadPath, fileName):
    """
    Upload a specified file to an established smb connection.

    Takes a valid smb connection, and uploads 'fileName' to
    the specified share\\'uploadPath' on the target.

    Returns "success" if file is uploaded, "" otherwise
    """

    # if the share isn't specified, default to C$
    if not share or share == "":
        share = "C$"

    # get the remote IP for this smb connection
    target = smbConn.getRemoteHost()

    try:
        try:
            # extract out just the name of the file to upload
            uploadName = fileName.split("/")[-1]

            # read in the file contents and attempt to upload it to the smb connection
            f = open(fileName)
            smbConn.putFile(share, uploadPath+"\\"+uploadName, f.read)
            f.close()

            print helpers.color("\n [*] File "+fileName+" successfully uploaded to "+target+":"+share+"\\"+uploadPath)
            return "success"
        
        # sanity check in case 'fileName' doesn't exist
        except IOError as e:
            print helpers.color("\n [!] File "+fileName+" doesn't exist!", warning=True)

    # try to do a bit of error handling
    except Exception as e:
        if "The NETBIOS connection with the remote host timed out" in str(e):
            print helpers.color("\n [!] The NETBIOS connection with "+target+" timed out", warning=True)
        else:
            print helpers.color("\n [!] SMB file upload of "+fileName+" unsuccessful on " + target, warning=True)

    return ""


def deleteFileConn(smbConn, share, fileName):
    """
    Deletes the specified share\\fileName from an established SMB connection.

    Returns "success" if file is uploaded, "" otherwise
    """

    # if the share isn't specified, default to C$
    if not share or share == "":
        share = "C$"

    # get the remote IP for this smb connection
    target = smbConn.getRemoteHost()

    try:
        try:
            # issue the smb command to delete the file
            smbConn.deleteFile(share,fileName)
            print helpers.color("\n [*] File "+share+"\\"+fileName+" successfully deleted from "+target)
            return "success"
        
        # sanity check in case 'fileName' doesn't exist
        except IOError as e:
            print helpers.color("\n [!] File "+fileName+" doesn't exist!", warning=True)

    # try to do a bit of error handling
    except Exception as e:
        if "The NETBIOS connection with the remote host timed out" in str(e):
            print helpers.color("\n [!] The NETBIOS connection with "+target+" timed out", warning=True)
        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
            print helpers.color("\n [!] SMB file delete of "+fileName+" unsuccessful on " + target + " : file not found!", warning=True)
        else:
            print helpers.color("\n [!] SMB file delete of "+fileName+" unsuccessful on " + target, warning=True)

    return ""


def uploadFile(target, username, password, share, uploadPath, fileName, timeout=5):
    """
    Version of uploadFile() that utilizes credentials to establish
    a new smb connection instead of using an existing smb connection.

    Uploads 'fileName' to the specified share\\uploadPath on the target.

    Returns "success" if file is uploaded, "" otherwise
    """

    # establish and SMB connection
    conn = smbConn(target, username, password, timeout)

    # call the main uploadFileConn() method
    return uploadFileConn(conn, share, uploadPath, fileName)


def uploadFiles(target, username, password, share, uploadPath, fileNames, timeout=5):
    """
    Version of uploadFile() that handles multiple files.

    Returns "success" if the last file was uploaded successfully, "" otherwise
    """
    # establish and SMB connection
    conn = smbConn(target, username, password, timeout)

    result = ""
    # call the main uploadFileConn() method for each file
    for fileName in fileNames:
        result = uploadFileConn(conn, share, uploadPath, fileName)

    return result


def deleteFile(target, username, password, fileName, share="C$"):
    """
    Version of deleteFile() that utilizes credentials to establish
    a new smb connection instead of using an existing smb connection.

    Deletes the file share\\fileName on the target.

    Returns "success" if file is uploaded, "" otherwise
    """

    # establish and SMB connection
    conn = smbConn(target, username, password)

    # try to extract out the share from the fileName
    if fileName[1] == ":":
        share = fileName[0].upper() + "$"
        fileName = "\\" + "\\".join(fileName.split("\\")[1:])

    # call the main deleteFileConn() method
    return deleteFileConn(conn, share, fileName)


def deleteFiles(target, username, password, fileNames, share="C$"):
    """
    Version of deleteFile() that handles multiple files.

    Returns "success" if the last file was deleted successfully, "" otherwise
    """
    # establish and SMB connection
    conn = smbConn(target, username, password, timeout)

    result = ""
    # call the main uploadFileConn() method for each file
    for fileName in fileNames:
        # try to extract out the share from the fileName
        if fileName[1] == ":":
            share = fileName[0].upper() + "$"
            fileName = "\\" + "\\".join(fileName.split("\\")[1:])
        
        result = deleteFileConn(conn, share, fileName)

    return result


class ThreadedSMBServer(threading.Thread):
    """
    Threaded SMB server that can be spun up locally.

    Hosts the files in /tmp/shared/ as HOST\\SYSTEM\\
    """

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','SERVICE')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','/tmp/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section("SYSTEM")
        smbConfig.set("SYSTEM",'comment','system share')
        smbConfig.set("SYSTEM",'read only','yes')
        smbConfig.set("SYSTEM",'share type','0')
        smbConfig.set("SYSTEM",'path',"/tmp/shared/")

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)

        print '\n [*] setting up SMB server...'
        self.smb.processConfigFile()
        try:
            self.smb.serve_forever()
        except:
            pass

    def shutdown(self):
        print '\n [*] killing SMB server...'
        self.smb.shutdown()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass


##############################################################
#
# The following is stolen from Impacket and slightly modified
# 
##############################################################

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, protocols = None, 
                 username = '', password = '', domain = '', hashes = None, mode = None, share = None, serviceName=None, outputFile="__output"):
        if not protocols:
            protocols = PSEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        if not serviceName:
            self.__serviceName = 'SystemDiag'.encode('utf-16le')
        else:
            self.__serviceName = serviceName.upper().encode('utf-16le')
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__outputfile = outputFile
        self.__mode  = mode
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr, smbcmd):
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "\n\n [*] Trying protocol "+protocol+" on " + addr
            print " [*] Creating service %s..." % self.__serviceName

            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

            try:
                # create the object to execute our command
                self.executor = SmbExecute(self.__share, rpctransport, self.__mode, self.__serviceName, self.__outputfile)
                # actually execute the command
                out = self.executor.execute_remote(smbcmd)
                # return the output
                return out

            except  (Exception, KeyboardInterrupt), e:
                print e
                sys.stdout.flush()
                return ""

class SmbExecute():
    def __init__(self, share, rpc, mode, serviceName, outputFile):
        self.__share = share
        self.__mode = mode
        if not outputFile:
            self.__output = None
        else:
            self.__output = 'C:\\Windows\\Temp\\'+outputFile

        self.__batchFile = '%TEMP%\\execute.bat'
        self.__outputBuffer = ''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc

        dce = rpc.get_dce_rpc()
        try:
            dce.connect()
        except Exception, e:
            print e
            sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        # open the service handler and get the handle to this created service
        dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
        resp = self.rpcsvc.OpenSCManagerW()
        self.__scHandle = resp['ContextHandle']
        self.transferClient = rpc.get_smb_connection()


    def execute_remote(self, data):
        """
        Execute a particular command ('data') that outputs the command
        to self.__output.
        """
        
        # if we don't have an output file, modify the command
        if not self.__output:
            command = self.__shell + 'echo ' + data + ' > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        else:
            command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        command += ' & ' + 'del ' + self.__batchFile 

        # actually create the service
        try:
            resp = self.rpcsvc.CreateServiceW(self.__scHandle, self.__serviceName, self.__serviceName, command.encode('utf-16le'))

        except Exception as e:
            print "Exception:",e
            if "ERROR_SERVICE_EXISTS" in str(e):
                print helpers.color(" [!] Service already exists! Deleting and recreating...", warning=True)

                # try to stop/remove this service if it exists
                resp2 = self.rpcsvc.OpenServiceW(self.__scHandle, self.__serviceName)
                service = resp2['ContextHandle']
                try:self.rpcsvc.StopService(service)
                except: pass
                try: self.rpcsvc.DeleteService(service)
                except: pass

                # recreate the service again
                resp = self.rpcsvc.CreateServiceW(self.__scHandle, self.__serviceName, self.__serviceName, command.encode('utf-16le'))

        # start the service
        service = resp['ContextHandle']
        try: 
            self.rpcsvc.StartServiceW(service)
        except Exception as e: pass

        print " [*] Removing service %s..." % self.__serviceName
        # delete the service and close the service handler
        # self.rpcsvc.StopService(service)
        self.rpcsvc.DeleteService(service)
        self.rpcsvc.CloseServiceHandle(service)

        # don't try to return output if we specified no output file
        if not self.__output: return None
        # otherwise return the output
        else: return self.get_output()


    def get_output(self):
        """
        Get the results of the output file.
        """
        def output_callback(data):
            self.__outputBuffer += data

        self.transferClient.getFile(self.__share, self.__output, output_callback)
        self.transferClient.deleteFile(self.__share, self.__output)

        return self.__outputBuffer

