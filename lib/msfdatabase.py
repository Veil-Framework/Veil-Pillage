"""

Abstracts a class that represents the backend MSF database.

Provides methods to query the users and credentials currently in the backend.

"""

from lib import helpers
import base64

import settings, psycopg2

class Database:


    def __init__(self, args):
        
        # metasploit DB connection object
        self.conn = None

        # Database name
        self.databasename = None


    def connect(self, databaseString=None):
        """
        Connect to a MSF database.

        If a custom database connection string is passed, use
        that to connect, otherwise pull the connection string
        from settings.MSF_DATABASE
        Saves the connection to the internal self.conn connection object.

        databaseString = user:pass@host:port/db
        msf3:BLAHBLAHBLAH...@127.0.0.1:5432/msf3

        Returns True if successful, False if the connection fails.
        """

        if self.conn and self.conn.closed == 0:
            # already connected to the database
            print ""
            print helpers.color(" [!] Already connected to the MSF database", warning=True)
            print ""
        else:
            try:
                # if we have a custom database connection string
                if databaseString:
                    userPass, details = databaseString.split("@")
                    username, password = userPass.split(":")
                    hostport, self.databasename = details.split("/")
                    dbHost, dbPort = hostport.split(":")

                # try to grab the config string from the /etc/veil/settings.py file
                else:
                    s = settings.MSF_DATABASE.strip()
                    if s != "":
                        userPass, details = s.split("@")
                        username, password = userPass.split(":")
                        hostport, self.databasename = details.split("/")
                        dbHost, dbPort = hostport.split(":")
                    else:
                        print helpers.color("\n [!] Could not connect to the MSF database!", warning=True)
                        print helpers.color(" [!] Please specify a MSF_DATABASE connection string in /etc/veil/settings.py", warning=True)
                        print helpers.color(" [!] Or do 'service postgresql start' and rerun ./update.py\n", warning=True)
                        self.conn = False
                        return False
                
                self.conn = psycopg2.connect(host=dbHost, port=dbPort, database=self.databasename, user=username, password=password)

                print ""
                print helpers.color(" [*] Successfully connected to the MSF database")
                print ""

                return True

            except Exception as e:
                print helpers.color(" [!] Error connecting to the MSF database!", warning=True)
                print "exception:",e
                self.conn = False
                return False


    def close(self):
        """
        Close off the metasploit DB connection if it's active.
        """
        if self.conn and self.conn.closed == 0:
            self.conn.close()


    def getMSFHosts(self):
        """
        Query the MSF database for unique hosts and return them as a list.
        """

        if not self.conn or self.conn.closed == "1":
            print helpers.color("\n [!] Not currently connected to the MSF database\n", warning=True)
            return ""
        
        else:
            # get a cursor for our database connection
            cur = self.conn.cursor()

            # execute the query for unique host addresses
            cur.execute('SELECT DISTINCT address from %s.public.hosts;' % self.databasename)

            # get ALL the results and close off our cursor
            results = cur.fetchall()
            cur.close()

            # flatten the tuples into a list
            hosts = [element for tupl in results for element in tupl]

            return hosts


    def getMSFCreds(self):
        """
        Query the MSF database for credentials and return them as a list.
        """

        if not self.conn or self.conn.closed == "1":
            print helpers.color("\n [!] Not currently connected to the MSF database\n", warning=True)
            return ""

        else:
            # get a cursor for our database connection
            cur = self.conn.cursor()

            # execute the query for creds -> gotta join the creds, services and hosts tables
            cur.execute('SELECT hosts.address, services.port, creds.user, creds.pass FROM %s.public.creds creds INNER JOIN %s.public.services services on creds.service_id = services.id INNER JOIN %s.public.hosts on services.host_id = hosts.id;' % tuple([self.databasename]*3))

            # get ALL the results and close off our cursor
            creds = cur.fetchall()
            cur.close()

            return creds


    def getCSListeners(self):
        """
        Query the MSF database for Cobalt Strike listeners and return them.
        """

        if not self.conn or self.conn.closed == "1":
            print helpers.color("\n [!] Not currently connected to the MSF database\n", warning=True)
            return ""
        
        else:
            # get a cursor for our database connection
            cur = self.conn.cursor()

            foundListeners = []

            cur.execute('SELECT data FROM %s.public.notes where ntype=\'cloudstrike.listeners\'' % self.databasename)

            # get ALL the results and close off our cursor
            results = cur.fetchall()
            cur.close()

            try:
                # flatten the tuples into a list
                raw = [element.decode('base64','strict') for tupl in results for element in tupl]

                if len(raw) > 0:
                    # decode the raw listener data
                    listeners = raw[0].split('\x00')[-1][1:].split("\x01=")[-1].split("!!")

                    for listener in listeners:
                        parts = listener.split("@@")
                        name, payload, lport, lhost = parts[0], parts[1], parts[2], parts[4]

                        # append the listener to our internal list
                        foundListeners.append((name, payload, lhost, lport))
            
            except: return []

            return foundListeners
