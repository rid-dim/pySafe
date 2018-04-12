import pySafe

session=pySafe.connection.Connection()
import getpass

username=getpass.getpass()

key=getpass.getpass()

session.login(username,key)