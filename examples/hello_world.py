import pySafe

session=pySafe.connection.Connection()

#todo better ways to get key/pass
import getpass

username = getpass.getpass()
key = getpass.getpass()



session.login(username,key)