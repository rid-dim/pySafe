import pySafe

session=pySafe.connection.Connection()

#todo better ways to get key/pass
import getpass

# username = getpass.getpass()
# key = getpass.getpass()

username = 'foo'
key = 'bar'

session.login(username,key)