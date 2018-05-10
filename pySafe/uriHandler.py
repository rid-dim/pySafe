import sys

with open('/home/riddim/maidsafe/pySafe/pySafe/answer','w') as f:
    f.write('Number of arguments:' + str(len(sys.argv)) + 'arguments.\n')
    f.write('Argument List:' + str(sys.argv))
