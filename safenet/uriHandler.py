import sys
import os

with open(sys.argv[0][:-13]+'answer','w') as f:
    f.write('Number of arguments:' + str(len(sys.argv)) + 'arguments.\n')
    f.write('Argument List:' + str(sys.argv))
