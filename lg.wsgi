
import sys
import os

sitepath = os.path.realpath(os.path.dirname(sys.argv[0]))
sys.path.insert(0, sitepath)

from lg import app as application
