
import sys
import os

sitepath = os.path.realpath(os.path.dirname(__file__))
sys.path.insert(0, sitepath)

from lgproxy import app as application
