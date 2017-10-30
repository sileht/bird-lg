import sys

activate_this = '/path/to/bird-lg/venv/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

sys.path.insert(0, '/path/to/bird-lg')

from lgproxy import app as application
