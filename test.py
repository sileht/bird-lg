
from bird import BirdSocketSingleton

s = BirdSocketSingleton("h3", 9994)
print s.cmd("show protocols")
print s.cmd("show protocols all TETANEUTRAL")
