
from dns import resolver,reversename
import socket


def resolve(n, q):
	return str(resolver.query(n,q)[0])

def mask_is_valid(n):
	if not n: 
		return True
	try:
		mask = int(n)
		return ( mask >= 1 and mask <= 128)
	except:
		return False

def ipv4_is_valid(n):
    try:
        socket.inet_pton(socket.AF_INET, n)
        return True
    except socket.error:
        return False

def ipv6_is_valid(n):
    try:
        socket.inet_pton(socket.AF_INET6, n)
        return True
    except socket.error:
        return False



