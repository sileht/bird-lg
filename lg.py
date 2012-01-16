#!/usr/bin/python

import sys, os, subprocess, re
from dns import resolver,reversename
from flask import Flask, render_template, jsonify, redirect
app = Flask(__name__)

import socket

def get_ip(n, q):
	return str(resolver.query(n,q)[0])

def check_mask(n):
	if not n: 
		return True
	try:
		mask = int(n)
		return ( mask > 1 and mask < 128)
	except:
		return False

def check_ipv4(n):
    try:
        socket.inet_pton(socket.AF_INET, n)
        return True
    except socket.error:
        return False

def check_ipv6(n):
    try:
        socket.inet_pton(socket.AF_INET6, n)
        return True
    except socket.error:
        return False


def cleanup_output(text):
	return "\n".join([ add_link(re.sub(r'^[0-9]*-', r'  ', line)) for line in text.split("\n") if not line.startswith("0000") ])

def add_link(text):
	if text.strip().startswith("BGP.as_path:") or \
		text.strip().startswith("Neighbor AS:") :
		return re.sub(r'([0-9]*)',r'<a href="/whois/\1">\1</a>',text)
	else:
		return text

#@app.errorhandler(404)
#def notfound(error):
#	return redirect("/")

@app.route("/")
def hello():
	return render_template('index.html')

@app.route("/whois/<asnum>")
def whois(asnum):
	output = "<h3> Whois as" + asnum + "</h3><pre>"
	try:
		asnum = int(asnum)
	except:
		output += "Failed to parse as%s"%asnum
	else:
		output += subprocess.Popen(['whois', 'as%d'%asnum], stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore')
	output += "</pre>"
	return render_template('index.html', output=output, typ="whois", asnum=asnum)

@app.route("/prefix_detail/<host>/<proto>/")
@app.route("/prefix_detail/<host>/<proto>/<prefix>")
@app.route("/prefix_detail/<host>/<proto>/<prefix>/<mask>")
def show_route_for_prefix_detail(host, proto, prefix="", mask=""):
	return show_route_for_prefix(host, proto=proto, prefix=prefix, mask=mask, all = True)

@app.route("/prefix/<host>/<proto>/")
@app.route("/prefix/<host>/<proto>/<prefix>")
@app.route("/prefix/<host>/<proto>/<prefix>/<mask>")
def show_route_for_prefix(host, proto, prefix="", mask="", all=False):
	qprefix = prefix


	# security check
	allowed = True
	if not prefix:
		allowed = False
	elif not check_mask(mask):
		allowed = False
	elif proto == "ipv6":
		if not check_ipv6(prefix):
			try:
				qprefix = get_ip(prefix, "AAAA")
			except:
				qprefix = "unresolvable"
				allowed = False

		
	elif proto == "ipv4":
		if not check_ipv4(prefix):
			try:
				qprefix = get_ip(prefix, "A")
			except:
				qprefix = "unresolvable"
				allowed = False
	else:
		allowed = False

	output = '<h3>' + host + ' (' + proto + ') show route for ' + prefix + (prefix != qprefix and " (%s)"%qprefix or "") + (mask and '/' + mask or '' ) + (all and " all" or "") + '</h3>'

	if allowed:
		if mask: qprefix = qprefix +"/"+mask
		if mask: prefix = prefix +"/"+mask
		ok, string = get_cmd_result(host , proto, "show route for " + qprefix + (all and " all" or ""))
		if ok:
			output += '<pre>' + cleanup_output(string) + '</pre>'
		else:
			output += string
	else:
		if prefix and qprefix != "unresolvable":
			output += prefix + ' not valid'
		elif prefix:
			output += prefix + ' unresolvable'
		else:
			output += 'prefix missing'

	return render_template('index.html', output=output, typ="prefix" + (all and "_detail" or ""), host=host+"/"+proto, prefix=prefix)

@app.route("/detail/<host>/<proto>/")
@app.route("/detail/<host>/<proto>/<name>")
def detail(host, proto, name=""):
	output = '<h3>' + host + ' (' + proto + ') show protocols all ' + name + '</h3>'

	if not name:
		output += "name missing"
	else:
		ok, string = get_cmd_result(host , proto, "show protocols all " + name)
		if ok:
			output += '<pre>'
			output += "\n".join([ add_link(s.strip()) for s in string.split("\n") if s.startswith(" ")])
			output += '</pre>'
		else:
			output += string

	return render_template('index.html', output=output, typ="detail", host=host+"/"+proto, name=name)

@app.route("/summary/<host>")
@app.route("/summary/<host>/<proto>")
def summary(host, proto="ipv4"):
	output = '<h3>' + host + ' (' + proto + ') show protocols</h3>'

	ok, string = get_cmd_result(host , proto, "show protocols")
	if ok:
		output += '<pre><table>'
		for infos in string.split("\n"):
			if not infos.startswith(" "): continue
			d = infos.split()
			name = d[0]
			typ = d[1]
			if typ == "BGP":
				output += '<tr><td><a href="/detail/%s/%s/%s">%s</a><td><td>%s</td></tr>'%(host,proto,name,name,infos.replace(name,"").strip())
		output += '</table></pre>'
	else:
		output += string
	return render_template('index.html', output=output, typ="summary", host=host+"/"+proto)

@app.route("/<host>/<proto>/status")
def status(host, proto):
	string = get_cmd_result(host, proto, "show status")
	output = '<pre>' + string + '</pre>'
	return render_template('index.html', output=output, host=host+"/"+proto)

def get_cmd_result(host, proto, cmd):

	ret = True
	if proto == "ipv4":
		port = 9994
	else:
		port = 9996

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(3.0)
#	sock.setblocking(0)
	try:
		sock.connect((host, port))
		app.logger.debug("open socket on %s:%d", host, port)

		sock.send(cmd + "\n")
		app.logger.debug("send %s socket on %s:%d", cmd, host, port)

		bufsize = 4096
		data = sock.recv(bufsize)
		string = data
		app.logger.debug("read %s (%d)", data, len(data))
		code = string.split("\n")[-2][0:4]
		while not code[0] in ["0", "9", "8"]:
			data = sock.recv(bufsize)
			string = string + data
			app.logger.debug("read %s (%d)", data, len(data))
			code = string.strip()[len(string.strip())-4:]

		if code[0] in [ "9", "8" ]:
			ret = False

		app.logger.debug("return %s",string)
	except Exception as detail:
		ret = False
		string = "Failed connect to %s:%d (%s)"%(host, port, detail)
		app.logger.error(string)
	sock.close()
	return (ret, string)

app.debug = True
if __name__ == "__main__":
	app.run("0.0.0.0")
