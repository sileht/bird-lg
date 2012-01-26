

import subprocess
from urllib import unquote

from bird import BirdSocket

from flask import Flask, request, abort

app = Flask(__name__)
app.config.from_pyfile('lg-proxy.cfg')

def check_accesslist():
    if  app.config["ACCESS_LIST"] and request.remote_addr not in app.config["ACCESS_LIST"]:
        abort(401)

@app.route("/traceroute")
@app.route("/traceroute6")
def traceroute():
    check_accesslist()

    if request.path == '/traceroute6': o= "-6"
    else: o = "-4"

    query = request.args.get("q","")
    query = unquote(query)

    command = [ 'traceroute', o, '-A', '-q1', '-w2', query]
    result = subprocess.Popen( command , stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore').replace("\n","<br>")
    
    return result



@app.route("/bird")
@app.route("/bird6")
def bird():
    check_accesslist()

    if request.path == "/bird": b = BirdSocket(file="/var/run/bird.ctl")
    elif request.path == "/bird6": b = BirdSocket(file="/var/run/bird6.ctl")
    else: return "No bird socket selected"

    query = request.args.get("q","")
    query = unquote(query)

    status, result = b.cmd(query)
    b.close()
    # FIXME: use status
    return result
	

if __name__ == "__main__":
    app.debug = True
    app.run("0.0.0.0")

