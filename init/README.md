# bird-lg init

Systemd unit files for the bird-lg webservice, and for the proxy service running on routers.

You need to adapt the exact command used to start the service (`ExecStart`) and the `User`
under which it should run.  Don't run the services as root!

## Installation

Copy the init file under `/etc/systemd/system/` and run:

    systemctl daemon-reload
    systemctl start bird-lg-proxy
    systemctl enable bird-lg-proxy

## Credits

Adapted from <http://gitlab.netlib.re/arn/arn-confs/tree/master/routing/looking-glass>
