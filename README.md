> This project has not been updated since a long time. While it should still work and may be updated someday, you can consider using the well-maintained project "The Bastion" available here : https://github.com/ovh/the-bastion

TG
=========

TG is the greatest ssh bridge ever !
An SSH bridge, also known as SSH bastion or SSH gateway acts as proxy to handle your SSH connections.

Screenshots
--------------

tg -ls view:
![tg -ls view](http://pix.toile-libre.org/upload/original/1459643733.png)


Installation (Server side)
--------------

First of all, you must have an SSH key on your current machine.

If you don't, create one from your current machine (make sure you provide a password when it asks for one):

```sh
ssh-keygen -t rsa -b 4096
```


Connect to your future bastion server as root (important) :

Install dependencies:

Debian:

```sh
apt-get install openssh-server git libjson-perl libemail-mime-perl libdatetime-perl libemail-sender-perl  libemail-mime-creator-perl libjson-xs-perl libwww-perl screen libconvert-base32-perl libauthen-oath-perl
```

Clone repo in a directory (ex: _/opt/tg_)

```sh
git clone https://github.com/root-gg/tg.git /opt/tg
```

Create a new user without password and with the tg _cache_ program as shell :

```sh
adduser --system --shell /opt/tg/cache --group --disabled-password --home /home/YOURUSER YOURUSER
```
Replace YOURUSER by the username of your choice.

Now, you must create an SSH key to YOURUSER (this one will be without passphrase) :

```sh
sudo -u YOURUSER ssh-keygen -t rsa -b 4096 -N ''
```

Add your SSH key in _/home/YOURUSER/.ssh/authorized_keys_
If this file does not exist, create it:
```sh
touch /home/YOURUSER/.ssh/authorized_keys
```
And change his owner to YOURUSER
```sh
chown YOURUSER: /home/YOURUSER/.ssh/authorized_keys
```

Try to connect to your bastion host with your key :

```sh
ssh YOURUSER@yourbastionhost.com
```

Installation (Client side)
--------------

This part requires your bastion server to be installed and it must be done on each client you are using.

Choose one of these two methods for each client to fit your needs

First of all, try to connect to your bastion host with your key :

```sh
ssh YOURUSER@yourbastionhost.com
```

### Method 1: Client with tg official client

Clone tg in a folder (ex: ~/bin/tg) :

```sh
mkdir ~/bin
git clone https://github.com/root-gg/tg.git ~/bin/tg
```

Change your PATH to add ~/bin/tg :

```sh
echo 'export PATH="~/bin/tg::$PATH"' >> ~/.bashrc
```

Restart your shell !

Initialize TG client :

```sh
tg --init
```
Answer each question according to your bastion server.


### Method 2: Client with ssh bash alias

Replace YOURUSER by your bastion username and YOURBASTIONHOST by your bastion hostname.

Add tg alias to your bashrc :

```sh
echo 'alias tg="ssh -t -t YOURUSER@YOURBASTIONHOST --"' >> ~/.bashrc
```

Restart your shell !

### For both methods

Try the bastion is working :

```sh
tg -ls
```

If it displays beautiful lines with colors and such, you're good to go !

Optional : Change the default bastion user to root (to connect as root to your servers, by default) :

```sh
tg -su root
```

Usage
--------------

Main help (quite ugly and incomplete at this time):

```sh
tg -h
```


### List your hosts, aliases and sessions

```sh
tg -ls
```

### Add a new host to the list

Replace myserver.mydomain.com by the hostname of the server you want to add

Add host : 
```sh
tg -a myserver.mydomain.com
```

Automagically push bastion SSH key to your host (you must provide host password for this) :
```sh
tg -ak myserver.mydomain.com
```

Now you can connect to your host :
```sh
tg myserver.mydomain.com
```

### Add an host alias

Replace myserver.mydomain.com by your hostname and myalias by the alias you want

_tg myserver.mydomain.com_ is a bit long to type, let's make an alias for this one

Add your host alias : 
```sh
tg -aa myhostalias myserver.mydomain.com
```

Now you can connect to your host this way :
```sh
tg myalias
```

### Add a command alias

When you are pretty soon using a specific command on a host, _tg myalias_ and then _mycommand -foo bar_ is a bit long to type, let's make an alias for this one

Add your command alias : 
```sh
tg -aca mycommandalias myhostalias -- mycommand -foo bar
```

Now you can connect run your command on the host this way :
```sh
tg mycommandalias
```

### Enable TOR proxy feature (Optional)

This is used if you want to SSH to your hosts through TOR (if you are a privacy extremist or something...).

On your bastion server, install this dependancy : 
```sh
apt-get install netcat-openbsd
```

Debian:
On your bastion server, install tor client by following this procedure : https://www.torproject.org/docs/debian.html.en
Or, use this quick-win command: 
```sh
apt-get install tor
```

Replace myserver.mydomain.com by your hostname

Now you can connect to your hosts through tor this way :
```sh
tg -tor myserver.mydomain.com
```

### Enabling two factor authentication by mail (Optional)

Replace myemail@mydomain.com by your mail adress

Enable two factor authentication by mail :
```sh
tg -se myemail@mydomain.com
```

Now, when you use tg for the first time from a new ip adress, you will need a two-factor authentication code. This code will be sent to you by mail to verify your identity. If two factor authentication with Google Authenticator is also enabled, you can enter one of the two codes.

### Enabling two factor authentication with Google Authenticator (OTP) (Optional)

Follow the instructions to enable two factor authentication with Google Authenticator :
```sh
tg -sa
```

Now, when you use tg for the first time from a new ip adress, you will need a two-factor authentication code. This code will be sent to you by mail to verify your identity. If two factor authentication by mail is also enabled, you can enter one of the two codes.


