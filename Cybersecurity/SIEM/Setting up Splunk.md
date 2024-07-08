Configuring data ingestion is an important part of Splunk. This allows for the data to be indexed and searchable for the analysts. Splunk accepts data from various log sources like Operating System logs, Web Applications, Intrusion Detection logs, Osquery logs, etc. In this task, we will use Splunk Forwarder to ingest the Linux logs into our Splunk instance.

Splunk Forwarders

Splunk has two primary types of forwarders that can be used in different use cases. They are explained below:

**Heavy Forwarders**

Heavy forwarders are used when we need to apply a filter, analyze or make changes to the logs at the source before forwarding it to the destination. In this task, we will be installing and configuring Universal forwarders.

**Universal Forwarders**

It is a lightweight agent that gets installed on the target host, and its main purpose is to get the logs and send them to the Splunk instance or another forwarder without applying any filters or indexing. It has to be downloaded separately and has to be enabled before use. In our case, we will use a universal forwarder to ingest logs.

Universal forwarders can be downloaded from the official [Splunk website](https://www.splunk.com/en_us/download/universal-forwarder.html?locale=en_us). It supports various OS, as shown below:

**Note:** As of writing this, 9.0.3 is the latest version available on the Splunk site.

![Splunk Forwarder Installation step](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/b97173a010a680ebe268fe4f884564fe.png)

For this task, the 64-bit version of Linux Forwarder is already downloaded in the folder `~/Downloads/splunk`.

splunk: Forwarder

```shell-session
ubuntu@coffely:~/Downloads/splunk# ls
splunk_installer.tgz splunkforwarder.tgz
```

Install Forwarder

Change the user to sudo, unpack, and install the forwarder with the following command.  

splunk: Forwarder

```shell-session
ubuntu@coffely:~/Downloads/splunk# sudo su
root@coffely:/home/ubuntu/Downloads/splunk# tar xvzf splunkforwarder.tgz
splunkforwarder/
splunkforwarder/swidtag/
splunkforwarder/swidtag/splunk-UniversalForwarder-primary.swidtag
splunkforwarder/ftr
splunkforwarder/openssl/
...
...
splunkforwarder/etc/deployment-apps/
splunkforwarder/etc/deployment-apps/README
splunkforwarder/etc/log-debug.cfg
```

The above command will install all required files in the folder `splunkforwarder`. Next, we will move this folder to `/opt/` path with the command `mv splunkforwarder /opt/`.

We will run the Splunk forwarder instance now and provide it with the new credentials as shown below:

SplunkInstallation

```shell-session
root@coffey:~/Downloads/splunk# mv splunkforwarder /opt/
root@coffey:~/Downloads/splunk# cd /opt/splunkforwarder
root@coffey:/opt/splunkforwarder# ./bin/splunk start --accept-license
This appears to be your first time running this version of Splunk.
...
...
Please enter an administrator username: splunkadmin
Password must contain at least:
   * 8 total printable ASCII character(s).
Please enter a new password: 
Please confirm new password: 
Creating unit file...
Failed to auto-set default user.
...
...
Checking prerequisites...
	Checking mgmt port [8089]: not available
ERROR: mgmt port [8089] - port is already bound.  Splunk needs to use this port.
Would you like to change ports? [y/n]: y
Enter a new mgmt port: 8090
Setting mgmt to port: 8090
The server's splunkd port has been changed.
	Checking mgmt port [8090]: open		
Starting splunk server daemon (splunkd)...  
Done
```

By default, Splunk forwarder runs on port 8089. If the system finds the port unavailable, it will ask the user for the custom port. In this example, we are using 8090 for the forwarder.

Splunk Forwarder is up and running but does not know what data to send and where. This is what we are going to configure next.