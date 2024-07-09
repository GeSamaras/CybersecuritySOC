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



Now that we have installed the forwarder, it needs to know where to send the data. So we will configure it on the host end to send the data and configure Splunk so that it knows from where it is receiving the data.  
Splunk Configuration  
Log into Splunk and Go to Settings -> Forward and receiving tab as shown below:

![Splunk Forwarder Configuration steps](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5be56ab5768301a6f8b9eaaa91ffd581.png)

It will show multiple options to configure both forwarding and receiving. As we want to receive data from the Linux endpoint, we will click on **Configure receiving** and then proceed by configuring a new receiving port.  

![Splunk Forwarder Configuration steps](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/64c55412514e56c05b91b8f9c4ba6060.png)  

By default, the Splunk instance receives data from the forwarder on the port `9997`. It's up to us to use this port or change it. For now, we will configure our Splunk to start **listening on port 9997** and **Save**, as shown below:

![Splunk Forwarder Configuration steps](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/9a3f504672c0c499da3b5ab348b55a1f.png)  

Our listening port 9997 is now enabled and waiting for the data. If we want, we can delete this entry by clicking on the `Delete` option under the `Actions` column.  

![Splunk Forwarder Configuration steps](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/2c3f58c3f084cef145523820ac3c35f9.png)  

Creating Index  
Now that we have enabled a listening port, the important next step is to create an index that will store all the receiving data. If we do not specify an index, it will start storing received data in the default index, which is called the `main` index.  

![Steps to create an Index](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/525a1c69e54f9c53586dce9ab7e4f737.png)  

The indexes tab contains all the indexes created by the user or by default. This shows some important metadata about the indexes like Size, Event Count, Home Path, Status, etc.  

![Steps to create an Index](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/452a24902c85e7793953d7e72534502b.png)  

Click the **New Index** button, fill out the form, and click **Save** to create the index. Here we have created an index called `Linux_host` as shown below:

![Steps to create Index](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/b69a6dcf0bc5538e1ca56bf58763779c.png)

Configuring Forwarder  
It's time to configure the forwarder to ensure it sends the data to the right destination. Back in the Linux host terminal, go to the `/opt/splunkforwarder/bin` directory:

Splunk: Forwarder

```shell-session
root@coffely:/opt/splunkforwarder/bin# ./splunk add forward-server MACHINE_IP:9997
WARNING: Server Certificate Hostname Validation is disabled. Please see server.conf/[sslConfig]/cliVerifyServerName for details.
Splunk username: splunkadmin
Password:
Added forwarding to: MACHINE_IP:9997.
```

This command will add the forwarder server, which listens to port 9997.  
Linux Log Sources  
Linux stores all its important logs into the `/var/log` file, as shown below. In our case, we will ingest syslog into Splunk. All other logs can be ingested using the same method.  

![Shows log files in /var/log directory](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/c9b649f6b18509635485702fc601f06f.png)  

Next, we will tell Splunk forwarder which logs files to monitor. Here, we tell Splunk Forwarder to monitor the `/var/log/syslog` file.  

Ingest syslog file

```shell-session
root@coffely:/opt/splunkforwarder/bin# ./splunk add monitor /var/log/syslog -index Linux_host
WARNING: Server Certificate Hostname Validation is disabled. Please see server.conf/[sslConfig]/cliVerifyServerName for details.
Added monitor of '/var/log/syslog'.
```

Exploring Inputs.conf  
We can also open the **inputs.conf** file located in `/opt/splunkforwarder/etc/apps/search/local`, and look at the configuration added after the commands we used above.  

Inputs.conf

```shell-session
root@coffely:/opt/splunkforwarder/etc/apps/search/local# ls
inputs.conf
```

We can view the content of the `input.conf` using the cat command.

Inputs.conf

```shell-session
root@coffely:/opt/splunkforwarder/etc/apps/search/local# cat inputs.conf
[monitor:///var/log/syslog]
disabled = false
index = Linux_host
```

Utilizing Logger Utility

Logger is a built-in command line tool to create test logs added to the syslog file. As we are already monitoring the syslog file and sending all logs to the Splunk, the log we generate in the next step can be found with Splunk logs. To run the command, use the following command.  

  

Logger: syslog

```shell-session
tryhackme@coffely:/opt/splunkforwarder/bin# logger "coffely-has-the-best-coffee-in-town"
```

Logger: syslog

```shell-session
tryhackme@coffely:/tryhackme@coffleylab:/opt/splunkforwarder/bin# tail -1 /var/log/syslog
```

![Shows Splunk Search](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/bc95b067dfb4addc351782d7dfe4cbdd.png)  

Great, We have successfully installed and configured Splunk Forwarder to get the logs fom the syslog file into Splunk.
