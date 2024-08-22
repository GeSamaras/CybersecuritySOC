# Data Processing
Splunk is a powerful data analytics platform used for searching, monitoring, and analyzing large amounts of machine-generated data. Data parsing in Splunk involves extracting relevant fields and transforming the data into a structured format for efficient analysis. Here’s a step-by-step guide on how data is parsed in Splunk, including the use of `props.conf`:

Step 1: Understand the Data Format

First, you need to understand the data format you want to parse. Splunk supports various data formats, such as CSV, JSON, XML, syslog, and more. Determine the format of your data source and the relevant fields you want to extract.

Step 2: Identify the Sourcetype  

In Splunk, the sourcetype represents the format of the data being indexed. It helps Splunk apply the appropriate parsing rules. If your data source does not have a pre-defined sourcetype, you can create a custom one in Splunk.

Step 3: Configure `props.conf`  

The `props.conf` file defines data parsing settings for specific sourcetypes or data sources. It resides in the `$SPLUNK_HOME/etc/system/local` directory. Here’s an example of how you can configure `props.conf`:

```c
[source::/path/to/your/data] 
sourcetype = your_sourcetype
```

In this example, `/path/to/your/data` is the path to your data source, and `your_sourcetype` is the name of the sourcetype you want to assign to that data.

Step 4: Define Field Extractions  

You can define regular expressions or use pre-built extraction techniques to parse fields from the data. Here’s an example of defining field extractions in `props.conf`:

```c
[your_sourcetype] 
EXTRACT-fieldname1 = regular_expression1 
EXTRACT-fieldname2 = regular_expression2
```

Replace `your_sourcetype` with the actual sourcetype name you defined. `fieldname1` and `fieldname2` represent the names of the fields you want to extract, while `regular_expression1` and `regular_expression2` are the regular expressions used to match and extract the desired values.

Step 5: Save and Restart Splunk  

After making changes to `props.conf`, save the file, and restart Splunk to apply the new configurations. You can do this using the Splunk web interface or by using the command line.

Step 6: Verify and Search the Data  
  
Once Splunk restarts, you can search and verify that the data is being parsed correctly. You can use the extracted fields to filter and analyze the data effectively.

In the next task, we will explore important configuration files.

# Exploring Config Files

Splunk uses several [configuration files](https://docs.splunk.com/Documentation/Splunk/9.1.1/Admin/Listofconfigurationfiles) to control various data processing and indexing aspects. Let’s explore some of the key configuration files in Splunk, along with examples of their usage:

`inputs.conf`:

- **Purpose:** Defines data inputs and how to collect data from different sources.
- **Example:** Suppose you want to monitor a specific log file. You can configure `inputs.conf` as follows:

```c
[monitor:///path/to/logfile.log]
sourcetype = my_sourcetype
```

`props.conf`:

- **Purpose:** Specifies parsing rules for different sourcetypes to extract fields and define field extractions.  
    
- **Example:** Suppose you have a custom sourcetype named `my_sourcetype` and want to extract fields using regular expressions. You can define them in `props.conf`:
    

```c
[my_sourcetype] EXTRACT-field1 = regular_expression1 
EXTRACT-field2 = regular_expression2
```

`transforms.conf`

- **Purpose:** Allows you to define field transformations and enrichments on indexed events.  
    
- **Example:** Suppose you want to add a new event field based on existing field values. You can use `transforms.conf`:

```c
[add_new_field] REGEX = existing_field=(.*) FORMAT = new_field::$1
```

`indexes.conf`

- **Purpose:** Manages the configuration of indexes in Splunk, including storage, retention policies, and access control.  
    
- **Example:** Suppose you want to create a new index named `my_index` with specific settings. You can configure `indexes.conf`:
    

```c
[my_index] homePath = $SPLUNK_DB/my_index/db 
coldPath = $SPLUNK_DB/my_index/colddb 
thawedPath = $SPLUNK_DB/my_index/thaweddb 
maxTotalDataSizeMB = 100000
```

`outputs.conf`

- **Purpose:** Specifies the destination and settings for sending indexed data to various outputs, such as remote Splunk instances or third-party systems.
- **Example:** Suppose you want to forward your indexed data to a remote Splunk indexer. You can configure `outputs.conf`:
    

```c
[tcpout] defaultGroup = my_indexers 
[tcpout:my_indexers] 
server = remote_indexer:9997
```

`authentication.conf`

- **Purpose:** Manages authentication settings and user authentication methods.
- **Example:** Suppose you want to enable LDAP authentication for Splunk users. You can configure `authentication.conf`:

```c
[authentication] 
authSettings = LDAP 
[authenticationLDAP] 
SSLEnabled = true
```

These are just a few examples of the various configuration files used in Splunk. Each file serves a specific purpose and allows you to customize Splunk’s behavior based on your data sources, parsing requirements, indexing settings, output destinations, and more.

# ﻿STANZAS in Splunk Configurations

Splunk configurations contain various stanza configurations that define how data is processed and indexed. These stanzas have a certain purpose, and it's important to understand what these are and how they are used. A brief summary of the common stanzas are explained below:

|Stanza|Explanation|Example|
|---|---|---|
|`[sourcetype]`|Specifies the configuration for a specific sourcetype. It allows you to define how the data from that sourcetype should be parsed and indexed.|`[apache:access]` - Configures parsing and indexing settings for Apache access logs.|
|`TRANSFORMS`|Applies field transformations to extracted events. You can reference custom or pre-defined field transformation configurations to modify or create new fields based on the extracted data.|`TRANSFORMS-mytransform = myfield1, myfield2` - Applies the transformation named “mytransform” to fields `myfield1` and `myfield2`.|
|`REPORT`|Defines extraction rules for specific fields using regular expressions. It associates a field name with a regular expression pattern to extract desired values. This stanza helps in parsing and extracting structured fields from unstructured or semi-structured data.|`REPORT-field1 = pattern1` - Extracts `field1` using `pattern1` regular expression.|
|`EXTRACT`|Defines extraction rules for fields using regular expressions and assigns them specific names. It is similar to the `REPORT` stanza, but it allows more flexibility in defining custom field extractions.|`EXTRACT-field1 = (?<fieldname>pattern1)` - Extracts `field1` using `pattern1` regular expression and assigns it to `fieldname`.|
|`TIME_PREFIX`|Specifies the prefix before the timestamp value in events. This stanza is used to identify the position of the timestamp within the event.|`TIME_PREFIX = \[timestamp\]` - Identifies the prefix `[timestamp]` before the actual timestamp in events.|
|`TIME_FORMAT`|Defines the format of the timestamp present in the events. It allows Splunk to correctly extract and parse timestamps based on the specified format.|`TIME_FORMAT = %Y-%m-%d %H:%M:%S` - Specifies the timestamp format as `YYYY-MM-DD HH:MM:SS`.|
|`LINE_BREAKER`|Specifies a regular expression pattern that identifies line breaks within events. This stanza is used to split events into multiple lines for proper parsing and indexing.|`LINE_BREAKER = ([\r\n]+)` - Identifies line breaks using the regular expression `[\r\n]+`.|
|`SHOULD_LINEMERGE`|Determines whether lines should be merged into a single event or treated as separate events. It controls the behavior of line merging based on the specified regular expression pattern in the `LINE_BREAKER` stanza.|`SHOULD_LINEMERGE = false` - Disables line merging, treating each line as a separate event.|
|`BREAK_ONLY_BEFORE`|Defines a regular expression pattern that marks the beginning of an event. This stanza is used to identify specific patterns in the data that indicate the start of a new event.|`BREAK_ONLY_BEFORE = ^\d{4}-\d{2}-\d{2}` - Identifies the start of a new event if it begins with a date in the format `YYYY-MM-DD`.|
|`BREAK_ONLY_AFTER`|Specifies a regular expression pattern that marks the end of an event. It is used to identify patterns in the data that indicate the completion of an event.|`BREAK_ONLY_AFTER = \[END\]` - Marks the end of an event if it contains the pattern `[END]`.|
|`KV_MODE`|Specifies the key-value mode used for extracting field-value pairs from events. The available modes are: `auto`, `none`, `simple`, `multi`, and `json`. This stanza determines how fields are extracted from the events based on the key-value pairs present in the data. It helps in parsing structured data where fields are represented in a key-value format.|`KV_MODE = json` - Enables JSON key-value mode for parsing events with JSON formatted fields.|

These examples demonstrate the usage of each stanza in `props.conf` and provide a better understanding of how they can be applied to configure data parsing behavior in Splunk.

In the next task, we will use some of these stanzas explained above to better understand.

# Simple Splunk App
We have explored the importance and usage of various configuration files and the purpose-based stanzas within those configuration files. We will be using them extensively in the coming tasks. For now, let’s create a simple Splunk app using the following steps and generate our first sample event using inputs.conf file.

#### Start Splunk

Splunk is installed in the `/opt/splunk` directory. Go to this directory and run the following command `bin/splunk start` to start the Splunk instance with root privileges. Use the following credentials to log in to the Splunk Interface:

**Username:** `splunk`

**Password:** `splunk123`  

Once it is done, open `MACHINE_IP:8000` in the browser.

About Splunk Apps  
Splunk apps are pre-packaged software modules or extensions that enhance the functionality of the Splunk platform. The purpose of Splunk apps is to provide specific sets of features, visualizations, and configurations tailored to meet the needs of various use cases and industries.  

#### Create a simple App

Once the Splunk Instance is loaded, click on the Manage App tab as highlighted below:

![Manage App tab](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/f1a700a5eb1e4121010a6858eb7e4485.png)  

It will take us to the page that contains all the available apps in Splunk. To create a new app, Click on the `Create App` tab as shown below:

![Shows list of apps installed or available](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/0e77b3c3ac476a9aec075d729d8a1823.png)  

Next, fill in the details about the new app that we want to create. The new app will be placed in the `/opt/splunk/etc/apps` directory as highlighted below:

![Shows steps to create an app](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/d84da00ef3445e5c1297b6f6c68c06aa.png)  

Great. A new Splunk app has been created successfully and it can be shown on the Apps page. Click on the `Launch App` to see if there is any activity logged yet.

![Shows App successfully installed](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/7c198667d09c8ab0b4fe69c82d12814c.png)  

As it is evident, no activity has been logged yet. Follow the next steps to generate sample logs.

![Shows Search Head with empty results](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/b41bfc9c4d215b588ea88d1cb71ab18a.png)  

Understand the App directory

Go to the app directory `/opt/splunk/etc/apps` , where we can locate our newly created app `DataApp`, as shown below:

App Directory

```shell-session
root@tryhackme:/opt/splunk/etc/apps# ls 
DataApp                        splunk-dashboard-studio
SplunkForwarder                splunk_archiver
SplunkLightForwarder           splunk_assist
alert_logevent                 splunk_essentials_9_0
alert_webhook                  splunk_gdi
appsbrowser                    splunk_httpinput
introspection_generator_addon  splunk_instrumentation
journald_input                 splunk_internal_metrics
launcher                       splunk_metrics_workspace
learned                        splunk_monitoring_console
legacy                         splunk_rapid_diag
python_upgrade_readiness_app   splunk_secure_gateway
sample_app                     user-prefs
search
```

Content within the App directory

App Directory

```shell-session
root@tryhackme:/opt/splunk/etc/apps# ls  DataApp
bin  default  local  metadata
```

## Splunk App directory

Some of the key directories and files that are present in the app directory are explained briefly below:

|File/Directory|Description|
|---|---|
|`app.conf`|Metadata file defining the app’s name, version, and more.|
|`bin` (directory)|Holds custom scripts or binaries required by the app.|
|`default` (directory)|Contains XML files defining app dashboards and views.|
|`local` (directory)|Optionally used for overriding default UI configurations.|

### Create a Python script to generate sample logs

As we learned that the `**bin**` directory contains the scripts required by the app, let's go to the `bin` directory and create a simple Python script using the command `nano samplelogs.py`, copy the following line in the file, and save.

```c
print("This is a sample log...")
```

Let’s use python3 to run the file as shown below and see what output we get:

python script

```shell-session
root@tryhackme:/opt/splunk/etc/apps/DataApp/bin# python3 samplelogs.py 
This is a sample log...
```

It seems, the script is ready. Note down the full path of the script file, that is `/opt/splunk/etc/apps/DataApp/bin/samplelogs.py`, which we will need later.

## Creating Inputs.conf

In the default directory, we will create all necessary configuration files like inputs.conf, transform.conf, etc. For now, let’s create an inputs.conf using the command `nano inputs.conf` add the following content into the file and save.

```c
[script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]
index = main
source = test_log
sourcetype = testing
interval = 5
```

The above configuration picks the output from the script samplelogs.py and sends it to Splunk with the index `main` every 5 seconds.

Restart Splunk using the command `/opt/splunk/bin/splunk restart`.

![Shows Splunk Search with logs ingested at run-time](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/d8bef4883bc3cbd5d984af35a7fac2fe.gif)  

Summary

So far, we have created a simple Splunk app, used the bin directory to create a simple Python script, and then created inputs.conf file to pick the output of the script and throw the output into Splunk in the `main` index every 5 seconds. In the coming tasks, we will work on the scripts that will generate some events that will have visible parsing issues and then we will work with different configuration files to fix those parsing issues.

# Event Boundaries
Event breaking in Splunk refers to breaking raw data into individual events based on specified boundaries. Splunk uses event-breaking rules to identify where one event ends, and the next begins. Let’s walk through an example using a sample log to understand how event breaking works in Splunk.  
Understanding the Events  
In this room, we will be working on the DataApp created in the previous task and is placed at `/opt/splunk/etc/apps/DataApp/`.

For this task, we will use the Python script `vpnlogs` from the `~/Downloads/scripts` directory, as shown below:

![Shows scripts in the /Downloads/script directory](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/cff22b44aeec7afdc514ba75c54d2ca0.png)  

This directory contains various scripts, which we will explore later in this room. For now, let’s focus on the vpnlogs script.

Let’s say our client has a custom VPN application that generates VPN logs that contain information about the user, the VPN server, and the action performed on the connection, as shown in the output below when we run the command `./vpnlogs`:

![Shows output of the vpnlogs script](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/2001736efc0579891f54074c86183f61.png)  

Generating Events

Our first task is to configure Splunk to ingest these VPN logs. Copy the vpnlogs script into the `bin` directory, open the `inputs.conf` , and write these lines:

```c
[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
index = main
source = vpn
sourcetype = vpn_logs
interval = 5
```

The above lines tell Splunk to run the script `vpnlogs` every 5 seconds and send the output to the `main` index with sourcetype `vpn_logs` and host value as `vpn_server`. The `inputs.conf` file looks like this:

![Shows inputs.conf configuration](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/00e16bbc970998b7872894014c86ae2a.png)  

##### Restart Splunk

Save the file and restart Splunk using the command `/opt/splunk/bin/splunk restart`. Open the Splunk instance at `MACHINE_IP:8000` and navigate to the search head.

##### Search Head

Select the time range  `All time (Real-time)` and use the following search query to see if we are getting the logs.**  
Search Query:** `index=main sourcetype=vpn_logs`

![Shows search head result showing VPN logs in real-time](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/c97efef3e9b75d0d388463d24f550dec.png)  

Identifying the problem  
Excellent, we are getting the VPN logs after every 5 seconds. But can you observe the problem? It's evident that Splunk cannot determine the boundaries of each event and considers multiple events as a single event. By default, Splunk breaks the event after carriage return.

#### Fixing the Event Boundary

We need to fix the event boundary. To configure Splunk to break the events in this case, we have to make some changes to the `props.conf` file. First, we will create a regex to determine the end of the event. The sample events are shown below:

**Sample Events**

```c
User: Emily Davis, Server: Server C, Action: DISCONNECT
User: John Doe, Server: Server B, Action: DISCONNECT
User: Bob Johnson, Server: Server B, Action: DISCONNECT
User: Emily Davis, Server: Server D, Action: CONNECT
User: Alice Smith, Server: Server D, Action: CONNECT
User: Alice Smith, Server: Server A, Action: DISCONNECT
User: Bob Johnson, Server: Server C, Action: DISCONNECT
User: John Doe, Server: Server D, Action: DISCONNECT
User: John Doe, Server: Server B, Action: DISCONNECT
User: Michael Brown, Server: Server E, Action: CONNECT
```

We will use [reg101.com](https://tryhackme.com/r/room/reg101.com) to create a regex pattern. If we look closely, all events end with the terms `DISCONNECT` or `CONNECT`. We can use this information to create a regex pattern `(DISCONNECT|CONNECT)` , as shown below:

![Shows regex pattern matching for VPN logs](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/45cd1d767436fc2f6287feaa4629df7f.png)

Now, let’s create a `props.conf` in the default directory within the DataApp and add the following lines:

```c
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)
```

This configuration tells Splunk to take the sourcetype to merge all lines and it **must break** the events when you see the pattern matched in the mentioned regex.

##### Restart Splunk

Save the file and restart Splunk using the command `/opt/bin/splunk restart`. Open the Splunk instance at `MACHINE_IP:8000` and navigate to the search head.

![Shows Splunk Search with Event Boundary issue fixed](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/dc6f01dab0ea4576b2bc4e4ad467d489.gif)  

That’s it. We can see that with a few changes in the `props.conf` file, we changed how Splunk broke these VPN logs generated by the custom vpn_server.

In the next task, we will look at a different case study.

# Parsing Multi-Line Events
As we know, different log sources have their own ways of generating logs. What if, a log source generates event logs that comprise of multi-lines? One such example is Windows Event logs. In order to understand how multi-line events can be handled in Splunk, we will use the event logs generated from the script `authentication_logs`. The sample event log is shown below:

```c
[Authentication]:A login attempt was observed from the user Michael Brown and machine MAC_01
at: Mon Jul 17 08:10:12 2023 which belongs to the Custom department. The login attempt looks suspicious.
```

As it is clearly shown, the event contains multiple lines. Let’s update the `inputs.conf` file to include this script and see if Splunk is able to break the event as intended.

Copy the `authentication_logs` script from the `~/Downloads/scripts` directory into the bin folder of the DataApp and add the following lines in inputs.conf, save the file, and restart Splunk:

```c
[script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]
interval = 5
index = main
sourcetype= auth_logs
host = auth_server
```

#### Search Head

Let’s look at the Splunk Search head to see how these logs are reflected.  

**Search Query**: `index=main sourcetype = auth_logs`

![Shows authentication logs in Splunk Search head](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/b7636850f4a54323e16f28f8bc386c0b.png)  

Identifying the problem

If we observe the events, we will see that Splunk is breaking the 2-line Event into 2 different events and is unable to determine the boundaries.

#### Fixing the Event Boundary

In order to fix this issue, we can use different `stanzas` in the `props.conf` file. If we run the script a few times to observe the output, we can see that each event starts with the term `[Authentication]`, indicating the start of the event. We can use this as the regex pattern with the stanza `BREAK_ONLY_BEFORE` and see if it could fix this problem. Copy the following lines in `props.conf` file, save the file, and then restart Splunk to apply changes.

```c
[auth_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Authentication\]
```

#### Search head

Go to Splunk Search head, and use the following search query.

**Search Query**: `index=main sourcetype = auth_logs`

![Shows Splunk Search with parsing issue fixed](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/6c37c54e87e0462c2d5fcd623d8ca762.gif)  

Great. See, now Splunk is able to break the event exactly how it was intended.

# Masking Sensitive Data
Masking sensitive fields, such as credit card numbers, is essential for maintaining compliance with standards like PCI DSS (Payment Card Industry Data Security Standard) and HIPAA (Health Insurance Portability and Accountability Act). Splunk provides features like field masking and anonymization to protect sensitive data. Here’s an example of credit card numbers being populated in the Event logs generated by the script `purchase-details` present in the `~/Downloads/scripts` directory.

Sample Output

```c
User William made a purchase with credit card 3714-4963-5398-4313.
User John Boy made a purchase with credit card 3530-1113-3330-0000.
User Alice Johnson made a purchase with credit card 6011-1234-5678-9012.
User David made a purchase with credit card 3530-1113-3330-0000.
User Bob Williams made a purchase with credit card 9876-5432-1098-7654.
```

Copy this script file into the bin folder of the DataApp and configure the inputs.conf file to ingest these logs into Splunk. To do so, add the following lines in the `inputs.conf` file.

```c
[script:///opt/splunk/etc/apps/DataApp/bin/purchase-details]
interval = 5
index = main
source = purchase_logs
sourcetype= purchase_logs
host = order_server
```

This configuration tells Splunk to get the output from the `purchase-details` script, and index into the `main` index every 5 seconds, with sourcetype  `purchase_logs` and host as `order_server`. Now, save the file and restart Splunk. Log on to Splunk and apply the following search query: **Search Query**: `index=main sourcetype=purchase_logs`

![Shows purchase logs in Splunk Search head](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/202289ab0e3fed8fd192daac9b78b0b6.png)

It looks like we have two problems to address. We need to hide the credit card information that is being added to each event and also need to fix the event boundaries.

## Fixing Event Boundaries

We will use `regex101.com` to create a regex pattern to identify the end boundary of each event, as shown below:

![Shows regex pattern matching result](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/3511419fee664679d298f20af2c52251.png)

Let’s update the `props.conf`, as shown below:

![Shows content of props.conf file](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/4e5cd0b1370529864ae5c204b175931d.png)

Save the file, and restart Splunk. If everything goes well, the event should be propagating correctly, as shown below:

![Shows purchase logs in real-time](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/20eb8179773eb23a52a255a34c633133.png)

Now that we have fixed the event boundary issue. It’s time to mask the sensitive information from the events.

Introducing SEDCMD

In Splunk, the `sedcmd` configuration setting is used in the `props.conf` file to modify or transform data during indexing. It allows us to apply regular expression-based substitutions on the incoming data before indexing it. The `sedcmd` setting uses the syntax and functionality of the Unix `sed` command.

Here’s a brief explanation of how the `sedcmd` works in `props.conf`:

1. Open the `props.conf` file in your Splunk configuration directory.
2. Locate or create a stanza for the data source you want to modify.
3. Add the `sedcmd` setting under the stanza.
4. Specify the regular expression pattern and the replacement string using the `s/` syntax similar to the `sed` command.

Here’s an example of using `sedcmd` in `props.conf` to modify a field called `myField`:

```c
[source::/path/to/your/data]
SEDCMD-myField = s/oldValue/newValue/g
```

In this example, the `sedcmd` setting is applied to the data from a specific source path. It uses the regular expression pattern `oldValue` and replaces it globally with newValue using the g flag in the `myField` field. This transformation occurs before Splunk indexes the data.

It is important to note that, this `sedcmd` is just one of the configuration settings `props.conf` used for data transformation. There are other options available, such as `REGEX`, `TRANSFORMS`, etc.

Masking CC Information

Let’s now use the above knowledge gain to create a regex that replaces the credit card number with something like this -> `6011-XXXX-XXXX-XXXX.`, as shown below:

![Shows Regex pattern matching results](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/15c3a8ab96262801209a54fc9fb3cad8.png)

Now, our task is to use this `s/OLD_VALUE>/<NEW_VALUE>/g` regex in sedcmd to replace the credit card numbers with `XXXX-XXXX-XXXX`. The final sedcmd value will become `s/-\d{4}-\d{4}-\d{4}/-XXXX-XXXX-XXXX/g`

Our configuration in the `props.conf` would look like this:

![Shows updated content of props.conf](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/9ab9690ecd51fd9d6f8e27c755068da3.png)

Restart Splunk and check Splunk Instance to see how our changes are reflected in the logs.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/f242295b6339d120bd6d5c9d6020557a.gif)

Great. With some changes in the configurations, we were able to mask the sensitive information. As a SOC analyst, it is important to understand the criticality of masking sensitive information before being logged in order to comply with standards like HIPAA, PCI-DSS, etc.

# Extracting Custom Fields

From a SOC analyst’s point of view, we would often encounter logs either custom log sources, where not all fields are extracted by the SIEM automatically, or we are required to extract custom fields to improve the analysis. In that case, we need a way to extract custom fields from the logs. To demonstrate this with an example, let’s go back to our vpn_logs case. The output we are getting in Splunk is, as shown below:

![Shows VPN logs in real-time](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/6008fdcbe188a4daf5e2fe5a86792a42.png)  

It's clear that none of the fields are extracted automatically, and we can not perform any analysis on these events until fields like **username**, **server**, and **action** are extracted.

## Extracting Username

Let’s first go through the process of extracting the usernames and putting them under the field as **Username**, and then we can follow the same steps to extract other fields as well.

## Creating Regex Pattern

Our first task would be to create a regex pattern to capture the username values we are trying to capture. Sample event logs look like this:

```c
User: John Doe, Server: Server C, Action: CONNECT
User: John Doe, Server: Server A, Action: DISCONNECT
User: Emily Davis, Server: Server E, Action: CONNECT
User: Emily Davis, Server: Server D, Action: DISCONNECT
User: Michael Brown, Server: Server A, Action: CONNECT
User: Alice Smith, Server: Server C, Action: CONNECT
User: Emily Davis, Server: Server C, Action: DISCONNECT
User: John Doe, Server: Server C, Action: CONNECT
User: Michael Brown, Server: Server A, Action: DISCONNECT
User: John Doe, Server: Server D, Action: DISCONNECT
```

By creating a regex pattern as: `User:\s([\w\s]+)` and creating a capturing group, we have successfully captured all the usernames that we want to extract.

![Shows regex pattern matching for username](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/651c0ef3e751e5224cf954b3baca2309.png)  

Creating and Updating `transforms.conf`  

Now, let’s create a `transforms.conf` in the default folder of the DataApp directory, and put the following configurations in it as it is.

```c
[vpn_custom_fields]
REGEX = User:\s([\w\s]+)
FORMAT = Username::$1
WRITE_META = true
```

The `transforms.conf` would look like this:

![Shows content of transforms.conf file](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/6e2802825fdbb9f2fb9945889f210a6e.png)  

**Explanation:** We have created a custom identifier `vpn_custom_fields`, used the regex pattern to pull the usernames from the logs, mentioned the field name as Username, and asked to capture the first group by referring to it as `$1`. Save the configuration and move to the next step.

Updating `props.conf`

We need to update the props.conf to mention the recent updates we did in transforms.conf. Here, we are appending the configuration for sourcetype **vpn_logs** with the line `TRANSFORM-vpn = vpn_custom_fields`, as shown below:

![Shows content of props.conf file](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5f1426cfe1335078ce43430856edeefc.png)  

Creating and Updating `fields.conf`

The next step would be to create fields.conf and mention the field we are going to extract from the logs, which is `Username`. `INDEXED = true` means we are telling Splunk to extract this field at the indexed time.

```c
[Username]
INDEXED = true
```

Fields.conf file would look like this:

![Shows content of fields.conf file](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/31a583a37218d90b754beaa9fb8a5323.png)  

### Restart Splunk

That’s all we need in order to extract the custom fields. Now, restart the Splunk instance so that the changes we have made are committed. Go to the Splunk instance and use the search query `index=main sourcetype=vpn_logs`

![Shows results in Splunk with one custom field extracted](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/2f3cb792e75ebd502e65f96bd0111c8f.gif)  

This is it. With some changes to the configuration files, we were able to extract a custom field from the logs.

Let's use the same process and extract the remaining two fields as well.

Creating Regex Pattern

This regex pattern `User:\s([\w\s]+),.+(Server.+),.+:\s(\w+)` captures all the three fields and places them into the groups, as shown below:

![Shows Regex pattern matching in reg101.com](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/d28ffd1ff8b2797de3e27aa5f7e7d42d.png)  

Updating transforms.conf

Now that we have captured the fields that we want to extract, let's update the transforms.conf file, as shown below:

![Shows the updated content of transforms.conf](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/9c46fec97fef30117181e93ed589c382.png)  

In the configuration file, we have updated the **REGEX** pattern and the **FORMAT**, where we have specified different fields separating with a space.

Updating fields.conf

Now it's time to update the fields.conf with the field names that we want Splunk to extract at index time.  

![Shows the content of fields.conf](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5c52c5de7bb5b60eccfc27a995eaa8b6.png)  

Restart Splunk

As we have updated the configuration, we will need to restart Splunk for the changes to work. After restarting, go to the Splunk instance and use the search query `index=main sourcetype=vpn_logs`  to check the impact of the changes we made earlier.  

![Shows results in Splunk with all custom fields extracted](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/73d0639bb0a0c82c2debac1a86d10c86.gif)

