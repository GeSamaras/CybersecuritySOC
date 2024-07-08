Splunk Search Processing Language comprises of multiple functions, operators and commands that are used together to form a simple to complex search and get the desired results from the ingested logs. Main components of SPL are explained below:

﻿**Search Field Operators**  

Splunk field operators are the building blocks used to construct any search query. These field operators are used to filter, remove, and narrow down the search result based on the given criteria. Common field operators are Comparison operators, wildcards, and boolean operators.  

Comparison Operators

﻿These operators are used to compare the values against the fields. Some common comparisons operators are mentioned below:  

|   |   |   |   |
|---|---|---|---|
|**Field Name  <br>**|**Operator  <br>**|**Example**|**Explanation  <br>**|
|**Equal  <br>**|=|UserName=Mark|This operator is used to match values against the field. In this example, it will look for all the events, where the value of the field UserName is equal to Mark.|
|**Not Equal to  <br>**|!=|UserName!=Mark|This operator returns all the events where the UserName value does not match Mark.|
|**Less than  <br>**|<|Age < 10|Showing all the events with the value of Age less than 10.|
|**Less than or Equal to  <br>**|<=|Age <= 10|Showing all the events with the value of Age less than or equal to 10.|
|**Greater than  <br>**|>|Outbound_traffic > 50 MB|This will return all the events where the Outbound traffic value is over 50 MB.|
|**Greater Than or Equal to  <br>**|>=|Outbound_traffic >= 50 MB|This will return all the events where the Outbound traffic value is greater or equal to 50 MB.|

﻿﻿Lets use the comparison operator to display all the event logs from the index "windowslogs", where AccountName is not Equal to "System"

**Search Query:** `index=windowslogs AccountName !=SYSTEM`  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/681a126a98263612b87def7014583ffb.png)  

Boolean Operators

Splunk supports the following Boolean operators, which can be very handy in searching/filtering and narrowing down results.  

|   |   |   |
|---|---|---|
|**Operator  <br>**|**Syntax  <br>**|**Explanation  <br>**|
|**NOT  <br>**|field_A **NOT** value|Ignore the events from the result where field_A contain the specified value.|
|**OR  <br>**|field_A=value1 **OR** field_A=value2|Return all the events in which field_A contains either value1 or value2.|
|**AND  <br>**|field_A=value1 **AND** field_B=value2|Return all the events in which field_A contains value1 and field_B contains value2.|

﻿To understand how boolean operator works in SPL, lets add the condition to show the events from the James account.

**Search Query:** `index=windowslogs AccountName !=SYSTEM **AND** AccountName=James`  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/42c8963dccbd05128f52665c38877f47.png)  

  

Wild Card

Splunk supports wildcards to match the characters in the strings.  

|   |   |   |
|---|---|---|
|**Wildcard symbol**|**Example**|**Explanation**|
|***  <br>**|status=fail*|It will return all the results with values like<br><br>status=failed<br><br>status=failure|

In the events, there are multiple DestinationIPs reported. Let's use the wildcard only to show the **DestinationIP** starting from 172.*

**Search Query:** `index=windowslogs DestinationIp=172.*`  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5530cae0739755e6a682641f5057b1a5.png)