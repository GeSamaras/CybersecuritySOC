**Elastic stack**

Elastic stack is the collection of different open source components linked together to help users take the data from any source and in any format and perform a search, analyze and visualize the data in real-time.

![Shows Elasticstack components](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/f858c0d22d015b663438dae207981532.png)  

﻿Let's explore each component briefly and see how they work together.  

**Elasticsearch**

Elasticsearch is a full-text search and analytics engine used to store JSON-formated documents. Elasticsearch is an important component used to store, analyze, perform correlation on the data, etc. Elasticsearch supports RESTFul API to interact with the data.  

**Logstash**

Logstash is a data processing engine used to take the data from different sources, apply the filter on it or normalize it, and then send it to the destination which could be Kibana or a listening port. A logstash configuration file is divided into three parts, as shown below.

The **input** part is where the user defines the source from which the data is being ingested. Logstash supports many input plugins as shown in the reference [https://www.elastic.co/guide/en/logstash/8.1/input-plugins.html](https://www.elastic.co/guide/en/logstash/8.1/input-plugins.html)[](https://www.elastic.co/guide/en/logstash/8.1/input-plugins.html)

The **filter** part is where the user specifies the filter options to normalize the log ingested above. Logstash supports many filter plugins as shown in the reference documentation [https://www.elastic.co/guide/en/logstash/8.1/filter-plugins.html](https://www.elastic.co/guide/en/logstash/8.1/filter-plugins.html)

The Output part is where the user wants the filtered data to send. It can be a listening port, Kibana Interface, elasticsearch database, a file, etc. Logstash supports many Output plugins as shown in the reference documentation [https://www.elastic.co/guide/en/logstash/8.1/output-plugins.html](https://www.elastic.co/guide/en/logstash/8.1/output-plugins.html)

![Shows Logstash configuration file pattern](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/31e9ef413089c7b15ad64e09d3655c04.png)  

**Beats**

Beats is a host-based agent known as Data-shippers that is used to ship/transfer data from the endpoints to elasticsearch. Each beat is a single-purpose agent that sends specific data to the elasticsearch. All available beats are shown below.  

![Shows beats components](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/0f2969b20c466e7a371a49bc809a6d5b.png)

**Kibana**

Kibana is a web-based data visualization that works with elasticsearch to analyze, investigate and visualize the data stream in real-time. It allows the users to create multiple visualizations and dashboards for better visibility—more on Kibana in the following tasks.

**How they work together:**  

![ELK components](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/ec4f681a412aa825b284523dcd5b8650.png)  

- Beats is a set of different data shipping agents used to collect data from multiple agents. Like Winlogbeat is used to collect windows event logs, Packetbeat collects network traffic flows.
- Logstash collects data from beats, ports or files, etc., parses/normalizes it into field value pairs, and stores them into elasticsearch.
- Elasticsearch acts as a database used to search and analyze the data.
- Kibana is responsible for displaying and visualizing the data stored in elasticsearch. The data stored in elasticseach can easily be shaped into different visualizations, time charts, infographics, etc., using Kibana.


Kibana Discover tab is a place where analyst spends most of their time. This tab shows the ingested logs (also known as documents), the search bar, normalized fields, etc. Here analysts can perform the following tasks:

- Search for the logs
- Investigate anomalies
- Apply filter based on
    - search term
    - Time period

**Discover Tab**  

Discover tab within the Kibana interface contains the logs being ingested manually or in real-time, the time-chart, normalized fields, etc. Analysts use this tab mostly to search/investigate the logs using the search bar and filter options.

![Shows Discover tab with key functionalities numbered](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/9635453d465f7625f5dfda21966aa6a6.png)


