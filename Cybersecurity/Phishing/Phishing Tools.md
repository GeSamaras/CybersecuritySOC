Now it's time to direct your focus to the email body. This is where the malicious payload may be delivered to the recipient either as a link or an attachment. 

Links can be extracted manually, either directly from an HTML formatted email or by sifting through the raw email header.

Below is an example of obtaining a link manually from an email by right-clicking the link and choosing **Copy Link Location**. 

![](https://assets.tryhackme.com/additional/phishing2/copy-link.png)  

The same can be accomplished with the assistance of a tool. One tool that can aid us with this task is URL Extractor. 

- URL Extractor: [https://www.convertcsv.com/url-extractor.htm](https://www.convertcsv.com/url-extractor.htm)[](https://www.convertcsv.com/url-extractor.htm)

You can copy and paste the raw header into the text box for **Step 1: Select your input**. 

![](https://assets.tryhackme.com/additional/phishing2/url-extractor.png)  

The extracted URLs are visible in **Step 3**. 

![](https://assets.tryhackme.com/additional/phishing2/url-extractor-2.png)  

You may also use [CyberChef](https://gchq.github.io/CyberChef/) to extract URLs with the Extract URLs recipe.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/a31606afb772b8f87eebf0ff59f00fce.png)  

Tip: It's important to note the root domain for the extracted URLs. You will need to perform an analysis on the root domain as well.   

After extracting the URLs, the next step is to check the reputation of the URLs and root domain. You can use any of the tools mentioned in the previous task to aid you with this. 

If the email has an attachment, you'll need to obtain the attachment safely. Accomplishing this is easy in Thunderbird by using the Save button.

![](https://assets.tryhackme.com/additional/phishing2/save-attachment.png)  

After you have obtained the attachment, you can then get its hash. You can check the file's reputation with the hash to see if it's a known malicious document.

Obtain the file's SHA256 hash

```shell-session
user@machine$ sha256sum Double\ Jackpot\ Slots\ Las\ Vegas.dot
c650f397a9193db6a2e1a273577d8d84c5668d03c06ba99b17e4f6617af4ee83  Double Jackpot Slots Las Vegas.dot
```

There are many tools available to help us with this, but we'll focus on two primarily; they are listed below:

- Talos File Reputation: [https://talosintelligence.com/talos_file_reputation](https://talosintelligence.com/talos_file_reputation)[](https://talosintelligence.com/talos_file_reputation)

Per the [site](https://talosintelligence.com/talos_file_reputation), "_The Cisco Talos Intelligence Group maintains a reputation disposition on billions of files. This reputation system is fed into the AMP, FirePower, ClamAV, and Open-Source Snort product lines. The tool below allows you to do casual lookups against the Talos File Reputation system. This system limits you to one lookup at a time, and is limited to only hash matching. This lookup does not reflect the full capabilities of the Advanced Malware Protection (AMP) system_".

![](https://assets.tryhackme.com/additional/phishing2/talos-file-rep.png)

![](https://assets.tryhackme.com/additional/phishing2/talos-file-rep-2.png)  

- VirusTotal: [https://www.virustotal.com/gui/](https://www.virustotal.com/gui/)

Per the [site](https://www.virustotal.com/gui/), "Analyze suspicious files and URLs to detect types of malware, automatically share them with the security community."

![](https://assets.tryhackme.com/additional/phishing2/virustotal.png)  

![](https://assets.tryhackme.com/additional/phishing2/virustotal-2.png)  

Another tool/company worth mentioning is [Reversing Labs](https://www.reversinglabs.com/), which also has a [file reputation service](https://register.reversinglabs.com/file_reputation).


Luckily as Defenders, we don't need to have malware analysis skills to dissect and reverse engineer a malicious attachment to understand the malware better. 

There are online tools and services where malicious files can be uploaded and analyzed to better understand what the malware was programmed to do. These services are known as malware sandboxes. 

For instance, we can upload an attachment we obtained from a potentially malicious email and see what URLs it attempts to communicate with, what additional payloads are downloaded to the endpoint, persistence mechanisms, Indicators of Compromise (IOCs), etc. 

Some of these online malware sandboxes are listed below.

- Any.Run: [https://app.any.run/](https://app.any.run/)

Per the [site](https://app.any.run/), "_Analyze a network, file, module, and the registry activity. Interact with the OS directly from a browser. See the feedback from your actions immediately_".

![](https://assets.tryhackme.com/additional/phishing2/any-run.png)  

- Hybrid Analysis: [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/)

Per the site, _"This is a free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology_."

![](https://assets.tryhackme.com/additional/phishing2/hybrid-analysis.png)  

- [https://www.joesecurity.org/](https://www.joesecurity.org/)[](https://www.joesecurity.org/)

Per the site, "_Joe Sandbox empowers analysts with a large spectrum of product features. Among them: Live Interaction, URL Analysis & AI based Phishing Detection, Yara and Sigma rules support, MITRE ATT&CK matrix, AI based malware detection, Mail Monitor, Threat Hunting & Intelligence, Automated User Behavior, Dynamic VBA/JS/JAR instrumentation, Execution Graphs, Localized Internet Anonymization and many more_".

![](https://assets.tryhackme.com/additional/phishing2/joe-security.png)

We will interact with these services in the upcoming Phishing cases.


## Phishtool

_PhishTool combines threat intelligence, OSINT, email metadata and battle tested auto-analysis pathways into one powerful phishing response platform. Making you and your organisation a formidable adversary - immune to phishing campaigns that those with lesser email security capabilities fall victim to._"

Note: There is a free community edition you can download and use. :)

I uploaded a malicious email to PhishTool and connected VirusTotal to my account using my community edition API key. 

Below are a few screenshots of the malicious email and the PhishTool interface. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/0dcc25c992ddfdfc60532f6fb9416a70.png)  

From the image above, you can see the PhishTool conveniently grabs all the pertinent information we'll need regarding the email.

- Email sender
- Email recipient (in this case, a long list of CCed email addresses)
- Timestamp
- Originating IP and Reverse DNS lookup

We can obtain information about the SMTP relays, specific X-header information, and IP info information.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/9665b8957923a892e721a0e02e42ea9f.png)  

Below is a snippet of Hop 1 of 6 (SMTP relays).

![](https://assets.tryhackme.com/additional/phishing2/phish-smtp.png)  

Notice that the tool notifies us that '**Reply-To no present**' although it provides the alternative header information, **Return-Path**.

To the right of the PhishTool dashboard, we can see the email body. There are two tabs across the top that we can toggle to view the email in text format or its HTML source code. 

Text view:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/94366a297a0abb9b7f680e006c421b45.png)  

HTML view:  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/e5eb24859d263b8d233f52c1502aaed4.png)  

The bottom two panes will display information about attachments and URLs.

The right pane will show if any URLs were found in the email. In this case, no emails were found.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/a737376ca1243a926f7a41a765cb7a1e.png)  

The left pane will show information about the attachment. This particular malicious email has a zip file.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/685f9bb5291973038d55aca7c09ffd1e.png)  

We can automatically get feedback from VirusTotal since our community edition API key is connected.

Here we can grab the zip file name and its hashes without manually interacting with the malicious email.

 There is an ellipsis at the far right of the above image. If that is clicked, we are provided additional actions that we can perform with the attachment.

Below is a screenshot of the additional options sub-menu.

![](https://assets.tryhackme.com/additional/phishing2/phish-options.png)  

Let's look at the Strings output.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/e1f11b62dbd9ed415177bdbc44a13d2d.png)  

Next, let's look at the information from VirusTotal.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/5c0556b15a803638a2d289915edc8946.png)  

Since the VirusTotal API key is the free community edition, an analyst can manually navigate to VirusTotal and do a file hash search to view more information about this attachment. 

Lastly, any submissions you upload to PhishTool, you can flag as malicious and resolve with notes. Similar to how you would if you were a SOC Analyst.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/31728d39e79f36340ab8bcdd740940d6.png)

The attachment file name and file hashes will be marked as malicious. Next, click on **Resolve**.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/64c5e32e65919e17e352161594fbb627.png)  

In the next screen, an analyst can mark the email based on dropdown selections. Refer to the GIF below.

![](https://assets.tryhackme.com/additional/phishing2/resolve-case.gif)  

**Note**: I didn't perform further analysis on the domain name or the IP address. Neither did I perform any research regarding the root domain the email originated from. The attachment can further be analyzed by uploading it to a malware sandbox to see what exactly it's doing, which I did not do. Hence the reason why additional Flag artifacts and Classifications codes weren't selected for this malicious email. :) 

To expand on classification codes briefly, not all phishing emails can be categorized as the same. A classification code allows us to tag a case with a specific code, such as Whaling (high-value target). Not all phishing emails will target a high-value target, such as a Chief Financial Officer (CFO).




The tools covered in this room are just some that can help you with analyzing phishing emails. 

As a defender, you'll come up with your own preferred tools and techniques to perform manual and automated analysis. 

Here are a few other tools that we have not covered in detail within this room that deserve a shout:

- [https://mxtoolbox.com/](https://mxtoolbox.com/)
- [https://phishtank.com/?](https://phishtank.com/?)
- [https://www.spamhaus.org/](https://www.spamhaus.org/)[](https://www.spamhaus.org/)

That's all, folks! Happy Hunting!