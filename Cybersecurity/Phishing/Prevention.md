What is the **Sender Policy Framework** (**SPF**)?  

Per [dmarcian](https://dmarcian.com/what-is-spf/), "_Sender Policy Framework (SPF) is used to authenticate the sender of an email. With an SPF record in place, Internet Service Providers can verify that a mail server is authorized to send email for a specific domain. An SPF record is a DNS TXT record containing a list of the IP addresses that are allowed to send email on behalf of your domain._"

Below is a visual workflow for SPF.

![](https://assets.tryhackme.com/additional/phishing4/dmarcian-spf.png)  

**Note:** Credit to dmarcian for the above image.

How does a basic SPF record look like?

`v=spf1 ip4:127.0.0.1 include:_spf.google.com -all`

An explanation for the above record:

- `v=spf1` -> This is the start of the SPF record
- `ip4:127.0.0.1` -> This specifies which IP (in this case version IP4 & not IP6) can send mail
- `include:_spf.google.com` -> This specifies which domain can send mail
- `-all` -> non-authorized emails will be rejected

Refer to the SPF Record Syntax on dmarcian [here](https://dmarcian.com/spf-syntax-table/) and [here](https://dmarcian.com/what-is-the-difference-between-spf-all-and-all/).

Let's look at Twitter's SPF record using dmarcian's SPF Surveyor [tool](https://dmarcian.com/spf-survey/).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/66c0270a75718fd985664b223e549cde.png)  

Refer to this resource on [dmarcian](https://dmarcian.com/create-spf-record/) on how to create your own SPF records. 

Let's look at another sample.

The image below is from [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/), which was used to analyze a malicious email.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/5d9bea5f9fd4e1409d4cb28bfdfea94e.png)  

The above image shows the status of an SPF record check. It reports back as **softfail**.

Let's use the **Domain Health Checker** from [dmarcian.com](https://dmarcian.com/domain-checker/) and check the DMARC status of **microsoft.com**. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/9b94a157faf86848b26093efb30c2126.png)  

And the results are...

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/72bc9ea8efe179361c958a951f9db9fb.png)  

Microsoft passed all checks. We can drill down into **DMARC**, **SPF**, or **DKIM** to get more details.

**DMARC**:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/d0b2fc15e23d1466ff98efc98afef61e.png)


What is **[S/MIME](https://docs.microsoft.com/en-us/exchange/security-and-compliance/smime-exo/smime-exo)**?  

Per Microsoft, "_S/MIME (Secure/Multipurpose internet Mail Extensions) is a widely accepted protocol for sending digitally signed and encrypted messages_."

As you can tell from the definition above, the 2 main ingredients for S/MIME are:

1. **Digital Signatures**
2. **Encryption**

Using [Public Key Cryptography](https://www.ibm.com/docs/en/ztpf/2023?topic=concepts-public-key-cryptography), S/MIME guarantees data integrity and nonrepudiation.   

- If Bob wishes to use S/MIME, then he'll need a digital certificate. This digital certificate will contain his public key. 
- With this digital certificate, Bob can "sign" the email message with his private key. 
- Mary can then decrypt Bob's message with Bob's public key. 
- Mary will do the same (send her certificate to Bob) when she replies to his email, and Bob complete the same process on his end.
- Both will now have each other's certificates for future correspondence. 

The illustration below will help you understand how public key cryptography works. 

![A diagram visualising encryption workflow described above](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/27cb0b439d172324f453e57c9cbf7ac0.png)  

Refer to this Microsoft documentation [here](https://docs.microsoft.com/en-us/exchange/security-and-compliance/smime-exo/smime-exo) for more information on S/MIME and steps on how to configure Office 365 to send/receive S/MIME emails.