## **Find**

The find command is fantastic in the sense that it can be used both very simply or rather complex depending upon what it is you want to do exactly.
If we remember the filename, we can simply use `find -name passwords.txt` where the command will look through every folder in our current directory for that specific file like so:

Using "find" to find a file with the name of "passwords.txt"

```shell-session
tryhackme@linux1:~$ find -name passwords.txt
./folder1/passwords.txt
tryhackme@linux1:~$
```
 `find -name *.txt` . Where "Find" has been able to _find_ every .txt file and has then given us the location of each one:

## **Grep**

Another great utility that is a great one to learn about is the use of `grep`. The `grep` command allows us to search the contents of files for specific values that we are looking for.
Using "wc" to count the number of entries in "access.log"

```shell-session
tryhackme@linux1:~$ wc -l access.log
244 access.log
tryhackme@linux1:~$
```

We can use `grep` to search the entire contents of this file for any entries of the value that we are searching for. Going with the example of a web server's access log, we want to see everything that the IP address "81.143.211.90" has visited (note that this is fictional)

Using "grep" to find any entries with the IP address of "81.143.211.90" in "access.log"

```shell-session
tryhackme@linux1:~$ grep "81.143.211.90" access.log
81.143.211.90 - - [25/Mar/2021:11:17 + 0000] "GET / HTTP/1.1" 200 417 "-" "Mozilla/5.0 (Linux; Android 7.0; Moto G(4))"
tryhackme@linux1:~$
```

## Operators

|   |   |
|---|---|
|Symbol / Operator|Description|
|&|This operator allows you to run commands in the background of your terminal.|
|&&|This operator allows you to combine multiple commands together in one line of your terminal.|
|>|This operator is a redirector - meaning that we can take the output from a command (such as using cat to output a file) and direct it elsewhere.|
|>>|This operator does the same function of the `>` operator but appends the output rather than replacing (meaning nothing is overwritten).|