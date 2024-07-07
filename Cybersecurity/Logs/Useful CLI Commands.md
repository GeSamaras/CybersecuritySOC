cat

The `cat` command (short for "concatenate") is a simple utility that reads one or more files and displays its content in the terminal. When used for log files, it prints the entire log content to the screen.

For example, to view the contents of a log file named `apache.log`, you can use the command:

cat Example

```shell-session
user@tryhackme$ cat apache.log        
203.0.113.42 - - [31/Jul/2023:12:34:56 +0000] "GET /index.php HTTP/1.1" 200 1234 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) 
```

Due to its large output, it is typically not the best approach for dealing with long log files.

less

The `less` command is an improvement over `cat` when dealing with larger files. It allows you to view the file's data page by page, providing a more convenient way to read through lengthy logs. When using `less` to open a file, it displays the first page by default, and you can scroll down using the arrow keys or with _Page Up_ and _Page Down_.

For example, to view the same log file using `less`, use the command:

less Example

```shell-session
user@tryhackme$ less apache.log      
HTTP/1.1" 200 7890 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 
~
~
(END)
```

You can exit the command's output via the `q` key.

tail

The `tail` command is specifically designed for viewing the end of files and is very useful for seeing a summary of recently generated events in the case of log files. The most common use of `tail` is coupled with the `-f` option, which allows you to "follow" the log file in real-time, as it continuously updates the terminal with new log entries as they are generated and written. This is extremely useful when monitoring logs for live events or real-time system behavior.

By default, `tail` will only display the last ten lines of the file. However, we can change this with the `-n` option and specify the number of lines we want to view.

For example, if we only wanted to print the last five lines of the `apache.log` file and "follow" the logs in real-time, we can use the command:

tail Example

```shell-session
user@tryhackme$ tail -f -n 5 apache.log
176.145.201.99 - - [31/Jul/2023:12:34:24 +0000] "GET /login.php HTTP/1.1" 200 1234 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) 
```

Being able to sort, filter, and manipulate log files from the command line is a crucial aspect of performing effective log analysis. Analysts often need to extract specific information, filter out relevant data, aggregate results, and transform logs to uncover insights and identify anomalies.

**Note:** The opposite of the `tail` command is `head`, which allows you to view the _first_ ten lines of a file by default and takes in the same arguments. Feel free to experiment with this as well!

wc

The `wc` (word count) command is a simple but powerful utility that can be quite useful for quick analysis and statistics gathering. The output of `wc` provides information about the number of lines, words, and characters in a log file. This can help security analysts understand the size and volume of log data they are dealing with before diving into a more detailed analysis.

wc Example

```shell-session
user@tryhackme$ wc apache.log     
   70  1562 14305 apache.log
```

After running `wc` on `apache.log`, we can determine that the file contains **70** lines, **1562** individual words (separated by whitespace), and **14305** individual characters.

cut

The `cut` command extracts specific columns (fields) from files based on specified delimiters. This is a handy command for working with log files that have structured or tab-separated data.

If we want to extract all of the IP addresses in the file, we can use the `cut` command to specify a delimiter of a `space` character and only select the first field returned.

cut Example

```shell-session
user@tryhackme$ cut -d ' ' -f 1 apache.log
203.0.113.42
120.54.86.23
...
```

The above command will return a list of every IP address in the log file. Expanding on this, we can change the field number to `-f 7` to extract the URLs and `-f 9` to extract the HTTP status codes.

sort

Sometimes, it's helpful to sort the returned entries chronologically or alphabetically. The `sort` command arranges the data in files in ascending or descending order based on specific criteria. This can be crucial for identifying patterns, trends, or outliers in our log data. It is also common to combine the _output_ of another command (cut, for example) and use it as the _input_ of the sort command using the pipe `|` redirection character.

For example, to sort the list of returned IP addresses from the above `cut` command, we can run:

sort Example

```shell-session
user@tryhackme$ cut -d ' ' -f 1 apache.log | sort -n
76.89.54.221
76.89.54.221
...
```

In the above command, we piped the output from `cut` into the `sort` command and added the `-n` option to sort _numerically_. This changed the output to list the IP addresses in ascending order.

If we want to reverse the order, we can add the `-r` option:

sort Example (Reversed)

```shell-session
user@tryhackme$ cut -d ' ' -f 1 apache.log | sort -n -r
221.90.64.76
211.87.186.35
203.78.122.88
...
```

uniq

The `uniq` command identifies and removes adjacent duplicate lines from sorted input. In the context of log analysis, this can be a useful tool for simplifying data lists (like collected IP addresses), especially when log entries may contain repeated or redundant information. The `uniq` command is often combined with the `sort` command to **sort** the data before removing the duplicate entries.

For example, the output of the `sort` command we ran above contains a few duplicate IP addresses, which is easier to spot when the data is sorted numerically. To remove these repeatedly extracted IPs from the list, we can run:

uniq Example

```shell-session
user@tryhackme$ cut -d ' ' -f 1 apache.log | sort -n -r | uniq
221.90.64.76
211.87.186.35
...
```

We can also append the `-c` option to output unique lines and prepend the count of occurrences for each line. This can be very useful for quickly determining IP addresses with unusually high traffic.

uniq Example (with count)

```shell-session
user@tryhackme$ cut -d ' ' -f 1 apache.log | sort -n -r | uniq -c
      1 221.90.64.76
      1 211.87.186.35
      1 203.78.122.88
      6 203.64.78.90
      1 203.0.113.42
...
...
```

sed

Both `sed` and `awk` are powerful text-processing tools commonly used for log analysis. They are sometimes used interchangeably, but both commands have their use cases and can allow security analysts to manipulate, extract, and transform log data efficiently.

Using the substitute syntax, `sed` can replace specific patterns or strings into log entries. For example, to replace all occurrences of "**31/Jul/2023**" with "**July 31, 2023**" in the `apache.log` file, we can use:

sed Example

```shell-session
user@tryhackme$ sed 's/31\/Jul\/2023/July 31, 2023/g' apache.log
203.0.113.42 - - [July 31, 2023:12:34:56 +0000] "GET /index.php HTTP/1.1" 200 1234 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36"
120.54.86.23 - - [July 31, 2023:12:34:57 +0000] "GET /contact.php HTTP/1.1" 404 5678 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
...
```

Note that the backslash character `\` is required to "escape" the forward slash in our pattern and tell `sed` to treat the forward slash as a literal character. Also, note that the `sed` command _does not_ change the `apache.log` file directly; instead, it only outputs the modified version of the file to the standard output in the command line. If you want to overwrite the file, you can add the `-i` option to edit the file in place or use a redirect operator `>` to save the output to the original or another file.

**Caution:** If you use the `-i` option with `sed`, you risk overwriting the original file and losing valuable data. Ensure to keep a backup copy!

awk

For the `awk` command, a common use case, is conditional actions based on specific field values. For example, to print log entries where the HTTP response code is greater than or equal to `400` (which would indicate HTTP error statuses), we can use the following command:

awk Example

```shell-session
user@tryhackme$ awk '$9 >= 400' apache.log
120.54.86.23 - - [31/Jul/2023:12:34:57 +0000] "GET /contact.php HTTP/1.1" 404 5678 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
156.98.34.12 - - [31/Jul/2023:12:35:02 +0000] "GET /about.php HTTP/1.1" 404 5678 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Safari/537.36"
189.76.230.44 - - [31/Jul/2023:12:35:06 +0000] "GET /about.php HTTP/1.1" 404 1234 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.170 Safari/537.36"
...
...
```

In this case, we're using the `$9` field (which in this log example refers to the HTTP status codes), requiring it to be greater than or equal to `400`.

This only scratches the surface of the power of these commands, and it is highly encouraged to read more about their options and use cases [here](https://www.theunixschool.com/p/awk-sed.html).

grep

The `grep` command is a powerful text search tool widely used on UNIX systems and provides exceptional use cases in log analysis. It allows you to search for specific patterns or regular expressions within files or streams of text. Using `grep` can help analysts quickly identify relevant log entries that match specific criteria, particular resources or keywords, or patterns associated with security incidents.

The most basic usage of `grep` is to search for specific strings within log files. For example, if we are suspicious about any log entries that hit the `/admin.php` webpage on the server, we can `grep` for "admin" to return any relevant results:

grep Example

```shell-session
user@tryhackme$ grep "admin" apache.log
145.76.33.201 - - [31/Jul/2023:12:34:54 +0000] "GET /admin.php HTTP/1.1" 200 4321 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.330 Safari/537.36"
```

Like the `uniq -c` command, we can append the `-c` option to `grep` to count the entries matching the search criteria. For example, because only a single line was returned in the above command, appending `-c` will return "1".

grep Example (with count)

```shell-session
user@tryhackme$ grep -c "admin" apache.log
1
```

If we wanted to know which **line number** in the log file relates to the matched entries, we could add the `-n` option to help quickly locate specific occurrences:

grep Example (line number)

```shell-session
user@tryhackme$ grep -n "admin" apache.log                           
37:145.76.33.201 - - [31/Jul/2023:12:34:54 +0000] "GET /admin.php HTTP/1.1" 200 4321 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.330 Safari/537.36"
```

In this case, the line number **"37"** is prepended to the log entry output.

Lastly, we can **invert** our command using the `-v` option only to select lines that **do not** contain the specified pattern or keyword(s). This can be useful for quickly filtering out unwanted or irrelevant lines from log files. For example, if we're not interested in any log entries that hit the `/index.php` page, we can run the following command to filter it out:

grep Example (inverted)

```shell-session
user@tryhackme$ grep -v "/index.php" apache.log | grep "203.64.78.90"
203.64.78.90 - - [31/Jul/2023:12:35:01 +0000] "GET /about.php HTTP/1.1" 404 4321 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.170 Safari/537.36"
203.64.78.90 - - [31/Jul/2023:12:34:53 +0000] "GET /about.php HTTP/1.1" 200 1234 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.210 Safari/537.36"
```

Notice that in the above command, we filtered out the `index.php` page and piped the output into another grep command that only pulled log entries that contained the IP address `203.64.78.90`.

Like with `awk` and `sed`, `grep` is an extremely powerful tool that cannot be fully covered in a single task. It is highly encouraged to read more about it on the official GNU manual page [here](https://www.gnu.org/software/grep/manual/grep.html).

While command-line log analysis offers powerful capabilities, it might only suit some scenarios, especially when dealing with vast and complex log datasets. A dedicated log analysis solution, like the Elastic (ELK) Stack or Splunk, can be more efficient and offer additional log analysis and visualization features. However, the command line remains essential for quick and straightforward log analysis tasks.

![[Pasted image 20240707035529.png]]

