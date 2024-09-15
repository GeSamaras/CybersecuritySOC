## Using Tmux

Terminal multiplexers, like `tmux` or `Screen`, are great utilities for expanding a standard Linux terminal's features, like having multiple windows within one terminal and jumping between them. Let's see some examples of using `tmux`, which is the more common of the two. If `tmux` is not present on our Linux system, we can install it with the following command:

  Basic Tools

```shell-session
ChoccyCorgi@htb[/htb]$ sudo apt install tmux -y
```

Once we have `tmux`, we can start it by entering `tmux` as our command: ![tmux_1](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_1.jpg)


The default key to input `tmux` commands prefix is `[CTRL + B]`. In order to open a new window in `tmux`, we can hit the prefix 'i.e. `[CTRL + B]`' and then hit `C`: ![tmux_2](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_2.jpg)

We see the numbered windows at the bottom. We can switch to each window by hitting the prefix and then inputting the window number, like `0` or `1`. We can also split a window vertically into panes by hitting the prefix and then `[SHIFT + %]`: ![tmux_3](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_3.jpg)

We can also split into horizontal panes by hitting the prefix and then `[SHIFT + "]`: ![tmux_4](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_4.jpg)

We can switch between panes by hitting the prefix and then the `left` or `right` arrows for horizontal switching or the `up` or `down` arrows for vertical switching. The commands above cover some basic `tmux` usage. It is a powerful tool and can be used for many things, including logging, which is very important during any technical engagement. This [cheatsheet](https://tmuxcheatsheet.com/) is a very handy reference. Also, this [Introduction to tmux](https://www.youtube.com/watch?v=Lqehvpe_djs) video by `ippsec` is worth your time.

---

## Using Vim

[Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) is a great text editor that can be used for writing code or editing text files on Linux systems. One of the great benefits of using `Vim` is that it relies entirely on the keyboard, so you do not have to use the mouse, which (once we get the hold of it) will significantly increase your productivity and efficiency in writing/editing code. We usually find `Vim` or `Vi` installed on compromised Linux systems, so learning how to use it allows us to edit files even on remote systems. `Vim` also has many other features, like extensions and plugins, which can significantly extend its usage and make for a great code editor. Let's see some of the basics of `Vim`. To open a file with `Vim`, we can add the file name after it:

  Basic Tools

```shell-session
ChoccyCorgi@htb[/htb]$ vim /etc/hosts
```

![vim_1](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_1.jpg)

If we want to create a new file, input the new file name, and `Vim` will open a new window with that file. Once we open a file, we are in read-only `normal mode`, which allows us to navigate and read the file. To edit the file, we hit `i` to enter `insert mode`, shown by the "`-- INSERT --`" at the bottom of `Vim`. Afterward, we can move the text cursor and edit the file:

![vim_2](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_2.jpg)

Once we are finished editing a file, we can hit the escape key `esc` to get out of `insert mode`, back into `normal mode`. When we are in `normal mode`, we can use the following keys to perform some useful shortcuts:

|Command|Description|
|---|---|
|`x`|Cut character|
|`dw`|Cut word|
|`dd`|Cut full line|
|`yw`|Copy word|
|`yy`|Copy full line|
|`p`|Paste|

Tip: We can multiply any command to run multiple times by adding a number before it. For example, '4yw' would copy 4 words instead of one, and so on.

If we want to save a file or quit `Vim`, we have to press`:` to go into `command mode`. Once we do, we will see any commands we type at the bottom of the vim window: ![vim_3](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_3.jpg)

There are many commands available to us. The following are some of them:

|Command|Description|
|---|---|
|`:1`|Go to line number 1.|
|`:w`|Write the file, save|
|`:q`|Quit|
|`:q!`|Quit without saving|
|`:wq`|Write and quit|

`Vim` is a very powerful tool and has many other commands and features. This [cheatsheet](https://vimsheet.com/) is an excellent resource for further unlocking the power of `Vim`.

###### Setup

  [Getting Started with a Pentest Distro](https://academy.hackthebox.com/module/77/section/722)[Staying Organized](https://academy.hackthebox.com/module/77/section/766)[Connecting Using VPN](https://academy.hackthebox.com/module/77/section/723)

###### Pentesting Basics

[Common Terms](https://academy.hackthebox.com/module/77/section/724)  [Basic Tools](https://academy.hackthebox.com/module/77/section/847)  [Service Scanning](https://academy.hackthebox.com/module/77/section/726)  [Web Enumeration](https://academy.hackthebox.com/module/77/section/728)  [Public Exploits](https://academy.hackthebox.com/module/77/section/843)[Types of Shells](https://academy.hackthebox.com/module/77/section/725)  [Privilege Escalation](https://academy.hackthebox.com/module/77/section/844)[Transferring Files](https://academy.hackthebox.com/module/77/section/849)

###### Getting Started with Hack The Box (HTB)

[Starting Out](https://academy.hackthebox.com/module/77/section/727)[Navigating HTB](https://academy.hackthebox.com/module/77/section/731)

###### Attacking Your First Box

  [Nibbles - Enumeration](https://academy.hackthebox.com/module/77/section/850)  [Nibbles - Web Footprinting](https://academy.hackthebox.com/module/77/section/851)  [Nibbles - Initial Foothold](https://academy.hackthebox.com/module/77/section/852)  [Nibbles - Privilege Escalation](https://academy.hackthebox.com/module/77/section/853)[Nibbles - Alternate User Method - Metasploit](https://academy.hackthebox.com/module/77/section/854)

###### Problem Solving

[Common Pitfalls](https://academy.hackthebox.com/module/77/section/730)[Getting Help](https://academy.hackthebox.com/module/77/section/729)

###### What's Next?

[Next Steps](https://academy.hackthebox.com/module/77/section/732)  [Knowledge Check](https://academy.hackthebox.com/module/77/section/859)

