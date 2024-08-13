Docker can seem overwhelming at first. However, the commands are pretty intuitive, and with a bit of practice, you’ll be a Docker wizard in no time.

The syntax for Docker can be categorised into four main groups:

- Running a container
- Managing & Inspecting containers
- Managing Docker images
- Docker daemon stats and information

We will break down each of these categories in this task.
## Managing Docker Images

Docker Pull  
Before we can run a Docker container, we will first need an image. Recall from the “[Intro to Containerisation](https://tryhackme.com/room/introtocontainerisation)” room that images are instructions for what a container should execute. There’s no use running a container that does nothing!  

In this room, we will use the Nginx image to run a web server within a container. Before downloading the image, let’s break down the commands and syntax required to download an image. Images can be downloaded using the `docker pull` command and providing the name of the image.

For example, `docker pull nginx`. Docker must know where to get this image (such as from a repository which we’ll come onto in a later task).


Continuing with our example above, let’s download this Nginx image!

A terminal showing the downloading of the "Nginx" image

```shell-session
cmnatic@thm:~$ docker pull nginx
Using default tag: latest
latest: Pulling from library/nginx
-- omitted for brevity --
Status: Downloaded newer image for nginx:latest
cmnatic@thm:~$
```
By running this command, we are downloading the latest version of the image titled “nginx”. Images have these labels called _tags_. These _tags_ are used to refer to variations of an image. For example, an image can have the same name but different tags to indicate a different version. I’ve provided an example of how tags are used within the table below:

|   |   |   |   |
|---|---|---|---|
|**Docker Image**|**Tag**|**Command Example**|**Explanation**|
|ubuntu|latest|docker pull ubuntu<br><br>**- IS THE SAME AS -**<br><br>docker pull ubuntu:latest|This command will pull the latest version of the "ubuntu" image. If no tag is specified, Docker will assume you want the "latest" version if no tag is specified.<br><br>It is worth remembering that you do not always want the "latest". This image is quite literally the "latest" in the sense it will have the most recent changes. This could either fix or break your container.|
|ubuntu|22.04|docker pull ubuntu:22.04|This command will pull version "22.04 (Jammy)" of the "ubuntu" image.|
|ubuntu|20.04|docker pull ubuntu:20.04|This command will pull version "20.04 (Focal)" of the "ubuntu" image.|
|ubuntu|18.04|docker pull ubuntu:18.04|This command will pull version "18.04 (Bionic)" of the "ubuntu" image.|

  

When specifying a tag, you must include a colon `:` between the image name and tag, for example, `ubuntu:22.04` (image:tag). Don’t forget about tags - we will return to these in a future task!

Docker Image x/y/z  

The `docker image` command, with the appropriate option, allows us to manage the images on our local system. To list the available options, we can simply do `docker image` to see what we can do. I’ve done this for you in the terminal below:

A terminal showing the various arguments we can provide with "docker image"  

```shell-session
cmnatic@thm:~$ docker image

Usage:  docker image COMMAND

Manage images

Commands:
  build       Build an image from a Dockerfile
  history     Show the history of an image
  import      Import the contents from a tarball to create a filesystem image
  inspect     Display detailed information on one or more images
  load        Load an image from a tar archive or STDIN
  ls          List images
  prune       Remove unused images
  pull        Pull an image or a repository from a registry
  push        Push an image or a repository to a registry
  rm          Remove one or more images
  save        Save one or more images to a tar archive (streamed to STDOUT by default)
  tag         Create a tag TARGET_IMAGE that refers to SOURCE_IMAGE

Run 'docker image COMMAND --help' for more information on a command.
cmnatic@thm:~$
```

- In this room, we are only going to cover the following options for docker images:
    
    - pull (we have done this above!)
    - ls (list images)
    - rm (remove an image)
    - build (we will come onto this in the “Building your First Container” task)

Docker Image ls  

This command allows us to list all images stored on the local system. We can use this command to verify if an image has been downloaded correctly and to view a little bit more information about it (such as the tag, when the image was created and the size of the image).

A terminal listing the Docker images that are stored on the host operating system  

```shell-session
cmnatic@thm:~$ docker image ls
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
ubuntu       22.04     2dc39ba059dc   10 days ago   77.8MB
nginx        latest    2b7d6430f78d   2 weeks ago   142MB
cmnatic@thm:~$
```

For example, in the terminal above, we can see some information for two images on the system:

|   |   |   |   |   |
|---|---|---|---|---|
|**Repository**|**Tag**|**Image ID**|**Created**|**Size**|
|ubuntu|22.04|2dc39ba059dc|10 days ago|77.8MB|
|nginx|latest|2b7d6430f78d|2 weeks ago|142MB|

Docker Image rm  

If we want to remove an image from the system, we can use `docker image rm` along with the name (or Image ID). In the following example, I will remove the "_ubuntu_" image with the tag "_22.04_". My command will be `docker image rm ubuntu:22.04`:

It is important to remember to include the _tag_ with the image name.

A terminal displaying the untagging of an image  

```shell-session
cmnatic@thm:~$ docker image rm ubuntu:22.04
Untagged: ubuntu:22.04
Untagged: ubuntu@sha256:20fa2d7bb4de7723f542be5923b06c4d704370f0390e4ae9e1c833c8785644c1
Deleted: sha256:2dc39ba059dcd42ade30aae30147b5692777ba9ff0779a62ad93a74de02e3e1f
Deleted: sha256:7f5cbd8cc787c8d628630756bcc7240e6c96b876c2882e6fc980a8b60cdfa274
cmnatic@thm:~$
```

If we were to run a `docker image ls`, we would see that the image is no longer listed:  
  
A terminal confirming that our Docker image has been deleted

```shell-session
cmnatic@thm:~$ docker image ls
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
nginx        latest    2b7d6430f78d   2 weeks ago   142MB
cmnatic@thm:~$
```


The Docker run command creates running containers from images. This is where commands from the Dockerfile (as well as our own input at runtime) are run. Because of this, it must be some of the first syntaxes you learn.

The command works in the following way: `docker run [OPTIONS] IMAGE_NAME [COMMAND] [ARGUMENTS...]`  the options enclosed in brackets are not required for a container to run.

Docker containers can be run with various options - depending on how we will use the container. This task will explain some of the most common options that you may want to use.

First, Simply Running a Container  

Let's recall the syntax required to run a Docker container: `docker run [OPTIONS] IMAGE_NAME [COMMAND] [ARGUMENTS...]` . In this example, I am going to configure the container to run:  

- An image named "helloworld"
- "Interactively" by providing the `-it` switch in the [OPTIONS] command. This will allow us to interact with the container directly.
- I am going to spawn a shell within the container by providing `/bin/bash` as the [COMMAND] part. This argument is where you will place what commands you want to run within the container (such as a file, application or shell!)

So, to achieve the above, my command will look like the following: `docker run -it helloworld /bin/bash`

A terminal showing a container being launched in 'interactive' mode

```shell-session
cmnatic@thm-intro-to-docker:~$ docker run -it helloworld /bin/bash
root@30eff5ed7492:/#
```

We can verify that we have successfully launched a shell because our prompt will change to another user account and hostname. The hostname of a container is the container ID (which can be found by using `docker ps`). For example, in the terminal above, our username and hostname are `root@30eff5ed7492`

Running Containers...Continued  

As previously mentioned, Docker containers can be run with various options. The purpose of the container and the instructions set in a Dockerfile (we'll come onto this in a later task) determines what options we need to run the container with. To start, I've put some of the most common options you may need to run your Docker container into the table below.


These are just some arguments we can provide when running a container. Again, most arguments we need to run will be determined by how the container is built. However, arguments such as `--rm` and `--name` will instruct Docker on how to run the container. Other arguments include (but are not limited to!):

- Telling Docker what network adapter the container should use
- What capabilities the container should have access to. This is covered in the "[Docker Rodeo](https://tryhackme.com/room/dockerrodeo)" room on TryHackMe.
- Storing a value into an environment variable

If you wish to explore more of these arguments, I highly suggest reading the [Docker run documentation](https://docs.docker.com/engine/reference/run/).

Listing Running Containers  

To list running containers, we can use the docker ps command. This command will list containers that are currently running - like so:

A terminal showing a list of running containers and their information

```shell-session
cmnatic@thm:~/intro-to-docker$ docker ps
CONTAINER ID   IMAGE                           COMMAND        CREATED        STATUS      PORTS     NAMES                                                                                      
                             
a913a8f6e30f   cmnatic/helloworld:latest   "sleep"   1 months ago   Up 3 days   0.0.0.0:8000->8000/tcp   helloworld
cmnatic@thm:~/intro-to-docker$
```

  

This command will also show information about the container, including:

- The container's ID
- What command is the container running
- When was the container created
- How long has the container been running
- What ports are mapped
- The name of the container

**Tip:** To list all containers (even stopped), you can use `docker ps -a`:

A terminal showing a list of ALL containers and their information

```shell-session
cmnatic@thm:~/intro-to-docker$ docker ps -a
CONTAINER ID   IMAGE                             COMMAND                  CREATED             STATUS     PORTS    NAMES                                                                                  
00ba1eed0826   gobuster:cmnatic                  "./gobuster dir -url…"   an hour ago   Exited an hour ago practical_khayyam
```


# Docker Files

Dockerfiles play an essential role in Docker. Dockerfiles is a formatted text file which essentially serves as an instruction manual for what containers should do and ultimately assembles a Docker image.

You use Dockerfiles to contain the commands the container should execute when it is built. To get started with Dockerfiles, we need to know some basic syntax and instructions. Dockerfiles are formatted in the following way:

`INSTRUCTION argument`

First, let’s cover some essential instructions:

|   |   |   |
|---|---|---|
|**Instruction**|**Description**|**Example**|
|FROM|This instruction sets a build stage for the container as well as setting the base image (operating system). All Dockerfiles must start with this.|FROM ubuntu|
|RUN|This instruction will execute commands in the container within a new layer.|RUN whoami|
|COPY|This instruction copies files from the local system to the working directory in the container (the syntax is similar to the `cp` command).|COPY /home/cmnatic/myfolder/app/|
|WORKDIR|This instruction sets the working directory of the container. (similar to using `cd` on Linux).|WORKDIR /  <br>(sets to the root of the filesystem in the container)|
|CMD|This instruction determines what command is run when the container starts (you would use this to start a service or application).|CMD /bin/sh -c script.sh|
|EXPOSE|This instruction is used to tell the person who runs the container what port they should publish when running the container.|EXPOSE 80<br><br>(tells the person running the container to publish to port 80 i.e. `docker run -p 80:80`)|

Now that we understand the core instructions that make up a Dockerfile, let’s see a working example of a Dockerfile. But first, I’ll explain what I want the container to do:  

1. Use the “Ubuntu” (version 22.04) operating system as the base.
2. Set the working directory to be the root of the container.
3. Create the text file “helloworld.txt”.

```yml
# THIS IS A COMMENT
# Use Ubuntu 22.04 as the base operating system of the container
FROM ubuntu:22.04

# Set the working directory to the root of the container
WORKDIR / 

# Create helloworld.txt
RUN touch helloworld.txt
```

Remember, the commands that you can run via the `RUN` instruction will depend on the operating system you use in the `FROM` instruction. (In this example, I have chosen Ubuntu. It’s important to remember that the operating systems used in containers are usually very minimal. I.e., don’t expect a command to be there from the start (even commands like _curl_, _ping_, etc., may need to be installed.)

Building Your First Container  

Once we have a Dockerfile, we can create an image using the `docker build` command. This command requires a few pieces of information:

1. Whether or not you want to name the image yourself (we will use the `-t` (tag) argument).
2. The name that you are going to give the image.
3. The location of the Dockerfile you wish to build with.

I’ll provide the scenario and then explain the relevant command. Let’s say we want to build an image - let’s fill in the two required pieces of information listed above:

1. We are going to name it ourselves, so we are going to use the `-t` argument.
2. We want to name the image.
3. The Dockerfile is located in our current working directory (`.`).

The Dockerfile we are going to build is the following:

  

```yml
# Use Ubuntu 22.04 as the base operating system of the container
FROM ubuntu:22.04

# Set the working directory to the root of the container
WORKDIR / 

# Create helloworld.txt
RUN touch helloworld.txt
```

# Docker Compose

Let’s first understand what Docker Compose is and why it’s worth understanding. So far, we’ve only interacted with containers individually. Docker Compose, in summary, allows multiple containers (or applications) to interact with each other when needed while running in isolation from one another.

You may have noticed a problem with Docker so far. More often than not, applications require additional services to run, which we cannot do in a single container. For example, modern - dynamic - websites use services such as databases and a web server. For the sake of this task, we will consider each application as a “microservice”.

While we can spin up multiple containers or “microservices” individually and connect them, doing so one by one is cumbersome and inefficient. Docker Compose allows us to create these “microservices” as one singular “service”. 

This illustration shows how containers are deployed together using Docker Compose Vs. Docker:

A blue box (representing a computer) with a caption of docker, is isolated from another set of blue boxes (representing a computer).

Before we demonstrate Docker Compose, let’s cover the fundamentals of using Docker Compose.
We need Docker Compose installed (it does not come with Docker by default). Installing it is out of scope for this room, as it changes depending on your operating system and other factors. You can check out the installation documentation here.
We need a valid docker-compose.yml file - we will come onto this shortly.
A fundamental understanding of using Docker Compose to build and manage containers.
I have put some of the essential Docker Compose commands into the table below:

Command	Explanation	Example
up	This command will (re)create/build and start the containers specified in the compose file.	
docker-compose up

start	This command will start (but requires the containers already being built) the containers specified in the compose file.
docker-compose start

down	This command will stop and delete the containers specified in the compose file.
docker-compose down

stop	This command will stop (not delete) the containers specified in the compose file.
docker-compose stop

build	This command will build (but will not start) the containers specified in the compose file.
docker-compose build

﻿Note: These are just a few of the possible commands. Check out the compose documentation for all possible options.

A Showcase of Docker Compose

With that said, let’s look into how we can use Docker Compose ourselves. In this scenario, I am going to assume the following requirements:

An E-commerce website running on Apache
This E-commerce website stores customer information in a MySQL database
Now, we could manually run the two containers via the following:

Creating the network between the two containers: docker network create ecommerce
Running the Apache2 webserver container: docker run -p 80:80 --name webserver --net ecommerce webserver
Running the MySQL Database server: docker run --name database --net ecommerce webserver
An illustration showing the two containers spun up using docker compose. Note that they are unable to communicate with one another

An illustration shows two containers running independently of each other and is unable to communicate with one another.

…but do we want to do this every time? Or what if we decide to scale up and get many web servers involved? Do we want to do this for every container, every time? I certainly don’t.

Instead, we can use Docker Compose via docker-compose up to run these containers together, giving us the advantages of:

One simple command to run them both
These two containers are networked together, so we don’t need to go about configuring the network.
Extremely portable. We can share our docker-compose.yml file with someone else, and they can get the setup working precisely the same without understanding how the containers work individually.
Easy to maintain and change. We don’t have to worry about specific containers using (perhaps outdated) images.


An illustration showing two containers deployed as a combined service. These two containers can communicate with one another.

Docker-compose.yml files 101

One file to rule them all. The formatting of a docker-compose.yml file is different to that of a Dockerfile. It is important to note that YAML requires indentation (a good practice is two spaces which must be consistent!). First, I’ll show some of the new instructions that you will need to learn to be able to write a docker-compose.yml file before we go into creating a docker-compose.yml file:

Instruction	Explanation	Example
version	This is placed at the top of the file and is used to identify what version of Compose the docker-compose.yml is written for.
'3.3'
services	This instruction marks the beginning of the containers to be managed.	services:
name (replace value)	This instruction is where you define the container and its configuration. "name" needs to be replaced with the actual name of the container you want to define, i.e. "webserver" or "database".	webserver
build	This instruction defines the directory containing the Dockerfile for this container/service. (you will need to use this or an image).	./webserver
ports	This instruction publishes ports to the exposed ports (this depends on the image/Dockerfile).	'80:80'
volumes	This instruction lists the directories that should be mounted into the container from the host operating system.	'./home/cmnatic/webserver/:/var/www/html'
environment	This instruction is used to pass environment variables (not secure), i.e. passwords, usernames, timezone configurations, etc.	MYSQL_ROOT_PASSWORD=helloworld
image	This instruction defines what image the container should be built with (you will need to use this or build).	mysql:latest
networks	This instruction defines what networks the containers will be a part of. Containers can be part of multiple networks (i.e. a web server can only contact one database, but the database can contact multiple web servers).	ecommerce
Note: These are just some of the possible instructions possible. Check out the compose file documentation for all possible instructions.

With that said, let’s look at our first docker-compose.yml file. This docker-compose.yml file assumes the following:

We will run one web server (named web) from the previously mentioned scenario.
We will run a database server (named database) from the previously mentioned scenario.
The web server is going to be built using its Dockerfile, but we are going to use an already-built image for the database server (MySQL)
The containers will be networked to communicate with each other (the network is called ecommerce).
Our directory listing looks like the following:
docker-compose.yml
web/Dockerfile
Here is what our docker-compose.yml file would look like (as a reminder, it is essential to pay attention to the indentation):

version: '3.3'
services:
  web:
    build: ./web
    networks:
      - ecommerce
    ports:
      - '80:80'


  database:
    image: mysql:latest
    networks:
      - ecommerce
    environment:
      - MYSQL_DATABASE=ecommerce
      - MYSQL_USERNAME=root
      - MYSQL_ROOT_PASSWORD=helloword
    
networks:
  ecommerce:

