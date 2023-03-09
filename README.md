# System
Restrict system calls in the container execution environment (currently docker only) with eBPF.
Create a container for the test environment and use eBPF to record the system calls issued by the container.
Create a seccomp profile configured to allow recorded system calls and apply it to the production container.
The Seccomp profile is then applied to the container in the production environment.
This system allows containers to be restricted from issuing unnecessary system calls.


# Attention
### several problems
This system has several problems and is not recommended for use in a production environment.
* Seccomp profiles cannot be created for containers that use system calls not supported by this system.
* In the case of co-dependent containers, the ENTRYPOINT of Docker is used to run programs and commands, which makes it impossible to create the correct Seccomp profile.
* Unclear to use in production environment because only a small number of commands and programs have been verified
* No support for container runtimes other than Docker

### Before running the system
* docker-compose.yml and Dockerfile place the specified directory.
* To describe commands for executing programs or commands in shell scripts.
* Run bcc ( BPF Compiler Collection ) in the built environment
* To search the location of docker-compose and Dockerfile with the specified name, please name the directory accordingly
* Once the system is started, both the test and production environments are created, so there is no need for the user to start these containers.
* Commands that enter the container are executed in the test environment by default (creation of a bash process).
* Check the docker logs to see if the service has started in the container, and then exit from the container.


## System Environment
* OS: Ubuntu 20.04.4 LTS 
* kernel version: 
* bcc ( BPF Compiler Collection )
* Python 3.8.10
* Docker: Docker version 20.10.12


## How to run the system
Create docker-compose and Dockerfile based on the "name rule"
and place them in the specified directory.
Dockerfile and docker-compose examples for test and production environments exist in the sample directory
If the above steps are completed, run In the directory where the main.py file is located Execute the following command in the directory containing the main.py file

```angular2html
sudo python3 main.py
```

## name rule (Dockerfile docker-compose)
- Separate directories for each container and place a Dockerfile in each directory.
- Give the same name as the container name specified in docker-compose and the directory name for each container.
- Please align the container name with the name of the seccomp profile specified in the security opt in the production environment.