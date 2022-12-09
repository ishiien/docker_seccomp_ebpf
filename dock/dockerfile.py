import yaml
import subprocess
import time

def Check_Docker_Compose(container_list):
    with open("./dockerfile_test/docker-compose.yml") as file:
        dockerfs = file.readlines()
        for dockerf in dockerfs:
            if "container_name" in dockerf:
                container_list.append(dockerf)

        return container_list

def Create_Container_Test():
    # Create Container Only
    cmd = ("docker-compose","up","--no-start")
    s = subprocess.run(cmd,cwd="./dockerfile_test")

def Start_Container_Test():
    # Start Container and Exec container
    print("start container")
    cmd = ("docker-compose","start")
    s = subprocess.run(cmd,cwd="./dockerfile_test")
    Enter_Container_Test()

def Exec_Dockerfile_Production():
    cmd = ("docker-compose","up","--no-start")
    s = subprocess.run(cmd, cwd="./dockerfile_production")
    cmd = ("docker-compose","start")
    a = subprocess.run(cmd, cwd="./dockerfile_production")

def Enter_Container_Test():
    print("please enter 'exit'")
    cmd = ("docker-compose", "exec", "php", "/bin/bash")
    s = subprocess.run(cmd, cwd="./dockerfile_test")


