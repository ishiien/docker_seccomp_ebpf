import yaml
import subprocess
import time

def Check_Docker_Compose(container_list):
    with open("./dockerfile_test/docker-compose.yml") as file:
        dockerfs = file.readlines()
        for dockerf in dockerfs:
            if "container_name" in dockerf:
                container_name = dockerf.replace("container_name:", "").strip()
                container_list.append(container_name)
        return container_list

def Check_Docker_Compose_CMD(command_list):
    with open("./dockerfile_test/Dockerfile") as file:
        dockerfs = file.readlines()
        for dockerf in dockerfs:
            if "CMD" in dockerf:
                command = dockerf.replace("CMD", "").strip()
                command_list.append(command.replace(",", " ").replace('"', "").replace("[","").replace("]",""))
        return command_list

def Create_Container_Test():
    # Create Container Only
    command = ("docker-compose","build","--no-cache")
    a = subprocess.run(command,cwd='./dockerfile_test')
    cmd = ("docker-compose","up","--no-start")
    s = subprocess.run(cmd,cwd="./dockerfile_test")

def Start_Container_Test(container_id):
    # Start Container and Exec container
    print("start container")
    cmd = ("docker","start","%s" % (container_id))
    s = subprocess.run(cmd,cwd="./dockerfile_test")
    Enter_Container_Test(container_id)

def Enter_Container_Test(container_id):
    print("please enter 'exit'")
    shell = "/bin/bash"
    cmd = ("docker","exec","-it",container_id,shell)
    s = subprocess.run(cmd, cwd="./dockerfile_test")


def Down_Dockerfile_Test():
    print("Down Test Container")
    command = ("docker-compose","down")
    a = subprocess.run(command,cwd="./dockerfile_test")

def Exec_Dockerfile_Production():
    print("Now, make container Production")
    command = ("docker-compose", "build", "--no-cache")
    a = subprocess.run(command, cwd='./dockerfile_production')
    cmd = ("docker-compose","up","--no-start")
    s = subprocess.run(cmd, cwd="./dockerfile_production")
    cmd = ("docker-compose","start")
    c = subprocess.run(cmd, cwd="./dockerfile_production")


