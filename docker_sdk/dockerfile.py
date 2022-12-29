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

def Check_Docker_Compose_Production(container_list):
    with open("./dockerfile_production/docker-compose.yml") as file:
        dockerfs = file.readlines()
        for dockerf in dockerfs:
            if "container_name" in dockerf:
                container_name = dockerf.replace("container_name:","").strip()
                container_list.append(container_name)
        return container_list

#def Check_Docker_Compose_CMD(command_list):
#    with open("./dockerfile_test/Dockerfile") as file:
#        dockerfs = file.readlines()
#        for dockerf in dockerfs:
#            if "CMD" in dockerf:
#                command = dockerf.replace("CMD", "").strip()
#                command_list.append(command.replace(",", " ").replace('"', "").replace("[","").replace("]",""))
#        return command_list

def Check_Exec_Command(container_id,container_name,get_command_list):
    command = []
    directory = "./dockerfile_test/" + container_name + "/cmd.sh"
    with open(directory) as file:
        dockerfs = file.readlines()
        counter = 0
        for comm in dockerfs:
            if counter == 0:
                counter = counter + 1
                continue
            if comm == "\n":
                continue
            comm = comm.replace("\n","")
            command.append(comm)
        get_command_list[container_id] = command
        return get_command_list

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

def Enter_Container_Test(container_id):
    print("please enter 'exit'")
    shell = "/bin/bash"
    cmd = ("docker","exec","-it",container_id,shell)
    s = subprocess.run(cmd, cwd="./dockerfile_test")

def Stop_Container_Test(container_id):
    print("stop container")
    cmd = ("docker", "stop", "%s" % (container_id))
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



