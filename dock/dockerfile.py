import yaml
import subprocess
import time

def check_docker_compose(container_list):
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
    # Start Container
    print("start container")
    cmd = ("docker-compose","start")
    s = subprocess.run(cmd,cwd="./dockerfile_test")

def exec_dockerfile_production():
    cmd = ("docker-compose", "up", "--build")
    s = subprocess.run(cmd, cwd="./dockerfile_production")