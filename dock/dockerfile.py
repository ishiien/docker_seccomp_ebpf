import yaml
import subprocess



def check_docker_file(exec_list):
    with open("./dockerfile_test/Dockerfile") as file:
        dockerfs = file.readlines()
        for dockerf in dockerfs:
            if "CMD" in dockerf:
                dockerf.replace("CMD","")
                dockerf.replace("\n","")
                exec_list.append(dockerf)

        return exec_list

def check_docker_compose(container_list):
    with open("./dockerfile_test/docker-compose.yml") as file:
        dockerfs = file.readlines()
        for dockerf in dockerfs:
            if "container_name" in dockerf:
                container_list.append(dockerf)

        return container_list

def exec_dock_directory():
    s = subprocess.run("docker-compose up --build")


