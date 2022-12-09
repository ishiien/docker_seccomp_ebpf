import docker

container_id_list = []

def ContainerName_to_ContainerId(container_name):
    client = docker.from_env()
    while 1:
        try:
            for c in client.containers.list(all=True,filters={"name": container_name}):
                container_id = c.attrs['Id']
                return container_id[0:12]
        except Exception:
            continue

def Container_Running_Inform(target):
    client = docker.from_env()
    while 1:
        try:
            for c in client.containers.list():
                container_id = c.attrs['Id']
                if target == container_id[0:12]:
                    print(container_id[0:12])
                    inform_flag = True
                    return inform_flag
        except Exception:
            continue



