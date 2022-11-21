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



