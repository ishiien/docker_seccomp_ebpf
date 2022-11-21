import docker

container_id_list = []

def check_container_name(target_name):
    client = docker.from_env()
    for c in client.containers.list(all=True, filters={"name": target_name}):
        container_id = c.attrs['Id']
        if container_id != 0:
            return container_id

    returner = 0
    return returner


