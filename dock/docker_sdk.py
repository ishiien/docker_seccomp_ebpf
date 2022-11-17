import docker

def check_container_name(name):
    client = docker.from_env()
    for c in client.containers.list(all=True):
        container_id = c.attrs['Id']
        container_name = c.attrs['Name']
        container_name = container_name.replace("/","").strip()
        if container_name == name:
            print(container_name)
            return container_id[0:12]

    returener_container_id = 0
    return returener_container_id


