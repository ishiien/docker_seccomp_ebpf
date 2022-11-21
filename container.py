import docker

container_id_list = []
client = docker.from_env()
container_name = "nginx_tester"
while 1:
    try:
        for c in client.containers.list(all=True,filters={"name": container_name}):
            container_id = c.attrs['Id']
            print(container_id)
            exit()
    except Exception:
        continue
