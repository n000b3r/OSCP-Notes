# Docker

<details>

<summary>Building and running from Dockerfile</summary>

```bash
wget the dockerfile from github

docker build -t yourusername/repository-name . (eg: docker build -t jean_blanchard/2.35_glibc .)
docker images
docker run -itd --rm --name <container_name> yourusername/repository-name
docker exec -it <container_name> sh
```

</details>

<details>

<summary>Check Status of Container</summary>

```bash
docker ps
```

</details>

<details>

<summary>Remove Containers</summary>

```bash
docker rm <container ID>
docker rm -f $(docker ps -a -q)
```

</details>

<details>

<summary>Check Docker Images</summary>

```bash
docker images
```

</details>

<details>

<summary>Remove Images</summary>

```bash
docker rmi <image ID>
docker rmi $(docker images -a -q)
```

</details>

<details>

<summary>More Info</summary>



Only able to run Linux containers on Linux host, Windows containers on Windows host (because containers use the same kernel, underlying OS)

In short, [**docker run**](https://docs.docker.com/engine/reference/run/) is the command you use to create a new container from an image, whilst **docker exec** lets you run commands on an already running container!

`sudo docker network ls` --> shows all docker network driver means network type

`docker run -itd --rm --name thor busybox`

* \-itd: makes it interactable and detached (running in the background)
* \--rm: remove the container once it exits/stops
* \--name: name of the box
* last parameter: image to be used for the container

`sudo docker ps`

* Checking status of docker containers

`bridge link`

* Shows name of interface connected to the bridge (network switch)

`docker inspect bridge`

* Shows more details of the bridge network

`docker exec -u 0 -it thor sh`

* Runs the thor container

`docker run -itd --rm -p 80:80 --name stormbreaker nginx`

* Exposes container's port 80 to host port 80.

`docker stop stormbreaker`

* Stops the stormbreaker container.

`docker container ls -a`

* Shows all containers (even those not running) `docker rm -f $(docker ps -a -q)`
* Remove all containers

### Create Own Network (user-defined bridge)

`docker network create asgard`

* Create a docker network named asgard

`docker run -itd --rm --network asgard --name loki busybox`

* Create new container called loki with busybox image and connected to the asgard network

`docker inspect asgard`

* Inspects the asgard network

</details>
