### Docker Files

This folder contains some files that allow to spawn a docker container, which 
exposes some vulnerable Java RMI interfaces. The corresponding RMI endpoints can be used
to check the correct functionality of *rmg* and might also be useful for educational purposes. 


### Configuration Details

By using the **docker-compose.yml** file you will spawn a container that provides a RMI
registry on port **1099**. The corresponding RMI interfaces will be bound on random
ports and register theirself under the name *SuperCoolServer* and *AnotherSuperCoolServer*.

The *SuperCoolServer* RMI interface exposes three methods:

* public String notRelevant()
* public String execute(String command)
* public String system(String command, String[] args)

The *AnotherSuperCoolServer* RMI interface exposes three methods:

* public String notRelevant() throws RemoteException;
* public int execute(String cmd) throws RemoteException;
* public String system(String[] args) throws RemoteException;

For remote method guessing only the last two methods on each interface are of interest,
as both allow the execution of arbitrary operating system commands. 

The **docker-compose.yml** file does not map any ports on your docker host system. You have to 
target the ip address of the docker container explicitly to connect to the exposed services.


### Startup & Shutdown

Make sure you have installed docker compose:

```bash
pip install docker-compose
```

For starting and stopping the container you can simply use the following commands:

```bash
docker-compose up # Startup
docker-compose stop # Shutdown
```
