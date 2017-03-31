# The shell sub-task

This sub-task allows you to use ``pig`` on interactive mode. For doing this you should call the
application with the following arguments:

```
you@SOMEWHERE:~/over/the/rainbow# pig --sub-task=shell
```

Just after will be presented a very simple shell prompt:

```
you@SOMEWHERE:~/over/the/rainbow# pig --sub-task=shell
~ _
```

With this shell you are able to do anything that you do on batch mode and also things that you do not.

Even on interactive mode is necessary to indicate the options ``--gateway`` or ``--no-gateway``, ``--net-mask``, ``--lo-iface``.
Depending on the loaded signatures, you also need to specify some additional options related with your desired task.

## Setting the pig options

There are two ways for doing this. You can pass these options when starting ``pig`` on "shell mode" or into the ``shell``
specify the options using the command ``set`` as follows:

```
~ set net-mask=255.255.255.0
~ set gateway=10.0.2.2
~ set lo-iface=eth0
```

To probe any ``pig``'s option you should call ``set`` without arguments.

```
~ set
        pig
        --sub-task=shell
        --net-mask=255.255.255.0
        --gateway=10.0.2.2
        --lo-iface=eth0
~
```

If due to some reason you want to remove an option you should use the command ``unset``:

```
~ unset net-mask
```

## Inline definition of pigsties

The interactive mode allows us to use the shell prompt as a very simple text editor and define signatures on the fly.

Any command started with ``[`` and ended with ``]`` is considered a pigsty. So:

```
~ [ ip.version = 4, ip.protocol = 6, signature = "silly-one" ]
1 signature was added. --
```

All we should do is define a pigsty using the rules explained in the main [``README.md``](https://github.com/rafael-santiago/pig/blob/master/README.md).

Sometimes a pigsty can be longer so a good way is to escape the line with a backslash to keep your sanity:

```
~ [ ip.version = 4,\
... ip.protocol = 17,\
... ip.src = user-defined-ip,\
... ip.dst = 224.12.23.3,\
... udp.src = 6,\
... udp.dst = 20,\
... udp.payload = "(null)",\
... signature = "s1lly-t0o" ]
1 signature was added. --
```

I find it good but only for minor tasks, things that you do not need to follow any method.

## Manipulating your loaded pigsties

When you have some specific routine task to perform, the best way is to save the related pigsties as files
and later load them all. When you use ``pig`` on standard ``batch-mode`` you can load previous pigsties with
the option ``--signatures``. On ``shell`` you can use the command ``pigsty`` with its ``sub-command`` called ``ld``:

```
~ pigsty ld /usr/local/pigsty/pentest-session-1.pigsty
```

If you have more than one file to load, you can pass them as a comma separated list. Take a look:

```
~ pigsty ld /usr/local/pigsty/pentest-session-1.pigsty, /usr/local/pigsty/pentest-session-2.pigsty,\
... /usr/local/pigsty/snort-rules-test/worms.pigsty,\
... /usr/local/pigsty/snort-rules-test/backdoors.pigsty,\
... /usr/local/pigsty/snort-rules-test/ddos-from-last-3-weeks.pigsty
```

Once the signatures loaded you can probe what your ``pig`` has into his brain using the sub-command ``ls``:

```
~ pigsty ls
-- SIGNATURES

        * silly-one
        * s1lly-t0o

2 entries were found. --
```

If you are looking for some specific pattern of signature name you can use the ``ls`` with a ``glob``:

```
~ pigsty ls *droids*
-- SIGNATURES

        * the-droids-that-we-are-looking-for

1 entry was found. --
```

We can also pass a comma separated list of patterns:

```
~ pigsty silly-one, *[Ss]ub?7*, *deep*
```

You can load a set of pigsties from a file with the sub-command ``ld``. In order to remove them from memory you should use the
sub-command ``rm``.

```
~ pigsty rm silly-one
```

The ``rm`` argument is taken as a glob, so:

```
~ pigsty rm *
```

Will remove every loaded pigsty from memory.

Also is valid to call ``rm`` as follows:

```
~ pigsty rm silly-one, *[Ss]ub?7*
```

There is a synonym for ``pigsty rm *`` command that is ``pigsty clear``.

## Sending packets without method, a.k.a flooding

In order to do it you should use the command ``flood``

```
~ flood
```

It will send random signatures based on the signatures previously read throught ``pigsty ld`` and/or ``--signatures=(...)``.
If you want to cancel this endless flood session you should press ``CTRL + c``.

Is also possible to flood with just a specific amount of random signatures:

```
~ flood 15
```

Again, if you want to cancel it, you should press ``CTRL + c``.

## Sending packets with some method

In ``shell`` mode ``pig`` allows you to do a more specific packet crafting. You can send a specific signature or still a
set of signatures based on a glob pattern. Besides the specification of signatures is also possible to indicate the
total of sendings for each found signature based on the supplied search pattern.

The command that allows you do it is ``oink``. Look:

```
~ oink SpaceCadet, Catamaran
```

The command sample above will send the signatures "SpaceCadet" and "Catamaran".

After the glob pattern, you can also specify the total of sendings:

```
~ oink "SpaceCadet", 10, Catamaran
```

This last shown command will send 10 packets of "SpaceCadet" signature and then 1 of "Catamaran".

```
~ oink "[sS]ub?7*", "NewApt*[Ww][Oo][Rr][Mm]*", 60
```

Now all signatures named using the pattern ``[sS]ub?7`` will be sent. Also any signature that its name matches the
pattern ``NewApt*[Ww][Oo][Rr][Mm]*`` will be sent sixty times.

## Executing external commands from the shell

When you are doing some pentest session or anything related, sometimes you need to switch to other applications, maybe
a text editor to take some notes, etc. Being on ``shell`` mode you can use the "outsider marker" in order to execute the
supplied command outside from the pig's shell.

The outsider marker is denoted by an exclamation symbol:

```
~ !ls /usr/local/report.txt
```

After the command execution you will back to the ``shell`` mode, so is possible to run programs that will hang the
prompt until their exit:

```
~ !mcedit /usr/local/report.txt
```

## Pig shell tricks

If you really enjoy using ``pig`` on shell mode and the ``network mask``, ``gateway`` and ``lo-iface`` data
never changes, you can pass this data when starting ``pig``:

```
you@SOMEWHERE:~/over/the/rainbow# pig --sub-task=shell \
> --net-mask=255.255.255.0 --gateway=10.0.2.2 --lo-iface=eth0
```

Even better: you can create a shell script to automate this call...

```bash
# pig-shell.sh
pig --sub-task=shell --net-mask=255.255.255.0 --gateway=10.0.2.2 --lo-iface=eth0
```

...and then:

```
you@SOMEWHERE:~/over/the/rainbow# ./pig-shell.sh
```

Maybe change the script to read the network config data from ``$1``...``$n`` arguments. Anyway, it is up to you.


## Commands summary

Well, now that you master all shell aspects present in ``pig`` here goes a short summary of all you have
been learning during this reading:


|     **Command**          |                      **What does it perform?**                            |
|:------------------------:|:-------------------------------------------------------------------------:|
| ``set <option>=<value>`` | Sets an option that will be used by the application                       |
| ``unset <option>``       | Removes a previous set option                                             |
| ``[ ... ]``              | Defines an inline pigsty                                                  |
| ``pigsty ld <file-path>``| Loads into the memory the supplied pigsty file                            |
| ``pigsty ls [<glob>]``   | Lists the current loaded pigsties                                         |
| ``pigsty rm <glob>``     | Removes signatures that match with the supplied glob pattern              |
| ``pigsty clear``         | Removes all pigsties from the memory                                      |
| ``flood  [<n>]``         | Sends random loaded signatures                                            |
| ``oink <glob>, [<n>]``   | Sends one time or n times signatures that match the supplied glob pattern |
| ``!<external-command>``  | Executes out of the shell the supplied command and returns back           |

The command line ``pig --sub-task=shell --help`` shows the command line help about this sub-task.

That's it! Have fun!
