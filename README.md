# Pig

``Pig`` (which can be understood as ``P``acket ``i``ntruder ``g``enerator) is a ``Linux`` packet crafting tool.
You can use ``Pig`` to test your ``IDS``/``IPS`` among other stuffs.

``Pig`` brings a bunch of well-known attack signatures ready to be used and you can expand this collection
with more specific things according your requirements.

Until now it is possible to create ``IPv4`` signatures with transport layer based on ``TCP``, ``UDP`` and ``ICMP``.

# How to clone this repo?

It is pretty simple:

``git clone https://github.com/rafael-santiago/pig pig``

``cd pig``

``git submodule update --init``

# How to build it?

You need to use the [``Hefesto``](https://github.com/rafael-santiago/hefesto) to build ``pig``. After following
the steps to put ``Hefesto`` working on your system. Move to the ``pig`` subdirectory named as ``src`` and run the following command:

``hefesto``

After this command you should find the ``pig`` binary under the path ``src/bin``.

# The pigsty files

``Pigsty files`` are plain text files where you can define a set of packet signatures. There is a specific syntax to be
followed. Look out an example of a pigsty file:

        [ signature   =      "Hello",
          ip.version  =            4,
          ip.ihl      =            5,
          ip.tos      =            0,
          ip.src      = 192.30.70.10,
          ip.dst      =  192.30.70.3,
          ip.protocol =           17,
          udp.dst     =         1008,
          udp.src     =        32000,
          udp.payload =    "Hello!!" ]

Basically, all signature data must goes between square brackets: ``[`` ... ``]``.

Inside this area the piece of information is supplied by the scheme ``field = data``.

If you have some experience with Computer Networks is sure that the majority of fields listed on ``Table 1``
have strong meaning for you. You must use these fields to create your further signatures.

**Table 1**: The ``pig`` signature fields.

|    **Field**    |   **Stands for**   |  **Protocol** | **Data type** |     **Sample definition**   |
|:---------------:|:------------------:|:-------------:|:-------------:|:---------------------------:|
| ``signature``   | The signature name |       -       |     string    | ``signature = "Udp flood"`` |
|``ip.version``   |    IP version      |      *IP*     |     number    |      ``ip.version = 4``     |
|  ``ip.ihl``     | Internet Header Len|      *IP*     |     number    |         ``ip.ihl = 5``      |
|  ``ip.tos``     |    Type of service |      *IP*     |     number    |         ``ip.tos = 0 ``     |
| ``ip.tlen``     |     Total Length   |      *IP*     |     number    |         ``ip.tlen = 20``    |
|  ``ip.id``      |       Packet ID    |      *IP*     |     number    |       ``ip.id = 0xbeef``    |
| ``ip.flags``    |       IP Flags     |      *IP*     |     number    |       ``ip.flags = 4``      |
| ``ip.offset``   |   Fragment offset  |      *IP*     |     number    |       ``ip.offset = 0``     |
|  ``ip.ttl``     |   Time to live     |      *IP*     |     number    |          ``ip.ttl = 64``    |
|``ip.protocol``  |       Protocol     |      *IP*     |     number    |       ``ip.protocol = 6``   |
|``ip.checksum``  |       Checksum     |      *IP*     |     number    |       ``ip.checksum = 0``   |
|   ``ip.src``    |   Source address   |      *IP*     |  ip address   |    ``ip.src = 192.30.70.3`` |
|   ``ip.dst``    |   Dest. address    |      *IP*     |  ip address   |    ``ip.dst = 192.30.70.3`` |
| ``ip.payload``  |   IP raw payload   |      *IP*     |     string    |  ``ip.payload = "\x01\x02"``|
|   ``tcp.src``   |    Source port     |      *TCP*    |     number    |         ``tcp.src = 80``    |
|   ``tcp.dst``   |    Dest. port      |      *TCP*    |     number    |         ``tcp.dst = 21``    |
| ``tcp.seqno``   |  Sequence number   |      *TCP*    |     number    |        ``tcp.seqno = 10202``|
| ``tcp.ackno``   | Acknowledge number |      *TCP*    |     number    |       ``tcp.ackno = 10200`` |
|  ``tcp.size``   |     TCP Length     |      *TCP*    |     number    |       ``tcp.size = 4``      |
|``tcp.reserv``   | TCP reserv. field  |      *TCP*    |     number    |       ``tcp.reserv = 0``    |
|   ``tcp.urg``   |  TCP urg. flag     |      *TCP*    |       bit     |       ``tcp.urg = 0``       |
|   ``tcp.ack``   |  TCP ack. flag     |      *TCP*    |       bit     |       ``tcp.ack = 1``       |
|   ``tcp.psh``   |  TCP psh. flag     |      *TCP*    |       bit     |       ``tcp.psh = 0``       |
|   ``tcp.rst``   |  TCP psh. flag     |      *TCP*    |       bit     |       ``tcp.rst = 0``       |
|   ``tcp.syn``   |  TCP syn. flag     |      *TCP*    |       bit     |       ``tcp.syn = 0``       |
|   ``tcp.fin``   |  TCP fin. flag     |      *TCP*    |       bit     |       ``tcp.fin = 0``       |
|  ``tcp.wsize``  |  TCP window size   |      *TCP*    |     number    |       ``tcp.wsize = 0``     |
|``tcp.checksum`` |    Checksum        |      *TCP*    |     number    |       ``tcp.checksum = 0``  |
|``tcp.urgp``     |  Urgent pointer    |      *TCP*    |     number    |      ``tcp.urgp = 0``       |
|``tcp.payload``  |      Payload       |      *TCP*    |     string    | ``tcp.payload = "\x01abc"`` |
|   ``udp.src``   |    Source port     |      *UDP*    |     number    |        ``udp.src = 53``     |
|   ``udp.dst``   |    Dest. port      |      *UDP*    |     number    |        ``udp.dst = 7``      |
|   ``udp.size``  |     UDP Length     |      *UDP*    |     number    |       ``udp.size = 8``      |
|``udp.checksum`` |      Checksum      |      *UDP*    |     number    |       ``udp.checksum = 0``  |
|``udp.payload``  |      Payload       |      *UDP*    |     number    |    ``udp.payload = "boo!"`` |
| ``icmp.type``   |     ICMP type      |     *ICMP*    |     number    |       ``icmp.type = 0``     |
| ``icmp.code``   |     ICMP code      |     *ICMP*    |     number    |        ``icmp.code = 0``    |
|``icmp.checksum``|     Checksum       |     *ICMP*    |     number    |    ``icmp.checksum = 0``    |
|``icmp.payload`` |     Payload        |     *ICMP*    |     string    |  ``icmp.payload = "ping!"`` |

When creating a signature you do not need specify all data. If you specify only the most relevant packet parts
the remaining parts will be filled up with default values. The ``checksums`` are **always** recalculated.

Tip: take a look in subdirectory ``pigsty``. You will find lots of signature files and you will see that is pretty simple define new ones.

## Specifying IP addresses geographically

Yes, this is possible. In order to use this feature you just need to specify the values listed on ``Table 2``
in ``ip adddress`` typed fields.

**Table 2**: IPs by geographic area.

|   **Value to use**  |          **Stands for**         |
|:-------------------:|:-------------------------------:|
|``north-american-ip``| IP addresses from North America |
|``south-american-ip``| IP addresses from South America |
|    ``asian-ip``     | IP addresses from Asia          |
|   ``european-ip``   | IP addresses from Europe        |

## Specifying my own addresses

You should in any ``ip address`` typed field use ``user-defined-ip`` as value. Note that you need to use the
command line option ``--targets`` in this case. See section "``Using pig``" for more information.

# Contribute sending more packet signatures

If you create ``pigsty files`` that you judge be relevant beyond your own environment open a pull request in order
to include these useful files here. Thank you in advance!

# Using pig

The ``Pig`` usage is very straightforward being necessary to supply four basic options which are: ``--signatures``, ``--gateway``, ``--net-mask``, ``--lo-iface``.

Do you want to know more about each option, huh?... So let's go:

- The option ``--signatures`` receives a list of file paths to ``pigsty files``.
- The option ``--gateway`` is where you specify your gateway address. Be aware that ``pig`` generates or at least try to generate the ``ethernet frames`` too. Due to it the gateway address is rather important in order to right composition of the ``layer-1`` data.
- The option ``--net-mask`` for routing issues must receive your network mask.
- The option ``--lo-iface`` is the place where you should inform the name of the local network interface you will use to "drain out" the generated packets.

Supposing that we want to generate ``DDos`` based traffic:

``pig --signatures=pigsty/ddos.pigsty --gateway=10.0.2.2 --net-mask=255.255.255.0 --lo-iface=eth0``

Now we want to messing around with everything:

``pig --signatures=pigsty/ddos.pigsty,pigsty/attackresponses.pigsty,pigsty/badtraffic.pigsty,pigsty/backdoors.pigsty --gateway=10.0.2.2 --net-mask=255.255.255.0 --lo-iface=eth0``

## Extra options

### Defining timeouts between the signature sendings

For it use the option ``--timeout=<millisecs>``

### Echo suppressing

Use the ``--no-echo`` option.

### Defining targets

Use the ``--targets`` option. You can specify a list based on exact IPs, IP masks and [``CIDRs``](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

Look this:

``pig --signatures=pigsty/local-mess.pigsty --targets=192.30.70.3,192.30.70.*,192.30.70.0/9 --gateway=10.0.2.2 --net-mask=255.255.255.0 --lo-iface=eth0``

### Sending only one signature and going back

Maybe you need to send only one signature and so return to the caller in order to check what happened after. This kind of
requirement is common when you use this application as support for ``system tests`` or ``unit tests``. So, if you need
to do this you should try to use the option ``--single-test``:

``pig --signature=pigsty/syn-scan.pigsty --targets=127.0.0.1 --single-test --gateway=10.0.2.2 --net-mask=255.255.255.0 --lo-iface=eth0``

After run this command ``pig`` will select only one signature from the file ``syn-scan.pigsty`` and try to send it and then exit.
If some error has occurred during the process ``pig`` will exit with ``exit-code`` equals to ``1`` otherwise ``pig`` will exit
with ``exit-code`` equals to ``0``.

## Testing from scratch

Save the following data as ``"oink.pigsty"``:

        [ signature   =           "oink",
          ip.version  =                4,
          ip.ihl      =                5,
          ip.tos      =                0,
          ip.src      =        127.0.0.1,
          ip.dst      =  user-defined-ip,
          ip.protocol =               17,
          udp.dst     =             1008,
          udp.src     =            32000,
          udp.payload =        "Oink!!\n" ]

On another ``tty`` run the ``netcat`` in ``UDP mode`` listen for connections on port ``1008``:

``nc -u -l -p 1008``

Now run ``pig`` using this ``pigsty file`` and informing as target the ``loopback``:

``pig --signatures=oink.pigsty --targets=127.0.0.1 --gateway=10.0.2.2 --net-mask=255.255.255.0 --lo-iface=eth0``

The ``netcat`` should start receive several ``oinks`` and... yes, congrats!! ``pig`` is up and running on your system! ;)

Try to sniff your Network to get more information about these ``UDP packets`` that are flowing around your interfaces... Have fun!

Santiago.
