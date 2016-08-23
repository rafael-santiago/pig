# The pcap-import sub-task

This sub-task can be useful when you have a ``PCAP`` file and want to export all packets inside of it
into a pigsty file.

For instance, supposing that you have sniffed attacks on your network and saved it as a ``PCAP`` file.
Later you realize that it should be nice to reconstruct the "crime scene" in order to know more about
how your Network reacts to it.

To convert a huge ``PCAP`` file into a pigsty can be a hard work. Then the ``pcap-import`` can save
your ass...

It requires two basic options:

- ``--pcap=<pcap-file-path>``
- ``--pigsty=<output-pigsty-file-path>``

If you have ``PCAP`` data into a file called ``net0WNrk.pcap``. You should:

```
you@SOMEWHERE:~/over/the/hacked/rainbow# pig --sub-task=pcap-import\
> --pcap=net0WNrk.pcap\
> --pigsty=crime-scene.pigsty
```

Now you can use ``crime-scene.pigsty`` to reconstruct the attack. However, in this specific case the usage of
``--loop=sequential`` should be necessary. Bear in mind that it is useful to see how your Network protections
react. Do not be naive thinking that it will restabilish the connections... Ha-ha!

The ``--pigsty`` option does not overwrite a previous existent pigsty. If it already exists the imported
data will be appended to it.

If you are looking for exporting even the ``Ethernet`` frames in order to use the original physical addresses
present into the ``PCAP`` file. You should add the option ``--include-ethernet-frames`` to the importing command.

When imported, the packets are named using sequential indexing. Then, if you are appending these data into a
previous pigsty is important to use a signature name which does not produce any name clash with the previous ones.
For doing it use the option ``--signature-fmt=<signature-name>``. Into the ``<signature-name>`` you can use ``%d``
to indicate where the index should be placed. For instance:

```
you@SOMEWHERE:~/over/the/hacked/rainbow# pig --sub-task=pcap-import\
> --signature-fmt="w33k_2-packet[%d]"\
> --pcap=all-over-again.pcap --pigsty=crime-scene.pigsty\
> --include-ethernet-frames
```

Now you master this sub-task. Anyway, if for some reason you want to access the command line help:

```
you@SOMEWHERE:~/over/the/rainbow# pig --sub-task=pcap-import --help
```
