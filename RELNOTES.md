# pig - Release Notes

## Version: 0.0.1

### Features

- Signatures based on ``IPv4`` packets (``TCP``/``UDP``).

- Signatures based on ``IPv4`` packets (non ``TCP``/``UDP``) using raw definition by ``ip.payload`` field.

- ``Geo-ip`` usage on ``ip.src`` and ``ip.dst`` fields.

- Targets range specifying for ``ip.src`` and ``ip.dst`` fields.

- Timeout setting up.

### Bugfixes

- SIGNATURE_FIELDS[] misconfiguration [``commit-id``: #13cbb3]

- Buffer overrun when making udp packet buffers with payloads [``commit-id``: #53517f].

- ``Issue#1``: Adding to the repo the GPL copy [``commit-id``: #855773].

- ``Issue#2``: Reserved identifier violation [``commit-id``: #4a8857].

- ``Issue#3``: Fix signal handler [``commit-id``: #2b6a8f].

## Version: 0.0.2

### Features

- Signatures based on ``IPv4/ICMP`` packets.

- Ethernet frame generation.

- Including three new mandatory options: ``--gateway``, ``--net-mask`` and ``--lo-iface``.

- Including this release notes (``RELNOTES.md``).

- Loopback packets handling.

- Improvements on pigsty parser and compiler.

### Bugfixes

- Pigsty parsing improvements [``commit-id``: #2834ab].

- Usage tip [``commit-id``: #8817bc].

- Buffer overrun [``commit-id``: #388f0a].

- Packet sending [``commit-id``: #6bc106].

- Ethernet frame composition [``commit-id``: #95ca99].

- Binary payload parsing [``commit-id``: #b9605c].

- Good manner: stripping off the evil strcat [``commit-id``: #7f9a80].

## Version: 0.0.3

### Features

- Signatures based on ``ARP`` packets.

- Optional gateway usage.

- Including a little ``ARP Spoofing how to``.

### Bugfixes

- Segmentation Fault on IPv4 verifying [``commit-id``: #19e1a4].
