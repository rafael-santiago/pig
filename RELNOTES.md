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

## Version: 0.0.2 - rc

### Features

- Signatures based on ``IPv4/ICMP`` packets.

- Ethernet frame generation.

- Including three new mandatory options: ``--gateway``, ``--net-mask`` and ``--lo-iface``.

- Including this release notes (``RELNOTES.md``).

### Bugfixes

- Pigsty parsing improvements [``commit-id``: #2834ab].

- Usage tip [``commit-id``: #8817bc].

- Buffer overrun [``commit-id``: #388f0a].

- Packet sending [``commit-id``: #6bc106].

- Ethernet frame composition [``commit-id``: #95ca99].
