# Discover and backup status
<!-- group: See your fleet; order: 26; pages: /discover, /backup-status -->

See every device on your networks, including the ones mustra does not manage yet, and whether your virtual machines and servers are backed up.

## Before you start

- Reading needs **See the fleet**. Labelling devices needs **Manage computer groups**; Discover's settings and connecting backup systems need **Manage settings**; network surveys need **Deploy software**.

## Discover

Every endpoint reports the devices it sees on its local network (its ARP neighbours). **Discover** combines them into one list: every IP and MAC address, the vendor of its network card, when it was first and last seen, and whether it runs the mustra agent.

1. Open **Discover**. Devices without an agent are the ones to look at: printers and phones are expected, an unknown laptop is not.
2. Choose **Label** on a device to name it, so it stops looking unknown.
3. Turn on new-device alerts to get a Guide item when a device appears for the first time.

To install the agent on Linux and macOS devices found here, use **Client Management → Network Scan & Push**. See [Install agents](install-agents.md).

## Identify devices with a network survey

A neighbour table says a device is there, not what it is. A survey asks the devices themselves, using read-only requests: SNMP, IPP for printers, Modbus device identification, BACnet Who-Is, EtherNet/IP List Identity and Profinet DCP Identify. Nothing is ever written to a device. Creating and running surveys needs **Deploy software**; SNMP needs the server's credential encryption key.

1. Under **Network surveys**, choose **New survey**.
2. Pick one or more endpoints that sit on the network you want to look at, and enter the subnets, one per line (for example `192.168.10.0/24`, at most a /22 each). Each subnet must be a network the endpoint is directly attached to; tick **Allow subnets the endpoints are not directly attached to** only when you mean to probe across a router.
3. Choose the protocols. For SNMP, enter a read-only v2c community or a v3 user. The secrets are stored encrypted and never shown again; leave a field empty when editing to keep it.
4. Keep the rate gentle on networks with old controllers: 20 probes per second and 8 hosts at once are the defaults. **Stop the run after** ends the run whatever it has reached.
5. Tick **Enabled**, choose **Create survey**, then **Run now**. Set **Repeat every** to run it on a schedule.

**Recent runs** shows each endpoint's run: *running*, *finished*, *timed out*, *no response* (the endpoint is offline or did not answer), *refused* (none of the subnets is on its networks) or *agent too old*. Devices that answered appear in the list above with their type, vendor and model; choose **Details** for firmware, serial number, toner levels and interfaces, and filter the list by **type**. Profinet works from Linux endpoints only.

## Backup status

**Backup Status** shows whether each virtual machine, container and server has a recent, verified backup.

- **Proxmox VE**: install the mustra agent on each Proxmox node. It reads every guest's newest backup and whether a backup job covers it.
- **Proxmox Backup Server** and **Rubrik Security Cloud**: under **Connect a backup system**, enter the address and a read-only API token or service account, and choose **Connect**. They are read every 15 minutes; **Read now** reads them immediately.

Each guest or server is rated **ok**, **overdue** (no backup in the last 36 hours, by default), **never** backed up, or **not covered** by any job. Overdue and never raise a Guide item, once per episode. Change the threshold under the page's settings and choose **Save**.
