# Provisioning
<!-- group: Manage endpoints; order: 12; pages: /provisioning -->

Install Ubuntu, Debian or Windows on a machine that boots from the network, or reinstall an existing endpoint, with the mustra agent enrolled at the new system's first boot.

## Before you start

- Turning provisioning on and adding images needs **Manage settings**. Machines and reimaging need **Deploy**; approving a reimage needs **Decide approvals**, and somebody other than the requester.
- Set the console's public URL (Client Management): installed systems enroll against it.
- Your DHCP server must hand network-booting machines iPXE (see **Chainload from DHCP**). mustra runs no DHCP or TFTP server.
- iPXE is not signed for Secure Boot: turn Secure Boot off on machines you install this way.

## Turn it on

1. Open **Provisioning → Settings**.
2. Enter the **Boot URL**, the address machines reach this server at, such as `http://10.0.20.5:8069`. With `MUSTRA_BOOT_HTTP_ADDR` set, the boot endpoints listen there and not on the console's address.
3. List the provisioning networks under **Allowed networks**, so nothing else is answered.
4. Tick **Provisioning on** and save.

## Chainload from DHCP

Give clients that are not iPXE yet an iPXE binary over TFTP (option 66, the TFTP server; option 67, `ipxe.efi` for UEFI or `undionly.kpxe` for BIOS). Give clients that already run iPXE the script shown under **Settings**, or build it into iPXE with `EMBED=`. The deployment guide has a proxy-DHCP example with dnsmasq that leaves your DHCP server alone.

## Add an image

1. Open **Provisioning → Images** and choose **Add an image**.
2. Pick the family and enter its boot files:
   - **Ubuntu:** `casper/vmlinuz` and `casper/initrd` from the live-server ISO, and the ISO's own URL as the install source.
   - **Debian:** the netboot `linux` and `initrd.gz`, and a mirror as the install source.
   - **Windows:** `wimboot`, and `BCD`, `boot.sdi` and `boot.wim` from your WinPE; the share holding your installation media (with `setup.exe` at its root) as the install source, with its user and password.
3. Each boot file is a URL, or a file you upload after saving. Uploaded files are served to anything that network-boots, so upload nothing secret.
4. Set a default administrator password, and defaults such as the timezone. Leave the answer template blank for the built-in one.

## Install a new machine

1. Open **Provisioning → Machines**, enter its MAC address, a name and its image, and save.
2. Choose **Install next boot**. Its disk is erased at its next network boot.
3. Boot it from the network. **Installs** shows the boot script served, the answer file fetched, the installer's reports and, last, the agent enrolling.

A machine boots its own disk after its answer file is fetched, and an arming nobody used lapses after a day.

## Reimage an endpoint

1. Open **Provisioning → Reimage** and pick the endpoint, its network interface and the image.
2. Type the endpoint's hostname and choose **Request reimage**.
3. Somebody else approves it under **Access → Approvals**. Then the endpoint is set to boot from the network once and restarts a minute later.
4. If the answer says the next boot could not be set (BIOS, macOS, an older agent), restart the machine and choose network boot from its boot menu, usually F12. It stays armed until it boots or the arming lapses.

## If a machine boots its disk instead

- It is not armed, or its arming lapsed: check **Machines**.
- Its image is missing a boot file, or a value cannot be written safely into the boot script: the audit log has a `provisioning.boot_refused` entry saying which.
- Its address is outside **Allowed networks**, or provisioning is off.
