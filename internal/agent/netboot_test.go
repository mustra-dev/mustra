package agent

import "testing"

const efibootmgrSample = `BootCurrent: 0001
Timeout: 0 seconds
BootOrder: 0001,0003,0004,0005,0000
Boot0000* UiApp	FvVol(7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1)/FvFile(462caa21-7614-4503-836e-8ab6f4662331)
Boot0001* UEFI QEMU HARDDISK QM00001 	PciRoot(0x0)/Pci(0x1,0x1)/Ata(Primary,Master,0x0){auto_created_boot_option}
Boot0003* UEFI PXEv4 (MAC:525400AABBCC)	PciRoot(0x0)/Pci(0x3,0x0)/MAC(525400aabbcc,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0){auto_created_boot_option}
Boot0004* UEFI PXEv6 (MAC:525400AABBCC)	PciRoot(0x0)/Pci(0x3,0x0)/MAC(525400aabbcc,0x1)/IPv6([::]:<->[::]:,0x0){auto_created_boot_option}
Boot0005* UEFI HTTPv4 (MAC:525400AABBCC)	PciRoot(0x0)/Pci(0x3,0x0)/MAC(525400aabbcc,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri(){auto_created_boot_option}
Boot0006* UEFI PXEv4 (MAC:525400DDEEFF)	PciRoot(0x0)/Pci(0x4,0x0)/MAC(525400ddeeff,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0){auto_created_boot_option}
`

// The armed interface's IPv4 PXE entry wins over IPv6, HTTP and another
// interface's PXE entry, and the disk is never chosen.
func TestChooseNetworkEntryEfibootmgr(t *testing.T) {
	entries := parseEfibootmgr(efibootmgrSample)
	if len(entries) != 6 {
		t.Fatalf("parsed %d entries, want 6", len(entries))
	}
	e := chooseNetworkEntry(entries, "52:54:00:aa:bb:cc")
	if e == nil || e.ID != "0003" {
		t.Fatalf("chose %+v, want Boot0003", e)
	}
	if e := chooseNetworkEntry(entries, "52:54:00:dd:ee:ff"); e == nil || e.ID != "0006" {
		t.Fatalf("for the second NIC chose %+v, want Boot0006", e)
	}
	// An unknown MAC still gets an IPv4 PXE entry rather than nothing.
	if e := chooseNetworkEntry(entries, "00:11:22:33:44:55"); e == nil || (e.ID != "0003" && e.ID != "0006") {
		t.Fatalf("for an unlisted MAC chose %+v, want an IPv4 PXE entry", e)
	}
	disks := parseEfibootmgr("Boot0001* ubuntu\tHD(1,GPT,abc)/File(\\EFI\\ubuntu\\shimx64.efi)\nBoot0002* Windows Boot Manager\tHD(1,GPT,def)\n")
	if e := chooseNetworkEntry(disks, "52:54:00:aa:bb:cc"); e != nil {
		t.Fatalf("no network entry exists, but %+v was chosen", e)
	}
}

const bcdeditSample = `Firmware Boot Manager
---------------------
identifier              {fwbootmgr}
displayorder            {bootmgr}
                        {1d2c3b4a-0000-11ef-9a6b-806e6f6e6963}
                        {5e6f7a8b-0000-11ef-9a6b-806e6f6e6963}
timeout                 2

Windows Boot Manager
--------------------
identifier              {bootmgr}
device                  partition=\Device\HarddiskVolume1
path                    \EFI\Microsoft\Boot\bootmgfw.efi
description             Windows Boot Manager

Firmware Application (101fffff)
-------------------------------
identifier              {1d2c3b4a-0000-11ef-9a6b-806e6f6e6963}
description             EFI SCSI Device

Firmware Application (101fffff)
-------------------------------
identifier              {5e6f7a8b-0000-11ef-9a6b-806e6f6e6963}
description             EFI Network 0 for IPv4 (00-15-5D-01-02-03)

Firmware Application (101fffff)
-------------------------------
identifier              {9a8b7c6d-0000-11ef-9a6b-806e6f6e6963}
description             EFI Network 0 for IPv6 (00-15-5D-01-02-03)
`

func TestChooseNetworkEntryBcdedit(t *testing.T) {
	entries := parseBcdeditFirmware(bcdeditSample)
	if len(entries) != 3 {
		t.Fatalf("parsed %d firmware applications, want 3 (the boot managers are not entries): %+v", len(entries), entries)
	}
	e := chooseNetworkEntry(entries, "00:15:5d:01:02:03")
	if e == nil || e.ID != "{5e6f7a8b-0000-11ef-9a6b-806e6f6e6963}" {
		t.Fatalf("chose %+v, want the IPv4 network entry", e)
	}
	if e.Description != "EFI Network 0 for IPv4 (00-15-5D-01-02-03)" {
		t.Fatalf("description %q", e.Description)
	}
}

// bcdedit's field names are localized; the parser goes by shape.
func TestParseBcdeditLocalized(t *testing.T) {
	out := "Firmwareanwendung (101fffff)\r\n-------------------------------\r\nBezeichner              {5e6f7a8b-0000-11ef-9a6b-806e6f6e6963}\r\nBeschreibung            UEFI: PXE IPv4 Intel(R) Ethernet Connection\r\n"
	entries := parseBcdeditFirmware(out)
	if len(entries) != 1 || chooseNetworkEntry(entries, "") == nil {
		t.Fatalf("a German listing was not understood: %+v", entries)
	}
}
