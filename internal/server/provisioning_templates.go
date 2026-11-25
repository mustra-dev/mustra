package server

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

// The built-in answer templates, one per family. An image may carry its
// own instead; it sees the same answerData and the same escapers
// (answerFuncs), and is test-rendered when saved.
//
// The rule every template follows: a value goes through the escaper for
// the format it lands in — yaml for autoinstall, line for preseed, xml for
// unattend.xml, sh inside a shell command — even though every variable is
// already held to a narrow pattern. The pattern is what the value may be;
// the escaper is what makes the file read it as exactly that.

// Report is the shell command that posts an installer status with curl.
// It never fails the step it runs in.
func (d answerData) Report(status string) string {
	return "curl -fsS -m 10 -d status=" + status + " " + shQuote(d.StatusURL) + " >/dev/null 2>&1 || true"
}

// ReportWget is Report for the Debian installer, whose busybox has wget
// but no curl.
func (d answerData) ReportWget(status string) string {
	return "wget -q -O /dev/null --post-data=status=" + status + " " + shQuote(d.StatusURL) + " || true"
}

// DiskPath is the disk as a Linux device path, or "" (largest disk).
func (d answerData) DiskPath() string {
	if strings.HasPrefix(d.Disk, "/dev/") {
		return d.Disk
	}
	return ""
}

// DiskNumber is the disk as a Windows disk number, 0 unless one was given.
func (d answerData) DiskNumber() string {
	if d.Disk != "" && !strings.HasPrefix(d.Disk, "/dev/") {
		return d.Disk
	}
	return "0"
}

// FirstbootUnit is the systemd unit the Debian template installs to run
// FirstbootScript once, after the network is up.
const firstbootUnit = `[Unit]
Description=Enroll the mustra agent (first boot)
Wants=network-online.target
After=network-online.target
ConditionPathExists=/usr/local/sbin/mustra-firstboot

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/bin/sh /usr/local/sbin/mustra-firstboot && rm -f /usr/local/sbin/mustra-firstboot'

[Install]
WantedBy=multi-user.target
`

// DebianLateCommand installs the first-boot enrollment (and the SSH key)
// into the new system and reports the install finished. Files go across
// base64-encoded, whose alphabet the shell does not interpret, and are
// decoded by the target's own coreutils.
func (d answerData) DebianLateCommand() string {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	parts := []string{
		"echo " + b64(d.FirstbootScript) + " > /target/tmp/mustra-firstboot.b64",
		"echo " + b64(firstbootUnit) + " > /target/tmp/mustra-firstboot.unit.b64",
		"in-target sh -c 'base64 -d /tmp/mustra-firstboot.b64 > /usr/local/sbin/mustra-firstboot && chmod 700 /usr/local/sbin/mustra-firstboot" +
			" && base64 -d /tmp/mustra-firstboot.unit.b64 > /etc/systemd/system/mustra-firstboot.service" +
			" && rm -f /tmp/mustra-firstboot.b64 /tmp/mustra-firstboot.unit.b64 && systemctl enable mustra-firstboot.service'",
	}
	if d.SSHKey != "" {
		home := "/home/" + d.AdminUser
		parts = append(parts, "echo "+b64(d.SSHKey+"\n")+" > /target/tmp/mustra-key.b64",
			"in-target sh -c "+shQuote("install -d -m 700 -o "+d.AdminUser+" -g "+d.AdminUser+" "+home+"/.ssh && base64 -d /tmp/mustra-key.b64 >> "+home+
				"/.ssh/authorized_keys && chown "+d.AdminUser+": "+home+"/.ssh/authorized_keys && chmod 600 "+home+"/.ssh/authorized_keys && rm -f /tmp/mustra-key.b64"))
	}
	parts = append(parts, d.ReportWget("installed"))
	return strings.Join(parts, "; ")
}

// WindowsFirstLogon is the command the first sign-in runs: report the
// install finished, then enroll, retrying until the console answers. It
// is a PowerShell -EncodedCommand, so nothing in it is parsed by cmd or by
// the answer file's XML.
func (d answerData) WindowsFirstLogon() string {
	script := "$ErrorActionPreference='Stop'\n" +
		"try { Invoke-RestMethod -UseBasicParsing -Method Post -Body 'status=installed' -Uri " + psQuoteString(d.StatusURL) + " | Out-Null } catch {}\n" +
		"for ($i = 0; $i -lt 30; $i++) {\n" +
		"  try { " + d.EnrollWindows + "; break } catch { Start-Sleep -Seconds 20 }\n" +
		"}\n"
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

var defaultAnswerTemplates = map[string]string{
	"ubuntu": `#cloud-config
# mustra answer file for {{line .Hostname}} (install {{line .InstallID}}). It is served once.
autoinstall:
  version: 1
  locale: {{yaml .Locale}}
  keyboard:
    layout: {{yaml .Keyboard}}
  timezone: {{yaml .Timezone}}
  identity:
    hostname: {{yaml .Hostname}}
    username: {{yaml .AdminUser}}
    password: {{yaml .AdminPasswordHash}}
  ssh:
    install-server: true
    allow-pw: {{if .SSHKey}}false{{else}}true{{end}}
{{- if .SSHKey}}
    authorized-keys:
      - {{yaml .SSHKey}}
{{- end}}
  storage:
    layout:
      name: lvm
      match:
{{- if .DiskPath}}
        path: {{yaml .DiskPath}}
{{- else}}
        size: largest
{{- end}}
  early-commands:
    - {{yaml (.Report "installing")}}
  late-commands:
    - {{yaml (.Report "installed")}}
  error-commands:
    - {{yaml (.Report "failed")}}
  user-data:
    runcmd:
      - [sh, -c, {{yaml .FirstbootScript}}]
`,

	"debian": `# mustra answer file for {{line .Hostname}} (install {{line .InstallID}}). It is served once.
d-i debian-installer/locale string {{line .Locale}}
d-i keyboard-configuration/xkb-keymap select {{line .Keyboard}}
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string {{line .Hostname}}
d-i netcfg/hostname string {{line .Hostname}}
d-i netcfg/get_domain string
d-i mirror/country string manual
d-i mirror/http/hostname string {{line .MirrorHost}}
d-i mirror/http/directory string {{line .MirrorPath}}
d-i mirror/http/proxy string
d-i passwd/root-login boolean false
d-i passwd/user-fullname string mustra administrator
d-i passwd/username string {{line .AdminUser}}
d-i passwd/user-password-crypted password {{line .AdminPasswordHash}}
d-i clock-setup/utc boolean true
d-i time/zone string {{line .Timezone}}
{{- if .DiskPath}}
d-i partman-auto/disk string {{line .DiskPath}}
{{- end}}
d-i partman-auto/method string lvm
d-i partman-auto-lvm/guided_size string max
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-efi/non_efi_system boolean true
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string curl sudo ca-certificates
d-i pkgsel/upgrade select safe-upgrade
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string default
d-i preseed/early_command string {{line (.ReportWget "installing")}}
d-i preseed/late_command string {{line .DebianLateCommand}}
d-i finish-install/reboot_in_progress note
`,

	"windows": `<?xml version="1.0" encoding="utf-8"?>
<!-- mustra answer file for {{xml .Hostname}} (install {{xml .InstallID}}). It is served once. -->
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>{{xml .LocaleTag}}</UILanguage></SetupUILanguage>
      <InputLocale>{{xml .Keyboard}}</InputLocale>
      <SystemLocale>{{xml .LocaleTag}}</SystemLocale>
      <UILanguage>{{xml .LocaleTag}}</UILanguage>
      <UserLocale>{{xml .LocaleTag}}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>{{xml .DiskNumber}}</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{{xml .ImageIndex}}</Value></MetaData></InstallFrom>
          <InstallTo><DiskID>{{xml .DiskNumber}}</DiskID><PartitionID>3</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
{{- if .ProductKey}}
        <ProductKey><Key>{{xml .ProductKey}}</Key></ProductKey>
{{- end}}
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{{xml .Hostname}}</ComputerName>
      <TimeZone>{{xml .Timezone}}</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>{{xml .Keyboard}}</InputLocale>
      <SystemLocale>{{xml .LocaleTag}}</SystemLocale>
      <UILanguage>{{xml .LocaleTag}}</UILanguage>
      <UserLocale>{{xml .LocaleTag}}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>{{xml .AdminUser}}</Name>
            <Group>Administrators</Group>
            <Password><Value>{{xml .AdminPassword}}</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>{{xml .AdminUser}}</Username>
        <Password><Value>{{xml .AdminPassword}}</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>{{xml .WindowsFirstLogon}}</CommandLine>
          <Description>Report the install and enroll the mustra agent</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
`,
}
