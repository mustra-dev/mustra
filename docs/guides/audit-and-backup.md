# Audit log and server backups
<!-- group: Run mustra; order: 62; pages: /logs, /backup -->

See who did what, forward it to your SIEM, and keep a backup of the server you can restore from.

## Before you start

- Reading the audit log needs **Read the audit log** (`audit.read`). Changing log settings and making backups needs **Manage settings**. Restoring a backup made elsewhere also needs **Restore outside backups**.

## The audit log

**Administration → Audit Log** lists every change and every action on an endpoint: who, what, which endpoint, from which address, and whether it succeeded. Filter by person, action, target or time.

To keep it outside mustra, under **Forward to syslog, Splunk, or a SIEM**, enter the destination and choose **Save**. Every new event is sent as it happens.

**Log level** sets how much the server writes to its own log, for troubleshooting.

## Back up the server

A backup is a full copy of the server's database: endpoints, packages, policies, accounts, settings and history.

1. Open **Backup** and choose **Back up now**. Add a note to say why.
2. To back up every night, set the time under **Nightly backup** and choose **Save schedule**. Old backups are pruned automatically.
3. Download backups and keep a copy away from the server.

**Two things a backup does not carry by default**, both on the server's host: the encryption key `MUSTRA_CREDENTIAL_ENCRYPTION_KEY` in `deploy/.env` (restore with a different key and stored credentials cannot be read), and the NATS certificates in `deploy/nats/certs/` (without them, agents cannot connect). Either keep both with your backups, separately and securely, or have backups carry them encrypted:

### Include the configuration, encrypted

Backups can carry `deploy/.env`, `deploy/version.env`, the NATS certificates and the Cloudflare Tunnel credentials, encrypted with [age](https://age-encryption.org) to a key only you hold. The server never has the private key, so a stolen backup does not give these away.

1. On a machine other than the server, make a key: `age-keygen -o mustra-backup.key`. It prints the public key, `age1…`. Keep `mustra-backup.key` somewhere safe and offline: without it, the configuration in your backups cannot be read.
2. On the server, add the public key to `deploy/.env`: `MUSTRA_BACKUP_CONFIG_RECIPIENT=age1…`. Several keys, separated by commas, each open it.
3. Restart the stack (`docker compose up -d`). The snapshot is taken each time it starts, so restart after changing any of those files.
4. **Backup** now says the configuration is included, with the key it is encrypted to. Every backup from then on carries `config.tar.age`.

To restore onto a new host: take `config.tar.age` out of the backup, run `age -d -i mustra-backup.key config.tar.age | tar -xz -C deploy/`, start the stack, then restore the backup on **Backup → Restore**.

## Restore

1. **Backup → Restore**: choose **restore** on a backup in the list, or upload a file and choose **Restore from this file**.
2. Confirm. A restore replaces everything, including accounts and API tokens, with the backup's contents. Everyone is signed out.
