# Enforce settings
<!-- group: Secure; order: 43; pages: /enforce -->

Hold a setting in place: check it on a timer, and put it back when it drifts. For example, keep the firewall on, keep BitLocker on, keep a risky service disabled.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`), because a fix runs a command on endpoints with full rights.
- Reading escrowed BitLocker recovery keys needs **Read BitLocker recovery keys** (`enforce.recovery_keys`), and every read is audited.

## How it keeps you safe

- **New policies only report.** They check and record and change nothing until you switch them to enforce.
- **Dry run** shows what an enforcing policy would do, without doing it.
- **It re-checks after fixing.** A fix only counts as *remediated* if the second check passes.
- **It gives up.** After three failed fixes in a row on one endpoint, it stops trying there and shows *given up*. Editing the policy or choosing **Reset history** lets it try again.
- **Every fix is in the audit log.**

## Create a policy

1. Open **Enforce → Policies**, then **New policy**.
2. Choose the platform and the computer group it applies to.
3. Choose **Add a setting**. Either pick a ready-made kind (**Windows Firewall**, **BitLocker**, **Microsoft Defender** or **AppLocker** for Windows, **Ansible playbook** for Linux) and its options, or write your own:
   - **Rules** that decide whether the setting holds, in the same format Comply uses. For example `c:systemctl is-active ufw -> r:^active` runs a command and matches its output.
   - A **Fix** command per platform. Leave it empty to only report drift.
   - Or start from a benchmark check in Comply (**Findings → create Enforce setting**). Its rules become the setting's test and you write the fix. See [Compliance](compliance.md#fix-failures-automatically).
4. Leave the mode on **Report — check and record only** and choose **Save policy**.
5. Choose **Run now** and read **Standing, per endpoint**: which endpoints are *compliant* and which have *drifted*.
6. When the results look right, edit the policy, set the mode to **Enforce — fix what has drifted**, and save. It runs every 30 minutes by default.

## Promote ring by ring

Instead of switching the whole policy to enforce at once, choose **Promote in rings** on a report-mode policy under **Standing** and pick a rollout plan (create plans under **Enforce → Rollouts**).

- The policy stays in report mode. Each pass enforces only on the endpoints of the rings promoted so far.
- A ring passes when enough of its endpoints came back *compliant* or *remediated* since it was promoted. *Unknown*, *drifted*, *failed* and endpoints that did not answer all count against it. After its soak it is checked again and the next ring is promoted.
- When the last ring passes, the policy switches to enforce for everything it targets.
- A ring that misses its threshold **halts** the promotion: its endpoints keep enforcing, no new ring is added. **Resume** accepts the ring and moves on; **Abort** puts every endpoint back to report.

## Hold Linux endpoints to an Ansible playbook

1. Install `ansible-core` on the endpoints, along with any roles or collections the playbook uses. Only the playbook itself is sent.
2. In **Enforce → Policies**, set **Policy type** to **Ansible playbook**.
3. Paste the playbook. Each play must be for `hosts: localhost` (or `all`): the endpoint runs it against itself.
4. Optionally add **Extra variables** as YAML, for example `motd: Managed by mustra`.
5. Tick **record what each task would change** to see diffs in the results. Diffs can show file contents to everyone who can read Enforce results, so mark tasks that handle secrets `no_log: true`.
6. Save in report mode and choose **Run now**. Each endpoint runs `ansible-playbook --check`: **drifted** lists the tasks that would change (choose **what would change**), **compliant** means none would.
7. Switch to enforce mode when the results look right. A drifted endpoint then runs the playbook and checks again.

A task that fails in check mode makes the result **unknown**, and an unknown endpoint is never changed. A task that needs an earlier task's change (a service from a package the play installs, say) fails in check mode; guard it with `when: not ansible_check_mode`.

## Read the results

**Standing, per endpoint** shows each endpoint's state for each setting:

| State | Meaning |
| --- | --- |
| compliant | The setting holds |
| drifted | It does not, and the policy is in report mode (or has no fix) |
| remediated | It did not, the fix ran, and the re-check passed |
| failed | The fix ran but the re-check still failed |
| given up | Three fixes failed in a row; it has stopped trying on this endpoint |
| unknown | The endpoint could not evaluate the rule (for a playbook: Ansible is missing, the playbook failed in check mode, or the endpoint is not Linux) |

Choose **output** to see what the check and fix commands printed.

**Coverage** shows the security posture of every endpoint: firewall, disk encryption, antivirus, application control and whether a recovery key is escrowed.
