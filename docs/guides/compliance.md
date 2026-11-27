# Compliance
<!-- group: Secure; order: 42; pages: /compliance -->

Check endpoints against a security baseline such as the CIS Benchmarks, see a hardening score per endpoint, and report by control for NIST SP 800-53 and 800-171.

## Before you start

- Reading results needs **See the fleet**. Importing policies and running scans needs **Manage patches** (`patches.manage`).

## How it works

A **policy** is a list of checks: "the firewall is on", "SSH root login is disabled", "the disk is encrypted". Each endpoint runs the checks for its own operating system and reports **pass**, **fail** or **unknown**. A check the endpoint cannot evaluate is *unknown*, never a pass.

A built-in **Linux baseline** works from the first minute. For Windows and macOS, and for full benchmarks on Linux, import CIS policies.

## Run the built-in baseline

1. Open **Comply → Policies**.
2. Choose **run on fleet** next to **Linux baseline (built in)**.
3. Results appear under **Findings** within a minute or two.

## Import a CIS Benchmark

mustra reads policies in the Wazuh SCA format, which covers CIS Benchmarks for most operating systems.

1. Download the policy for your OS from the Wazuh project's `ruleset/sca` folder (for example `cis_ubuntu22-04.yml` or `cis_win11_enterprise.yml`).
2. **Comply → Policies**, under **Import a Wazuh SCA policy**, choose the file and **Import**.
3. Choose **Scan now** on the Comply page. Endpoints whose OS matches the benchmark run it.
4. To scan every day by itself, tick **scan every endpoint daily** (this needs **Manage settings**).

## Read the results

- **Hardening score per endpoint**: the share of checks passing.
- **Checks, worst first**: each check with how many endpoints fail it. Open one to see the endpoints and the reason.
- **Failures by endpoint**: the same, per machine.
- **Controls**: results grouped by framework control (NIST SP 800-53, NIST SP 800-171 and others listed in the benchmark). Each control is *failing* if any check mapped to it fails. **Export CSV** gives auditors the full table.

## Accept a known exception

Some failures are deliberate, such as a kiosk that must auto-login.

1. On the failing check, choose **add exception** (or **Comply → Exceptions → Add exception**).
2. Choose the check, the endpoints or group, a reason, and an expiry date.
3. Excepted results show as **excepted**, not pass, and come back as failures when the exception expires.

## Fix failures automatically

Comply reports; it changes nothing. To put a setting right and keep it right, create an **Enforce** policy. See [Enforce settings](enforce.md).

You can start one from a check. This needs **Deploy software and run actions** (`deploy.manage`), as writing an Enforce setting does:

1. Under **Findings**, choose **create Enforce setting** on a check, or on one endpoint's failure. To do several at once, tick them (or filter the Check column by a benchmark's name and choose **Select the failing checks shown**), then **Add to Enforce**.
2. Choose where it goes: a new policy, which starts in report mode, or an existing policy that is still in report mode.
3. Write the **Fix**. The benchmark's remediation text is copied in as `#` comments. Comments run nothing, so a fix with only comments reports drift and never "fixes" anything.
4. Choose **Create setting**, then open the policy in Enforce, run it, and read the results before you switch it to enforce.

The setting's test is the check's own rules, unchanged. If the engine cannot read some of them on that platform (a registry rule on Linux, a regular expression Go cannot compile), the dialog names each one and says why. They are kept, not dropped. Where they decide the result the setting reports *unknown*, never compliant, and it can't have a fix: the re-check after a fix could never confirm it.

Making a setting from a check that already has one links to that setting rather than copying it. The exception is adding the check to a different existing policy on purpose.
