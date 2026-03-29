# wazuh-auditd-laurel

Wazuh detection rules for Linux audit logs processed by [LAUREL](https://github.com/threathunters-io/laurel). Includes auditd rules, a LAUREL installation script, and the Wazuh decoders/rules to make sense of it all.

## What's in here

```
auditd/ubuntu/audit.rules       # auditd ruleset (Ubuntu-targeted, mostly portable)
auditd/ubuntu/audit-test.sh     # Script to verify every audit rule fires correctly
laurel/install-laurel.sh        # Builds and installs LAUREL from source
wazuh/decoders/laurel_decoder.xml  # Wazuh decoder for LAUREL JSON output
wazuh/rules/laurel_rules.xml    # Wazuh alerting rules for LAUREL events
```

## How the pieces fit together

1. **auditd** captures kernel-level events (file access, execve, privilege escalation, etc.)
2. **LAUREL** sits as an auditd plugin, enriches the raw audit events, and writes structured JSON
3. **Wazuh agent** reads LAUREL's JSON log and forwards it to the Wazuh manager
4. **Wazuh manager** decodes the JSON and evaluates it against the detection rules

## Setup

### Agent side (monitored host)

0. If not yet installed, install auditd and clone this repository.

1. Deploy the rules:
   ```
   sudo cp auditd/ubuntu/audit.rules /etc/audit/rules.d/audit.rules
   systemctl restart auditd
   ```

2. Install LAUREL:
   ```
   sudo bash laurel/install-laurel.sh
   ```

### Manager side

1. Deploy the decoder and rules:
   ```
   cp wazuh/decoders/laurel_decoder.xml /var/ossec/etc/decoders/
   cp wazuh/rules/laurel_rules.xml /var/ossec/etc/rules/
   ```
   Or add the decoder and rules via the Dashboard.

2. Restart the Wazuh manager:
   ```
   systemctl restart wazuh-manager
   ```

3. Add the LAUREL log to the group config for the agents:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/laurel/audit.log</location>
   </localfile>
   ```

## Testing

Run the audit rule verification script on the agent:

```
sudo bash auditd/ubuntu/audit-test.sh --verbose
```

It triggers each audit rule category and checks that auditd recorded the expected events.

## What the rules cover

The auditd ruleset and Wazuh rules cover: command execution, privilege escalation, service/cron/kernel module changes, credential file access, SSH/PAM/sudoers modifications, SSL key access, network and firewall changes, time manipulation, DAC permission changes, data exfiltration indicators, reconnaissance tools, and Wazuh agent integrity monitoring.

MITRE ATT&CK technique IDs are mapped in the Wazuh rules where applicable.

## License

GPLv3
