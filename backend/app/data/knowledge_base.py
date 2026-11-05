"""Seed content for the security knowledge base (original, general-purpose defensive guidance).

Each document uses the labelled paragraphs 'Overview:', 'Indicators:', 'Investigation steps:' and
'Mitigation:' so the template fallback report can pull out specific sections.
"""

KNOWLEDGE_DOCUMENTS = [
    {
        "slug": "brute-force-attacks",
        "title": "Brute-Force Attacks Against Authentication Services",
        "category": "Brute Force Attack",
        "content": """Overview: A brute-force attack repeatedly submits guessed credentials to a login service such as SSH, RDP, a web login or a database. Variants include password guessing against one account, password spraying (one password against many accounts) and credential stuffing (reused leaked credentials). Failed login bursts from one source address in a short time are the classic signal.

Indicators:
- Many failed authentication events from one source IP within seconds or minutes.
- Attempts spread across many usernames, or one username targeted repeatedly.
- A successful login immediately after a long run of failures, which suggests the guessing worked.
- Attempts against administrative services (SSH, RDP) from external addresses.

Investigation steps:
- Count failed attempts per source, per target service and per account over the incident window.
- Check whether any login from the same source succeeded during or after the failures.
- Determine whether the source is an internal host, a known scanner, a partner or an unknown external address.
- Review authentication logs on the targeted host for the accounts involved.
- Check whether the targeted account is privileged and whether multi-factor authentication is enforced.

Mitigation:
- After analyst approval, consider temporarily blocking or rate-limiting the source at the firewall.
- Enforce account lockout or progressive delays and multi-factor authentication.
- Restrict administrative services to VPN or allow-listed addresses.
- Rotate credentials for any account that may have been successfully accessed.""",
    },
    {
        "slug": "port-scanning",
        "title": "Port Scanning and Service Discovery",
        "category": "Port Scanning",
        "content": """Overview: Port scanning probes many TCP or UDP ports on a host (a vertical scan) or one port across many hosts (a horizontal sweep) to discover which services are listening. It is usually a preparation step before targeted exploitation, but it is also performed by legitimate vulnerability scanners and monitoring tools.

Indicators:
- One source contacting many distinct destination ports on one target in a short time.
- Mostly failed, reset or blocked connections, because most probed ports are closed.
- Very short connection durations and sequential or evenly spaced port numbers.
- Little or no application-layer data exchanged.

Investigation steps:
- List the distinct ports and the success or failure status of each probe.
- Check whether the source belongs to an approved internal scanner or a scheduled security assessment.
- Look for ports that did respond, because those are the services the source now knows about.
- Search for follow-up activity from the same source against any open port, such as login attempts.
- Check whether other targets were probed by the same source.

Mitigation:
- After analyst approval, consider rate-limiting or blocking the source at the perimeter.
- Close or firewall services that do not need to be reachable.
- Patch services that responded to the scan.
- Add the source to a watch list to detect follow-up exploitation attempts.""",
    },
    {
        "slug": "denial-of-service-attacks",
        "title": "Denial-of-Service and Connection Flood Indicators",
        "category": "Denial of Service",
        "content": """Overview: A denial-of-service (DoS) attack tries to exhaust a service's capacity, such as bandwidth, connection tables or application threads, so legitimate users cannot reach it. When many sources are involved it is a distributed attack (DDoS). A single source sending an abnormal volume of connection attempts can indicate a flood, a misconfigured client or a runaway script.

Indicators:
- Connection attempt volume far above the normal baseline for that source or service.
- Many half-open or repeated connection attempts to a single destination and port.
- Rising latency, error rates or resource use on the targeted service.
- Traffic that does not complete application-level conversations.

Investigation steps:
- Compare the observed attempt rate with the normal rate for that source and target.
- Determine whether the traffic comes from one source or many.
- Check the health and capacity metrics of the targeted service during the window.
- Rule out benign causes such as load tests, retry storms from a failing client or a batch job.
- Confirm whether the destination is business critical.

Mitigation:
- After analyst approval, consider rate limiting, connection limits or upstream filtering for the offending source.
- Enable SYN cookies and connection timeouts on exposed services.
- Engage the hosting or network provider if the volume exceeds local capacity.
- Review capacity planning and redundancy for critical services.""",
    },
    {
        "slug": "suspicious-login-activity",
        "title": "Suspicious Login Activity",
        "category": "Suspicious Login Activity",
        "content": """Overview: Suspicious login activity covers authentication events that deviate from an account's or host's normal pattern: unusual source locations, unusual hours, impossible travel, repeated failures followed by success, or logins to services a user never normally touches. It can signal stolen credentials as well as ordinary user error.

Indicators:
- Bursts of failed logins that end in a successful one.
- Logins from addresses never previously associated with the account.
- Authentication outside normal working hours or from unexpected networks.
- Multiple accounts failing from the same source.

Investigation steps:
- Establish the normal login baseline for the affected account and host.
- Verify with the account owner whether the activity was theirs.
- Check what the session did after login, such as new processes, privilege changes or data access.
- Look for the same source targeting other accounts or hosts.

Mitigation:
- After analyst approval, force a password reset and revoke active sessions for affected accounts.
- Require multi-factor authentication for the account.
- Add alerting for logins from new locations on privileged accounts.""",
    },
    {
        "slug": "network-reconnaissance",
        "title": "Network Reconnaissance Techniques",
        "category": "Network Reconnaissance",
        "content": """Overview: Reconnaissance is the information-gathering phase that precedes many attacks. In network terms it includes host discovery sweeps, port scans, service and version probing, and banner grabbing. Reconnaissance alone does not compromise a system, but it reveals what an attacker may target next, so it deserves attention proportional to the asset exposed.

Indicators:
- Sequential or wide-ranging probing of addresses and ports from one source.
- Connections that open and close without meaningful data.
- Probes touching services rarely used in the environment.
- Activity that is quiet and slow, designed to stay under simple thresholds.

Investigation steps:
- Identify which hosts and services were probed and which responded.
- Compare against scheduled internal scans and asset inventory.
- Search for later activity from the same source against the discovered services.
- Check external threat intelligence on the source address if policy allows.

Mitigation:
- Reduce the exposed attack surface by closing unneeded ports.
- Keep an accurate asset inventory so unexpected probing stands out.
- After analyst approval, add blocking or rate limiting for persistent unauthorised scanners.""",
    },
    {
        "slug": "incident-response-procedure",
        "title": "Incident Response Procedure for Network Alerts",
        "category": "Incident Response",
        "content": """Overview: A consistent incident response process keeps analysts effective and keeps evidence trustworthy. A common lifecycle is preparation, detection and analysis, containment, eradication, recovery and lessons learned. Every containment action should be authorised by a human owner and recorded.

Indicators:
- An alert has been raised and needs triage.
- Evidence must be preserved before systems are changed.

Investigation steps:
- Triage: confirm the alert is real by reviewing the underlying events and noting what is observed versus assumed.
- Scope: identify the affected hosts, accounts and time range.
- Preserve evidence: keep original event records and log excerpts unchanged.
- Record every action and finding in the incident notes so the audit trail is complete.
- Decide a status: investigating, resolved or false positive, and document the reasoning.

Mitigation:
- Contain with the least disruptive effective action, such as rate limiting before a full block.
- Obtain approval from the system owner before blocking addresses or disabling accounts.
- After recovery, review detection thresholds and update playbooks with lessons learned.""",
    },
    {
        "slug": "threat-severity-classification",
        "title": "Threat Severity Classification Guide",
        "category": "Severity Classification",
        "content": """Overview: Severity expresses how urgently an incident needs attention. It combines the confidence that the activity is malicious, the sensitivity of the targeted asset, the evidence of success, and the potential impact. Four levels are commonly used: Low, Medium, High and Critical.

Indicators:
- Low: unusual but probably benign or very limited activity, with no sign of success.
- Medium: suspicious behaviour with limited evidence of intent or impact.
- High: strong indicators of attack activity against exposed assets, such as sustained brute force or scanning.
- Critical: evidence of successful compromise, very high intensity, or impact on critical systems.

Investigation steps:
- Raise severity when a successful login, data access or lateral movement follows the suspicious activity.
- Raise severity when the target is a critical or internet-facing system.
- Lower severity when the source is verified as an approved scanner or test.
- Re-evaluate severity whenever new evidence arrives and record the change.

Mitigation:
- Match response urgency to severity, with Critical incidents handled immediately and Low incidents batched for review.
- Document the reasoning for severity changes in the incident notes.""",
    },
    {
        "slug": "basic-network-security-practices",
        "title": "Basic Network Security Practices",
        "category": "Network Security Basics",
        "content": """Overview: Strong baseline controls make attacks harder and make suspicious activity easier to spot. The goal is to expose as little as possible, authenticate strongly and log what happens.

Indicators:
- Services reachable from the internet that do not need to be.
- Shared or default credentials, and administrative services open to all addresses.
- Missing or inconsistent logging.

Investigation steps:
- Review firewall rules and listening services against the asset inventory.
- Confirm that authentication and firewall logs are collected centrally and retained.
- Verify that time is synchronised across systems so event timelines line up.

Mitigation:
- Apply least privilege: allow only the ports and sources a service needs.
- Segment networks so that one compromised host cannot reach everything.
- Use multi-factor authentication, patch regularly and monitor logs.
- Keep tested backups and a rehearsed response plan.""",
    },
    {
        "slug": "suspicious-port-activity",
        "title": "Suspicious Port Activity and Remote-Access Backdoors",
        "category": "Suspicious Port Activity",
        "content": """Overview: Some ports are associated with remote administration, legacy insecure protocols or malware command channels, for example Telnet (23), SMB (445), RDP (3389), VNC (5900), IRC (6667) and ports such as 4444 or 31337 commonly used by exploitation frameworks and backdoors. Traffic to these ports is not proof of compromise, but it is worth attention when unexpected.

Indicators:
- Repeated connections to commonly abused ports, especially from external addresses.
- Inbound connections to ports on hosts that should not offer that service.
- Outbound connections from internal hosts to unusual high ports, which may indicate a command channel.

Investigation steps:
- Identify which host owns the port and whether the service is intended to be running.
- Check whether the connections succeeded and whether data was exchanged.
- Inspect the host for unexpected listening processes or recent configuration changes.
- Determine whether the source is a legitimate administrator or tool.

Mitigation:
- Disable unneeded services and block risky ports at the perimeter.
- Restrict remote administration to VPN or allow-listed addresses.
- After analyst approval, isolate a host that shows signs of a backdoor and investigate it.""",
    },
    {
        "slug": "connection-anomalies-and-unusual-ports",
        "title": "Repeated Connections and Unusual Destination Ports",
        "category": "Connection Anomalies",
        "content": """Overview: Repeated connections from one source to the same service, or connections to ports outside an organisation's expected service list, are weak signals on their own. They gain meaning in context: automated beaconing from malware, a misbehaving application, an unsanctioned service or early-stage probing can all look like this.

Indicators:
- Regular, evenly spaced connections to the same destination and port (beaconing).
- A source making many connections to one service with no apparent business reason.
- Connections to uncommon ports that are not in the expected service list.
- New services appearing on ports that were previously unused.

Investigation steps:
- Compare the pattern with the source's normal behaviour and with known applications.
- Identify the process or application on the source host that generates the traffic.
- Determine whether the destination port is an approved service.
- Check timing regularity, which suggests automation rather than a person.

Mitigation:
- Update the expected-port list if the service is legitimate, to avoid repeat alerts.
- Block unapproved services and investigate the host that runs them.
- After analyst approval, rate-limit or block sources with clearly abusive repeated connections.""",
    },
]
