'use strict';

/**
 * Brute Force / Credential Stuffing Attack Scenario
 *
 * Simulates a multi-phase credential stuffing attack originating from an
 * external IP block. The attack progresses through reconnaissance, mass
 * authentication attempts, a single successful breach, and lateral movement
 * within the compromised environment.
 *
 * MITRE ATT&CK mapping:
 *   T1595  - Active Scanning (recon)
 *   T1110  - Brute Force / Credential Stuffing
 *   T1078  - Valid Accounts (post-breach)
 *   T1021  - Remote Services (lateral movement)
 *   T1570  - Lateral Tool Transfer
 */

module.exports = {
  name: 'brute-force',
  description: 'Simulates credential stuffing / brute force attack with lateral movement',

  // -----------------------------------------------------------------------
  // Actors — resolved by the correlation engine at runtime.
  // Template references like {{attacker.ip}} are replaced with concrete
  // values drawn from the actor definitions below.
  // -----------------------------------------------------------------------
  actors: {
    attacker: {
      type: 'external',
      ip: { cidr: '203.0.113.0/24' },
      geo: 'random_foreign',
      userAgent: 'python-requests/2.31.0'
    },
    victim: {
      type: 'internal_user',
      username: { pattern: 'first.last' },
      email: { pattern: '{{victim.username}}@{{org.domain}}' },
      department: 'random'
    },
    target_host: {
      type: 'internal_server',
      hostname: { pattern: 'role-location-number' },
      ip: { cidr: '10.20.0.0/16' },
      os: 'Windows Server 2022'
    },
    // Additional internal hosts reached during lateral movement
    lateral_hosts: {
      type: 'internal_server',
      count: { min: 2, max: 5 },
      hostname: { pattern: 'role-location-number' },
      ip: { cidr: '10.20.0.0/16' }
    }
  },

  // -----------------------------------------------------------------------
  // Phases — executed sequentially; durations are randomised within the
  // given range so no two scenario runs produce identical timing.
  // -----------------------------------------------------------------------
  phases: [
    // -- Phase 1: Reconnaissance -----------------------------------------
    // The attacker probes the target host across common service ports.
    // All traffic is denied by the firewall; this is pure scanning.
    {
      name: 'reconnaissance',
      duration: { min: 120000, max: 300000 }, // 2-5 minutes
      events: [
        {
          sourcetype: 'pan:traffic',
          weight: 1.0,
          overrides: {
            src_ip: '{{attacker.ip}}',
            dst_ip: '{{target_host.ip}}',
            action: { values: ['deny'], weights: [1.0] },
            dst_port: {
              type: 'sequential_scan',
              range: [22, 23, 80, 443, 445, 3389, 5985, 5986, 8080, 8443]
            },
            src_port: { type: 'ephemeral' },
            app: 'incomplete',
            session_end_reason: 'policy-deny',
            bytes_sent: { min: 60, max: 120 },
            bytes_received: 0,
            packets_sent: { min: 1, max: 3 },
            packets_received: 0,
            rule: 'deny-inbound-scan'
          },
          rateMultiplier: 0.5
        }
      ]
    },

    // -- Phase 2: Credential Stuffing ------------------------------------
    // High-volume authentication failures across Okta, Windows Security,
    // and corresponding firewall traffic. The attacker cycles through
    // leaked credential lists against the victim account.
    {
      name: 'credential_stuffing',
      duration: { min: 600000, max: 900000 }, // 10-15 minutes
      events: [
        // Okta authentication failures
        {
          sourcetype: 'okta:system',
          weight: 0.35,
          overrides: {
            eventType: 'user.session.start',
            'outcome.result': 'FAILURE',
            'outcome.reason': {
              values: [
                'INVALID_CREDENTIALS',
                'PASSWORD_EXPIRED',
                'ACCOUNT_LOCKED',
                'VERIFICATION_ERROR'
              ],
              weights: [0.7, 0.1, 0.15, 0.05]
            },
            'actor.alternateId': '{{victim.email}}',
            'actor.displayName': '{{victim.username}}',
            'client.ipAddress': '{{attacker.ip}}',
            'client.userAgent.rawUserAgent': '{{attacker.userAgent}}',
            'client.geographicalContext.country': '{{attacker.geo.country}}',
            'client.geographicalContext.city': '{{attacker.geo.city}}',
            'securityContext.isp': '{{attacker.geo.isp}}',
            'debugContext.debugData.requestUri': '/api/v1/authn'
          },
          rateMultiplier: 4.0
        },
        // Firewall traffic — mostly denied with some allowed through
        {
          sourcetype: 'pan:traffic',
          weight: 0.30,
          overrides: {
            src_ip: '{{attacker.ip}}',
            dst_ip: '{{target_host.ip}}',
            dst_port: { values: [443], weights: [1.0] },
            src_port: { type: 'ephemeral' },
            app: 'ssl',
            action: { values: ['allow', 'deny'], weights: [0.3, 0.7] },
            session_end_reason: {
              values: ['policy-deny', 'tcp-rst-from-server', 'aged-out'],
              weights: [0.6, 0.3, 0.1]
            },
            bytes_sent: { min: 200, max: 800 },
            bytes_received: { min: 0, max: 400 },
            rule: {
              values: ['allow-https-inbound', 'deny-brute-force-rate'],
              weights: [0.3, 0.7]
            }
          },
          rateMultiplier: 3.0
        },
        // Windows Security Event 4625 — failed logon
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.25,
          overrides: {
            variant: '4625_failed_logon',
            EventCode: 4625,
            TargetUserName: '{{victim.username}}',
            TargetDomainName: '{{org.domain_short}}',
            IpAddress: '{{attacker.ip}}',
            IpPort: { type: 'ephemeral' },
            LogonType: 10,
            FailureReason: {
              values: [
                '%%2313',  // Unknown user name or bad password
                '%%2304',  // Account currently disabled
                '%%2310'   // Account logon time restriction violation
              ],
              weights: [0.85, 0.10, 0.05]
            },
            Status: '0xc000006d',
            SubStatus: {
              values: ['0xc000006a', '0xc0000064'],
              weights: [0.8, 0.2]
            },
            WorkstationName: '{{target_host.hostname}}'
          },
          rateMultiplier: 4.0
        },
        // CrowdStrike detection — brute force pattern
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.10,
          overrides: {
            event_simpleName: 'UserLogonFailed2',
            SeverityName: 'Medium',
            UserName: '{{victim.username}}',
            Tactic: 'CredentialAccess',
            Technique: 'Brute Force',
            RemoteAddressIP4: '{{attacker.ip}}',
            ComputerName: '{{target_host.hostname}}'
          },
          rateMultiplier: 1.5
        }
      ]
    },

    // -- Phase 3: Successful Breach --------------------------------------
    // After many failures the attacker finds valid credentials. A single
    // successful authentication appears across all log sources, along
    // with an immediate CrowdStrike alert.
    {
      name: 'successful_breach',
      duration: { min: 60000, max: 120000 }, // 1-2 minutes
      events: [
        // Okta successful authentication
        {
          sourcetype: 'okta:system',
          weight: 0.25,
          overrides: {
            eventType: 'user.session.start',
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{victim.email}}',
            'actor.displayName': '{{victim.username}}',
            'client.ipAddress': '{{attacker.ip}}',
            'client.userAgent.rawUserAgent': '{{attacker.userAgent}}',
            'client.geographicalContext.country': '{{attacker.geo.country}}',
            'client.geographicalContext.city': '{{attacker.geo.city}}',
            'debugContext.debugData.requestUri': '/api/v1/authn'
          },
          rateMultiplier: 0.1
        },
        // Windows Security Event 4624 — successful logon
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.25,
          overrides: {
            variant: '4624_successful_logon',
            EventCode: 4624,
            TargetUserName: '{{victim.username}}',
            TargetDomainName: '{{org.domain_short}}',
            IpAddress: '{{attacker.ip}}',
            IpPort: { type: 'ephemeral' },
            LogonType: 10,  // RemoteInteractive (RDP)
            AuthenticationPackageName: 'Negotiate',
            WorkstationName: '{{target_host.hostname}}'
          },
          rateMultiplier: 0.2
        },
        // CrowdStrike — suspicious authentication from foreign IP
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: 'SuspiciousLogon',
            SeverityName: 'High',
            UserName: '{{victim.username}}',
            Tactic: 'CredentialAccess',
            Technique: 'Valid Accounts',
            RemoteAddressIP4: '{{attacker.ip}}',
            ComputerName: '{{target_host.hostname}}',
            DetectDescription: 'Successful logon from a foreign IP after multiple authentication failures'
          },
          rateMultiplier: 0.5
        },
        // Okta MFA bypass or MFA prompt (attacker may have obtained MFA token)
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: 'user.authentication.auth_via_mfa',
            'outcome.result': {
              values: ['SUCCESS', 'FAILURE'],
              weights: [0.6, 0.4]
            },
            'actor.alternateId': '{{victim.email}}',
            'client.ipAddress': '{{attacker.ip}}',
            'debugContext.debugData.factor': {
              values: ['OKTA_VERIFY_PUSH', 'SMS', 'TOTP'],
              weights: [0.5, 0.3, 0.2]
            }
          },
          rateMultiplier: 0.3
        },
        // Firewall — sustained connection from attacker
        {
          sourcetype: 'pan:traffic',
          weight: 0.10,
          overrides: {
            src_ip: '{{attacker.ip}}',
            dst_ip: '{{target_host.ip}}',
            dst_port: { values: [3389, 443], weights: [0.6, 0.4] },
            app: { values: ['ms-rdp', 'ssl'], weights: [0.6, 0.4] },
            action: 'allow',
            bytes_sent: { min: 5000, max: 50000 },
            bytes_received: { min: 10000, max: 200000 },
            session_end_reason: 'aged-out',
            rule: 'allow-remote-access'
          },
          rateMultiplier: 0.3
        }
      ]
    },

    // -- Phase 4: Lateral Movement ---------------------------------------
    // The attacker pivots from the compromised host to other internal
    // systems using the stolen credentials. Internal east-west traffic
    // increases, and CrowdStrike detects lateral tool usage.
    {
      name: 'lateral_movement',
      duration: { min: 300000, max: 600000 }, // 5-10 minutes
      events: [
        // Windows Security Event 4624 — network logons to lateral hosts
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.30,
          overrides: {
            variant: '4624_successful_logon',
            EventCode: 4624,
            TargetUserName: '{{victim.username}}',
            TargetDomainName: '{{org.domain_short}}',
            IpAddress: '{{target_host.ip}}',  // coming FROM the compromised host
            LogonType: 3,  // Network logon
            AuthenticationPackageName: {
              values: ['NTLM', 'Kerberos'],
              weights: [0.4, 0.6]
            },
            WorkstationName: '{{lateral_hosts.hostname}}'
          },
          rateMultiplier: 1.0
        },
        // CrowdStrike — lateral movement tooling detected
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: 'ProcessRollup2',
            SeverityName: {
              values: ['Medium', 'High'],
              weights: [0.6, 0.4]
            },
            Tactic: 'LateralMovement',
            Technique: {
              values: [
                'Remote Services: SMB/Windows Admin Shares',
                'Remote Services: RDP',
                'Windows Management Instrumentation'
              ],
              weights: [0.4, 0.3, 0.3]
            },
            UserName: '{{victim.username}}',
            ComputerName: '{{target_host.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\net.exe',
                'C:\\Windows\\System32\\nltest.exe',
                'C:\\Windows\\System32\\wmic.exe',
                'C:\\Windows\\System32\\mstsc.exe',
                'C:\\Windows\\System32\\cmd.exe'
              ],
              weights: [0.25, 0.15, 0.25, 0.2, 0.15]
            },
            CommandLine: {
              values: [
                'net view /domain',
                'net group "Domain Admins" /domain',
                'nltest /dclist:{{org.domain_short}}',
                'wmic /node:"{{lateral_hosts.hostname}}" process list brief',
                'net use \\\\{{lateral_hosts.hostname}}\\C$ /user:{{victim.username}}'
              ],
              weights: [0.2, 0.2, 0.2, 0.2, 0.2]
            }
          },
          rateMultiplier: 2.0
        },
        // Firewall — internal east-west traffic spike (SMB, RPC, LDAP)
        {
          sourcetype: 'pan:traffic',
          weight: 0.25,
          overrides: {
            src_ip: '{{target_host.ip}}',
            dst_ip: '{{lateral_hosts.ip}}',
            action: 'allow',
            app: {
              values: ['ms-ds-smb', 'msrpc', 'ldap', 'ms-rdp', 'kerberos'],
              weights: [0.3, 0.2, 0.2, 0.2, 0.1]
            },
            dst_port: {
              values: [445, 135, 389, 3389, 88],
              weights: [0.3, 0.2, 0.2, 0.2, 0.1]
            },
            src_port: { type: 'ephemeral' },
            bytes_sent: { min: 1000, max: 50000 },
            bytes_received: { min: 500, max: 25000 },
            session_end_reason: {
              values: ['tcp-fin', 'tcp-rst-from-client', 'aged-out'],
              weights: [0.6, 0.2, 0.2]
            },
            rule: 'allow-internal-east-west'
          },
          rateMultiplier: 3.0
        },
        // Windows Security Event 4672 — special privileges assigned
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.10,
          overrides: {
            variant: '4672_special_logon',
            EventCode: 4672,
            SubjectUserName: '{{victim.username}}',
            SubjectDomainName: '{{org.domain_short}}',
            PrivilegeList: {
              values: [
                'SeDebugPrivilege\n\t\t\tSeTcbPrivilege',
                'SeBackupPrivilege\n\t\t\tSeRestorePrivilege',
                'SeImpersonatePrivilege'
              ],
              weights: [0.4, 0.3, 0.3]
            }
          },
          rateMultiplier: 0.5
        },
        // CrowdStrike — credential dumping detected on compromised host
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.10,
          overrides: {
            event_simpleName: 'SuspiciousActivity',
            SeverityName: 'Critical',
            Tactic: 'CredentialAccess',
            Technique: 'OS Credential Dumping',
            UserName: '{{victim.username}}',
            ComputerName: '{{target_host.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\rundll32.exe',
                'C:\\Windows\\Temp\\mimikatz.exe',
                'C:\\Windows\\System32\\comsvcs.dll'
              ],
              weights: [0.4, 0.3, 0.3]
            },
            DetectDescription: 'Potential credential dumping activity detected'
          },
          rateMultiplier: 0.3
        }
      ]
    }
  ]
};
