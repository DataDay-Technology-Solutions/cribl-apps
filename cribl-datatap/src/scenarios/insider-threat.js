'use strict';

/**
 * Insider Threat Scenario
 *
 * Simulates a malicious insider — an employee with valid credentials who
 * operates outside normal business hours, escalates their own privileges,
 * creates backdoor accounts, and attempts to cover their tracks.
 *
 * MITRE ATT&CK mapping:
 *   T1078  - Valid Accounts
 *   T1098  - Account Manipulation
 *   T1136  - Create Account
 *   T1484  - Domain Policy Modification
 *   T1070  - Indicator Removal on Host (log clearing)
 *   T1562  - Impair Defenses
 *   T1053  - Scheduled Task / Job (persistence)
 */

module.exports = {
  name: 'insider-threat',
  description: 'Simulates insider threat with after-hours access, privilege escalation, account manipulation, and anti-forensics',

  // -----------------------------------------------------------------------
  // Actors
  // -----------------------------------------------------------------------
  actors: {
    insider: {
      type: 'internal_user',
      username: { pattern: 'first.last' },
      email: { pattern: '{{insider.username}}@{{org.domain}}' },
      department: {
        values: ['ops', 'engineering', 'devops'],
        weights: [0.4, 0.35, 0.25]
      },
      ip: { cidr: '10.10.0.0/16' },
      hostname: { pattern: 'role-location-number' },
      os: 'Windows 11'
    },
    // Backdoor account created by the insider
    backdoor_account: {
      type: 'synthetic_user',
      username: {
        values: ['svc_update', 'sys_monitor', 'admin_temp', 'svc_healthcheck'],
        weights: [0.3, 0.3, 0.2, 0.2]
      },
      email: { pattern: '{{backdoor_account.username}}@{{org.domain}}' }
    },
    domain_controller: {
      type: 'internal_server',
      hostname: 'DC-NYC-0001',
      ip: { cidr: '10.20.0.0/24' }
    },
    target_servers: {
      type: 'internal_server',
      count: { min: 3, max: 8 },
      hostname: { pattern: 'role-location-number' },
      ip: { cidr: '10.20.0.0/16' }
    }
  },

  // -----------------------------------------------------------------------
  // Phases
  // -----------------------------------------------------------------------
  phases: [
    // -- Phase 1: After-Hours Access -------------------------------------
    // The insider logs in outside business hours (late night / early
    // morning) when fewer colleagues and security staff are watching.
    {
      name: 'after_hours_access',
      duration: { min: 180000, max: 300000 }, // 3-5 minutes
      timeWindow: { start: '23:00', end: '03:00' },
      events: [
        // Okta authentication at unusual hour
        {
          sourcetype: 'okta:system',
          weight: 0.25,
          overrides: {
            eventType: 'user.session.start',
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{insider.email}}',
            'actor.displayName': '{{insider.username}}',
            'client.ipAddress': '{{insider.ip}}',
            'client.userAgent.rawUserAgent': '{{insider.userAgent}}',
            'client.geographicalContext.country': 'United States',
            'debugContext.debugData.requestUri': '/api/v1/authn',
            // After-hours flag would be set by detection rules
            'securityContext.asNumber': { min: 1000, max: 60000 }
          },
          rateMultiplier: 0.3
        },
        // MFA bypass or push acceptance (insider has the device)
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: 'user.authentication.auth_via_mfa',
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{insider.email}}',
            'client.ipAddress': '{{insider.ip}}',
            'debugContext.debugData.factor': {
              values: ['OKTA_VERIFY_PUSH', 'TOTP'],
              weights: [0.6, 0.4]
            }
          },
          rateMultiplier: 0.2
        },
        // Windows logon — interactive or RDP
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: '4624_successful_logon',
            EventCode: 4624,
            TargetUserName: '{{insider.username}}',
            TargetDomainName: '{{org.domain_short}}',
            IpAddress: '{{insider.ip}}',
            LogonType: {
              values: [2, 10],  // Interactive, RemoteInteractive (RDP)
              weights: [0.4, 0.6]
            },
            AuthenticationPackageName: 'Negotiate',
            WorkstationName: '{{insider.hostname}}'
          },
          rateMultiplier: 0.3
        },
        // VPN connection at unusual hour
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: { type: 'random_public' },
            dst_ip: '{{domain_controller.ip}}',
            dst_port: {
              values: [443, 4443],
              weights: [0.5, 0.5]
            },
            app: {
              values: ['ssl-vpn', 'globalprotect'],
              weights: [0.5, 0.5]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 5000 },
            bytes_received: { min: 1000, max: 10000 },
            rule: 'allow-vpn-inbound'
          },
          rateMultiplier: 0.2
        },
        // CrowdStrike — logon at unusual time
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: 'UserLogon',
            SeverityName: 'Low',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            LogonType: {
              values: ['Interactive', 'RemoteInteractive'],
              weights: [0.4, 0.6]
            }
          },
          rateMultiplier: 0.3
        },
        // Reconnaissance — identifying targets
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.10,
          overrides: {
            event_simpleName: 'ProcessRollup2',
            SeverityName: 'Informational',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\net.exe',
                'C:\\Windows\\System32\\nltest.exe',
                'C:\\Windows\\System32\\dsquery.exe',
                'C:\\Windows\\System32\\whoami.exe'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            },
            CommandLine: {
              values: [
                'net group "Domain Admins" /domain',
                'nltest /dclist:{{org.domain_short}}',
                'dsquery group -name "Admin*"',
                'whoami /priv'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            }
          },
          rateMultiplier: 0.5
        }
      ]
    },

    // -- Phase 2: Privilege Escalation -----------------------------------
    // The insider attempts to elevate their privileges — accessing
    // resources above their role, modifying group memberships, and
    // exploiting writable GPOs or service accounts.
    {
      name: 'privilege_escalation',
      duration: { min: 300000, max: 600000 }, // 5-10 minutes
      events: [
        // Accessing sensitive admin shares
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: '5140_network_share_access',
            EventCode: 5140,
            TargetUserName: '{{insider.username}}',
            IpAddress: '{{insider.ip}}',
            ShareName: {
              values: [
                '\\\\*\\ADMIN$', '\\\\*\\C$', '\\\\*\\SYSVOL',
                '\\\\*\\NETLOGON', '\\\\*\\IPC$'
              ],
              weights: [0.3, 0.25, 0.2, 0.15, 0.1]
            }
          },
          rateMultiplier: 1.5
        },
        // Privilege escalation attempts — requesting elevated tokens
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: {
              values: ['4672_special_logon', '4673_privileged_service_called', '4674_privileged_object_operation'],
              weights: [0.4, 0.35, 0.25]
            },
            EventCode: {
              values: [4672, 4673, 4674],
              weights: [0.4, 0.35, 0.25]
            },
            SubjectUserName: '{{insider.username}}',
            SubjectDomainName: '{{org.domain_short}}',
            PrivilegeList: {
              values: [
                'SeDebugPrivilege',
                'SeTakeOwnershipPrivilege',
                'SeBackupPrivilege\n\t\t\tSeRestorePrivilege',
                'SeImpersonatePrivilege',
                'SeLoadDriverPrivilege'
              ],
              weights: [0.25, 0.2, 0.2, 0.2, 0.15]
            }
          },
          rateMultiplier: 2.0
        },
        // Okta — accessing admin console or policy-restricted apps
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: {
              values: [
                'app.auth.sso',
                'policy.evaluate_sign_on',
                'user.account.privilege.grant'
              ],
              weights: [0.4, 0.35, 0.25]
            },
            'outcome.result': {
              values: ['SUCCESS', 'FAILURE', 'SKIPPED'],
              weights: [0.3, 0.5, 0.2]
            },
            'actor.alternateId': '{{insider.email}}',
            'client.ipAddress': '{{insider.ip}}',
            'target.displayName': {
              values: [
                'Okta Admin Console',
                'AWS Console',
                'Azure Portal',
                'Active Directory Federation Services'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            }
          },
          rateMultiplier: 1.5
        },
        // CrowdStrike — privilege escalation tools detected
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: {
              values: ['ProcessRollup2', 'SuspiciousActivity'],
              weights: [0.6, 0.4]
            },
            SeverityName: {
              values: ['Medium', 'High'],
              weights: [0.5, 0.5]
            },
            Tactic: 'PrivilegeEscalation',
            Technique: {
              values: [
                'Access Token Manipulation',
                'Exploitation for Privilege Escalation',
                'Abuse Elevation Control Mechanism',
                'Valid Accounts: Domain Accounts'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            },
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\runas.exe',
                'C:\\Windows\\System32\\cmd.exe',
                'C:\\Windows\\System32\\powershell.exe',
                'C:\\Windows\\System32\\mmc.exe',
                'C:\\Windows\\System32\\dcomcnfg.exe'
              ],
              weights: [0.25, 0.2, 0.25, 0.15, 0.15]
            },
            CommandLine: {
              values: [
                'runas /user:{{org.domain_short}}\\administrator cmd.exe',
                'powershell -ep bypass -c "Import-Module ActiveDirectory; Add-ADGroupMember -Identity \'Domain Admins\' -Members \'{{insider.username}}\'"',
                'cmd /c net localgroup administrators {{insider.username}} /add',
                'powershell -c "Set-ADUser -Identity {{insider.username}} -Replace @{adminCount=1}"'
              ],
              weights: [0.3, 0.3, 0.25, 0.15]
            }
          },
          rateMultiplier: 2.0
        },
        // LDAP queries to domain controller
        {
          sourcetype: 'pan:traffic',
          weight: 0.20,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{domain_controller.ip}}',
            dst_port: {
              values: [389, 636, 3268, 3269],
              weights: [0.3, 0.3, 0.2, 0.2]
            },
            app: {
              values: ['ldap', 'ldaps', 'ms-ds-smb'],
              weights: [0.4, 0.4, 0.2]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 10000 },
            bytes_received: { min: 2000, max: 100000 },
            rule: 'allow-internal-east-west'
          },
          rateMultiplier: 2.5
        }
      ]
    },

    // -- Phase 3: Account Manipulation -----------------------------------
    // The insider creates new accounts, modifies group memberships,
    // and establishes persistent backdoor access.
    {
      name: 'account_manipulation',
      duration: { min: 300000, max: 600000 }, // 5-10 minutes
      events: [
        // Windows — new account created
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: '4720_user_account_created',
            EventCode: 4720,
            SubjectUserName: '{{insider.username}}',
            SubjectDomainName: '{{org.domain_short}}',
            TargetUserName: '{{backdoor_account.username}}',
            TargetDomainName: '{{org.domain_short}}',
            SamAccountName: '{{backdoor_account.username}}',
            DisplayName: {
              values: ['Service Update Agent', 'System Monitor Service', 'Temp Admin', 'Health Check Service'],
              weights: [0.3, 0.3, 0.2, 0.2]
            },
            UserAccountControl: '%%2080 %%2082'  // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWD
          },
          rateMultiplier: 0.3
        },
        // Windows — account added to privileged groups
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: {
              values: ['4728_member_added_global_group', '4732_member_added_local_group', '4756_member_added_universal_group'],
              weights: [0.4, 0.35, 0.25]
            },
            EventCode: {
              values: [4728, 4732, 4756],
              weights: [0.4, 0.35, 0.25]
            },
            SubjectUserName: '{{insider.username}}',
            MemberName: '{{backdoor_account.username}}',
            TargetUserName: {
              values: [
                'Domain Admins', 'Administrators', 'Remote Desktop Users',
                'Backup Operators', 'Server Operators'
              ],
              weights: [0.3, 0.25, 0.2, 0.15, 0.1]
            }
          },
          rateMultiplier: 0.5
        },
        // Windows — password changes and account modifications
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.15,
          overrides: {
            variant: {
              values: ['4724_password_reset', '4738_user_account_changed'],
              weights: [0.5, 0.5]
            },
            EventCode: {
              values: [4724, 4738],
              weights: [0.5, 0.5]
            },
            SubjectUserName: '{{insider.username}}',
            TargetUserName: {
              values: ['{{backdoor_account.username}}', '{{insider.username}}'],
              weights: [0.6, 0.4]
            },
            TargetDomainName: '{{org.domain_short}}'
          },
          rateMultiplier: 0.5
        },
        // Okta — admin actions: user creation and role assignment
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: {
              values: [
                'user.lifecycle.create',
                'user.account.privilege.grant',
                'group.user_membership.add',
                'policy.lifecycle.update'
              ],
              weights: [0.3, 0.25, 0.3, 0.15]
            },
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{insider.email}}',
            'client.ipAddress': '{{insider.ip}}',
            'target.alternateId': {
              values: ['{{backdoor_account.email}}', '{{insider.email}}'],
              weights: [0.6, 0.4]
            },
            'target.displayName': {
              values: [
                '{{backdoor_account.username}}',
                'Super Admins',
                'Application Administrators',
                'Global MFA Policy'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            }
          },
          rateMultiplier: 0.5
        },
        // CrowdStrike — admin tools and account creation commands
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: 'ProcessRollup2',
            SeverityName: {
              values: ['Medium', 'High'],
              weights: [0.5, 0.5]
            },
            Tactic: 'Persistence',
            Technique: {
              values: ['Create Account: Domain Account', 'Account Manipulation', 'Scheduled Task/Job'],
              weights: [0.4, 0.35, 0.25]
            },
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\net.exe',
                'C:\\Windows\\System32\\dsadd.exe',
                'C:\\Windows\\System32\\powershell.exe',
                'C:\\Windows\\System32\\schtasks.exe'
              ],
              weights: [0.3, 0.25, 0.3, 0.15]
            },
            CommandLine: {
              values: [
                'net user {{backdoor_account.username}} P@ssw0rd123! /add /domain',
                'net group "Domain Admins" {{backdoor_account.username}} /add /domain',
                'dsadd user "CN={{backdoor_account.username}},CN=Users,DC={{org.domain_short}},DC=local" -pwd P@ssw0rd123! -memberof "CN=Domain Admins,CN=Users"',
                'powershell -c "New-ADUser -Name \'{{backdoor_account.username}}\' -AccountPassword (ConvertTo-SecureString \'P@ssw0rd123!\' -AsPlainText -Force) -Enabled $true"',
                'schtasks /create /tn "SystemHealthCheck" /tr "C:\\Windows\\Temp\\beacon.exe" /sc daily /st 02:00 /ru SYSTEM'
              ],
              weights: [0.25, 0.2, 0.2, 0.2, 0.15]
            }
          },
          rateMultiplier: 1.0
        },
        // Firewall — SMB and LDAP to domain controller during manipulation
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{domain_controller.ip}}',
            dst_port: {
              values: [445, 389, 636, 88, 135],
              weights: [0.25, 0.25, 0.2, 0.15, 0.15]
            },
            app: {
              values: ['ms-ds-smb', 'ldap', 'ldaps', 'kerberos', 'msrpc'],
              weights: [0.25, 0.25, 0.2, 0.15, 0.15]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 10000 },
            bytes_received: { min: 1000, max: 20000 },
            rule: 'allow-internal-east-west'
          },
          rateMultiplier: 2.0
        }
      ]
    },

    // -- Phase 4: Covering Tracks ----------------------------------------
    // The insider attempts to erase evidence of their activities by
    // clearing event logs, disabling security services, modifying
    // audit policies, and timestomping files.
    {
      name: 'covering_tracks',
      duration: { min: 180000, max: 360000 }, // 3-6 minutes
      events: [
        // Windows — audit log cleared
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: '1102_audit_log_cleared',
            EventCode: 1102,
            SubjectUserName: '{{insider.username}}',
            SubjectDomainName: '{{org.domain_short}}',
            // The irony: clearing the log still generates this one event
            LogName: {
              values: ['Security', 'System', 'Application'],
              weights: [0.5, 0.3, 0.2]
            }
          },
          rateMultiplier: 0.3
        },
        // Windows — audit policy changed
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.15,
          overrides: {
            variant: '4719_audit_policy_changed',
            EventCode: 4719,
            SubjectUserName: '{{insider.username}}',
            SubjectDomainName: '{{org.domain_short}}',
            CategoryId: {
              values: [
                '%%8274',  // Logon/Logoff
                '%%8277',  // Object Access
                '%%8280'   // Account Management
              ],
              weights: [0.4, 0.35, 0.25]
            },
            SubcategoryGuid: 'audit category changed',
            AuditPolicyChanges: {
              values: ['%%8224', '%%8226'],  // Success removed, Failure removed
              weights: [0.5, 0.5]
            }
          },
          rateMultiplier: 0.5
        },
        // CrowdStrike — security service tampering
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: {
              values: ['ProcessRollup2', 'SuspiciousActivity', 'ServiceStarted'],
              weights: [0.5, 0.3, 0.2]
            },
            SeverityName: {
              values: ['High', 'Critical'],
              weights: [0.6, 0.4]
            },
            Tactic: 'DefenseEvasion',
            Technique: {
              values: [
                'Indicator Removal on Host: Clear Windows Event Logs',
                'Impair Defenses: Disable or Modify Tools',
                'Indicator Removal on Host: Timestomp',
                'Impair Defenses: Disable Windows Event Logging'
              ],
              weights: [0.3, 0.3, 0.2, 0.2]
            },
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\wevtutil.exe',
                'C:\\Windows\\System32\\powershell.exe',
                'C:\\Windows\\System32\\sc.exe',
                'C:\\Windows\\System32\\reg.exe',
                'C:\\Windows\\System32\\cmd.exe'
              ],
              weights: [0.25, 0.25, 0.2, 0.15, 0.15]
            },
            CommandLine: {
              values: [
                'wevtutil cl Security',
                'wevtutil cl System',
                'powershell -c "Clear-EventLog -LogName Security,System,Application"',
                'sc stop WinDefend',
                'sc config WinDefend start= disabled',
                'reg add "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Security" /v MaxSize /t REG_DWORD /d 0 /f',
                'powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"',
                'wevtutil sl Security /e:false'
              ],
              weights: [0.15, 0.1, 0.15, 0.1, 0.1, 0.1, 0.15, 0.15]
            }
          },
          rateMultiplier: 2.0
        },
        // CrowdStrike — anti-forensics: timestomping, secdelete
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: {
              values: ['ProcessRollup2', 'SuspiciousActivity'],
              weights: [0.5, 0.5]
            },
            SeverityName: 'High',
            Tactic: 'DefenseEvasion',
            Technique: 'Indicator Removal on Host',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\powershell.exe',
                'C:\\Windows\\System32\\cipher.exe',
                'C:\\Windows\\System32\\fsutil.exe'
              ],
              weights: [0.4, 0.35, 0.25]
            },
            CommandLine: {
              values: [
                'powershell -c "(Get-Item C:\\Windows\\Temp\\beacon.exe).LastWriteTime = \'01/01/2024 08:00:00\'"',
                'cipher /w:C:\\Users\\{{insider.username}}\\staging',
                'fsutil usn deletejournal /d C:',
                'powershell -c "Remove-Item -Path C:\\Users\\{{insider.username}}\\staging -Recurse -Force"'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            }
          },
          rateMultiplier: 1.0
        },
        // Okta — disabling security policies
        {
          sourcetype: 'okta:system',
          weight: 0.10,
          overrides: {
            eventType: {
              values: [
                'policy.lifecycle.update',
                'policy.lifecycle.deactivate',
                'system.org.rate_limit.violation',
                'user.mfa.factor.deactivate'
              ],
              weights: [0.3, 0.3, 0.15, 0.25]
            },
            'outcome.result': {
              values: ['SUCCESS', 'FAILURE'],
              weights: [0.6, 0.4]
            },
            'actor.alternateId': '{{insider.email}}',
            'client.ipAddress': '{{insider.ip}}',
            'target.displayName': {
              values: [
                'Global Session Policy',
                'MFA Enrollment Policy',
                'Sign-On Policy — High Security',
                'API Access Management Policy'
              ],
              weights: [0.3, 0.3, 0.2, 0.2]
            }
          },
          rateMultiplier: 0.5
        },
        // Firewall — insider accessing multiple servers to clear remote logs
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{target_servers.ip}}',
            dst_port: {
              values: [5985, 5986, 445, 3389],
              weights: [0.3, 0.2, 0.3, 0.2]
            },
            app: {
              values: ['wsman', 'ms-ds-smb', 'ms-rdp'],
              weights: [0.4, 0.35, 0.25]
            },
            action: 'allow',
            bytes_sent: { min: 1000, max: 20000 },
            bytes_received: { min: 500, max: 10000 },
            session_end_reason: {
              values: ['tcp-fin', 'aged-out'],
              weights: [0.7, 0.3]
            },
            rule: 'allow-internal-east-west'
          },
          rateMultiplier: 2.5
        }
      ]
    }
  ]
};
