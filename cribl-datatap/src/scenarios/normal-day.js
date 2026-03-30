'use strict';

/**
 * Normal Business Day Scenario
 *
 * Simulates an uneventful day of enterprise operations with no attack
 * narrative. Traffic patterns follow realistic business-hour curves:
 * morning ramp-up, lunch dip, afternoon peak, evening wind-down, and
 * quiet overnight automated tasks.
 *
 * This scenario is useful as:
 *   - Baseline noise against which attack scenarios are overlaid
 *   - Standalone training data for SOC analysts learning to distinguish
 *     normal from anomalous activity
 *   - Volume/load testing for log pipelines
 */

module.exports = {
  name: 'normal-day',
  description: 'Simulates a normal business day with realistic enterprise traffic patterns and no attack activity',

  // -----------------------------------------------------------------------
  // Actors — a pool of normal users and infrastructure assets
  // -----------------------------------------------------------------------
  actors: {
    employees: {
      type: 'internal_user',
      count: { min: 20, max: 50 },
      username: { pattern: 'first.last' },
      email: { pattern: '{{employees.username}}@{{org.domain}}' },
      department: 'random'
    },
    workstations: {
      type: 'internal_endpoint',
      count: { min: 20, max: 50 },
      hostname: { pattern: 'role-location-number' },
      ip: { cidr: '10.10.0.0/16' },
      os: {
        values: ['Windows 11', 'Windows 10', 'macOS 14'],
        weights: [0.5, 0.3, 0.2]
      }
    },
    servers: {
      type: 'internal_server',
      count: { min: 10, max: 20 },
      hostname: { pattern: 'role-location-number' },
      ip: { cidr: '10.20.0.0/16' }
    },
    saas_destinations: {
      type: 'external',
      domains: [
        'login.microsoftonline.com', 'outlook.office365.com',
        'teams.microsoft.com', 'salesforce.com',
        'drive.google.com', 'zoom.us', 'slack.com',
        'github.com', 'aws.amazon.com', 'console.cloud.google.com',
        'app.datadoghq.com', 'jira.atlassian.com'
      ]
    }
  },

  // -----------------------------------------------------------------------
  // Phases — modelled on a 24-hour clock.
  // Each phase has its own traffic mix and volume profile.
  // -----------------------------------------------------------------------
  phases: [
    // -- Phase 1: Early Morning / Overnight (00:00-07:00) ----------------
    // Minimal human activity. Automated backup jobs, scheduled tasks,
    // AV signature updates, and a few scattered overseas employees.
    {
      name: 'overnight',
      duration: { min: 420000, max: 420000 }, // 7 minutes (representing 7 hours)
      timeWindow: { start: '00:00', end: '07:00' },
      events: [
        // Scheduled backup traffic
        {
          sourcetype: 'pan:traffic',
          weight: 0.30,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: '{{servers.ip}}',
            app: {
              values: ['ms-ds-smb', 'ssh', 'nfs'],
              weights: [0.4, 0.3, 0.3]
            },
            dst_port: {
              values: [445, 22, 2049],
              weights: [0.4, 0.3, 0.3]
            },
            action: 'allow',
            bytes_sent: { min: 50000, max: 500000000 },
            bytes_received: { min: 1000, max: 50000 },
            session_end_reason: 'tcp-fin',
            rule: 'allow-backup-traffic'
          },
          rateMultiplier: 0.1
        },
        // Windows scheduled tasks and service accounts
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.25,
          overrides: {
            variant: '4624_successful_logon',
            EventCode: 4624,
            TargetUserName: {
              values: ['SYSTEM', 'svc_backup', 'svc_monitoring', 'svc_antivirus'],
              weights: [0.4, 0.3, 0.2, 0.1]
            },
            LogonType: {
              values: [5, 3],  // 5=Service, 3=Network
              weights: [0.7, 0.3]
            },
            IpAddress: '{{servers.ip}}'
          },
          rateMultiplier: 0.1
        },
        // CrowdStrike — AV/EDR signature updates
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.20,
          overrides: {
            event_simpleName: {
              values: ['SensorHeartbeat', 'ConfigStateUpdate', 'ChannelVersionRequired'],
              weights: [0.5, 0.3, 0.2]
            },
            SeverityName: 'Informational',
            ComputerName: '{{workstations.hostname}}'
          },
          rateMultiplier: 0.05
        },
        // DNS queries — mostly infrastructure
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_port: 53,
            app: 'dns',
            action: 'allow',
            bytes_sent: { min: 60, max: 200 },
            bytes_received: { min: 80, max: 500 },
            rule: 'allow-dns'
          },
          rateMultiplier: 0.05
        },
        // Occasional remote employee (overseas timezone)
        {
          sourcetype: 'okta:system',
          weight: 0.10,
          overrides: {
            eventType: {
              values: ['user.session.start', 'app.auth.sso'],
              weights: [0.3, 0.7]
            },
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{employees.email}}',
            'client.ipAddress': '{{employees.ip}}',
            'client.geographicalContext.country': {
              values: ['India', 'United Kingdom', 'Germany', 'Australia'],
              weights: [0.4, 0.3, 0.2, 0.1]
            }
          },
          rateMultiplier: 0.02
        }
      ]
    },

    // -- Phase 2: Morning Ramp-Up (07:00-09:00) --------------------------
    // Employees arrive, VPN in, authenticate to Okta, launch apps.
    // Traffic rises steeply.
    {
      name: 'morning_rampup',
      duration: { min: 120000, max: 120000 }, // 2 minutes (representing 2 hours)
      timeWindow: { start: '07:00', end: '09:00' },
      events: [
        // VPN connections
        {
          sourcetype: 'pan:traffic',
          weight: 0.20,
          overrides: {
            src_ip: { type: 'random_public' },
            dst_ip: '{{servers.ip}}',
            dst_port: {
              values: [443, 4443, 10443],
              weights: [0.5, 0.3, 0.2]
            },
            app: {
              values: ['ssl-vpn', 'ipsec', 'globalprotect'],
              weights: [0.4, 0.3, 0.3]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 5000 },
            bytes_received: { min: 1000, max: 10000 },
            session_end_reason: 'n/a',
            rule: 'allow-vpn-inbound'
          },
          rateMultiplier: 1.5
        },
        // Okta authentications — SSO to various apps
        {
          sourcetype: 'okta:system',
          weight: 0.25,
          overrides: {
            eventType: {
              values: [
                'user.session.start',
                'user.authentication.auth_via_mfa',
                'app.auth.sso',
                'policy.evaluate_sign_on'
              ],
              weights: [0.3, 0.25, 0.35, 0.1]
            },
            'outcome.result': {
              values: ['SUCCESS', 'FAILURE'],
              weights: [0.95, 0.05]  // occasional fat-finger
            },
            'actor.alternateId': '{{employees.email}}',
            'client.ipAddress': '{{employees.ip}}',
            'client.userAgent.rawUserAgent': '{{employees.userAgent}}',
            'client.geographicalContext.country': 'United States'
          },
          rateMultiplier: 2.0
        },
        // Windows logon events
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.25,
          overrides: {
            variant: {
              values: ['4624_successful_logon', '4625_failed_logon'],
              weights: [0.95, 0.05]
            },
            EventCode: {
              values: [4624, 4625],
              weights: [0.95, 0.05]
            },
            TargetUserName: '{{employees.username}}',
            LogonType: {
              values: [2, 10, 3],  // Interactive, RemoteInteractive, Network
              weights: [0.5, 0.3, 0.2]
            },
            IpAddress: '{{workstations.ip}}'
          },
          rateMultiplier: 1.5
        },
        // CrowdStrike — normal process starts
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.20,
          overrides: {
            event_simpleName: {
              values: ['ProcessRollup2', 'SensorHeartbeat', 'NetworkListenIP4'],
              weights: [0.6, 0.2, 0.2]
            },
            SeverityName: 'Informational',
            UserName: '{{employees.username}}',
            ComputerName: '{{workstations.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE',
                'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Program Files\\Microsoft\\Teams\\current\\Teams.exe',
                'C:\\Windows\\explorer.exe'
              ],
              weights: [0.25, 0.15, 0.25, 0.2, 0.15]
            }
          },
          rateMultiplier: 1.5
        },
        // DNS lookups for SaaS apps
        {
          sourcetype: 'pan:traffic',
          weight: 0.10,
          overrides: {
            src_ip: '{{workstations.ip}}',
            dst_port: 53,
            app: 'dns',
            action: 'allow',
            bytes_sent: { min: 60, max: 200 },
            bytes_received: { min: 80, max: 500 },
            rule: 'allow-dns'
          },
          rateMultiplier: 1.0
        }
      ]
    },

    // -- Phase 3: Business Hours — Morning (09:00-12:00) -----------------
    // Steady-state productivity. Web browsing, SaaS usage, file shares,
    // email, code repos, cloud console access.
    {
      name: 'business_hours_am',
      duration: { min: 180000, max: 180000 }, // 3 minutes (representing 3 hours)
      timeWindow: { start: '09:00', end: '12:00' },
      events: [
        // Web browsing and SaaS traffic
        {
          sourcetype: 'pan:traffic',
          weight: 0.30,
          overrides: {
            src_ip: '{{workstations.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: {
              values: [443, 80],
              weights: [0.9, 0.1]
            },
            app: {
              values: [
                'ssl', 'web-browsing', 'ms-office365',
                'ms-teams', 'salesforce', 'google-base',
                'github', 'slack', 'zoom'
              ],
              weights: [0.2, 0.15, 0.15, 0.1, 0.1, 0.1, 0.08, 0.07, 0.05]
            },
            action: {
              values: ['allow', 'deny'],
              weights: [0.97, 0.03]  // occasional content filter block
            },
            bytes_sent: { min: 500, max: 100000 },
            bytes_received: { min: 1000, max: 5000000 },
            session_end_reason: {
              values: ['tcp-fin', 'aged-out'],
              weights: [0.8, 0.2]
            },
            rule: {
              values: ['allow-web-outbound', 'deny-category-block'],
              weights: [0.97, 0.03]
            }
          },
          rateMultiplier: 2.5
        },
        // Okta SSO into apps
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: {
              values: ['app.auth.sso', 'user.session.start', 'app.access'],
              weights: [0.5, 0.2, 0.3]
            },
            'outcome.result': {
              values: ['SUCCESS', 'FAILURE'],
              weights: [0.98, 0.02]
            },
            'actor.alternateId': '{{employees.email}}',
            'client.ipAddress': '{{employees.ip}}',
            'client.geographicalContext.country': 'United States'
          },
          rateMultiplier: 1.0
        },
        // File share access
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.15,
          overrides: {
            variant: {
              values: ['4663_object_access', '5140_network_share_access', '4624_successful_logon'],
              weights: [0.4, 0.3, 0.3]
            },
            EventCode: {
              values: [4663, 5140, 4624],
              weights: [0.4, 0.3, 0.3]
            },
            TargetUserName: '{{employees.username}}',
            IpAddress: '{{workstations.ip}}',
            ObjectName: {
              values: [
                '\\\\FILESRV\\Shared\\Documents\\*',
                '\\\\FILESRV\\Shared\\Projects\\*',
                '\\\\FILESRV\\Department\\*',
                '\\\\FILESRV\\Home\\{{employees.username}}\\*'
              ],
              weights: [0.3, 0.3, 0.2, 0.2]
            },
            ShareName: {
              values: ['\\\\*\\Shared', '\\\\*\\Department', '\\\\*\\Home'],
              weights: [0.4, 0.3, 0.3]
            }
          },
          rateMultiplier: 1.5
        },
        // Internal east-west server traffic
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: '{{servers.ip}}',
            app: {
              values: ['ms-sql', 'oracle', 'ssl', 'http', 'ldap'],
              weights: [0.25, 0.15, 0.25, 0.2, 0.15]
            },
            dst_port: {
              values: [1433, 1521, 443, 8080, 389],
              weights: [0.25, 0.15, 0.25, 0.2, 0.15]
            },
            action: 'allow',
            bytes_sent: { min: 200, max: 50000 },
            bytes_received: { min: 200, max: 500000 },
            rule: 'allow-internal-app-traffic'
          },
          rateMultiplier: 1.5
        },
        // CrowdStrike — normal operations
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: {
              values: [
                'ProcessRollup2', 'DnsRequest', 'NetworkConnectIP4',
                'SensorHeartbeat', 'FileWritten'
              ],
              weights: [0.3, 0.2, 0.2, 0.15, 0.15]
            },
            SeverityName: {
              values: ['Informational', 'Low'],
              weights: [0.9, 0.1]
            },
            UserName: '{{employees.username}}',
            ComputerName: '{{workstations.hostname}}'
          },
          rateMultiplier: 1.0
        },
        // Email / SMTP relay traffic
        {
          sourcetype: 'pan:traffic',
          weight: 0.10,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: {
              values: [25, 587, 443],
              weights: [0.3, 0.3, 0.4]
            },
            app: {
              values: ['smtp', 'ssl'],
              weights: [0.5, 0.5]
            },
            action: 'allow',
            bytes_sent: { min: 1000, max: 500000 },
            bytes_received: { min: 200, max: 5000 },
            rule: 'allow-email-outbound'
          },
          rateMultiplier: 0.8
        }
      ]
    },

    // -- Phase 4: Lunch Dip (12:00-13:00) --------------------------------
    // Reduced activity. Some people step away, others browse personal
    // sites or stream content.
    {
      name: 'lunch_dip',
      duration: { min: 60000, max: 60000 }, // 1 minute (representing 1 hour)
      timeWindow: { start: '12:00', end: '13:00' },
      events: [
        // Reduced web traffic — more personal browsing
        {
          sourcetype: 'pan:traffic',
          weight: 0.40,
          overrides: {
            src_ip: '{{workstations.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: 443,
            app: {
              values: [
                'ssl', 'web-browsing', 'youtube',
                'netflix', 'spotify', 'ms-teams', 'slack'
              ],
              weights: [0.2, 0.15, 0.15, 0.1, 0.1, 0.15, 0.15]
            },
            action: {
              values: ['allow', 'deny'],
              weights: [0.92, 0.08]
            },
            bytes_sent: { min: 200, max: 50000 },
            bytes_received: { min: 500, max: 10000000 },
            rule: {
              values: ['allow-web-outbound', 'deny-streaming-policy'],
              weights: [0.92, 0.08]
            }
          },
          rateMultiplier: 0.6
        },
        // CrowdStrike — low activity
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.20,
          overrides: {
            event_simpleName: {
              values: ['SensorHeartbeat', 'ProcessRollup2', 'ScreensaverStarted'],
              weights: [0.5, 0.3, 0.2]
            },
            SeverityName: 'Informational',
            ComputerName: '{{workstations.hostname}}'
          },
          rateMultiplier: 0.3
        },
        // Occasional Okta activity
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: {
              values: ['app.auth.sso', 'user.session.extend'],
              weights: [0.4, 0.6]
            },
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{employees.email}}'
          },
          rateMultiplier: 0.3
        },
        // Server-to-server continues (automated, not human)
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: '{{servers.ip}}',
            app: {
              values: ['ms-sql', 'ssl', 'http'],
              weights: [0.4, 0.3, 0.3]
            },
            action: 'allow',
            rule: 'allow-internal-app-traffic'
          },
          rateMultiplier: 1.0  // server traffic doesn't dip at lunch
        },
        // Windows — screen locks, idle
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.10,
          overrides: {
            variant: '4800_workstation_locked',
            EventCode: {
              values: [4800, 4624],  // Lock and unlock events
              weights: [0.6, 0.4]
            },
            TargetUserName: '{{employees.username}}'
          },
          rateMultiplier: 0.4
        }
      ]
    },

    // -- Phase 5: Business Hours — Afternoon (13:00-17:00) ---------------
    // Back to full productivity. Similar to morning but with more
    // collaborative traffic (meetings, shared documents).
    {
      name: 'business_hours_pm',
      duration: { min: 240000, max: 240000 }, // 4 minutes (representing 4 hours)
      timeWindow: { start: '13:00', end: '17:00' },
      events: [
        // Web and SaaS traffic — afternoon peak
        {
          sourcetype: 'pan:traffic',
          weight: 0.30,
          overrides: {
            src_ip: '{{workstations.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: {
              values: [443, 80],
              weights: [0.92, 0.08]
            },
            app: {
              values: [
                'ssl', 'web-browsing', 'ms-office365',
                'ms-teams', 'zoom', 'salesforce',
                'github', 'slack', 'google-base'
              ],
              weights: [0.18, 0.12, 0.15, 0.12, 0.1, 0.1, 0.08, 0.08, 0.07]
            },
            action: {
              values: ['allow', 'deny'],
              weights: [0.97, 0.03]
            },
            bytes_sent: { min: 500, max: 150000 },
            bytes_received: { min: 1000, max: 8000000 },
            rule: {
              values: ['allow-web-outbound', 'deny-category-block'],
              weights: [0.97, 0.03]
            }
          },
          rateMultiplier: 2.5
        },
        // Okta — sessions, app access
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: {
              values: [
                'app.auth.sso', 'user.session.start',
                'app.access', 'user.session.extend'
              ],
              weights: [0.35, 0.15, 0.3, 0.2]
            },
            'outcome.result': {
              values: ['SUCCESS', 'FAILURE'],
              weights: [0.98, 0.02]
            },
            'actor.alternateId': '{{employees.email}}',
            'client.ipAddress': '{{employees.ip}}'
          },
          rateMultiplier: 1.0
        },
        // File and printer access
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.15,
          overrides: {
            variant: {
              values: ['4663_object_access', '5140_network_share_access', '4688_process_creation'],
              weights: [0.35, 0.3, 0.35]
            },
            EventCode: {
              values: [4663, 5140, 4688],
              weights: [0.35, 0.3, 0.35]
            },
            TargetUserName: '{{employees.username}}',
            IpAddress: '{{workstations.ip}}'
          },
          rateMultiplier: 1.5
        },
        // CrowdStrike — steady normal operations
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: {
              values: [
                'ProcessRollup2', 'DnsRequest', 'NetworkConnectIP4',
                'FileWritten', 'SensorHeartbeat'
              ],
              weights: [0.3, 0.2, 0.2, 0.15, 0.15]
            },
            SeverityName: {
              values: ['Informational', 'Low'],
              weights: [0.92, 0.08]
            },
            UserName: '{{employees.username}}',
            ComputerName: '{{workstations.hostname}}'
          },
          rateMultiplier: 1.0
        },
        // Internal server traffic — afternoon batch processing
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: '{{servers.ip}}',
            app: {
              values: ['ms-sql', 'oracle', 'ssl', 'http', 'ldap', 'kerberos'],
              weights: [0.2, 0.15, 0.2, 0.2, 0.15, 0.1]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 100000 },
            bytes_received: { min: 500, max: 1000000 },
            rule: 'allow-internal-app-traffic'
          },
          rateMultiplier: 2.0
        },
        // Print jobs (afternoon reports)
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.10,
          overrides: {
            variant: '307_print_job',
            EventCode: 307,
            TargetUserName: '{{employees.username}}',
            PrinterName: {
              values: [
                '\\\\PRINTSRV\\HP-Floor3',
                '\\\\PRINTSRV\\HP-Floor2',
                '\\\\PRINTSRV\\Xerox-Main'
              ],
              weights: [0.4, 0.35, 0.25]
            }
          },
          rateMultiplier: 0.3
        }
      ]
    },

    // -- Phase 6: Evening Wind-Down (17:00-19:00) ------------------------
    // Employees log off, VPN disconnects, sessions end. A few
    // workaholics hang around.
    {
      name: 'evening_winddown',
      duration: { min: 120000, max: 120000 }, // 2 minutes (representing 2 hours)
      timeWindow: { start: '17:00', end: '19:00' },
      events: [
        // Session endings and logoffs
        {
          sourcetype: 'okta:system',
          weight: 0.25,
          overrides: {
            eventType: {
              values: ['user.session.end', 'user.session.start', 'app.auth.sso'],
              weights: [0.5, 0.2, 0.3]
            },
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{employees.email}}'
          },
          rateMultiplier: 1.0
        },
        // Windows logoff events
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.25,
          overrides: {
            variant: {
              values: ['4634_logoff', '4647_user_initiated_logoff', '4624_successful_logon'],
              weights: [0.4, 0.3, 0.3]
            },
            EventCode: {
              values: [4634, 4647, 4624],
              weights: [0.4, 0.3, 0.3]
            },
            TargetUserName: '{{employees.username}}',
            LogonType: {
              values: [2, 10, 3],
              weights: [0.5, 0.3, 0.2]
            }
          },
          rateMultiplier: 1.0
        },
        // VPN disconnects
        {
          sourcetype: 'pan:traffic',
          weight: 0.20,
          overrides: {
            src_ip: { type: 'random_public' },
            dst_ip: '{{servers.ip}}',
            app: {
              values: ['ssl-vpn', 'ipsec', 'globalprotect'],
              weights: [0.4, 0.3, 0.3]
            },
            action: 'allow',
            session_end_reason: {
              values: ['tcp-fin', 'aged-out'],
              weights: [0.7, 0.3]
            },
            bytes_sent: { min: 100000, max: 50000000 },
            bytes_received: { min: 500000, max: 200000000 },
            rule: 'allow-vpn-inbound'
          },
          rateMultiplier: 0.8
        },
        // Declining web traffic
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{workstations.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: 443,
            app: {
              values: ['ssl', 'web-browsing', 'ms-office365'],
              weights: [0.4, 0.3, 0.3]
            },
            action: 'allow',
            rule: 'allow-web-outbound'
          },
          rateMultiplier: 0.5
        },
        // CrowdStrike — machines going idle
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: {
              values: ['SensorHeartbeat', 'ProcessRollup2', 'UserLogoff'],
              weights: [0.5, 0.3, 0.2]
            },
            SeverityName: 'Informational',
            ComputerName: '{{workstations.hostname}}'
          },
          rateMultiplier: 0.4
        }
      ]
    },

    // -- Phase 7: Off-Hours (19:00-00:00) --------------------------------
    // Very quiet. Automated processes, monitoring, and a handful of
    // late-working employees.
    {
      name: 'off_hours',
      duration: { min: 300000, max: 300000 }, // 5 minutes (representing 5 hours)
      timeWindow: { start: '19:00', end: '00:00' },
      events: [
        // Automated monitoring and health checks
        {
          sourcetype: 'pan:traffic',
          weight: 0.30,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: '{{servers.ip}}',
            app: {
              values: ['ssl', 'http', 'snmp', 'ntp'],
              weights: [0.3, 0.3, 0.2, 0.2]
            },
            action: 'allow',
            bytes_sent: { min: 100, max: 5000 },
            bytes_received: { min: 100, max: 5000 },
            rule: {
              values: ['allow-monitoring', 'allow-internal-app-traffic'],
              weights: [0.6, 0.4]
            }
          },
          rateMultiplier: 0.15
        },
        // CrowdStrike heartbeats
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: {
              values: ['SensorHeartbeat', 'ConfigStateUpdate'],
              weights: [0.7, 0.3]
            },
            SeverityName: 'Informational',
            ComputerName: '{{workstations.hostname}}'
          },
          rateMultiplier: 0.05
        },
        // Occasional late-worker activity
        {
          sourcetype: 'okta:system',
          weight: 0.15,
          overrides: {
            eventType: {
              values: ['app.auth.sso', 'user.session.extend'],
              weights: [0.5, 0.5]
            },
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{employees.email}}'
          },
          rateMultiplier: 0.05
        },
        // Windows service accounts — scheduled tasks
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: '4624_successful_logon',
            EventCode: 4624,
            TargetUserName: {
              values: ['SYSTEM', 'svc_monitoring', 'svc_backup', 'svc_etl'],
              weights: [0.4, 0.3, 0.2, 0.1]
            },
            LogonType: 5,  // Service
            IpAddress: '{{servers.ip}}'
          },
          rateMultiplier: 0.1
        },
        // Nightly database maintenance
        {
          sourcetype: 'pan:traffic',
          weight: 0.10,
          overrides: {
            src_ip: '{{servers.ip}}',
            dst_ip: '{{servers.ip}}',
            dst_port: {
              values: [1433, 1521, 5432, 3306],
              weights: [0.3, 0.25, 0.25, 0.2]
            },
            app: {
              values: ['ms-sql', 'oracle', 'postgresql', 'mysql'],
              weights: [0.3, 0.25, 0.25, 0.2]
            },
            action: 'allow',
            bytes_sent: { min: 10000, max: 500000 },
            bytes_received: { min: 50000, max: 5000000 },
            rule: 'allow-db-maintenance'
          },
          rateMultiplier: 0.2
        }
      ]
    }
  ]
};
