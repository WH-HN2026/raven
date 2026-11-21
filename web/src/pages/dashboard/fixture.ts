// Sample GET /api/dashboard body for the tests.
import type { Dashboard } from './ui'

const run = (id: number) => ({
  id,
  profile_id: 1,
  status: 'done' as const,
  started_at: '2026-11-21T10:00:00Z',
  finished_at: '2026-11-21T10:01:30Z',
})

export const dashboard: Dashboard = {
  findings: {
    by_severity: [
      { severity: 'Critical', count: 2 },
      { severity: 'High', count: 14 },
      { severity: 'Medium', count: 0 },
      { severity: 'Low', count: 7 },
      { severity: 'Info', count: 31 },
    ],
    total: 54,
  },
  hosts: { active: 1204, unstable: 3, inactive: 1, services_open: 3871 },
  changes: {
    from: run(41),
    to: run(42),
    summary: { hosts_new: 1, hosts_gone: 1, services_new: 0, services_gone: 0, services_changed: 1 },
    hosts_new: [{ ip: '172.30.0.12', other_run: 'not_scanned', ports: [8080] }],
    hosts_gone: [{ ip: '172.30.0.11', other_run: 'down', ports: [22] }],
    services_new: [],
    services_gone: [],
    services_changed: [
      {
        ip: '172.30.0.10',
        port: 80,
        proto: 'tcp',
        before: { name: 'http', product: 'Apache httpd', version: '2.4.49', title: '', technologies: [] },
        after: { name: 'http', product: 'Apache httpd', version: '2.4.50', title: '', technologies: [] },
        fields: ['version'],
      },
    ],
    truncated: false,
  },
  new_hosts: [
    { ip: '172.30.0.12', hostnames: ['jenkins.lab'], state: 'active', first_seen: '2026-11-21T10:00:30Z', ports: [8080] },
  ],
  new_hosts_total: 1,
  unstable_hosts: [
    {
      ip: '172.30.0.11',
      hostnames: [],
      state: 'unstable',
      last_seen: '2026-11-20T10:00:00Z',
      miss_count: 1,
      up_runs: 3,
      seen_runs: 5,
    },
    {
      ip: '172.30.0.13',
      hostnames: [],
      state: 'inactive',
      last_seen: '2026-11-18T10:00:00Z',
      miss_count: 3,
      up_runs: 0,
      seen_runs: 0,
    },
  ],
  technologies: [
    { name: 'Nginx', hosts: 4 },
    { name: 'Apache HTTP Server', hosts: 2 },
  ],
  cve_matches: [
    {
      ip: '172.30.0.10',
      port: 80,
      proto: 'tcp',
      product: 'Apache httpd',
      version: '2.4.49',
      severity: 'Critical',
      max_cvss: 9.8,
      kev: 2,
      cves: 5,
    },
  ],
  cve_total: 1,
  runs: [
    {
      ...run(42),
      profile: 'lab',
      created_at: '2026-11-21T10:00:00Z',
      duration_ms: 90000,
      hosts_total: 6,
      hosts_up: 5,
      batches_total: 2,
      batches_done: 2,
    },
  ],
  latest_run: run(42),
}
