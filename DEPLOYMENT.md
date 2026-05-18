# OmniKernel Agent Deployment Guide

This guide provides a detailed, production-ready deployment procedure for OmniKernel Agent across your Linux fleet.

## Pre-Deployment Checklist

- [ ] Linux kernel 5.13 or newer
- [ ] Kernel BTF available at `/sys/kernel/btf/vmlinux`
- [ ] `CONFIG_BPF_LSM=y` enabled
- [ ] Valid OmniKernel license (format: `OMNIKERNEL_LICENSE`)
- [ ] HMAC signing key for alert payload
- [ ] Mesh hub endpoint URL (or equivalent SIEM endpoint)
- [ ] Staging environment for testing

## Phase 1: Preparation

### Obtain the Package

Download from GitHub releases or your internal package repository:

```bash
wget https://github.com/devopsgeek1979/omni-kernel/releases/download/v1.0.0/omnikernel-agent-1.0.0.tar.gz
```

### Verify Integrity

```bash
sha256sum -c omnikernel-agent-1.0.0.tar.gz.sha256
```

### Extract and Inspect

```bash
tar -xzf omnikernel-agent-1.0.0.tar.gz -C /tmp/
ls -la /tmp/omnikernel-agent-1.0.0/
```

Expected contents:
- `omnikernel-agent` (binary)
- `omnikernel_lsm.o` (eBPF object)
- `omnikernel-agent.service` (systemd unit)
- `agent.env.example` (environment template)

## Phase 2: Staging Environment Testing

### Deploy to a Test Node

```bash
sudo mkdir -p /opt/omnikernel-agent
sudo tar -xzf omnikernel-agent-1.0.0.tar.gz -C /opt/omnikernel-agent
```

### Configure Environment

```bash
sudo cp /opt/omnikernel-agent/agent.env.example /etc/omnikernel/agent.env
sudo vi /etc/omnikernel/agent.env
```

Set these values:
```bash
OMNIKERNEL_LICENSE="your-signed-license"
OMNIKERNEL_SIGNING_KEY="your-hmac-key"
OMNIKERNEL_MESH_HUB_URL="https://soc.example.com/mesh/ingest"
OMNIKERNEL_ALLOWED_PATHS="/usr/bin:/usr/local/bin:/opt/app:/etc"
OMNIKERNEL_BPF_OBJECT="/opt/omnikernel-agent/omnikernel_lsm.o"
```

### Install Service

```bash
sudo cp /opt/omnikernel-agent/omnikernel-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable omnikernel-agent
```

### Start in Audit Mode

```bash
# Set enforcement_mode=0 (audit only) via environment
echo "OMNIKERNEL_ENFORCEMENT_MODE=0" | sudo tee -a /etc/omnikernel/agent.env

sudo systemctl start omnikernel-agent
```

### Monitor Logs

```bash
sudo journalctl -u omnikernel-agent -f
```

Expected logs:
```
eBPF LSM runtime initialised
whitelist map populated with X entries
listening for security events on ring buffer
```

### Verify eBPF Attachment

```bash
sudo bpftool prog list | grep lsm
```

Expected output:
```
123: lsm  name file_open  tag deadbeef  gpl
124: lsm  name bprm_check_security  tag deadbeef  gpl
```

### Run in Audit Mode (48–72 Hours)

Collect baseline security events:
```bash
sudo journalctl -u omnikernel-agent --since "2 days ago" | grep "event received"
```

## Phase 3: Policy Tuning

### Review Audit Logs

Identify legitimate processes that were not in the whitelist:
```bash
sudo journalctl -u omnikernel-agent | grep "path=" | tail -20
```

### Update Whitelist

Add necessary paths to `/etc/omnikernel/agent.env`:
```bash
OMNIKERNEL_ALLOWED_PATHS="/usr/bin:/usr/local/bin:/opt/app:/etc:/snap/bin"
```

Restart to apply:
```bash
sudo systemctl restart omnikernel-agent
```

### Iterate Until Stable

Continue adjusting the policy until there are no false positives during normal operations.

## Phase 4: Enforce Mode Pilot

### Enable Enforcement on Pilot Group

```bash
echo "OMNIKERNEL_ENFORCEMENT_MODE=1" | sudo tee -a /etc/omnikernel/agent.env
sudo systemctl restart omnikernel-agent
```

### Monitor for 24–48 Hours

```bash
sudo journalctl -u omnikernel-agent -f
```

Look for:
- No unexpected service crashes
- Denied events are legitimate threats
- Alerts reach SOC correctly

### Collect Metrics

```bash
events_denied=$(sudo journalctl -u omnikernel-agent | grep "verdict=deny" | wc -l)
events_allowed=$(sudo journalctl -u omnikernel-agent | grep "verdict=0" | wc -l)
echo "Denied: $events_denied, Allowed: $events_allowed"
```

## Phase 5: Production Rollout

### Gradual Fleet Deployment

1. **Wave 1 (5%)**: Deploy to 5% of production nodes, monitor 24 hours.
2. **Wave 2 (25%)**: Deploy to 25% of nodes, monitor 12 hours.
3. **Wave 3 (50%)**: Deploy to 50% of nodes, monitor 4 hours.
4. **Wave 4 (100%)**: Deploy to all nodes.

### Deployment Command (Ansible Example)

```yaml
- name: Deploy OmniKernel Agent
  hosts: production_nodes
  serial: "{{ deployment_wave_percent }}%"
  tasks:
    - name: Stop agent
      systemd:
        name: omnikernel-agent
        state: stopped

    - name: Extract agent package
      unarchive:
        src: /tmp/omnikernel-agent-1.0.0.tar.gz
        dest: /opt/omnikernel-agent
        owner: root
        group: root

    - name: Start agent
      systemd:
        name: omnikernel-agent
        state: started
        enabled: yes

    - name: Wait for eBPF initialization
      wait_for:
        timeout: 10
        delay: 2

    - name: Verify eBPF programs
      command: bpftool prog list
      register: bpf_check
      failed_when: "'lsm' not in bpf_check.stdout"
```

## Monitoring and Alerting

### Key Metrics to Track

- Agent service uptime
- eBPF program attachment status
- Event denial rate (blocked events per hour)
- Alert delivery latency
- CPU and memory consumption

### Example Prometheus Metrics

Export from agent logs (or via custom exporter):
```
omnikernel_events_denied_total 1234
omnikernel_events_allowed_total 5678
omnikernel_alerts_sent_total 1200
omnikernel_alerts_failed_total 2
omnikernel_ebpf_programs_attached 2
```

### Alert Rules

- Agent service is down for > 5 minutes
- eBPF program verification failures
- Alert delivery failures exceed 5 per minute
- CPU usage exceeds 10%

## Troubleshooting

### Agent Fails to Start

```bash
sudo journalctl -u omnikernel-agent -n 50
```

Check for:
- License validation errors
- Kernel BTF not available
- Permission issues with eBPF object file

### High False-Positive Denials

1. Switch to audit mode: `OMNIKERNEL_ENFORCEMENT_MODE=0`
2. Collect denied events: `journalctl -u omnikernel-agent | grep "verdict=deny"`
3. Update whitelist accordingly
4. Re-enable enforce mode after policy tuning

### Performance Degradation

Monitor eBPF program stats:
```bash
bpftool prog stat
```

If high CPU usage, consider:
- Reducing whitelist size (fewer map entries to check)
- Disabling on less-critical nodes
- Contacting support for optimization

## Rollback

If deployment causes issues, follow the rollback procedure in [ROLLBACK.md](ROLLBACK.md).

## Support

For issues or questions, contact: support@example.com
