# Rollback Plan for OmniKernel Agent

This guide provides step-by-step instructions to safely roll back OmniKernel Agent to the previous state if issues are detected after deployment.

## When to Roll Back

- Agent service crashes or causes host instability.
- Kernel panic or eBPF program verification failures.
- Excessive false-positive denials blocking legitimate workloads.
- Performance degradation (CPU, memory, or I/O).
- Licensing validation failures affecting service startup.

## Pre-Rollback Checklist

1. Document the issue with timestamp and affected hosts.
2. Collect systemd logs and kernel messages:
   ```bash
   journalctl -u omnikernel-agent -n 100 > /tmp/omnikernel-logs.txt
   dmesg -T | tail -50 >> /tmp/omnikernel-logs.txt
   ```
3. Capture current eBPF LSM state:
   ```bash
   bpftool prog list
   bpftool map list
   ```
4. Notify stakeholders (SOC, platform team) of rollback intent.

## Rollback Steps

### Step 1: Stop the Agent Service

```bash
sudo systemctl stop omnikernel-agent
```

Verify the service has stopped:
```bash
sudo systemctl status omnikernel-agent
```

Expected output: `inactive (dead)`.

### Step 2: Verify eBPF LSM Cleanup

Check that LSM programs are detached:
```bash
bpftool prog list | grep lsm
```

Expected output: No `lsm/file_open` or `lsm/bprm_check_security` programs should be listed.

If programs persist, force cleanup:
```bash
sudo ip link set lo up  # trigger eBPF link cleanup via network event
sleep 2
bpftool prog list | grep lsm  # verify again
```

### Step 3: Remove or Downgrade the Agent Package

**Option A: Uninstall the Agent**

```bash
sudo apt-get remove omnikernel-agent  # Debian/Ubuntu
# OR
sudo yum remove omnikernel-agent      # RHEL/Amazon Linux
# OR
sudo zypper remove omnikernel-agent   # SUSE
```

**Option B: Downgrade to Previous Version**

If you have a previous version archive:
```bash
sudo tar -xzf /tmp/omnikernel-agent-v1.0.0.tar.gz -C /opt/
sudo systemctl restart omnikernel-agent
```

### Step 4: Restore Previous Configuration

If configuration changes caused issues, restore from backup:

```bash
sudo cp /etc/omnikernel/agent.env.backup /etc/omnikernel/agent.env
sudo chown root:root /etc/omnikernel/agent.env
sudo chmod 600 /etc/omnikernel/agent.env
```

### Step 5: Restart Host (if necessary)

For severe issues, reboot to ensure all eBPF state is cleared:

```bash
sudo reboot
```

After reboot, verify:
```bash
systemctl status omnikernel-agent
bpftool prog list | grep lsm
```

### Step 6: Restore Audit/Alert Pipeline

If rollback affects monitoring, verify your SIEM ingestion is back to pre-agent baseline:

```bash
# Check if alerts are no longer being sent
curl -s https://your-mesh-hub/health | jq .

# Validate syslog or other fallback logging is working
logger "Test message for rollback verification"
grep "Test message" /var/log/syslog  # or your syslog location
```

## Rollback Verification

After rollback, confirm the system is in the expected state:

### Verification Checklist

- [ ] `systemctl status omnikernel-agent` shows `inactive (dead)` or `Unit not found`.
- [ ] `bpftool prog list` has no LSM programs.
- [ ] Host kernel logs show no new LSM errors.
- [ ] Service workloads are operating normally.
- [ ] Performance metrics (CPU, memory, I/O) return to baseline.
- [ ] No false-positive denials in application logs.

### Sample Verification Commands

```bash
#!/bin/bash
# rollback-verify.sh

echo "=== OmniKernel Rollback Verification ==="

# Check service state
echo "Service Status:"
systemctl is-active omnikernel-agent || echo "Service inactive (expected)"

# Check eBPF programs
echo -e "\neBPF LSM Programs:"
bpftool prog list 2>/dev/null | grep -c lsm && echo "LSM programs still loaded!" || echo "LSM programs cleared ✓"

# Check kernel messages
echo -e "\nRecent kernel messages:"
dmesg -T | tail -10

echo -e "\n=== Verification Complete ==="
```

## Testing Before Full Rollout

Before rolling back across your entire fleet, test on a single node:

```bash
ssh node-01.example.com
sudo systemctl stop omnikernel-agent
# Run verification script
bash /path/to/rollback-verify.sh
# Monitor for 30 minutes, then proceed with remaining nodes
```

## Gradual Rollback (Recommended for Large Fleets)

1. **Phase 1 (Pilot)**: Roll back 5% of nodes; monitor for 1 hour.
2. **Phase 2 (Canary)**: Roll back 20% of nodes; monitor for 2 hours.
3. **Phase 3 (Staged)**: Roll back 50% of nodes; monitor for 4 hours.
4. **Phase 4 (Complete)**: Roll back remaining nodes.

## Post-Rollback Analysis

Once the system is stable in rollback, capture telemetry for root-cause analysis:

```bash
# Collect logs from agent deployment
tar -czf /tmp/omnikernel-incident-$(date +%s).tar.gz \
  /var/log/omnikernel* \
  /tmp/omnikernel-logs.txt \
  /etc/omnikernel/

# Share with OmniKernel support team
```

## Contacting Support

If you encounter issues that require rollback, collect this information for your support case:

- Exact version deployed
- Timestamp when issues began
- Affected Linux distribution and kernel version
- `/tmp/omnikernel-incident-*.tar.gz` artifact
- Output of the verification script

## Re-Deployment After Rollback

Once the root cause is identified and fixed:

1. Update OmniKernel Agent to the patched version.
2. Test in a staging environment first.
3. Deploy to a small pilot group (5–10% of fleet).
4. Monitor for 24 hours before wider rollout.
5. Gradual rollout across remaining nodes.

## Prevention for Future Deployments

- Always test on staging before production rollout.
- Start with audit mode to catch policy issues without blocking.
- Use gradual enforcement rollout (audit → selective enforce → full enforce).
- Maintain backups of agent binaries and configuration.
- Keep systemd service and environment files under version control.
