This folder is used to store my presentation for BSides Canberra and accompanying files.

This repo contains things such as demo scripts, hook source file, auditd rules, OSquery, and triage one-liners mentioned in the presentation. 


# Lab Setup
Two VMs, with host-only network:
- control: clean system, used for initiating SSH connections. 
- target: victim system. All demos were run here.

# Vector 1 - PAM Module Abuse
MITRE: T1556.003 - Modify Authentication Process: PAM

## How it works
PAM is the authentication abstraction layer used by services such as sshd, sudo, su, login, cups, cron, and much more. A single line using pam_exec can allow an attacker-controlled script to run on every authentication event as root before the user sees any prompt.

```
session optional pam_exec.so /usr/local/bin/.pam_marker.sh
```

## Demo
pam_marker.sh is used to write a timestamped log entry and drops a root-owned marker file. You can change this to open netcat on the system or anything that your desire. The payload I've created is benign.

## Detection
**1. Package verification**
```
#Debian
dpkg -V openssh-server
#RHEL
rpm -Va | grep pam 
```

**2. Unpackaged files**
```
#replace the path with any script or file you desire.
dpkg -S /usr/local/bin/.pam_marker.sh
```

**3. Timestamps**
```
stat /etc/pam.d/sshd
```

**4. auditd**
Load the following:
```
# Catches the config tamper (must be loaded before the edit)
sudo auditctl -w /etc/pam.d/ -p wa -k pam_config
sudo auditctl -w /lib/x86_64-linux-gnu/security/ -p wa -k pam_modules

# Catches pam_exec executing anything
sudo auditctl -a always,exit -F arch=b64 -S execve \
  -F exe=/usr/sbin/sshd -k pam_exec_child

# Catches each execution of a known payload path
sudo auditctl -a always,exit -F arch=b64 -S execve \
  -F path=/usr/local/bin/.pam_marker.sh -k pam_exec_fired
```
To query the above:
```
sudo ausearch -k pam_config -i | tail
sudo ausearch -k pam_exec_child -i | grep 'a0=' 
sudo ausearch -k pam_exec_fired -i | tail
```
**5. OSQuery **
PAM Config files sorted by ctime. Look out for files modified outside office hours.
```
SELECT path,
       uid, gid, mode,
       datetime(mtime, 'unixepoch') AS modified,
       datetime(ctime, 'unixepoch') AS changed
FROM file
WHERE path LIKE '/etc/pam.d/%'
ORDER BY ctime DESC;
```

PAM Module directory 
```
SELECT path, size,
       datetime(mtime, 'unixepoch') AS modified,
       datetime(ctime, 'unixepoch') AS changed
FROM file
WHERE path LIKE '/lib/x86_64-linux-gnu/security/%'
   OR path LIKE '/lib64/security/%'
ORDER BY ctime DESC;
```

Integrity hash of key PAM files
```
SELECT path, md5, sha256
FROM hash
WHERE path IN (
  '/etc/pam.d/sshd',
  '/etc/pam.d/common-auth',
  '/etc/pam.d/sudo',
  '/lib/x86_64-linux-gnu/security/pam_unix.so',
  '/lib/x86_64-linux-gnu/security/pam_exec.so'
);
```



#Vector 2 - Dynamic Linker Abuse (LDPRELOAD)
MITRE: T1574.006 - Dynamic Linker Hijacking

## How it works
The dynamic linker (ld.so) is used to resolve library symbols at runtime. This is stored in the file /etc/ld.so/preload which forces a library to load into every new dynamically linked process before anything else. I created a hook to override the functions readdir and readdir64 controls which are used by all dynamically-linked tools that are used to find files on a system (ls, find).
**The file /etc/ld.so.preload does not exist by default.**

## Demo
hook.c is a minimally edited file for readdir and readdir64 hook that filters named entries from directory listings. This program hides specified files in an array such as the marker file and ld.so.preload itself.
To build the program, run:
```
gcc -Wall -fPIC -shared -o libprocesshider.so ldpreload/hook.c -ldl
strings libprocesshider.so | grep -E "bsides_marker|ld\.so\.preload"  
sudo cp libprocesshider.so /usr/local/lib/
sudo bash -c 'echo /usr/local/lib/libprocesshider.so > /etc/ld.so.preload'
```
If you make a mistake, disable the preload before building or copying. Copying a broken hook will cause a segfault which is never fun. Easiest fix is reverting to a clean snapshot.

## Detection
**1. The file itself**
Use busybox instead of ls as the hook hides it.
```
cat /etc/ld.so.preload                       # readable by direct path even when hidden from ls
stat /etc/ld.so.preload                      # ctime = when they moved in
/bin/busybox ls /etc/ | grep preload         # static binary bypasses the hook entirely
```

**2. Unpackaged Library**
The Debian package manager is used to determine whether SO file is an orphaned file.
```
dpkg -S /usr/local/lib/libprocesshider.so
```

**3. Live Process Mapping**
```
sleep 300 &
grep libprocesshider /proc/$!/maps
cat /proc/$!/environ | tr '\0' '\n' | grep LD_PRELOAD
kill $!
```

/proc/<pid>/maps goes through the kernel's procfs interface and not libc. The hook cannot intercept it. When you can't trust the filesystem, you can always fall back on /proc

**4. Static Binary as Ground Truth**
```
/bin/busybox ls -la <directory>
/bin/busybox cat /etc/ld.so.preload
```

**5. Auditd**
Deploy the following rules:
```
sudo auditctl -w /etc/ld.so.preload -p -wa -k ldpreload
sudo auditctl -w /etc/ld.so.conf.d/ -p wa -k ldconf
sudo auditctl -l
#Query with
sudo ausearch -k ldpreload -i | tail
```

environment variable preloads are hard without process-environment telemetry. 

**6. Memory**
If the box is compromised where userland tools can't be trusted, take a memory capture:
- AVML: Capture the memory image from a live system.
- Volatility: Used to analyze the system image.

**7. OSQuery**
Check if ld.so.preload exists
```
SELECT path, size, uid, gid,
       datetime(mtime, 'unixepoch') AS modified,
       datetime(ctime, 'unixepoch') AS changed
FROM file
WHERE path = '/etc/ld.so.preload';
```

Check running processes with LD_PRELOAD in their eivnornment.
This captures env-var preloads that bypass /etc/ld.so.preload.
```
SELECT p.pid, p.name, p.path, pe.value AS preload_path
FROM processes p
JOIN process_envs pe ON p.pid = pe.pid
WHERE pe.key = 'LD_PRELOAD';
```

Shared libraries mapped into processes from non-standard paths such as /usr/local/lib which is not a linker search path.
```
SELECT DISTINCT pm.pid, pr.name, pm.path AS mapped_lib
FROM process_memory_map pm
JOIN processes pr ON pm.pid = pr.pid
WHERE pm.path LIKE '/usr/local/lib/%.so%'
ORDER BY pr.name;
```

Broader hunt for .so files mapped from outside standard lib directories. You may need to tune based on your environment's legitimate preloads.
```
SELECT DISTINCT pm.pid, pr.name, pm.path AS mapped_lib
FROM process_memory_map pm
JOIN processes pr ON pm.pid = pr.pid
WHERE pm.path LIKE '%.so%'
  AND pm.path NOT LIKE '/lib/%'
  AND pm.path NOT LIKE '/usr/lib/%'
  AND pm.path NOT LIKE '/usr/share/%'
  AND pm.path NOT LIKE '/opt/%'          -- adjust if /opt is legitimate in your env
  AND pm.path != ''
ORDER BY pm.path;
```

ld.so config files sorted by recent changes to linker search path.
```
SELECT path, size,
       datetime(mtime, 'unixepoch') AS modified,
       datetime(ctime, 'unixepoch') AS changed
FROM file
WHERE path = '/etc/ld.so.conf'
   OR path LIKE '/etc/ld.so.conf.d/%'
ORDER BY ctime DESC;
```

Hash the preload file for baselining and cross-host comparison.
```
SELECT path, md5, sha256
FROM hash
WHERE path = '/etc/ld.so.preload';
```

If you want a triage script throw the following into a 
```
# PAM — verify package-owned files
dpkg -V openssh-server libpam-modules

# PAM — unpackaged files in pam_exec lines
grep -r pam_exec /etc/pam.d/ | awk '{print $NF}' | xargs -I{} dpkg -S {} 2>&1

# PAM — root-owned files in user home directories
find /home -maxdepth 2 -user root -type f 2>/dev/null

# LD_PRELOAD — check by direct path, not ls
cat /etc/ld.so.preload 2>/dev/null && echo "PRESENT — investigate"

# LD_PRELOAD — orphan libraries in system paths
for f in /usr/local/lib/*.so /usr/lib/*.so; do
  dpkg -S "$f" 2>&1 | grep -q "no path found" && echo "UNPACKAGED: $f"
done

# LD_PRELOAD — check running processes for unexpected preloads
for pid in /proc/[0-9]*/maps; do
  grep -l '\.so' "$pid" 2>/dev/null | xargs grep -l 'local/lib' 2>/dev/null
done
```
