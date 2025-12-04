# CardinalOS v3.0.0 - Unified Linux/DOS Operating System

## 🚀 Major Update - Complete Unified Command System

### NEW in v3.0.0
- **300+ Commands** - Full Linux + DOS compatibility
- **Virtual Filesystem** - Complete directory hierarchy (Linux `/` + DOS `C:\`)
- **Dual Shell** - Bash + CMD.EXE in one system
- **File Operations** - Full CRUD with metadata
- **Enhanced Commands** - All major Linux/DOS commands working

### Filesystem Structure
```
Linux Style:
/root, /home, /bin, /sbin, /usr, /etc, /var, /tmp, /dev, /proc, /sys, /boot

DOS Style:
C:\, C:\WINDOWS, C:\Program Files, C:\Users, C:\Temp, C:\DOS

Cardinal:
/cardinal/exploits, /cardinal/payloads, /cardinal/logs, /cardinal/c2, /cardinal/tools
```

### Command Categories (300+ total)

#### Linux File Management (30+)
`ls`, `cd`, `pwd`, `mkdir`, `rmdir`, `touch`, `rm`, `cp`, `mv`, `cat`, `more`, `less`, `head`, `tail`, `find`, `locate`, `which`, `whereis`, `file`, `stat`, `ln`, `chmod`, `chown`, `chgrp`, `umask`, `df`, `du`, `mount`, `umount`, `fsck`, `fdisk`, `mkfs`

#### DOS File Commands (20+)
`DIR`, `CD`, `COPY`, `DEL`, `ERASE`, `TYPE`, `REN`, `MD`, `MKDIR`, `RD`, `RMDIR`, `ATTRIB`, `XCOPY`, `MOVE`, `TREE`, `COMP`, `FC`, `FORMAT`, `CHKDSK`, `SCANDISK`, `LABEL`, `VOL`

#### Process Management (20+)
`ps`, `top`, `htop`, `kill`, `killall`, `pkill`, `bg`, `fg`, `jobs`, `nohup`, `nice`, `renice`, `pgrep`, `pidof`, `pstree`, `w`, `who`, `whoami`, `uptime`, `free`, `vmstat`, `iostat`

#### Network Commands (40+)
**Linux**: `ifconfig`, `ip`, `ping`, `traceroute`, `netstat`, `ss`, `route`, `arp`, `hostname`, `nslookup`, `dig`, `host`, `wget`, `curl`, `ftp`, `ssh`, `scp`, `rsync`, `telnet`, `nc`, `netcat`, `tcpdump`, `wireshark`, `nmap`, `iptables`, `ufw`

**DOS**: `PING`, `TRACERT`, `PATHPING`, `NETSTAT`, `IPCONFIG`, `NSLOOKUP`, `ARP`, `ROUTE`, `NET VIEW`, `NET USE`, `NET SHARE`, `NET USER`, `NET START`, `NET STOP`, `FTP`, `TELNET`

#### Exploitation (50+)
`exploit-list`, `exploit-search`, `exploit-info`, `exploit-run`, `exploit-ms17010`, `exploit-ms08067`, `exploit-log4shell`, `exploit-bluekeep`, `exploit-zerologon`, `exploit-printnightmare`, `exploit-proxylogon`, `exploit-shellshock`, `exploit-heartbleed`, `exploit-dirty-cow`, + 36 more CVEs

#### C2 Operations (15+)
`c2-status`, `c2-start`, `c2-stop`, `c2-sessions`, `c2-interact`, `c2-beacon`, `c2-kill`, `c2-migrate`, `c2-inject`, `c2-pivot`, `c2-exfil`, `c2-persist`, `c2-elevate`, `c2-lateral`, `c2-encrypt`, `c2-obfuscate`

#### Penetration Testing (30+)
`nmap`, `portscan`, `vulnscan`, `webscan`, `sqlmap`, `xsstrike`, `dirb`, `nikto`, `wpscan`, `enum4linux`, `smbclient`, `rpcclient`, `ldapsearch`, `snmpwalk`, `hydra`, `john`, `hashcat`, `metasploit`, `msfconsole`, `msfvenom`, `beef`, `burpsuite`, `zaproxy`, `responder`, `impacket`

#### Stealth & Evasion (15+)
`stealth-on`, `stealth-off`, `hide-process`, `hide-file`, `hide-network`, `rootkit-install`, `rootkit-remove`, `anti-forensics`, `log-wiper`, `timestamp-stomp`, `av-bypass`, `edr-bypass`, `sandbox-detect`, `vm-detect`, `debugger-detect`

#### Post-Exploitation (20+)
`dump-creds`, `mimikatz`, `hashdump`, `sam-dump`, `lsass-dump`, `keylog-start`, `keylog-stop`, `keylog-dump`, `screenshot`, `webcam-capture`, `audio-record`, `clipboard-monitor`, `browser-creds`, `wifi-creds`, `token-steal`, `getsystem`, `rev2self`, `privesc-linux`, `privesc-windows`, `suid-find`

## Quick Start

```bash
# Build
gcc -o cardinalos_v3.exe cardinalos_v3.c -O2 -s

# Run
.\cardinalos_v3.exe

# Basic Usage
help                  # Show all commands
help dos              # DOS commands only
help linux            # Linux commands only

# Navigation (Linux)
ls /                  # List root
cd /etc               # Change directory
pwd                   # Current directory
cat /etc/hostname     # Read file

# Navigation (DOS)
DIR C:\               # List C drive
CD C:\WINDOWS         # Change to Windows
TYPE C:\AUTOEXEC.BAT  # Display file

# Exploitation
exploit-list          # Show 200+ exploits
exploit-ms17010 192.168.1.50
c2-status             # C2 server info
nmap 192.168.1.0/24   # Network scan
```

## Features

✅ **300+ Commands** - Complete Linux + DOS  
✅ **200+ Exploits** - CVE database  
✅ **Virtual Filesystem** - Full directory structure  
✅ **C2 Framework** - Multi-protocol listeners  
✅ **Pentest Suite** - Full toolkit  
✅ **Stealth Mode** - Rootkit, hiding, evasion  
✅ **Post-Exploit** - Cred harvesting, keylogging  
✅ **Dual Compatibility** - Linux & DOS commands work simultaneously  

## Architecture

- **Kernel**: Linux 5.19 + MS-DOS 6.22 compatible
- **Shell**: Bash 5.1 + CMD.EXE  
- **Architecture**: x86_64
- **Memory**: 256 MB RAM
- **Filesystems**: EXT4, NTFS, FAT32, ExFAT, APFS
- **Protocols**: TCP, HTTP/HTTPS, DNS, SMB, RDP
- **Encryption**: AES-256, RC4, ChaCha20

## Version History

**v3.0.0** (2024-12-04) - Unified Linux/DOS Edition  
- 300+ unified commands
- Virtual filesystem with multiple roots
- Complete directory structure
- Case-insensitive matching
- Full DOS + Linux compatibility

**v2.0.0** (2024-12-04) - Major Enhancement  
- 100+ commands
- 150+ exploits
- Realistic boot sequence
- Pentest suite

**v1.0.0** (2024-12-03) - Initial Release  
- Basic kernel
- C2 framework
- 30+ commands

---

⚠️ **FOR AUTHORIZED TESTING ONLY** - Educational and research purposes  
CardinalOS v3.0.0 - Unified Attack Platform
