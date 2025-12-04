# CardinalOS v4.0 Enterprise Edition - User Guide

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [First Boot](#first-boot)
5. [User Management](#user-management)
6. [File System](#file-system)
7. [Security Features](#security-features)
8. [GUI Desktop Mode](#gui-desktop-mode)
9. [ISO Generation](#iso-generation)
10. [Command Reference](#command-reference)
11. [Performance Tuning](#performance-tuning)
12. [Troubleshooting](#troubleshooting)

---

## Introduction

CardinalOS v4.0 Enterprise Edition is an advanced penetration testing and security research operating system that combines the power of Linux with DOS compatibility. It features military-grade security, a comprehensive permission system, GUI desktop mode, and the ability to generate bootable ISO images.

### Key Features

- 🔐 **Advanced Security**: Multi-level permissions, SELinux, firewall, audit logging
- 👥 **Multi-User System**: Root and regular users with authentication
- 📁 **Complete Filesystem**: 500 directories, 1000 files, full FHS compliance
- 🖥️ **GUI Desktop**: Full graphical environment with window manager
- 💿 **ISO Generation**: Create bootable images for deployment
- ⚡ **High Performance**: Optimized compilation with -O3 and native CPU instructions
- 🛠️ **200+ Commands**: Complete Linux and DOS command compatibility

---

## System Requirements

### Minimum Requirements
- **OS**: Windows 7 or later (64-bit)
- **CPU**: Dual-core processor (2.0 GHz)
- **RAM**: 1 GB
- **Disk**: 100 MB free space

### Recommended Requirements
- **OS**: Windows 10/11 (64-bit)
- **CPU**: Quad-core processor (3.0+ GHz)
- **RAM**: 4 GB or more
- **Disk**: 500 MB free space (for ISO generation)

### Build Requirements
- GCC MinGW-w64 15.2.0 or later
- Windows PowerShell 5.1+

---

## Installation

### Pre-Built Binary

1. Download `cardinalos_v4.exe` from the releases page
2. Place it in a directory of your choice
3. Double-click to run, or execute from command line

### Building from Source

```powershell
# Clone the repository
git clone https://github.com/yourusername/MoonLignt-C2-Framework.git
cd Cardinal-C2-Framework

# Compile with optimizations
gcc -o cardinalos_v4.exe cardinalos_v4.c -O3 -march=native -s -ffast-math -funroll-loops

# Run
.\cardinalos_v4.exe
```

---

## First Boot

### Boot Sequence

When you first start CardinalOS, you'll see:

1. **BIOS Screen**: Hardware detection and initialization
2. **Kernel Loading**: 25+ boot stages showing system initialization
3. **Security Initialization**: Firewall, SELinux, audit system startup
4. **User Login**: Automatic login as root user (default)

### Initial Setup

```bash
# Check system information
version
uname -a
hostname

# View security status
security

# List available commands
help

# Explore the filesystem
ls /
cd /etc
cat /etc/hostname
```

---

## User Management

### Default Users

| Username | UID | Password | Admin | Description |
|----------|-----|----------|-------|-------------|
| root     | 0   | toor     | Yes   | Superuser account |
| admin    | 1000| password | Yes   | Administrator account |
| user     | 1001| password | No    | Regular user |
| operator | 1002| password | No    | Operator account |
| security | 1003| password | No    | Security analyst |
| audit    | 1004| password | No    | Audit specialist |

### User Commands

```bash
# Show current user
whoami

# List all users
users

# View user details
who

# Switch user (coming soon)
su admin

# Execute command as admin (coming soon)
sudo <command>

# Change password (coming soon)
passwd
```

### User Permissions

Users have different permission levels:
- **Admin (Root)**: Full system access, all commands
- **Regular User**: Limited access, restricted commands

Permission bits:
- `0x01` - READ: Can read files/directories
- `0x02` - WRITE: Can modify files/create directories
- `0x04` - EXECUTE: Can execute files/access directories
- `0x08` - ADMIN: Full administrative privileges

---

## File System

### Directory Structure

CardinalOS follows the Linux Filesystem Hierarchy Standard (FHS):

```
/                       Root directory
├── root/              Root user home
├── home/              User home directories
│   ├── admin/
│   ├── user/
│   └── operator/
├── bin/               Essential binaries
├── sbin/              System binaries
├── boot/              Boot files
├── dev/               Device files
├── etc/               Configuration files
│   ├── init.d/
│   ├── systemd/
│   ├── network/
│   └── security/
├── lib/               Libraries
├── lib64/             64-bit libraries
├── opt/               Optional software
├── proc/              Process information
├── sys/               System information
├── tmp/               Temporary files
├── usr/               User programs
│   ├── bin/
│   ├── sbin/
│   ├── lib/
│   ├── local/
│   ├── share/
│   ├── include/
│   └── src/
├── var/               Variable data
│   ├── log/
│   ├── tmp/
│   ├── cache/
│   ├── lib/
│   ├── spool/
│   └── mail/
├── mnt/               Mount points
├── media/             Removable media
├── srv/               Service data
├── run/               Runtime data
└── cardinal/          Cardinal C2 Framework
    ├── c2/
    ├── exploits/
    ├── payloads/
    ├── logs/
    ├── tools/
    ├── modules/
    ├── config/
    ├── database/
    └── sessions/
```

### DOS Compatibility

```
C:/                    DOS root
├── WINDOWS/           Windows system
│   ├── System32/
│   └── System/
├── Program Files/
├── Program Files (x86)/
├── Users/
│   ├── Administrator/
│   └── Public/
├── Temp/
├── ProgramData/
└── DOS/
```

### File Operations

```bash
# List files and directories
ls                    # List current directory
ls /etc              # List specific directory
dir C:/              # DOS-style listing

# Navigate directories
cd /var/log          # Change to directory
pwd                  # Print working directory
cd                   # Return to home directory

# Create directories
mkdir /tmp/mydir     # Linux style
md C:/Temp/test      # DOS style

# View files
cat /etc/hostname    # Display file content
type C:/AUTOEXEC.BAT # DOS-style view

# File information shows:
# - [DIR] or [FILE] indicator
# - Name (30 characters)
# - Size in bytes
# - Last modified timestamp
# - [ENC] tag if encrypted
# - [HIDDEN] tag if hidden
```

---

## Security Features

### Security Levels

CardinalOS supports four security levels:

1. **LOW**: Basic protection, minimal overhead
2. **MEDIUM**: Standard security for general use
3. **HIGH**: Enhanced protection (default)
4. **PARANOID**: Maximum security, all features enabled

### Security Status

```bash
# View comprehensive security report
security
```

Output includes:
- Security level
- Firewall status (ENABLED/DISABLED)
- SELinux status (ENFORCING/DISABLED)
- Audit system status
- Encryption level (AES-256-GCM)
- Anti-debug status
- Rootkit detection
- Network stealth

### Firewall Management

```bash
# Check firewall status
firewall status

# Enable firewall
firewall enable

# Disable firewall (admin only)
firewall disable
```

### Audit Logging

All privileged operations are logged:
- User authentication events
- File system modifications
- Security configuration changes
- Process management actions
- ISO generation requests

Audit logs show:
- Timestamp (YYYY-MM-DD HH:MM:SS)
- Username
- Action performed
- Details/parameters

### Permission System

Every file and directory has:
- **Owner UID**: User who owns the file
- **Group GID**: Group ownership
- **Permissions**: Read, Write, Execute, Admin bits

Permission checks occur on:
- File reading (`cat`)
- File writing (`echo >`)
- Directory access (`cd`)
- Directory listing (`ls`)
- File creation (`mkdir`, `touch`)
- File deletion (`rm`)

Admin users bypass all permission checks.

---

## GUI Desktop Mode

### Launching Desktop

```bash
# Start GUI desktop environment
desktop

# Alternative command
startx
```

### Desktop Features

CardinalOS Desktop includes:

1. **Window Manager**: Cardinal WM
   - Full window management
   - Window decorations
   - Virtual desktops
   - Keyboard shortcuts

2. **File Manager**: Cardinal Files
   - Graphical file browsing
   - Drag and drop support
   - File operations
   - Properties viewer

3. **Terminal**: Cardinal Terminal
   - Full terminal emulator
   - Color support
   - Tabbed interface
   - Copy/paste

4. **Process Monitor**: Cardinal Task Manager
   - Real-time process list
   - CPU/Memory graphs
   - Kill process capability
   - Priority management

5. **C2 Console**: Cardinal C2 GUI
   - Exploit management
   - Payload generation
   - Session handling
   - Target management

6. **Network Monitor**: Cardinal NetMon
   - Real-time traffic analysis
   - Port scanning
   - Connection tracking
   - Packet capture

7. **Security Dashboard**: Cardinal SecOps
   - Security status overview
   - Threat detection
   - Firewall rules
   - Audit log viewer

### Exiting Desktop

Press any key while in desktop mode to return to terminal.

---

## ISO Generation

### Creating Bootable ISO

```bash
# Generate ISO image (admin only)
iso-generate

# Alternative command
mkiso
```

### ISO Creation Process

The ISO generation includes 6 stages:

1. **Filesystem Preparation**
   - Creates 512 MB ext4 filesystem
   - Mounts filesystem
   - Copies all files and directories

2. **Bootloader Installation**
   - Installs GRUB 2.06
   - Configures boot menu
   - Writes MBR and GPT tables

3. **Kernel Building**
   - Compiles Linux kernel 6.1
   - Builds initramfs
   - Includes DOS compatibility layer

4. **Component Packaging**
   - Bundles C2 framework
   - Includes 200+ exploit database
   - Adds security tools
   - Packages GUI desktop

5. **ISO Image Creation**
   - Runs mkisofs/genisoimage
   - Makes hybrid UEFI/BIOS bootable
   - Calculates MD5 and SHA256 checksums

6. **Finalization**
   - Verifies ISO integrity
   - Creates torrent file
   - Generates documentation

### ISO Output

Generated ISO details:
- **Filename**: `CardinalOS-v4.0.0-enterprise-YYYYMMDD-HHMMSS.iso`
- **Size**: ~487 MB (511,705,088 bytes)
- **Format**: ISO 9660 + Joliet + Rock Ridge
- **Boot**: Hybrid UEFI + BIOS
- **Checksums**: MD5 and SHA256 provided

### Using the ISO

```bash
# Write to USB (Linux)
dd if=CardinalOS-v4.0.0-*.iso of=/dev/sdX bs=4M

# Write to USB (Windows)
# Use Rufus, BalenaEtcher, or similar tool

# Burn to DVD
# Use any ISO burning software
```

### Boot Options

1. Insert USB/DVD
2. Enter BIOS/UEFI boot menu (F12, F2, DEL, or ESC)
3. Select USB/DVD drive
4. Choose boot mode (UEFI or Legacy)
5. Follow installation wizard

---

## Command Reference

### System Information

```bash
help              # Show all available commands
version           # Display version information
ver               # Short version
uname             # System information
uname -a          # Detailed system info
hostname          # Show hostname
hostname <name>   # Set hostname (admin only)
uptime            # System uptime and load average
```

### File Operations

```bash
ls [path]         # List directory (Linux)
dir [path]        # List directory (DOS)
cd <path>         # Change directory
chdir <path>      # Change directory (DOS)
pwd               # Print working directory
mkdir <name>      # Create directory (Linux)
md <name>         # Create directory (DOS)
cat <file>        # Display file content
type <file>       # Display file (DOS)
touch <file>      # Create empty file (planned)
rm <file>         # Remove file (planned)
cp <src> <dst>    # Copy file (planned)
mv <src> <dst>    # Move/rename (planned)
```

### User Management

```bash
whoami            # Current username
users             # List all users
who               # Show logged-in users
su <user>         # Switch user (planned)
sudo <cmd>        # Run as admin (planned)
passwd            # Change password (planned)
```

### Process Management

```bash
ps                # List processes (Linux)
tasklist          # List processes (DOS)
top               # Real-time monitor (planned)
kill <pid>        # Terminate process (planned)
killall <name>    # Kill by name (planned)
```

### Network Commands

```bash
ifconfig          # Network interfaces (planned)
netstat           # Network connections (planned)
ping <host>       # Test connectivity (planned)
traceroute <host> # Trace route (planned)
```

### Security Commands

```bash
security          # Security status report
firewall status   # Check firewall
firewall enable   # Enable firewall
firewall disable  # Disable firewall (admin)
selinux <cmd>     # SELinux control (planned)
audit             # View audit logs (planned)
```

### Attack Commands

```bash
exploit-db        # List exploits (planned)
c2-start          # Start C2 server (planned)
payload-gen       # Generate payload (planned)
scan <target>     # Port scan (planned)
```

### Advanced Features

```bash
desktop           # Launch GUI mode
startx            # Launch GUI (alternative)
iso-generate      # Create bootable ISO
mkiso             # Create ISO (alternative)
benchmark         # Performance test (planned)
```

### System Control

```bash
clear             # Clear screen (Linux)
cls               # Clear screen (DOS)
exit              # Shutdown system
quit              # Shutdown (alternative)
reboot            # Restart (planned)
shutdown          # Power off (planned)
```

---

## Performance Tuning

### Compiler Optimizations

CardinalOS v4.0 is compiled with aggressive optimizations:

```bash
-O3                # Maximum optimization level
-march=native      # CPU-specific optimizations
-ffast-math        # Fast floating-point operations
-funroll-loops     # Loop unrolling for speed
-s                 # Strip symbols (smaller binary)
```

### Performance Features

1. **Fast File Lookup**: Optimized search algorithms
2. **Efficient String Operations**: Minimal allocations
3. **Quick Permission Checks**: Cached results
4. **Reduced Memory Footprint**: Compact data structures
5. **Fast Boot Time**: Parallel initialization

### Benchmarking

```bash
# Run performance test (coming soon)
benchmark

# Check system performance
uptime           # Load average
ps               # Process CPU/memory usage
security         # System resource status
```

### Tips for Best Performance

1. Run as administrator for fastest operation
2. Minimize number of open processes
3. Use desktop mode for GUI operations
4. Clear `/tmp` directory regularly
5. Disable audit logging if not needed
6. Use security level MEDIUM instead of PARANOID

---

## Troubleshooting

### Common Issues

#### "Permission denied" errors

**Problem**: Cannot access files or execute commands  
**Solution**: 
- Check if you're running as admin/root
- Use `whoami` to verify current user
- Switch to root account or use sudo

#### "Command not found"

**Problem**: Command doesn't exist  
**Solution**:
- Type `help` to see available commands
- Check spelling and capitalization
- Some commands may be planned for future release

#### "Directory not found"

**Problem**: Cannot change to directory  
**Solution**:
- Use `ls /` to see available directories
- Ensure directory path is correct
- Check permissions with `ls -l` (planned feature)

#### Slow performance

**Problem**: System feels sluggish  
**Solution**:
- Check process list with `ps`
- Reduce security level: `security-level medium`
- Close desktop mode if running
- Recompile with higher optimization level

#### ISO generation fails

**Problem**: Cannot create ISO image  
**Solution**:
- Ensure you're logged in as admin
- Check available disk space
- Verify all files are present
- Review audit logs for errors

### Getting Help

```bash
# Show command reference
help

# Check system status
uptime
security
ps

# View version information
version

# List all files
ls -R /
```

### Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| Permission denied | Insufficient privileges | Login as admin |
| Command not found | Invalid command | Type `help` |
| File not found | Path doesn't exist | Check with `ls` |
| Directory exists | Already created | Use different name |
| Invalid path | Malformed path | Use absolute path |

### Debug Mode

For detailed debugging:
1. Review audit logs for all operations
2. Check security status for restrictions
3. Verify file permissions
4. Examine process list for conflicts

---

## Advanced Usage

### Security Hardening

```bash
# Enable maximum security
firewall enable
selinux enforcing
security-level paranoid

# Enable audit logging
audit enable

# Check security status
security
```

### Automation

Create batch files for repeated tasks:

```bash
# Create file: /root/startup.sh
echo "Starting CardinalOS services"
firewall enable
c2-start
security
```

### Custom Directory Structure

```bash
# Create project workspace
mkdir /opt/project
cd /opt/project
mkdir src bin docs

# Organize exploits
cd /cardinal/exploits
mkdir windows linux macos
```

---

## Best Practices

1. **Security**: Always run firewall and audit logging in production
2. **Backups**: Regularly generate ISO images for system snapshots
3. **Updates**: Check for new versions and security patches
4. **Testing**: Use security level LOW for testing, HIGH for production
5. **Permissions**: Follow principle of least privilege
6. **Logging**: Review audit logs regularly for suspicious activity
7. **Documentation**: Document custom configurations and changes

---

## Additional Resources

- **CHANGELOG_V4.md**: Detailed release notes
- **COMMANDS.md**: Complete command reference
- **USAGE.md**: Usage examples
- **docs/**: Additional documentation

---

## License

CardinalOS v4.0 Enterprise Edition  
Proprietary Software - For Security Research and Educational Use Only

Copyright © 2025 Cardinal Security Research Team

---

**Happy Hacking! 🎯**
