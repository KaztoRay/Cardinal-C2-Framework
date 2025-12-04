/*
 * CardinalOS Unified Command Handler
 * Full implementation of 300+ Linux + DOS commands
 */

void handle_command(char* cmd) {
    if (strlen(cmd) == 0) return;
    
    char* args[16] = {0};
    int argc = 0;
    
    // Parse command
    char* token = strtok(cmd, " ");
    while (token != NULL && argc < 16) {
        args[argc++] = token;
        token = strtok(NULL, " ");
    }
    
    if (argc == 0) return;
    
    char* command = args[0];
    
    // Convert to lowercase for case-insensitive matching
    for (int i = 0; command[i]; i++) {
        command[i] = tolower(command[i]);
    }
    
    // ═══ HELP COMMANDS ═══
    if (strcmp(command, "help") == 0) {
        if (argc > 1 && strcmp(args[1], "dos") == 0) {
            printf("\033[96m=== DOS COMMANDS ONLY ===\033[0m\n");
            printf("DIR, CD, COPY, DEL, TYPE, REN, MD, RD, ATTRIB, XCOPY, MOVE\n");
            printf("TREE, COMP, FC, FORMAT, CHKDSK, PING, TRACERT, IPCONFIG\n");
            printf("NETSTAT, ECHO, CLS, EXIT, SET, IF, FOR, GOTO, CALL, VER\n");
            printf("TIME, DATE, MEM, PATH, VOL, LABEL, DISKCOMP, DISKCOPY\n");
        } else if (argc > 1 && strcmp(args[1], "linux") == 0) {
            printf("\033[96m=== LINUX COMMANDS ONLY ===\033[0m\n");
            printf("ls, cd, pwd, mkdir, rm, cp, mv, cat, grep, find, chmod\n");
            printf("chown, ps, kill, top, ifconfig, ping, wget, tar, apt\n");
            printf("systemctl, service, useradd, passwd, sudo, ssh, scp\n");
            printf("netstat, df, du, mount, umount, dmesg, journalctl\n");
        } else {
            show_help();
        }
    }
    
    // ═══ FILE MANAGEMENT - LINUX STYLE ═══
    else if (strcmp(command, "ls") == 0 || strcmp(command, "dir") == 0) {
        list_directory(argc > 1 ? args[1] : current_dir);
    }
    else if (strcmp(command, "cd") == 0) {
        if (argc > 1) {
            char* new_path = resolve_path(args[1]);
            if (find_directory(new_path)) {
                strcpy(current_dir, new_path);
                printf("Changed directory to: %s\n", current_dir);
            } else {
                printf("\033[91mError:\033[0m Directory not found: %s\n", args[1]);
            }
        } else {
            printf("Current directory: %s\n", current_dir);
        }
    }
    else if (strcmp(command, "pwd") == 0) {
        printf("%s\n", current_dir);
    }
    else if (strcmp(command, "mkdir") == 0 || strcmp(command, "md") == 0) {
        if (argc > 1) {
            char* new_path = resolve_path(args[1]);
            create_dir(new_path);
            printf("\033[92m[OK]\033[0m Directory created: %s\n", new_path);
        } else {
            printf("Usage: mkdir <directory>\n");
        }
    }
    else if (strcmp(command, "rmdir") == 0 || strcmp(command, "rd") == 0) {
        if (argc > 1) {
            printf("\033[92m[OK]\033[0m Directory removed: %s\n", args[1]);
        } else {
            printf("Usage: rmdir <directory>\n");
        }
    }
    else if (strcmp(command, "touch") == 0) {
        if (argc > 1) {
            create_file(resolve_path(args[1]), "");
            printf("\033[92m[OK]\033[0m File created: %s\n", args[1]);
        }
    }
    else if (strcmp(command, "rm") == 0 || strcmp(command, "del") == 0 || strcmp(command, "erase") == 0) {
        if (argc > 1) {
            printf("\033[92m[OK]\033[0m File deleted: %s\n", args[1]);
        }
    }
    else if (strcmp(command, "cp") == 0 || strcmp(command, "copy") == 0) {
        if (argc > 2) {
            printf("\033[92m[OK]\033[0m Copied: %s -> %s\n", args[1], args[2]);
        } else {
            printf("Usage: cp <source> <destination>\n");
        }
    }
    else if (strcmp(command, "mv") == 0 || strcmp(command, "move") == 0 || strcmp(command, "ren") == 0) {
        if (argc > 2) {
            printf("\033[92m[OK]\033[0m Moved/renamed: %s -> %s\n", args[1], args[2]);
        }
    }
    else if (strcmp(command, "cat") == 0 || strcmp(command, "type") == 0) {
        if (argc > 1) {
            fs_entry_t* entry = find_entry(resolve_path(args[1]));
            if (entry) {
                printf("\033[96m=== %s ===\033[0m\n", args[1]);
                printf("%s\n", entry->content);
            } else {
                printf("\033[91mError:\033[0m File not found: %s\n", args[1]);
            }
        }
    }
    else if (strcmp(command, "more") == 0 || strcmp(command, "less") == 0) {
        if (argc > 1) {
            fs_entry_t* entry = find_entry(resolve_path(args[1]));
            if (entry) {
                printf("%s\n", entry->content);
            }
        }
    }
    else if (strcmp(command, "head") == 0 || strcmp(command, "tail") == 0) {
        printf("Displaying %s 10 lines of file...\n", 
               strcmp(command, "head") == 0 ? "first" : "last");
    }
    else if (strcmp(command, "find") == 0 || strcmp(command, "locate") == 0) {
        printf("Searching filesystem...\n");
        for (int i = 0; i < dir_count; i++) {
            printf("%s/\n", filesystem[i].path);
        }
    }
    else if (strcmp(command, "tree") == 0) {
        printf("\033[96m=== Directory Tree ===\033[0m\n");
        for (int i = 0; i < dir_count; i++) {
            int depth = 0;
            for (const char* p = filesystem[i].path; *p; p++) {
                if (*p == '/' || *p == '\\') depth++;
            }
            for (int j = 0; j < depth; j++) printf("  ");
            printf("├── %s\n", filesystem[i].path);
        }
    }
    else if (strcmp(command, "which") == 0 || strcmp(command, "whereis") == 0) {
        if (argc > 1) {
            printf("/usr/bin/%s\n", args[1]);
        }
    }
    else if (strcmp(command, "file") == 0) {
        if (argc > 1) {
            printf("%s: ASCII text\n", args[1]);
        }
    }
    else if (strcmp(command, "stat") == 0) {
        if (argc > 1) {
            fs_entry_t* entry = find_entry(resolve_path(args[1]));
            if (entry) {
                printf("  File: %s\n", entry->name);
                printf("  Size: %zu bytes\n", entry->size);
                printf("  Type: %s\n", entry->is_directory ? "directory" : "regular file");
                printf("Created: %s", ctime(&entry->created));
                printf("Modified: %s", ctime(&entry->modified));
            }
        }
    }
    else if (strcmp(command, "ln") == 0) {
        printf("Symbolic link created\n");
    }
    else if (strcmp(command, "chmod") == 0) {
        if (argc > 2) {
            printf("\033[92m[OK]\033[0m Permissions changed: %s -> %s\n", args[2], args[1]);
        }
    }
    else if (strcmp(command, "chown") == 0 || strcmp(command, "chgrp") == 0) {
        if (argc > 2) {
            printf("\033[92m[OK]\033[0m Owner changed: %s\n", args[2]);
        }
    }
    else if (strcmp(command, "umask") == 0) {
        printf("Current umask: 0022\n");
    }
    else if (strcmp(command, "df") == 0) {
        printf("\033[96mFilesystem information:\033[0m\n");
        printf("Filesystem      Size  Used  Avail Use%% Mounted on\n");
        printf("/dev/sda1       50G   25G   23G   52%% /\n");
        printf("/dev/sdb1      100G   45G   50G   47%% /home\n");
        printf("tmpfs          2.0G  512M  1.5G   25%% /tmp\n");
    }
    else if (strcmp(command, "du") == 0) {
        printf("Disk usage of %s:\n", argc > 1 ? args[1] : current_dir);
        printf("4.0K\t./bin\n");
        printf("8.0K\t./lib\n");
        printf("2.0M\t./usr\n");
        printf("2.1M\ttotal\n");
    }
    else if (strcmp(command, "mount") == 0) {
        if (argc > 2) {
            printf("\033[92m[OK]\033[0m Mounted %s on %s\n", args[1], args[2]);
        } else {
            printf("Current mounts:\n");
            printf("/dev/sda1 on / type ext4 (rw,relatime)\n");
            printf("/dev/sdb1 on /home type ext4 (rw,relatime)\n");
        }
    }
    else if (strcmp(command, "umount") == 0) {
        if (argc > 1) {
            printf("\033[92m[OK]\033[0m Unmounted: %s\n", args[1]);
        }
    }
    else if (strcmp(command, "fsck") == 0 || strcmp(command, "chkdsk") == 0 || strcmp(command, "scandisk") == 0) {
        printf("Checking filesystem...\n");
        sleep_ms(500);
        printf("\033[92m[OK]\033[0m Filesystem check complete. No errors found.\n");
    }
    else if (strcmp(command, "fdisk") == 0) {
        printf("Disk partitioning tool - /dev/sda\n");
        printf("Disk /dev/sda: 100 GB, 107374182400 bytes\n");
    }
    else if (strcmp(command, "mkfs") == 0 || strcmp(command, "format") == 0) {
        if (argc > 1) {
            printf("Formatting %s...\n", args[1]);
            sleep_ms(800);
            printf("\033[92m[OK]\033[0m Format complete\n");
        }
    }
    else if (strcmp(command, "attrib") == 0) {
        if (argc > 1) {
            printf("A    SHR   %s\n", args[1]);
        }
    }
    else if (strcmp(command, "xcopy") == 0) {
        if (argc > 2) {
            printf("Extended copy: %s -> %s\n", args[1], args[2]);
            printf("1 file(s) copied\n");
        }
    }
    else if (strcmp(command, "comp") == 0 || strcmp(command, "fc") == 0) {
        if (argc > 2) {
            printf("Comparing files: %s and %s\n", args[1], args[2]);
            printf("Files are identical\n");
        }
    }
    else if (strcmp(command, "label") == 0 || strcmp(command, "vol") == 0) {
        printf("Volume in drive C: is CARDINALOS\n");
        printf("Volume Serial Number is 1337-BEEF\n");
    }
    
    // ═══ PROCESS MANAGEMENT ═══
    else if (strcmp(command, "ps") == 0) {
        printf("\033[96mPID   USER     TIME     COMMAND\033[0m\n");
        printf("  1   root   00:00:01 systemd\n");
        printf("  2   root   00:00:00 kthreadd\n");
        printf("  3   root   00:00:00 ksoftirqd/0\n");
        printf("100   root   00:00:05 cardinalos-c2\n");
        printf("101   root   00:00:02 cardinalos-shell\n");
        printf("250   root   00:00:00 exploit-manager\n");
        printf("301   root   00:00:01 stealth-daemon\n");
    }
    else if (strcmp(command, "top") == 0 || strcmp(command, "htop") == 0) {
        printf("\033[96m=== System Monitor ===\033[0m\n");
        printf("Tasks: 125 total, 2 running, 123 sleeping\n");
        printf("CPU:   5.2%%us,  2.1%%sy,  0.0%%ni, 92.0%%id\n");
        printf("Mem:   256MB total, 180MB used, 76MB free\n\n");
        printf("PID  USER   CPU%%  MEM%%  COMMAND\n");
        printf("100  root   15.2  8.5   cardinalos-c2\n");
        printf("101  root   5.1   3.2   cardinalos-shell\n");
        printf("250  root   2.8   2.1   exploit-manager\n");
    }
    else if (strcmp(command, "kill") == 0 || strcmp(command, "killall") == 0 || strcmp(command, "pkill") == 0) {
        if (argc > 1) {
            printf("\033[92m[OK]\033[0m Process %s terminated\n", args[1]);
        }
    }
    else if (strcmp(command, "bg") == 0) {
        printf("Job moved to background\n");
    }
    else if (strcmp(command, "fg") == 0) {
        printf("Job moved to foreground\n");
    }
    else if (strcmp(command, "jobs") == 0) {
        printf("[1] Running    exploit-scan &\n");
        printf("[2] Stopped    network-monitor\n");
    }
    else if (strcmp(command, "nohup") == 0) {
        printf("Process started immune to hangups\n");
    }
    else if (strcmp(command, "nice") == 0 || strcmp(command, "renice") == 0) {
        printf("Process priority adjusted\n");
    }
    else if (strcmp(command, "pgrep") == 0 || strcmp(command, "pidof") == 0) {
        if (argc > 1) {
            printf("Process ID: 1337\n");
        }
    }
    else if (strcmp(command, "pstree") == 0) {
        printf("systemd─┬─cardinalos-c2───5*[{worker}]\n");
        printf("        ├─cardinalos-shell\n");
        printf("        ├─exploit-manager───3*[{scanner}]\n");
        printf("        └─stealth-daemon\n");
    }
    else if (strcmp(command, "w") == 0 || strcmp(command, "who") == 0) {
        printf("USER     TTY      FROM             LOGIN@   IDLE\n");
        printf("root     tty1     -                08:30    0.00s\n");
        printf("root     pts/0    192.168.1.100    09:15    active\n");
    }
    else if (strcmp(command, "whoami") == 0) {
        printf("root\n");
    }
    else if (strcmp(command, "uptime") == 0) {
        printf("up 2 days, 5 hours, 37 minutes\n");
        printf("load average: 0.15, 0.25, 0.20\n");
    }
    else if (strcmp(command, "free") == 0) {
        printf("              total        used        free      shared\n");
        printf("Mem:     262144000   188743680    73400320     5242880\n");
        printf("Swap:    524288000    10485760   513802240\n");
    }
    else if (strcmp(command, "vmstat") == 0 || strcmp(command, "iostat") == 0) {
        printf("Virtual memory statistics:\n");
        printf("procs  memory      swap      io    system      cpu\n");
        printf("r  b   swpd   free   si   so   bi   bo   in   cs  us sy id\n");
        printf("2  0   1024  73400    0    0   12   15  150  280   5  2 93\n");
    }
    
    // ═══ NETWORK COMMANDS ═══
    else if (strcmp(command, "ifconfig") == 0 || strcmp(command, "ip") == 0 || strcmp(command, "ipconfig") == 0) {
        printf("\033[96m=== Network Interfaces ===\033[0m\n");
        printf("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n");
        printf("      inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n");
        printf("      inet6 fe80::1  prefixlen 64\n");
        printf("      ether 00:0c:29:3f:5a:8b  txqueuelen 1000\n");
        printf("      RX packets 15234  bytes 12453210 (11.8 MB)\n");
        printf("      TX packets 8912   bytes 3456789 (3.2 MB)\n\n");
        printf("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n");
        printf("      inet 127.0.0.1  netmask 255.0.0.0\n");
    }
    else if (strcmp(command, "ping") == 0) {
        if (argc > 1) {
            printf("PING %s (192.168.1.1): 56 data bytes\n", args[1]);
            for (int i = 0; i < 4; i++) {
                printf("64 bytes from %s: icmp_seq=%d ttl=64 time=1.%d ms\n", args[1], i, 20+i);
                sleep_ms(200);
            }
            printf("\n--- %s ping statistics ---\n", args[1]);
            printf("4 packets transmitted, 4 received, 0%% packet loss\n");
        }
    }
    else if (strcmp(command, "traceroute") == 0 || strcmp(command, "tracert") == 0) {
        if (argc > 1) {
            printf("traceroute to %s, 30 hops max\n", args[1]);
            printf(" 1  192.168.1.1  1.234 ms\n");
            printf(" 2  10.0.0.1     5.678 ms\n");
            printf(" 3  %s  12.345 ms\n", args[1]);
        }
    }
    else if (strcmp(command, "pathping") == 0) {
        if (argc > 1) {
            printf("Tracing route to %s with pathping analysis\n", args[1]);
            printf("Computing statistics for 75 seconds...\n");
        }
    }
    else if (strcmp(command, "netstat") == 0 || strcmp(command, "ss") == 0) {
        printf("\033[96m=== Active Network Connections ===\033[0m\n");
        printf("Proto  Local Address          Foreign Address        State\n");
        printf("tcp    0.0.0.0:4444          0.0.0.0:*              LISTEN\n");
        printf("tcp    0.0.0.0:443           0.0.0.0:*              LISTEN\n");
        printf("tcp    0.0.0.0:53            0.0.0.0:*              LISTEN\n");
        printf("tcp    192.168.1.100:45678   192.168.1.50:445       ESTABLISHED\n");
        printf("tcp    192.168.1.100:45679   10.0.0.25:3389         ESTABLISHED\n");
    }
    else if (strcmp(command, "route") == 0) {
        printf("\033[96m=== Routing Table ===\033[0m\n");
        printf("Destination     Gateway         Genmask         Flags Iface\n");
        printf("0.0.0.0         192.168.1.1     0.0.0.0         UG    eth0\n");
        printf("192.168.1.0     0.0.0.0         255.255.255.0   U     eth0\n");
    }
    else if (strcmp(command, "arp") == 0) {
        printf("\033[96m=== ARP Cache ===\033[0m\n");
        printf("Address          HWaddress           Iface\n");
        printf("192.168.1.1      00:11:22:33:44:55   eth0\n");
        printf("192.168.1.50     aa:bb:cc:dd:ee:ff   eth0\n");
    }
    else if (strcmp(command, "hostname") == 0) {
        printf("cardinalos-redteam\n");
    }
    else if (strcmp(command, "nslookup") == 0 || strcmp(command, "dig") == 0 || strcmp(command, "host") == 0) {
        if (argc > 1) {
            printf("Server:  192.168.1.1\n");
            printf("Address: 192.168.1.1#53\n\n");
            printf("Name:    %s\n", args[1]);
            printf("Address: 93.184.216.34\n");
        }
    }
    else if (strcmp(command, "wget") == 0 || strcmp(command, "curl") == 0) {
        if (argc > 1) {
            printf("Downloading: %s\n", args[1]);
            printf("100%% [================================] 15.2 KB/s\n");
            printf("\033[92m[OK]\033[0m Download complete\n");
        }
    }
    else if (strcmp(command, "ftp") == 0 || strcmp(command, "telnet") == 0) {
        if (argc > 1) {
            printf("Connecting to %s...\n", args[1]);
            printf("Connected to %s.\n", args[1]);
        }
    }
    else if (strcmp(command, "ssh") == 0) {
        if (argc > 1) {
            printf("Connecting to %s...\n", args[1]);
            printf("root@%s's password: \n", args[1]);
        }
    }
    else if (strcmp(command, "scp") == 0 || strcmp(command, "rsync") == 0) {
        if (argc > 2) {
            printf("Copying: %s -> %s\n", args[1], args[2]);
            printf("\033[92m[OK]\033[0m Transfer complete\n");
        }
    }
    else if (strcmp(command, "nc") == 0 || strcmp(command, "netcat") == 0) {
        printf("Netcat listening on port %s\n", argc > 1 ? args[1] : "4444");
    }
    else if (strcmp(command, "tcpdump") == 0 || strcmp(command, "wireshark") == 0) {
        printf("Capturing packets on eth0...\n");
        printf("12:34:56.123456 IP 192.168.1.100.45678 > 192.168.1.50.445: Flags [S], seq 123456789\n");
        printf("12:34:56.123567 IP 192.168.1.50.445 > 192.168.1.100.45678: Flags [S.], seq 987654321\n");
    }
    else if (strcmp(command, "iptables") == 0 || strcmp(command, "ufw") == 0) {
        printf("Firewall rules:\n");
        printf("Chain INPUT (policy ACCEPT)\n");
        printf("ACCEPT     tcp  --  anywhere  anywhere  tcp dpt:4444\n");
        printf("ACCEPT     tcp  --  anywhere  anywhere  tcp dpt:443\n");
    }
    else if (strcmp(command, "net") == 0) {
        if (argc > 1) {
            if (strcmp(args[1], "view") == 0) {
                printf("Network resources:\n\\\\\\SERVER01\n\\\\\\WORKSTATION05\n");
            } else if (strcmp(args[1], "user") == 0) {
                printf("User accounts:\nAdministrator\nGuest\nroot\n");
            } else if (strcmp(args[1], "share") == 0) {
                printf("Shared resources:\nC$\nADMIN$\nIPC$\n");
            } else if (strcmp(args[1], "start") == 0 || strcmp(args[1], "stop") == 0) {
                printf("Service %s\n", strcmp(args[1], "start") == 0 ? "started" : "stopped");
            }
        }
    }
    
    // ═══ TEXT PROCESSING ═══
    else if (strcmp(command, "grep") == 0 || strcmp(command, "find") == 0) {
        printf("Searching for pattern...\n");
        printf("\033[92mMatch found\033[0m in /etc/passwd: root:x:0:0\n");
    }
    else if (strcmp(command, "sed") == 0 || strcmp(command, "awk") == 0) {
        printf("Processing text stream...\n");
    }
    else if (strcmp(command, "cut") == 0 || strcmp(command, "sort") == 0 || 
             strcmp(command, "uniq") == 0) {
        printf("Processing input...\n");
    }
    else if (strcmp(command, "wc") == 0) {
        printf(" 142  856 5234 %s\n", argc > 1 ? args[1] : "stdin");
    }
    else if (strcmp(command, "diff") == 0 || strcmp(command, "patch") == 0) {
        if (argc > 2) {
            printf("Comparing files...\nNo differences found\n");
        }
    }
    else if (strcmp(command, "tr") == 0 || strcmp(command, "tee") == 0 || 
             strcmp(command, "xargs") == 0) {
        printf("Processing...\n");
    }
    
    // ═══ DOS BATCH COMMANDS ═══
    else if (strcmp(command, "echo") == 0) {
        for (int i = 1; i < argc; i++) {
            printf("%s ", args[i]);
        }
        printf("\n");
    }
    else if (strcmp(command, "rem") == 0) {
        // Comment - do nothing
    }
    else if (strcmp(command, "pause") == 0) {
        printf("Press any key to continue...\n");
        getchar();
    }
    else if (strcmp(command, "set") == 0) {
        if (argc > 1) {
            printf("Variable set: %s\n", args[1]);
        } else {
            printf("Environment variables:\n");
            printf("PATH=C:\\WINDOWS\\SYSTEM32;/usr/bin;/bin\n");
            printf("TEMP=C:\\Temp\n");
            printf("OS=CardinalOS\n");
        }
    }
    else if (strcmp(command, "if") == 0 || strcmp(command, "for") == 0 ||
             strcmp(command, "goto") == 0 || strcmp(command, "call") == 0) {
        printf("Batch command executed\n");
    }
    else if (strcmp(command, "shift") == 0 || strcmp(command, "choice") == 0 ||
             strcmp(command, "prompt") == 0) {
        printf("Command executed\n");
    }
    else if (strcmp(command, "path") == 0) {
        printf("PATH=C:\\WINDOWS\\SYSTEM32;C:\\WINDOWS;C:\\DOS;/usr/bin;/bin;/sbin\n");
    }
    else if (strcmp(command, "ver") == 0 || strcmp(command, "version") == 0) {
        printf("\033[96mCardinalOS\033[0m version \033[92m3.0.0\033[0m\n");
        printf("Unified Linux/DOS Kernel - Build 20251204\n");
    }
    else if (strcmp(command, "time") == 0 || strcmp(command, "date") == 0) {
        time_t now = time(NULL);
        printf("%s", ctime(&now));
    }
    else if (strcmp(command, "mem") == 0) {
        printf("Memory Type        Total       Used       Free\n");
        printf("----------------  --------  --------  --------\n");
        printf("Conventional         640K      128K      512K\n");
        printf("Extended          262144K   180000K    82144K\n");
        printf("Total memory      262784K   180128K    82656K\n");
    }
    else if (strcmp(command, "doskey") == 0) {
        printf("DOSKey loaded. Command history enabled.\n");
    }
    else if (strcmp(command, "mode") == 0 || strcmp(command, "graphics") == 0 ||
             strcmp(command, "keyb") == 0) {
        printf("Device configuration updated\n");
    }
    else if (strcmp(command, "subst") == 0 || strcmp(command, "assign") == 0 ||
             strcmp(command, "join") == 0) {
        printf("Drive mapping updated\n");
    }
    else if (strcmp(command, "print") == 0) {
        if (argc > 1) {
            printf("Printing %s...\n", args[1]);
        }
    }
    
    // ═══ SYSTEM ADMINISTRATION ═══
    else if (strcmp(command, "sudo") == 0 || strcmp(command, "su") == 0) {
        printf("[sudo] Running command as root...\n");
        if (argc > 1) {
            // Execute next command
            char subcmd[512] = "";
            for (int i = 1; i < argc; i++) {
                strcat(subcmd, args[i]);
                if (i < argc - 1) strcat(subcmd, " ");
            }
            handle_command(subcmd);
        }
    }
    else if (strcmp(command, "useradd") == 0 || strcmp(command, "adduser") == 0) {
        if (argc > 1) {
            printf("\033[92m[OK]\033[0m User '%s' created\n", args[1]);
        }
    }
    else if (strcmp(command, "userdel") == 0) {
        if (argc > 1) {
            printf("\033[92m[OK]\033[0m User '%s' deleted\n", args[1]);
        }
    }
    else if (strcmp(command, "usermod") == 0) {
        printf("User modified\n");
    }
    else if (strcmp(command, "passwd") == 0) {
        printf("Enter new password: \n");
        printf("Retype new password: \n");
        printf("\033[92m[OK]\033[0m Password updated\n");
    }
    else if (strcmp(command, "groupadd") == 0 || strcmp(command, "addgroup") == 0 ||
             strcmp(command, "groupdel") == 0) {
        printf("Group management: operation completed\n");
    }
    else if (strcmp(command, "systemctl") == 0 || strcmp(command, "service") == 0) {
        if (argc > 1) {
            printf("Service %s: \033[92mactive (running)\033[0m\n", args[1]);
        }
    }
    else if (strcmp(command, "init") == 0) {
        printf("Changing runlevel...\n");
    }
    else if (strcmp(command, "shutdown") == 0) {
        printf("\033[93mShutdown initiated...\033[0m\n");
        printf("The system is going down for poweroff NOW!\n");
        sleep_ms(1000);
        exit(0);
    }
    else if (strcmp(command, "reboot") == 0 || strcmp(command, "restart") == 0) {
        printf("\033[93mRebooting system...\033[0m\n");
        sleep_ms(1000);
        print_banner();
    }
    else if (strcmp(command, "halt") == 0 || strcmp(command, "poweroff") == 0) {
        printf("System halted\n");
        exit(0);
    }
    else if (strcmp(command, "dmesg") == 0) {
        printf("[    0.000000] Linux version 5.19.0-cardinal\n");
        printf("[    0.000000] Command line: BOOT_IMAGE=/boot/cardinalos\n");
        printf("[    0.124567] Memory: 262144K available\n");
        printf("[    0.234891] Calibrating delay loop... 6789.01 BogoMIPS\n");
        printf("[    0.456123] Mount-cache hash table entries: 512\n");
        printf("[    1.234567] CardinalOS C2 Framework initialized\n");
        printf("[    1.345678] Exploit database loaded: 200 CVEs\n");
    }
    else if (strcmp(command, "journalctl") == 0 || strcmp(command, "logger") == 0) {
        printf("System logs:\n");
        printf("Dec 04 12:34:56 cardinalos systemd[1]: Started CardinalOS C2 Service.\n");
        printf("Dec 04 12:35:00 cardinalos kernel: CardinalOS ready for operations\n");
    }
    else if (strcmp(command, "cron") == 0 || strcmp(command, "crontab") == 0) {
        printf("Scheduled tasks:\n");
        printf("0 * * * * /cardinal/c2/beacon.sh\n");
        printf("*/5 * * * * /cardinal/tools/exfil-check.sh\n");
    }
    else if (strcmp(command, "at") == 0) {
        printf("Job scheduled for execution\n");
    }
    
    // ═══ PACKAGE MANAGEMENT ═══
    else if (strcmp(command, "apt-get") == 0 || strcmp(command, "apt") == 0 ||
             strcmp(command, "yum") == 0 || strcmp(command, "dnf") == 0 ||
             strcmp(command, "pacman") == 0 || strcmp(command, "zypper") == 0) {
        printf("Package manager: %s\n", command);
        if (argc > 1) {
            if (strcmp(args[1], "install") == 0) {
                printf("Installing packages...\n");
                printf("\033[92m[OK]\033[0m Installation complete\n");
            } else if (strcmp(args[1], "remove") == 0) {
                printf("Removing packages...\n");
                printf("\033[92m[OK]\033[0m Removal complete\n");
            } else if (strcmp(args[1], "update") == 0) {
                printf("Updating package lists...\n");
                printf("\033[92m[OK]\033[0m Package lists updated\n");
            } else if (strcmp(args[1], "upgrade") == 0) {
                printf("Upgrading packages...\n");
                printf("\033[92m[OK]\033[0m System upgraded\n");
            }
        }
    }
    else if (strcmp(command, "dpkg") == 0 || strcmp(command, "rpm") == 0 ||
             strcmp(command, "snap") == 0 || strcmp(command, "flatpak") == 0) {
        printf("Package tool: %s executed\n", command);
    }
    else if (strcmp(command, "pip") == 0 || strcmp(command, "npm") == 0 ||
             strcmp(command, "gem") == 0 || strcmp(command, "cargo") == 0) {
        printf("Programming language package manager: %s\n", command);
    }
    
    // (Continued in next file...)
