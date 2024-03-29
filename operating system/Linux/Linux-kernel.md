
### 1、

6.6	Greg Kroah-Hartman & Sasha Levin	2023-10-29	Dec, 2026

6.1	Greg Kroah-Hartman & Sasha Levin	2022-12-11	Dec, 2026

5.15	Greg Kroah-Hartman & Sasha Levin	2021-10-31	Dec, 2026

5.10	Greg Kroah-Hartman & Sasha Levin	2020-12-13	Dec, 2026

5.4	Greg Kroah-Hartman & Sasha Levin	2019-11-24	Dec, 2025

4.19	Greg Kroah-Hartman & Sasha Levin	2018-10-22	Dec, 2024



### 2、The following is a comprehensive list of all CVEs in our index that affect the upstream kernel.

https://linuxkernelcves.com/cves

The following is a comprehensive list of all CVEs in our index that affect the upstream kernel.

CVE-2003-1604
CVE-2004-0230 tcp: implement RFC 5961 3.2
CVE-2005-3660
CVE-2006-3635
CVE-2006-5331
CVE-2006-6128
CVE-2007-3719
CVE-2007-4774
CVE-2007-6761
CVE-2007-6762
CVE-2008-2544
CVE-2008-4609
CVE-2008-7316
CVE-2009-2692
CVE-2010-0008
CVE-2010-3432
CVE-2010-4563
CVE-2010-4648
CVE-2010-5313
CVE-2010-5321
CVE-2010-5328
CVE-2010-5329
CVE-2010-5331
CVE-2010-5332
CVE-2011-4098
CVE-2011-4131 NFSv4: include bitmap in nfsv4 get acl data
CVE-2011-4915
CVE-2011-4916
CVE-2011-4917
CVE-2011-5321
CVE-2011-5327
CVE-2012-0957 kernel/sys.c: fix stack memory content leak via UNAME26
CVE-2012-2119 macvtap: zerocopy: fix offset calculation when building skb
CVE-2012-2136 net: sock: validate data_len before allocating skb in sock_alloc_send_pskb()
CVE-2012-2137 KVM: Fix buffer overflow in kvm_set_irq()
CVE-2012-2313 dl2k: Clean up rio_ioctl
CVE-2012-2319 hfsplus: Fix potential buffer overflows
CVE-2012-2372 rds: prevent BUG_ON triggered on congestion update to loopback
CVE-2012-2375 Fix length of buffer copied in __nfs4_get_acl_uncached
CVE-2012-2390 hugetlb: fix resv_map leak in error path
CVE-2012-2669 Tools: hv: verify origin of netlink connector message
CVE-2012-2744
CVE-2012-2745 cred: copy_process() should clear child->replacement_session_keyring
CVE-2012-3364 NFC: Prevent multiple buffer overflows in NCI
CVE-2012-3375
CVE-2012-3400 udf: Fortify loading of sparing table
CVE-2012-3412 net: Allow driver to limit number of GSO segments per skb
CVE-2012-3430 rds: set correct msg_namelen
CVE-2012-3510
CVE-2012-3511 mm: Hold a file reference in madvise_remove
CVE-2012-3520 af_netlink: force credentials passing [CVE-2012-3520]
CVE-2012-3552
CVE-2012-4220
CVE-2012-4221
CVE-2012-4222
CVE-2012-4398 usermodehelper: use UMH_WAIT_PROC consistently
CVE-2012-4444
CVE-2012-4461 KVM: x86: invalid opcode oops on SET_SREGS with OSXSAVE bit set (CVE-2012-4461)
CVE-2012-4467
CVE-2012-4508 ext4: race-condition protection for ext4_convert_unwritten_extents_endio
CVE-2012-4530 exec: use -ELOOP for max recursion depth
CVE-2012-4542
CVE-2012-4565 net: fix divide by zero in tcp algorithm illinois
CVE-2012-5374 Btrfs: fix hash overflow handling
CVE-2012-5375 Btrfs: fix hash overflow handling
CVE-2012-5517 mm/hotplug: correctly add new zone to all other nodes' zone lists
CVE-2012-6536 xfrm_user: ensure user supplied esn replay window is valid
CVE-2012-6537 xfrm_user: fix info leak in copy_to_user_tmpl()
CVE-2012-6538 xfrm_user: fix info leak in copy_to_user_auth()
CVE-2012-6539 net: fix info leak in compat dev_ifconf()
CVE-2012-6540 ipvs: fix info leak in getsockopt(IP_VS_SO_GET_TIMEOUT)
CVE-2012-6541 dccp: fix info leak via getsockopt(DCCP_SOCKOPT_CCID_TX_INFO)
CVE-2012-6542 llc: fix info leak via getsockname()
CVE-2012-6543
CVE-2012-6544 Bluetooth: L2CAP - Fix info leak via getsockname()
CVE-2012-6545 Bluetooth: RFCOMM - Fix info leak via getsockname()
CVE-2012-6546 atm: fix info leak via getsockname()
CVE-2012-6547 net/tun: fix ioctl() based info leaks
CVE-2012-6548 udf: avoid info leak on export
CVE-2012-6549 isofs: avoid info leak on export
CVE-2012-6638 tcp: drop SYN+FIN messages
CVE-2012-6647 futex: Forbid uaddr == uaddr2 in futex_wait_requeue_pi()
CVE-2012-6657 net: guard tcp_set_keepalive() to tcp sockets
CVE-2012-6689 netlink: fix possible spoofing from non-root processes
CVE-2012-6701 vfs: make AIO use the proper rw_verify_area() area helpers
CVE-2012-6703
CVE-2012-6704 net: cleanups in sock_setsockopt()
CVE-2012-6712 iwlwifi: Sanity check for sta_id
CVE-2013-0160 TTY: do not update atime/mtime on read/write
CVE-2013-0190 xen: Fix stack corruption in xen_failsafe_callback for 32bit PVOPS guests.
CVE-2013-0216 netback: correct netbk_tx_err to handle wrap around.
CVE-2013-0217 xen/netback: don't leak pages on failure in xen_netbk_tx_check_gop.
CVE-2013-0228 x86/xen: don't assume %ds is usable in xen_iret for 32-bit PVOPS.
CVE-2013-0231 xen-pciback: rate limit error messages from xen_pcibk_enable_msi{,x}()
CVE-2013-0268 x86/msr: Add capabilities check
CVE-2013-0290
CVE-2013-0309 mm: thp: fix pmd_present for split_huge_page and PROT_NONE with THP
CVE-2013-0310 cipso: don't follow a NULL pointer when setsockopt() is called
CVE-2013-0311 vhost: fix length for cross region descriptor
CVE-2013-0313 evm: checking if removexattr is not a NULL
CVE-2013-0343 ipv6: remove max_addresses check from ipv6_create_tempaddr
CVE-2013-0349 Bluetooth: Fix incorrect strncpy() in hidp_setup_hid()
CVE-2013-0871 ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up()
CVE-2013-0913 drm/i915: bounds check execbuffer relocation count
CVE-2013-0914 signal: always clear sa_restorer on execve
CVE-2013-1059 libceph: Fix NULL pointer dereference in auth client code
CVE-2013-1763
CVE-2013-1767 tmpfs: fix use-after-free of mempolicy object
CVE-2013-1772 printk: convert byte-buffer to variable-length record buffer
CVE-2013-1773 NLS: improve UTF8 -> UTF16 string conversion routine
CVE-2013-1774 USB: io_ti: Fix NULL dereference in chase_port()
CVE-2013-1792 keys: fix race with concurrent install_user_keyrings()
CVE-2013-1796 KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (CVE-2013-1796)
CVE-2013-1797 KVM: x86: Convert MSR_KVM_SYSTEM_TIME to use gfn_to_hva_cache functions (CVE-2013-1797)
CVE-2013-1798 KVM: Fix bounds checking in ioapic indirect register reads (CVE-2013-1798)
CVE-2013-1819 xfs: fix _xfs_buf_find oops on blocks beyond the filesystem end
CVE-2013-1826 xfrm_user: return error pointer instead of NULL
CVE-2013-1827 dccp: check ccid before dereferencing
CVE-2013-1828
CVE-2013-1848 ext3: Fix format string issues
CVE-2013-1858
CVE-2013-1860 USB: cdc-wdm: fix buffer overflow
CVE-2013-1928 fs/compat_ioctl.c: VIDEO_SET_SPU_PALETTE missing error check
CVE-2013-1929 tg3: fix length overflow in VPD firmware parsing
CVE-2013-1935
CVE-2013-1943
CVE-2013-1956 userns: Don't allow creation if the user is chrooted
CVE-2013-1957
CVE-2013-1958
CVE-2013-1959
CVE-2013-1979 net: fix incorrect credentials passing
CVE-2013-2015
CVE-2013-2017
CVE-2013-2058
CVE-2013-2094 perf: Treat attr.config as u64 in perf_swevent_init()
CVE-2013-2128
CVE-2013-2140 xen/blkback: Check device permissions before allowing OP_DISCARD
CVE-2013-2141 kernel/signal.c: stop info leak via the tkill and the tgkill syscalls
CVE-2013-2146 perf/x86: Fix offcore_rsp valid mask for SNB/IVB
CVE-2013-2147 cpqarray: fix info leak in ida_locked_ioctl()
CVE-2013-2148 fanotify: info leak in copy_event_to_user()
CVE-2013-2164 drivers/cdrom/cdrom.c: use kzalloc() for failing hardware
CVE-2013-2188
CVE-2013-2206 sctp: Use correct sideffect command in duplicate cookie handling
CVE-2013-2224
CVE-2013-2232 ipv6: ip6_sk_dst_check() must not assume ipv6 dst
CVE-2013-2234 af_key: fix info leaks in notify messages
CVE-2013-2237 af_key: initialize satype in key_notify_policy_flush()
CVE-2013-2239
CVE-2013-2546 crypto: user - fix info leaks in report API
CVE-2013-2547 crypto: user - fix info leaks in report API
CVE-2013-2548 crypto: user - fix info leaks in report API
CVE-2013-2596 vm: convert fb_mmap to vm_iomap_memory() helper
CVE-2013-2634 dcbnl: fix various netlink info leaks
CVE-2013-2635 rtnl: fix info leak on RTM_GETLINK request for VF devices
CVE-2013-2636
CVE-2013-2850 iscsi-target: fix heap buffer overflow on error
CVE-2013-2851 block: do not pass disk names as format strings
CVE-2013-2852 b43: stop format string leaking into error msgs
CVE-2013-2888 HID: validate HID report id size
CVE-2013-2889 HID: zeroplus: validate output report details
CVE-2013-2890
CVE-2013-2891
CVE-2013-2892 HID: pantherlord: validate output report details
CVE-2013-2893 HID: LG: validate HID output report details
CVE-2013-2894
CVE-2013-2895 HID: logitech-dj: validate output report details
CVE-2013-2896 HID: ntrig: validate feature report details
CVE-2013-2897
CVE-2013-2898
CVE-2013-2899 HID: picolcd_core: validate output report details
CVE-2013-2929 exec/ptrace: fix get_dumpable() incorrect tests
CVE-2013-2930 perf/ftrace: Fix paranoid level for enabling function tracer
CVE-2013-3076 crypto: algif - suppress sending source address information in recvmsg
CVE-2013-3222 atm: update msg_namelen in vcc_recvmsg()
CVE-2013-3223 ax25: fix info leak via msg_name in ax25_recvmsg()
CVE-2013-3224 Bluetooth: fix possible info leak in bt_sock_recvmsg()
CVE-2013-3225 Bluetooth: RFCOMM - Fix missing msg_namelen update in rfcomm_sock_recvmsg()
CVE-2013-3226
CVE-2013-3227 caif: Fix missing msg_namelen update in caif_seqpkt_recvmsg()
CVE-2013-3228 irda: Fix missing msg_namelen update in irda_recvmsg_dgram()
CVE-2013-3229 iucv: Fix missing msg_namelen update in iucv_sock_recvmsg()
CVE-2013-3230
CVE-2013-3231 llc: Fix missing msg_namelen update in llc_ui_recvmsg()
CVE-2013-3232 netrom: fix info leak via msg_name in nr_recvmsg()
CVE-2013-3233
CVE-2013-3234 rose: fix info leak via msg_name in rose_recvmsg()
CVE-2013-3235 tipc: fix info leaks via msg_name in recv_msg/recv_stream
CVE-2013-3236
CVE-2013-3237
CVE-2013-3301 tracing: Fix possible NULL pointer dereferences
CVE-2013-3302
CVE-2013-4125
CVE-2013-4127
CVE-2013-4129 bridge: fix some kernel warning in multicast timer
CVE-2013-4162 ipv6: call udp_push_pending_frames when uncorking a socket with AF_INET pending data
CVE-2013-4163
CVE-2013-4205
CVE-2013-4220
CVE-2013-4247
CVE-2013-4254 ARM: 7810/1: perf: Fix array out of bounds access in armpmu_map_hw_event()
CVE-2013-4270
CVE-2013-4299 dm snapshot: fix data corruption
CVE-2013-4300
CVE-2013-4312 unix: properly account for FDs passed over unix sockets
CVE-2013-4343
CVE-2013-4345 crypto: ansi_cprng - Fix off by one error in non-block size request
CVE-2013-4348 net: flow_dissector: fail on evil iph->ihl
CVE-2013-4350 net: sctp: fix ipv6 ipsec encryption bug in sctp_v6_xmit
CVE-2013-4387 ipv6: udp packets following an UFO enqueued packet need also be handled by UFO
CVE-2013-4470 ip6_output: do skb ufo init for peeked non ufo skb as well
CVE-2013-4483 ipc,sem: fine grained locking for semtimedop
CVE-2013-4511 uml: check length in exitcode_proc_write()
CVE-2013-4512 uml: check length in exitcode_proc_write()
CVE-2013-4513 staging: ozwpan: prevent overflow in oz_cdev_write()
CVE-2013-4514 staging: wlags49_h2: buffer overflow setting station name
CVE-2013-4515 Staging: bcm: info leak in ioctl
CVE-2013-4516 Staging: sb105x: info leak in mp_get_count()
CVE-2013-4563 ipv6: fix headroom calculation in udp6_ufo_fragment
CVE-2013-4579 ath9k_htc: properly set MAC address and BSSID mask
CVE-2013-4587 KVM: Improve create VCPU parameter (CVE-2013-4587)
CVE-2013-4588
CVE-2013-4591
CVE-2013-4592 KVM: perform an invalid memslot step for gpa base change
CVE-2013-4737
CVE-2013-4738
CVE-2013-4739
CVE-2013-5634
CVE-2013-6282 ARM: 7527/1: uaccess: explicitly check __user pointer when !CPU_USE_DOMAINS
CVE-2013-6367 KVM: x86: Fix potential divide by 0 in lapic (CVE-2013-6367)
CVE-2013-6368 KVM: x86: Convert vapic synchronization to _cached functions (CVE-2013-6368)
CVE-2013-6376 KVM: x86: fix guest-initiated crash with x2apic (CVE-2013-6376)
CVE-2013-6378 libertas: potential oops in debugfs
CVE-2013-6380 aacraid: prevent invalid pointer dereference
CVE-2013-6381 qeth: avoid buffer overflow in snmp ioctl
CVE-2013-6382 xfs: underflow bug in xfs_attrlist_by_handle()
CVE-2013-6383 aacraid: missing capable() check in compat ioctl
CVE-2013-6392
CVE-2013-6431
CVE-2013-6432 ping: prevent NULL pointer dereference on write to msg_name
CVE-2013-6885 x86, cpu, amd: Add workaround for family 16h, erratum 793
CVE-2013-7026 ipc,shm: fix shm_file deletion races
CVE-2013-7027 wireless: radiotap: fix parsing buffer overrun
CVE-2013-7263 inet: prevent leakage of uninitialized memory to user in recv syscalls
CVE-2013-7264 inet: prevent leakage of uninitialized memory to user in recv syscalls
CVE-2013-7265 inet: prevent leakage of uninitialized memory to user in recv syscalls
CVE-2013-7266 net: rework recvmsg handler msg_name and msg_namelen logic
CVE-2013-7267 net: rework recvmsg handler msg_name and msg_namelen logic
CVE-2013-7268 net: rework recvmsg handler msg_name and msg_namelen logic
CVE-2013-7269 net: rework recvmsg handler msg_name and msg_namelen logic
CVE-2013-7270 net: rework recvmsg handler msg_name and msg_namelen logic
CVE-2013-7271 net: rework recvmsg handler msg_name and msg_namelen logic
CVE-2013-7281 inet: prevent leakage of uninitialized memory to user in recv syscalls
CVE-2013-7339 rds: prevent dereference of a NULL device
CVE-2013-7348 aio: prevent double free in ioctx_alloc
CVE-2013-7421 crypto: prefix module autoloading with "crypto-"
CVE-2013-7445
CVE-2013-7446 unix: avoid use-after-free in ep_remove_wait_queue
CVE-2013-7470 net: fix cipso packet validation when !NETLABEL
CVE-2014-0038 x86, x32: Correct invalid use of user timespec in the kernel
CVE-2014-0049 kvm: x86: fix emulator buffer overflow (CVE-2014-0049)
CVE-2014-0055 vhost: validate vhost_get_vq_desc return value
CVE-2014-0069 cifs: ensure that uncached writes handle unmapped areas correctly
CVE-2014-0077 vhost: fix total length when packets are too short
CVE-2014-0100 net: fix for a race condition in the inet frag code
CVE-2014-0101 net: sctp: fix sctp_sf_do_5_1D_ce to verify if we/peer is AUTH capable
CVE-2014-0102
CVE-2014-0131 skbuff: skb_segment: orphan frags before copying
CVE-2014-0155 KVM: ioapic: fix assignment of ioapic->rtc_status.pending_eoi (CVE-2014-0155)
CVE-2014-0181 net: Use netlink_ns_capable to verify the permisions of netlink messages
CVE-2014-0196 n_tty: Fix n_tty_write crash when echoing in raw mode
CVE-2014-0203
CVE-2014-0205
CVE-2014-0206 aio: fix kernel memory disclosure in io_getevents() introduced in v3.10
CVE-2014-0972
CVE-2014-1438 x86, fpu, amd: Clear exceptions in AMD FXSAVE workaround
CVE-2014-1444 farsync: fix info leak in ioctl
CVE-2014-1445 wanxl: fix info leak in ioctl
CVE-2014-1446 hamradio/yam: fix info leak in ioctl
CVE-2014-1690 netfilter: nf_nat: fix access to uninitialized buffer in IRC NAT helper
CVE-2014-1737 floppy: ignore kernel-only members in FDRAWCMD ioctl input
CVE-2014-1738 floppy: don't write kernel-only members to FDRAWCMD ioctl output
CVE-2014-1739 [media] media-device: fix infoleak in ioctl media_enum_entities()
CVE-2014-1874 SELinux: Fix kernel BUG on empty security contexts.
CVE-2014-2038 nfs: always make sure page is up-to-date before extending a write to cover the entire page
CVE-2014-2039 s390: fix kernel crash due to linkage stack instructions
CVE-2014-2309 ipv6: don't set DST_NOCOUNT for remotely added routes
CVE-2014-2523 netfilter: nf_conntrack_dccp: fix skb_header_pointer API usages
CVE-2014-2568 core, nfqueue, openvswitch: Orphan frags in skb_zerocopy and handle errors
CVE-2014-2580 xen-netback: disable rogue vif in kthread context
CVE-2014-2672 ath9k: protect tid->sched check
CVE-2014-2673 powerpc/tm: Fix crash when forking inside a transaction
CVE-2014-2678 rds: prevent dereference of a NULL device in rds_iw_laddr_check
CVE-2014-2706 mac80211: fix AP powersave TX vs. wakeup race
CVE-2014-2739 IB/core: Don't resolve passive side RoCE L2 address in CMA REQ handler
CVE-2014-2851 net: ipv4: current group_info should be put after using.
CVE-2014-2889
CVE-2014-3122 mm: try_to_unmap_cluster() should lock_page() before mlocking
CVE-2014-3144 filter: prevent nla extensions to peek beyond the end of the message
CVE-2014-3145 filter: prevent nla extensions to peek beyond the end of the message
CVE-2014-3153 futex: Make lookup_pi_state more robust
CVE-2014-3180 compat: nanosleep: Clarify error handling
CVE-2014-3181 HID: magicmouse: sanity check report size in raw_event() callback
CVE-2014-3182 HID: logitech: perform bounds checking on device_id early enough
CVE-2014-3183 HID: logitech: fix bounds checking on LED report size
CVE-2014-3184 HID: fix a couple of off-by-ones
CVE-2014-3185 USB: whiteheat: Added bounds checking for bulk command response
CVE-2014-3186 HID: picolcd: sanity check report size in raw_event() callback
CVE-2014-3519
CVE-2014-3534 s390/ptrace: fix PSW mask check
CVE-2014-3535
CVE-2014-3601 kvm: iommu: fix the third parameter of kvm_iommu_put_pages (CVE-2014-3601)
CVE-2014-3610 KVM: x86: Check non-canonical addresses upon WRMSR
CVE-2014-3611 KVM: x86: Improve thread safety in pit
CVE-2014-3631 KEYS: Fix termination condition in assoc array garbage collection
CVE-2014-3645 nEPT: Nested INVEPT
CVE-2014-3646 kvm: vmx: handle invvpid vm exit gracefully
CVE-2014-3647 KVM: x86: Emulator fixes for eip canonical checks on near branches
CVE-2014-3673 net: sctp: fix skb_over_panic when receiving malformed ASCONF chunks
CVE-2014-3687 net: sctp: fix panic on duplicate ASCONF chunks
CVE-2014-3688 net: sctp: fix remote memory pressure from excessive queueing
CVE-2014-3690 x86,kvm,vmx: Preserve CR4 across VM entry
CVE-2014-3917 auditsc: audit_krule mask accesses need bounds checking
CVE-2014-3940 mm: add !pte_present() check on existing hugetlb_entry callbacks
CVE-2014-4014 fs,userns: Change inode_capable to capable_wrt_inode_uidgid
CVE-2014-4027 target/rd: Refactor rd_build_device_space + rd_release_device_space
CVE-2014-4157 MIPS: asm: thread_info: Add _TIF_SECCOMP flag
CVE-2014-4171 shmem: fix faulting into a hole while it's punched
CVE-2014-4322
CVE-2014-4323
CVE-2014-4508 x86_32, entry: Do syscall exit work on badsys (CVE-2014-4508)
CVE-2014-4608 lzo: check for length overrun in variable length encoding.
CVE-2014-4611 lz4: ensure length does not wrap
CVE-2014-4652 ALSA: control: Protect user controls against concurrent access
CVE-2014-4653 ALSA: control: Don't access controls outside of protected regions
CVE-2014-4654 ALSA: control: Fix replacing user controls
CVE-2014-4655 ALSA: control: Fix replacing user controls
CVE-2014-4656 ALSA: control: Handle numid overflow
CVE-2014-4667 sctp: Fix sk_ack_backlog wrap-around problem
CVE-2014-4699 ptrace,x86: force IRET path after a ptrace_stop()
CVE-2014-4943 net/l2tp: don't fall back on UDP [get|set]sockopt
CVE-2014-5045 fs: umount on symlink leaks mnt count
CVE-2014-5077 net: sctp: inherit auth_capable on INIT collisions
CVE-2014-5206 mnt: Only change user settable mount flags in remount
CVE-2014-5207 mnt: Correct permission checks in do_remount
CVE-2014-5332
CVE-2014-5471 isofs: Fix unbounded recursion when processing relocated directories
CVE-2014-5472 isofs: Fix unbounded recursion when processing relocated directories
CVE-2014-6410 udf: Avoid infinite loop when processing indirect ICBs
CVE-2014-6416 libceph: do not hard code max auth ticket len
CVE-2014-6417 libceph: do not hard code max auth ticket len
CVE-2014-6418 libceph: do not hard code max auth ticket len
CVE-2014-7145 [CIFS] Possible null ptr deref in SMB2_tcon
CVE-2014-7207 ipv6: reuse ip6_frag_id from ip6_ufo_append_data
CVE-2014-7283 xfs: fix directory hash ordering bug
CVE-2014-7284 net: avoid dependency of net_get_random_once on nop patching
CVE-2014-7822 ->splice_write() via ->write_iter()
CVE-2014-7825 tracing/syscalls: Ignore numbers outside NR_syscalls' range
CVE-2014-7826 tracing/syscalls: Ignore numbers outside NR_syscalls' range
CVE-2014-7841 net: sctp: fix NULL pointer dereference in af->from_addr_param on malformed packet
CVE-2014-7842 KVM: x86: Don't report guest userspace emulation error to userspace
CVE-2014-7843 arm64: __clear_user: handle exceptions on strb
CVE-2014-7970 mnt: Prevent pivot_root from creating a loop in the mount tree
CVE-2014-7975 fs: Add a missing permission check to do_umount
CVE-2014-8086 ext4: prevent bugon on race between write/fcntl
CVE-2014-8133 x86/tls: Validate TLS entries to protect espfix
CVE-2014-8134 x86, kvm: Clear paravirt_enabled on KVM guests for espfix32's benefit
CVE-2014-8159 IB/uverbs: Prevent integer overflow in ib_umem_get address arithmetic
CVE-2014-8160 netfilter: conntrack: disable generic tracking for known protocols
CVE-2014-8171 mm: memcg: do not trap chargers with full callstack on OOM
CVE-2014-8172 get rid of s_files and files_lock
CVE-2014-8173 mm: Fix NULL pointer dereference in madvise(MADV_WILLNEED) support
CVE-2014-8181
CVE-2014-8369
CVE-2014-8480
CVE-2014-8481
CVE-2014-8559 move d_rcu from overlapping d_child to overlapping d_alias
CVE-2014-8709 mac80211: fix fragmentation code, particularly for encryption
CVE-2014-8884 [media] ttusb-dec: buffer overflow in ioctl
CVE-2014-8989 userns: Don't allow setgroups until a gid mapping has been setablished
CVE-2014-9090 x86_64, traps: Stop using IST for #SS
CVE-2014-9322 x86_64, traps: Stop using IST for #SS
CVE-2014-9419 x86_64, switch_to(): Load TLS descriptors before switching DS and ES
CVE-2014-9420 isofs: Fix infinite looping over CE entries
CVE-2014-9428 batman-adv: Calculate extra tail size based on queued fragments
CVE-2014-9529 KEYS: close race between key lookup and freeing
CVE-2014-9584 isofs: Fix unchecked printing of ER records
CVE-2014-9585 x86_64, vdso: Fix the vdso address randomization algorithm
CVE-2014-9644 crypto: include crypto- module prefix in template
CVE-2014-9683 eCryptfs: Remove buggy and unnecessary write in file name decode routine
CVE-2014-9710 Btrfs: make xattr replace operations atomic
CVE-2014-9715 netfilter: nf_conntrack: reserve two bytes for nf_ct_ext->len
CVE-2014-9717 mnt: Update detach_mounts to leave mounts connected
CVE-2014-9728 udf: Verify i_size when loading inode
CVE-2014-9729 udf: Verify i_size when loading inode
CVE-2014-9730 udf: Check component length before reading it
CVE-2014-9731 udf: Check path length when reading symlink
CVE-2014-9777
CVE-2014-9778
CVE-2014-9779
CVE-2014-9780
CVE-2014-9781
CVE-2014-9782
CVE-2014-9783
CVE-2014-9784
CVE-2014-9785
CVE-2014-9786
CVE-2014-9787
CVE-2014-9788
CVE-2014-9789
CVE-2014-9803 Revert "arm64: Introduce execute-only page access permissions"
CVE-2014-9863
CVE-2014-9864
CVE-2014-9865
CVE-2014-9866
CVE-2014-9867
CVE-2014-9868
CVE-2014-9869
CVE-2014-9870
CVE-2014-9871
CVE-2014-9872
CVE-2014-9873
CVE-2014-9874
CVE-2014-9875
CVE-2014-9876
CVE-2014-9877
CVE-2014-9878
CVE-2014-9879
CVE-2014-9880
CVE-2014-9881
CVE-2014-9882
CVE-2014-9883
CVE-2014-9884
CVE-2014-9885
CVE-2014-9886
CVE-2014-9887
CVE-2014-9888 ARM: dma-mapping: don't allow DMA mappings to be marked executable
CVE-2014-9889
CVE-2014-9890
CVE-2014-9891
CVE-2014-9892
CVE-2014-9893
CVE-2014-9894
CVE-2014-9895 [media] media: info leak in __media_device_enum_links()
CVE-2014-9896
CVE-2014-9897
CVE-2014-9898
CVE-2014-9899
CVE-2014-9900
CVE-2014-9903
CVE-2014-9904 ALSA: compress: fix an integer overflow check
CVE-2014-9914 ipv4: fix a race in ip4_datagram_release_cb()
CVE-2014-9922 fs: limit filesystem stacking depth
CVE-2014-9940 regulator: core: Fix regualtor_ena_gpio_free not to access pin after freeing
CVE-2015-0239 KVM: x86: SYSENTER emulation is broken
CVE-2015-0274 xfs: remote attribute overwrite causes transaction overrun
CVE-2015-0275 ext4: allocate entire range in zero range
CVE-2015-0777
CVE-2015-1328
CVE-2015-1333 KEYS: ensure we free the assoc array edit if edit is valid
CVE-2015-1339 cuse: fix memory leak
CVE-2015-1350 fs: Avoid premature clearing of capabilities
CVE-2015-1420 vfs: read file_handle only once in handle_to_path
CVE-2015-1421 net: sctp: fix slab corruption from use after free on INIT collisions
CVE-2015-1465 ipv4: try to cache dst_entries which would cause a redirect
CVE-2015-1573 netfilter: nf_tables: fix flush ruleset chain dependencies
CVE-2015-1593 x86, mm/ASLR: Fix stack randomization on 64-bit systems
CVE-2015-1805 new helper: copy_page_from_iter()
CVE-2015-2041 net: llc: use correct size for sysctl timeout entries
CVE-2015-2042 net: rds: use correct size for max unacked packets and bytes
CVE-2015-2150 xen-pciback: limit guest control of command register
CVE-2015-2666 x86/microcode/intel: Guard against stack overflow in the loader
CVE-2015-2672 x86/fpu/xsaves: Fix improper uses of __ex_table
CVE-2015-2686 net: validate the range we feed to iov_iter_init() in sys_sendto/sys_recvfrom
CVE-2015-2830 x86/asm/entry/64: Remove a bogus 'ret_from_fork' optimization
CVE-2015-2877
CVE-2015-2922 ipv6: Don't reduce hop limit for an interface
CVE-2015-2925 dcache: Handle escaped paths in prepend_path
CVE-2015-3212 sctp: fix ASCONF list handling
CVE-2015-3214
CVE-2015-3288 mm: avoid setting up anonymous pages into file mapping
CVE-2015-3290 x86/nmi/64: Switch stacks on userspace NMI entry
CVE-2015-3291 x86/nmi/64: Use DF to avoid userspace RSP confusing nested NMI detection
CVE-2015-3331 crypto: aesni - fix memory usage in GCM decryption
CVE-2015-3332 tcp: Fix crash in TCP Fast Open
CVE-2015-3339 fs: take i_mutex during prepare_binprm for set[ug]id executables
CVE-2015-3636 ipv4: Missing sk_nulls_node_init() in ping_unhash().
CVE-2015-4001 ozwpan: Use unsigned ints to prevent heap overflow
CVE-2015-4002 ozwpan: Use proper check to prevent heap overflow
CVE-2015-4003 ozwpan: divide-by-zero leading to panic
CVE-2015-4004 staging: ozwpan: Remove from tree
CVE-2015-4036 vhost/scsi: potential memory corruption
CVE-2015-4167 udf: Check length of extended attributes and allocation descriptors
CVE-2015-4170 tty: Fix hang at ldsem_down_read()
CVE-2015-4176 mnt: Update detach_mounts to leave mounts connected
CVE-2015-4177 mnt: Fail collect_mounts when applied to unmounted mounts
CVE-2015-4178 fs_pin: Allow for the possibility that m_list or s_list go unused.
CVE-2015-4692 kvm: x86: fix kvm_apic_has_events to check for NULL pointer
CVE-2015-4700 x86: bpf_jit: fix compilation of large bpf programs
CVE-2015-5156 virtio-net: drop NETIF_F_FRAGLIST
CVE-2015-5157 x86/nmi/64: Switch stacks on userspace NMI entry
CVE-2015-5257 USB: whiteheat: fix potential null-deref at probe
CVE-2015-5283 sctp: fix race on protocol/netns initialization
CVE-2015-5307 KVM: x86: work around infinite loop in microcode when #AC is delivered
CVE-2015-5327 X.509: Fix the time validation [ver #2]
CVE-2015-5364 udp: fix behavior of wrong checksums
CVE-2015-5366 udp: fix behavior of wrong checksums
CVE-2015-5697 md: use kzalloc() when bitmap is disabled
CVE-2015-5706 path_openat(): fix double fput()
CVE-2015-5707 sg_start_req(): make sure that there's not too many elements in iovec
CVE-2015-6252 vhost: actually track log eventfd file
CVE-2015-6526 powerpc/perf: Cap 64bit userspace backtraces to PERF_MAX_STACK_DEPTH
CVE-2015-6619
CVE-2015-6646
CVE-2015-6937 RDS: verify the underlying transport exists before creating a connection
CVE-2015-7312
CVE-2015-7509 ext4: make orphan functions be no-op in no-journal mode
CVE-2015-7513 KVM: x86: Reload pit counters for all channels when restoring state
CVE-2015-7515 Input: aiptek - fix crash on detecting device without endpoints
CVE-2015-7550 KEYS: Fix race between read and revoke
CVE-2015-7553
CVE-2015-7566 USB: serial: visor: fix crash on detecting device without write_urbs
CVE-2015-7613 Initialize msg/shm IPC objects before doing ipc_addid()
CVE-2015-7799 isdn_ppp: Add checks for allocation failure in isdn_ppp_open()
CVE-2015-7833 [media] usbvision: revert commit 588afcc1
CVE-2015-7837
CVE-2015-7872 KEYS: Fix crash when attempt to garbage collect an uninstantiated keyring
CVE-2015-7884 [media] media/vivid-osd: fix info leak in ioctl
CVE-2015-7885 staging/dgnc: fix info leak in ioctl
CVE-2015-7990 RDS: fix race condition when sending a message on unbound socket
CVE-2015-8019 net: add length argument to skb_copy_and_csum_datagram_iovec
CVE-2015-8104 KVM: svm: unconditionally intercept #DB
CVE-2015-8215 ipv6: addrconf: validate new MTU before applying it
CVE-2015-8324
CVE-2015-8374 Btrfs: fix truncation of compressed and inlined extents
CVE-2015-8539
CVE-2015-8543 net: add validation for the socket syscall protocol argument
CVE-2015-8550 xen: Add RING_COPY_REQUEST()
CVE-2015-8551 xen/pciback: Return error on XEN_PCI_OP_enable_msi when device has MSI or MSI-X enabled
CVE-2015-8552 xen/pciback: Return error on XEN_PCI_OP_enable_msi when device has MSI or MSI-X enabled
CVE-2015-8553 xen/pciback: Don't allow MSI-X ops if PCI_COMMAND_MEMORY is not set.
CVE-2015-8569 pptp: verify sockaddr_len in pptp_bind() and pptp_connect()
CVE-2015-8575 bluetooth: Validate socket address length in sco_sock_bind().
CVE-2015-8660 ovl: fix permission checking for setattr
CVE-2015-8709 mm: Add a user_ns owner to mm_struct and fix ptrace permission checks
CVE-2015-8746 NFS: Fix a NULL pointer dereference of migration recovery ops for v4.2 client
CVE-2015-8767 sctp: Prevent soft lockup when sctp_accept() is called during a timeout event
CVE-2015-8785 fuse: break infinite loop in fuse_fill_write_pages()
CVE-2015-8787 netfilter: nf_nat_redirect: add missing NULL pointer check
CVE-2015-8812 iw_cxgb3: Fix incorrectly returning error on success
CVE-2015-8816 USB: fix invalid memory access in hub_activate()
CVE-2015-8830 aio: lift iov_iter_init() into aio_setup_..._rw()
CVE-2015-8839 ext4: fix races between page faults and hole punching
CVE-2015-8844 powerpc/tm: Block signal return setting invalid MSR state
CVE-2015-8845 powerpc/tm: Check for already reclaimed tasks
CVE-2015-8937
CVE-2015-8938
CVE-2015-8939
CVE-2015-8940
CVE-2015-8941
CVE-2015-8942
CVE-2015-8943
CVE-2015-8944 /proc/iomem: only expose physical resource addresses to privileged users
CVE-2015-8950 arm64: dma-mapping: always clear allocated buffers
CVE-2015-8952 ext2: convert to mbcache2
CVE-2015-8953 ovl: fix dentry reference leak
CVE-2015-8955 arm64: perf: reject groups spanning multiple HW PMUs
CVE-2015-8956 Bluetooth: Fix potential NULL dereference in RFCOMM bind callback
CVE-2015-8961 ext4: fix potential use after free in __ext4_journal_stop
CVE-2015-8962 sg: Fix double-free when drives detach during SG_IO
CVE-2015-8963 perf: Fix race in swevent hash
CVE-2015-8964 tty: Prevent ldisc drivers from re-using stale tty fields
CVE-2015-8966 [PATCH] arm: fix handling of F_OFD_... in oabi_fcntl64()
CVE-2015-8967 arm64: make sys_call_table const
CVE-2015-8970 crypto: algif_skcipher - Require setkey before accept(2)
CVE-2015-9004 perf: Tighten (and fix) the grouping condition
CVE-2015-9016 blk-mq: fix race between timeout and freeing request
CVE-2015-9289 [media] cx24116: fix a buffer overflow when checking userspace params
CVE-2016-0617 fs/hugetlbfs/inode.c: fix bugs in hugetlb_vmtruncate_list()
CVE-2016-0723 tty: Fix unsafe ldisc reference via ioctl(TIOCGETD)
CVE-2016-0728 KEYS: Fix keyring ref leak in join_session_keyring()
CVE-2016-0758 KEYS: Fix ASN.1 indefinite length object parsing
CVE-2016-0774
CVE-2016-0821 include/linux/poison.h: fix LIST_POISON{1,2} offset
CVE-2016-0823 pagemap: do not leak physical addresses to non-privileged userspace
CVE-2016-10044 aio: mark AIO pseudo-fs noexec
CVE-2016-10088 sg_write()/bsg_write() is not fit to be called under KERNEL_DS
CVE-2016-10147 crypto: mcryptd - Check mcryptd algorithm compatibility
CVE-2016-10150 KVM: use after free in kvm_ioctl_create_device()
CVE-2016-10153 libceph: introduce ceph_crypt() for in-place en/decryption
CVE-2016-10154 cifs: Fix smbencrypt() to stop pointing a scatterlist at the stack
CVE-2016-10200 l2tp: fix racy SOCK_ZAPPED flag check in l2tp_ip{,6}_bind()
CVE-2016-10208 ext4: validate s_first_meta_bg at mount time
CVE-2016-10229 udp: properly support MSG_PEEK with truncated buffers
CVE-2016-10318 fscrypto: add authorization check for setting encryption policy
CVE-2016-10723 mm, oom: remove sleep from under oom_lock
CVE-2016-10741 xfs: don't BUG() on mixed direct and mapped I/O
CVE-2016-10764 mtd: spi-nor: Off by one in cqspi_setup_flash()
CVE-2016-10905 GFS2: don't set rgrp gl_object until it's inserted into rgrp tree
CVE-2016-10906 net: arc_emac: fix koops caused by sk_buff free
CVE-2016-10907 iio: ad5755: fix off-by-one on devnr limit check
CVE-2016-1237 posix_acl: Add set_posix_acl
CVE-2016-1575 ovl: setattr: check permissions before copy-up
CVE-2016-1576 ovl: setattr: check permissions before copy-up
CVE-2016-1583 proc: prevent stacking filesystems on top
CVE-2016-2053 ASN.1: Fix non-match detection failure on data overrun
CVE-2016-2069 x86/mm: Add barriers and document switch_mm()-vs-flush synchronization
CVE-2016-2070 tcp: fix zero cwnd in tcp_cwnd_reduction
CVE-2016-2085 EVM: Use crypto_memneq() for digest comparisons
CVE-2016-2117 atl2: Disable unimplemented scatter/gather feature
CVE-2016-2143 s390/mm: four page table levels vs. fork
CVE-2016-2184 ALSA: usb-audio: Fix NULL dereference in create_fixed_stream_quirk()
CVE-2016-2185 Input: ati_remote2 - fix crashes on detecting device with invalid descriptor
CVE-2016-2186 Input: powermate - fix oops with malicious USB descriptors
CVE-2016-2187 Input: gtco - fix crash on detecting device without endpoints
CVE-2016-2188 USB: iowarrior: fix NULL-deref at probe
CVE-2016-2383 bpf: fix branch offset adjustment on backjumps after patching ctx expansion
CVE-2016-2384 ALSA: usb-audio: avoid freeing umidi object twice
CVE-2016-2543 ALSA: seq: Fix missing NULL check at remove_events ioctl
CVE-2016-2544 ALSA: seq: Fix race at timer setup and close
CVE-2016-2545 ALSA: timer: Fix double unlink of active_list
CVE-2016-2546 ALSA: timer: Fix race among timer ioctls
CVE-2016-2547 ALSA: timer: Harden slave timer list handling
CVE-2016-2548 ALSA: timer: Harden slave timer list handling
CVE-2016-2549 ALSA: hrtimer: Fix stall by hrtimer_cancel()
CVE-2016-2550
CVE-2016-2782 USB: visor: fix null-deref at probe
CVE-2016-2847 pipe: limit the per-user amount of pages allocated in pipes
CVE-2016-2853
CVE-2016-2854
CVE-2016-3044 KVM: PPC: Book3S HV: Sanitize special-purpose register values on guest exit
CVE-2016-3070 mm: migrate dirty page without clear_page_dirty_for_io etc
CVE-2016-3134 netfilter: x_tables: fix unconditional helper
CVE-2016-3135 netfilter: x_tables: check for size overflow
CVE-2016-3136 USB: mct_u232: add sanity checking in probe
CVE-2016-3137 USB: cypress_m8: add endpoint sanity check
CVE-2016-3138 USB: cdc-acm: more sanity checking
CVE-2016-3139 Input: wacom - compute the HID report size to get the actual packet size
CVE-2016-3140 USB: digi_acceleport: do sanity checking for the number of ports
CVE-2016-3156 ipv4: Don't do expensive useless work during inetdev destroy.
CVE-2016-3157 x86/iopl/64: Properly context-switch IOPL on Xen PV
CVE-2016-3672 x86/mm/32: Enable full randomization on i386 and X86_32
CVE-2016-3689 Input: ims-pcu - sanity check against missing interfaces
CVE-2016-3695
CVE-2016-3699
CVE-2016-3707
CVE-2016-3713 KVM: MTRR: remove MSR 0x2f8
CVE-2016-3775
CVE-2016-3802
CVE-2016-3803
CVE-2016-3841 ipv6: add complete rcu protection around np->opt
CVE-2016-3857 arm: oabi compat: add missing access checks
CVE-2016-3951 cdc_ncm: do not call usbnet_link_change from cdc_ncm_bind
CVE-2016-3955 USB: usbip: fix potential out-of-bounds write
CVE-2016-3961 x86/mm/xen: Suppress hugetlbfs in PV guests
CVE-2016-4440 kvm:vmx: more complete state update on APICv on/off
CVE-2016-4470 KEYS: potential uninitialized variable
CVE-2016-4482 USB: usbfs: fix potential infoleak in devio
CVE-2016-4485 net: fix infoleak in llc
CVE-2016-4486 net: fix infoleak in rtnetlink
CVE-2016-4557 bpf: fix double-fdput in replace_map_fd_with_map_ptr()
CVE-2016-4558 bpf: fix refcnt overflow
CVE-2016-4565 IB/security: Restrict use of the write() interface
CVE-2016-4568 [media] videobuf2-v4l2: Verify planes array in buffer dequeueing
CVE-2016-4569 ALSA: timer: Fix leak in SNDRV_TIMER_IOCTL_PARAMS
CVE-2016-4578 ALSA: timer: Fix leak in events via snd_timer_user_ccallback
CVE-2016-4580 net: fix a kernel infoleak in x25 module
CVE-2016-4581 propogate_mnt: Handle the first propogated copy being a slave
CVE-2016-4794 percpu: fix synchronization between chunk->map_extend_work and chunk destruction
CVE-2016-4805 ppp: take reference on channels netns
CVE-2016-4913 get_rock_ridge_filename(): handle malformed NM entries
CVE-2016-4951 tipc: check nl sock before parsing nested attributes
CVE-2016-4997 netfilter: x_tables: check for bogus target offset
CVE-2016-4998 netfilter: x_tables: check for bogus target offset
CVE-2016-5195 mm: remove gup_flags FOLL_WRITE games from __get_user_pages()
CVE-2016-5243 tipc: fix an infoleak in tipc_nl_compat_link_dump
CVE-2016-5244 rds: fix an infoleak in rds_inc_info_copy
CVE-2016-5340
CVE-2016-5342
CVE-2016-5343
CVE-2016-5344
CVE-2016-5400 media: fix airspy usb probe error path
CVE-2016-5412 KVM: PPC: Book3S HV: Pull out TM state save/restore into separate procedures
CVE-2016-5696 tcp: make challenge acks less predictable
CVE-2016-5728 misc: mic: Fix for double fetch security bug in VOP driver
CVE-2016-5828 powerpc/tm: Always reclaim in start_thread() for exec() class syscalls
CVE-2016-5829 HID: hiddev: validate num_values for HIDIOCGUSAGES, HIDIOCSUSAGES commands
CVE-2016-5870
CVE-2016-6130 s390/sclp_ctl: fix potential information leak with /dev/sclp
CVE-2016-6136 audit: fix a double fetch in audit_log_single_execve_arg()
CVE-2016-6156 platform/chrome: cros_ec_dev - double fetch bug in ioctl
CVE-2016-6162 udp: prevent bugcheck if filter truncates packet too much
CVE-2016-6187 apparmor: fix oops, validate buffer size in apparmor_setprocattr()
CVE-2016-6197 ovl: verify upper dentry before unlink and rename
CVE-2016-6198 vfs: add vfs_select_inode() helper
CVE-2016-6213 mnt: Add a per mount namespace limit on the number of mounts
CVE-2016-6327 IB/srpt: Simplify srpt_handle_tsk_mgmt()
CVE-2016-6480 aacraid: Check size values after double-fetch from user
CVE-2016-6516 vfs: ioctl: prevent double-fetch in dedupe ioctl
CVE-2016-6753
CVE-2016-6786 perf: Fix event->ctx locking
CVE-2016-6787 perf: Fix event->ctx locking
CVE-2016-6828 tcp: fix use after free in tcp_xmit_retransmit_queue()
CVE-2016-7039 net: add recursion limit to GRO
CVE-2016-7042 KEYS: Fix short sprintf buffer in /proc/keys show function
CVE-2016-7097 posix_acl: Clear SGID bit when setting file permissions
CVE-2016-7117 net: Fix use after free in the recvmmsg exit path
CVE-2016-7118
CVE-2016-7425 scsi: arcmsr: Buffer overflow in arcmsr_iop_message_xfer()
CVE-2016-7910 block: fix use-after-free in seq file
CVE-2016-7911 block: fix use-after-free in sys_ioprio_get()
CVE-2016-7912 usb: gadget: f_fs: Fix use-after-free
CVE-2016-7913 [media] xc2028: avoid use after free
CVE-2016-7914 assoc_array: don't call compare_object() on a node
CVE-2016-7915 HID: core: prevent out-of-bound readings
CVE-2016-7916 proc: prevent accessing /proc/<PID>/environ until it's ready
CVE-2016-7917 netfilter: nfnetlink: correctly validate length of batch messages
CVE-2016-8399 net: ping: check minimum size on ICMP header length
CVE-2016-8401
CVE-2016-8402
CVE-2016-8403
CVE-2016-8404
CVE-2016-8405 fbdev: color map copying bounds checking
CVE-2016-8406
CVE-2016-8407
CVE-2016-8630 kvm: x86: Check memopp before dereference (CVE-2016-8630)
CVE-2016-8632 tipc: check minimum bearer MTU
CVE-2016-8633 firewire: net: guard against rx buffer overflows
CVE-2016-8636 IB/rxe: Fix mem_check_range integer overflow
CVE-2016-8645 tcp: take care of truncations done by sk_filter()
CVE-2016-8646 crypto: algif_hash - Only export and import on sockets with data
CVE-2016-8650 mpi: Fix NULL ptr dereference in mpi_powm()
CVE-2016-8655 packet: fix race condition in packet_set_ring
CVE-2016-8658 brcmfmac: avoid potential stack overflow in brcmf_cfg80211_start_ap()
CVE-2016-8660
CVE-2016-8666 tunnels: Don't apply GRO to multiple layers of encapsulation.
CVE-2016-9083 vfio/pci: Fix integer overflows, bitmask check
CVE-2016-9084 vfio/pci: Fix integer overflows, bitmask check
CVE-2016-9120 staging/android/ion : fix a race condition in the ion driver
CVE-2016-9178 fix minor infoleak in get_user_ex()
CVE-2016-9191 sysctl: Drop reference added by grab_header in proc_sys_readdir
CVE-2016-9313 KEYS: Sort out big_key initialisation
CVE-2016-9555 sctp: validate chunk len before actually using it
CVE-2016-9576 Don't feed anything but regular iovec's to blk_rq_map_user_iov
CVE-2016-9588 kvm: nVMX: Allow L1 to intercept software exceptions (#BP and #OF)
CVE-2016-9604 KEYS: Disallow keyrings beginning with '.' to be joined as session keyrings
CVE-2016-9644 x86/mm: Expand the exception table logic to allow new handling options
CVE-2016-9685 xfs: fix two memory leaks in xfs_attr_list.c error paths
CVE-2016-9754 ring-buffer: Prevent overflow of size in ring_buffer_resize()
CVE-2016-9755 netfilter: ipv6: nf_defrag: drop mangled skb on ream error
CVE-2016-9756 KVM: x86: drop error recovery in em_jmp_far and em_ret_far
CVE-2016-9777 KVM: x86: fix out-of-bounds accesses of rtc_eoi map
CVE-2016-9793 net: avoid signed overflows for SO_{SND|RCV}BUFFORCE
CVE-2016-9794 ALSA: pcm : Call kill_fasync() in stream lock
CVE-2016-9806 netlink: Fix dump skb leak/double free
CVE-2016-9919
CVE-2017-0403
CVE-2017-0404
CVE-2017-0426
CVE-2017-0427
CVE-2017-0507
CVE-2017-0508
CVE-2017-0510
CVE-2017-0528
CVE-2017-0537
CVE-2017-0564
CVE-2017-0605 tracing: Use strlcpy() instead of strcpy() in __trace_find_cmdline()
CVE-2017-0627 media: uvcvideo: Prevent heap overflow when accessing mapped controls
CVE-2017-0630
CVE-2017-0749
CVE-2017-0750 f2fs: do more integrity verification for superblock
CVE-2017-0786 brcmfmac: add length check in brcmf_cfg80211_escan_handler()
CVE-2017-0861 ALSA: pcm: prevent UAF in snd_pcm_info
CVE-2017-1000 udp: consistently apply ufo or fragmentation
CVE-2017-1000111 packet: fix tp_reserve race in packet_set_ring
CVE-2017-1000112 udp: consistently apply ufo or fragmentation
CVE-2017-1000251 Bluetooth: Properly check L2CAP config option output buffer length
CVE-2017-1000252 KVM: VMX: Do not BUG() on out-of-bounds guest IRQ
CVE-2017-1000253 fs/binfmt_elf.c: fix bug in loading of PIE binaries
CVE-2017-1000255 powerpc/64s: Use emergency stack for kernel TM Bad Thing program checks
CVE-2017-1000363 char: lp: fix possible integer overflow in lp_setup()
CVE-2017-1000364 mm: larger stack guard gap, between vmas
CVE-2017-1000365 fs/exec.c: account for argv/envp pointers
CVE-2017-1000370 binfmt_elf: use ELF_ET_DYN_BASE only for PIE
CVE-2017-1000371 binfmt_elf: use ELF_ET_DYN_BASE only for PIE
CVE-2017-1000379 mm: larger stack guard gap, between vmas
CVE-2017-1000380 ALSA: timer: Fix race between read and ioctl
CVE-2017-1000405 mm, thp: Do not make page table dirty unconditionally in touch_p[mu]d()
CVE-2017-1000407 KVM: VMX: remove I/O port 0x80 bypass on Intel hosts
CVE-2017-1000410 Bluetooth: Prevent stack info leak from the EFS element.
CVE-2017-10661 timerfd: Protect the might cancel mechanism proper
CVE-2017-10662 f2fs: sanity check segment count
CVE-2017-10663 f2fs: sanity check checkpoint segno and blkoff
CVE-2017-10810 drm/virtio: don't leak bo on drm_gem_object_init failure
CVE-2017-10911 xen-blkback: don't leak stack data via response ring
CVE-2017-11089 cfg80211: Define nla_policy for NL80211_ATTR_LOCAL_MESH_POWER_MODE
CVE-2017-11176 mqueue: fix a use-after-free in sys_mq_notify()
CVE-2017-11472 ACPICA: Namespace: fix operand cache leak
CVE-2017-11473 x86/acpi: Prevent out of bound access caused by broken ACPI tables
CVE-2017-11600 xfrm: policy: check policy direction value
CVE-2017-12134 xen: fix bio vec merging
CVE-2017-12146 driver core: platform: fix race condition with driver_override
CVE-2017-12153 nl80211: check for the required netlink attributes presence
CVE-2017-12154 kvm: nVMX: Don't allow L2 to access the hardware CR8
CVE-2017-12168 arm64: KVM: pmu: Fix AArch32 cycle counter access
CVE-2017-12188 KVM: nVMX: update last_nonleaf_level when initializing nested EPT
CVE-2017-12190 fix unbalanced page refcounting in bio_map_user_iov
CVE-2017-12192 KEYS: prevent KEYCTL_READ on negative key
CVE-2017-12193 assoc_array: Fix a buggy node-splitting case
CVE-2017-12762 isdn/i4l: fix buffer overflow
CVE-2017-13080 mac80211: accept key reinstall without changing anything
CVE-2017-13166 media: v4l2-ioctl.c: use check_fmt for enum/g/s/try_fmt
CVE-2017-13167 ALSA: timer: Fix race at concurrent reads
CVE-2017-13168 scsi: sg: mitigate read/write abuse
CVE-2017-13215 crypto: algif_skcipher - Load TX SG list after waiting
CVE-2017-13216 staging: android: ashmem: fix a race condition in ASHMEM_SET_SIZE ioctl
CVE-2017-13220 Bluetooth: hidp_connection_add() unsafe use of l2cap_pi()
CVE-2017-13221
CVE-2017-13222
CVE-2017-13305 KEYS: encrypted: fix buffer overread in valid_master_desc()
CVE-2017-13686
CVE-2017-13693
CVE-2017-13694
CVE-2017-13695 ACPICA: acpi: acpica: fix acpi operand cache leak in nseval.c
CVE-2017-13715
CVE-2017-14051 scsi: qla2xxx: Fix an integer overflow in sysfs code
CVE-2017-14106 tcp: initialize rcv_mss to TCP_MIN_MSS instead of 0
CVE-2017-14140 Sanitize 'move_pages()' permission checks
CVE-2017-14156 video: fbdev: aty: do not leak uninitialized padding in clk to userspace
CVE-2017-14340 xfs: XFS_IS_REALTIME_INODE() should be false if no rt device present
CVE-2017-14489 scsi: scsi_transport_iscsi: fix the issue that iscsi_if_rx doesn't parse nlmsg properly
CVE-2017-14497 packet: Don't write vnet header beyond end of buffer
CVE-2017-14954 fix infoleak in waitid(2)
CVE-2017-14991 scsi: sg: fixup infoleak when using SG_GET_REQUEST_TABLE
CVE-2017-15102 usb: misc: legousbtower: Fix NULL pointer deference
CVE-2017-15115 sctp: do not peel off an assoc from one netns to another one
CVE-2017-15116 crypto: rng - Remove old low-level rng interface
CVE-2017-15121 mm: teach truncate_inode_pages_range() to handle non page aligned ranges
CVE-2017-15126 userfaultfd: non-cooperative: fix fork use after free
CVE-2017-15127 userfaultfd: hugetlbfs: remove superfluous page unlock in VM_SHARED case
CVE-2017-15128 userfaultfd: hugetlbfs: prevent UFFDIO_COPY to fill beyond the end of i_size
CVE-2017-15129 net: Fix double free and memory corruption in get_net_ns_by_id()
CVE-2017-15265 ALSA: seq: Fix use-after-free at creating a port
CVE-2017-15274 KEYS: fix dereferencing NULL payload with nonzero length
CVE-2017-15299 KEYS: don't let add_key() update an uninstantiated key
CVE-2017-15306 KVM: PPC: Fix oops when checking KVM_CAP_PPC_HTM
CVE-2017-15537 x86/fpu: Don't let userspace set bogus xcomp_bv
CVE-2017-15649 packet: in packet_do_bind, test fanout with bind_lock held
CVE-2017-15868 Bluetooth: bnep: bnep_add_connection() should verify that it's dealing with l2cap socket
CVE-2017-15951 KEYS: Fix race between updating and finding a negative key
CVE-2017-16525 USB: serial: console: fix use-after-free after failed setup
CVE-2017-16526 uwb: properly check kthread_run return value
CVE-2017-16527 ALSA: usb-audio: Kill stray URB at exiting
CVE-2017-16528 ALSA: seq: Cancel pending autoload work at unbinding device
CVE-2017-16529 ALSA: usb-audio: Check out-of-bounds access by corrupted buffer descriptor
CVE-2017-16530 USB: uas: fix bug in handling of alternate settings
CVE-2017-16531 USB: fix out-of-bounds in usb_set_configuration
CVE-2017-16532 usb: usbtest: fix NULL pointer dereference
CVE-2017-16533 HID: usbhid: fix out-of-bounds bug
CVE-2017-16534 USB: core: harden cdc_parse_cdc_header
CVE-2017-16535 USB: core: fix out-of-bounds access bug in usb_get_bos_descriptor()
CVE-2017-16536 [media] cx231xx-cards: fix NULL-deref on missing association descriptor
CVE-2017-16537 media: imon: Fix null-ptr-deref in imon_probe
CVE-2017-16538 media: dvb-usb-v2: lmedm04: Improve logic checking of warm start
CVE-2017-16643 Input: gtco - fix potential out-of-bound access
CVE-2017-16644 media: hdpvr: Fix an error handling path in hdpvr_probe()
CVE-2017-16645 Input: ims-psu - check if CDC union descriptor is sane
CVE-2017-16646 media: dib0700: fix invalid dvb_detach argument
CVE-2017-16647 net: usb: asix: fill null-ptr-deref in asix_suspend
CVE-2017-16648 dvb_frontend: don't use-after-free the frontend struct
CVE-2017-16649 net: cdc_ether: fix divide by 0 on bad descriptors
CVE-2017-16650 net: qmi_wwan: fix divide by 0 on bad descriptors
CVE-2017-16911 usbip: prevent vhci_hcd driver from leaking a socket pointer address
CVE-2017-16912 usbip: fix stub_rx: get_pipe() to validate endpoint number
CVE-2017-16913 usbip: fix stub_rx: harden CMD_SUBMIT path to handle malicious input
CVE-2017-16914 usbip: fix stub_send_ret_submit() vulnerability to null transfer_buffer
CVE-2017-16939 ipsec: Fix aborted xfrm policy dump crash
CVE-2017-16994 mm/pagewalk.c: report holes in hugetlb ranges
CVE-2017-16995 bpf: fix incorrect sign extension in check_alu_op()
CVE-2017-16996 bpf: fix incorrect tracking of register size truncation
CVE-2017-17052 fork: fix incorrect fput of ->exe_file causing use-after-free
CVE-2017-17053 x86/mm: Fix use-after-free of ldt_struct
CVE-2017-17448 netfilter: nfnetlink_cthelper: Add missing permission checks
CVE-2017-17449 netlink: Add netns check on taps
CVE-2017-17450 netfilter: xt_osf: Add missing permission checks
CVE-2017-17558 USB: core: prevent malicious bNumInterfaces overflow
CVE-2017-17712 net: ipv4: fix for a race condition in raw_sendmsg
CVE-2017-17741 KVM: Fix stack-out-of-bounds read in write_mmio
CVE-2017-17805 crypto: salsa20 - fix blkcipher_walk API usage
CVE-2017-17806 crypto: hmac - require that the underlying hash algorithm is unkeyed
CVE-2017-17807 KEYS: add missing permission check for request_key() destination
CVE-2017-17852 bpf: fix 32-bit ALU op verification
CVE-2017-17853 bpf/verifier: fix bounds calculation on BPF_RSH
CVE-2017-17854 bpf: fix integer overflows
CVE-2017-17855 bpf: don't prune branches when a scalar is replaced with a pointer
CVE-2017-17856 bpf: force strict alignment checks for stack pointers
CVE-2017-17857 bpf: fix missing error return in check_stack_boundary()
CVE-2017-17862 bpf: fix branch pruning logic
CVE-2017-17863 bpf: fix integer overflows
CVE-2017-17864 bpf: don't prune branches when a scalar is replaced with a pointer
CVE-2017-17975 media: usbtv: prevent double free in error case
CVE-2017-18017 netfilter: xt_TCPMSS: add more sanity tests on tcph->doff
CVE-2017-18075 crypto: pcrypt - fix freeing pcrypt instances
CVE-2017-18079 Input: i8042 - fix crash at boot time
CVE-2017-18169
CVE-2017-18174 pinctrl: amd: Use devm_pinctrl_register() for pinctrl registration
CVE-2017-18193 f2fs: fix a bug caused by NULL extent tree
CVE-2017-18200 f2fs: fix potential panic during fstrim
CVE-2017-18202 mm, oom_reaper: gather each vma to prevent leaking TLB entry
CVE-2017-18203 dm: fix race between dm_get_from_kobject() and __dm_destroy()
CVE-2017-18204 ocfs2: should wait dio before inode lock in ocfs2_setattr()
CVE-2017-18208 mm/madvise.c: fix madvise() infinite loop under special circumstances
CVE-2017-18216 ocfs2: subsystem.su_mutex is required while accessing the item->ci_parent
CVE-2017-18218 net: hns: Fix a skb used after free bug
CVE-2017-18221 mlock: fix mlock count can not decrease in race condition
CVE-2017-18222 net: hns: fix ethtool_get_strings overflow in hns driver
CVE-2017-18224 ocfs2: ip_alloc_sem should be taken in ocfs2_get_block()
CVE-2017-18232 scsi: libsas: direct call probe and destruct
CVE-2017-18241 f2fs: fix a panic caused by NULL flush_cmd_control
CVE-2017-18249 f2fs: fix race condition in between free nid allocator/initializer
CVE-2017-18255 perf/core: Fix the perf_cpu_time_max_percent check
CVE-2017-18257 f2fs: fix a dead loop in f2fs_fiemap()
CVE-2017-18261 clocksource/drivers/arm_arch_timer: Avoid infinite recursion when ftrace is enabled
CVE-2017-18270 KEYS: prevent creating a different user's keyrings
CVE-2017-18344 posix-timer: Properly check sigevent->sigev_notify
CVE-2017-18360 USB: serial: io_ti: fix div-by-zero in set_termios
CVE-2017-18379 nvmet-fc: ensure target queue id within range.
CVE-2017-18509 ipv6: check sk sk_type and protocol early in ip_mroute_set/getsockopt
CVE-2017-18549 scsi: aacraid: Don't copy uninitialized stack memory to userspace
CVE-2017-18550 scsi: aacraid: Don't copy uninitialized stack memory to userspace
CVE-2017-18551 i2c: core-smbus: prevent stack corruption on read I2C_BLOCK_DATA
CVE-2017-18552 RDS: validate the requested traces user input against max supported
CVE-2017-18595 tracing: Fix possible double free on failure of allocating trace buffer
CVE-2017-2583 KVM: x86: fix emulation of "MOV SS, null selector"
CVE-2017-2584 KVM: x86: Introduce segmented_write_std
CVE-2017-2596 kvm: fix page struct leak in handle_vmon
CVE-2017-2618 selinux: fix off-by-one in setprocattr
CVE-2017-2634
CVE-2017-2636 tty: n_hdlc: get rid of racy n_hdlc.tbuf
CVE-2017-2647 KEYS: Remove key_type::match in favour of overriding default by match_preparse
CVE-2017-2671 ping: implement proper locking
CVE-2017-5123 waitid(): Add missing access_ok() checks
CVE-2017-5546 mm/slab.c: fix SLAB freelist randomization duplicate entries
CVE-2017-5547 HID: corsair: fix DMA buffers on stack
CVE-2017-5548 ieee802154: atusb: do not use the stack for buffers to make them DMA able
CVE-2017-5549 USB: serial: kl5kusb105: fix line-state error handling
CVE-2017-5550 fix a fencepost error in pipe_advance()
CVE-2017-5551 tmpfs: clear S_ISGID when setting posix ACLs
CVE-2017-5576 drm/vc4: Fix an integer overflow in temporary allocation layout.
CVE-2017-5577 drm/vc4: Return -EINVAL on the overflow checks failing.
CVE-2017-5669 ipc/shm: Fix shmat mmap nil-page protection
CVE-2017-5715 x86/cpufeatures: Add X86_BUG_SPECTRE_V[12]
CVE-2017-5753 x86/cpufeatures: Add X86_BUG_SPECTRE_V[12]
CVE-2017-5754 x86/cpufeatures: Add Intel feature bits for Speculation Control
CVE-2017-5897 ip6_gre: fix ip6gre_err() invalid reads
CVE-2017-5967 time: Remove CONFIG_TIMER_STATS
CVE-2017-5970 ipv4: keep skb->dst around in presence of IP options
CVE-2017-5972 tcp: do not lock listener to process SYN packets
CVE-2017-5986 sctp: avoid BUG_ON on sctp_wait_for_sndbuf
CVE-2017-6001 perf/core: Fix concurrent sys_perf_event_open() vs. 'move_group' race
CVE-2017-6074 dccp: fix freeing skb too early for IPV6_RECVPKTINFO
CVE-2017-6214 tcp: avoid infinite loop in tcp_splice_read()
CVE-2017-6345 net/llc: avoid BUG_ON() in skb_orphan()
CVE-2017-6346 packet: fix races in fanout_add()
CVE-2017-6347 ip: fix IP_CHECKSUM handling
CVE-2017-6348 irda: Fix lockdep annotations in hashbin_delete().
CVE-2017-6353 sctp: deny peeloff operation on asocs with threads sleeping on it
CVE-2017-6874 ucount: Remove the atomicity from ucount->count
CVE-2017-6951 KEYS: Remove key_type::match in favour of overriding default by match_preparse
CVE-2017-7184 xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL replay_window
CVE-2017-7187 scsi: sg: check length passed to SG_NEXT_CMD_LEN
CVE-2017-7261 drm/vmwgfx: NULL pointer dereference in vmw_surface_define_ioctl()
CVE-2017-7273 HID: hid-cypress: validate length of report
CVE-2017-7277 tcp: mark skbs with SCM_TIMESTAMPING_OPT_STATS
CVE-2017-7294 drm/vmwgfx: fix integer overflow in vmw_surface_define_ioctl()
CVE-2017-7308 net/packet: fix overflow in check for priv area size
CVE-2017-7346 drm/vmwgfx: limit the number of mip levels in vmw_gb_surface_define_ioctl()
CVE-2017-7369
CVE-2017-7374 fscrypt: remove broken support for detecting keyring key revocation
CVE-2017-7472 KEYS: fix keyctl_set_reqkey_keyring() to not leak thread keyrings
CVE-2017-7477 macsec: avoid heap overflow in skb_to_sgvec
CVE-2017-7482 rxrpc: Fix several cases where a padded len isn't checked in ticket decode
CVE-2017-7487 ipx: call ipxitf_put() in ioctl error path
CVE-2017-7495 ext4: fix data exposure after a crash
CVE-2017-7518 KVM: x86: fix singlestepping over syscall
CVE-2017-7533 dentry name snapshots
CVE-2017-7541 brcmfmac: fix possible buffer overflow in brcmf_cfg80211_mgmt_tx()
CVE-2017-7542 ipv6: avoid overflow of offset in ip6_find_1stfragopt
CVE-2017-7558 sctp: Avoid out-of-bounds reads from address storage
CVE-2017-7616 mm/mempolicy.c: fix error handling in set_mempolicy and mbind.
CVE-2017-7618 crypto: ahash - Fix EINPROGRESS notification callback
CVE-2017-7645 nfsd: check for oversized NFSv2/v3 arguments
CVE-2017-7889 mm: Tighten x86 /dev/mem with zeroing reads
CVE-2017-7895 nfsd: stricter decoding of write-like NFSv2/v3 ops
CVE-2017-7979
CVE-2017-8061 [media] dvb-usb-firmware: don't do DMA on stack
CVE-2017-8062 [media] dw2102: don't do DMA on stack
CVE-2017-8063 [media] cxusb: Use a dma capable buffer also for reading
CVE-2017-8064 [media] dvb-usb-v2: avoid use-after-free
CVE-2017-8065 crypto: ccm - move cbcmac input off the stack
CVE-2017-8066 can: gs_usb: Don't use stack memory for USB transfers
CVE-2017-8067 virtio-console: avoid DMA from stack
CVE-2017-8068 pegasus: Use heap buffers for all register access
CVE-2017-8069 rtl8150: Use heap buffers for all register access
CVE-2017-8070 catc: Use heap buffer for memory size test
CVE-2017-8071 HID: cp2112: fix sleep-while-atomic
CVE-2017-8072 HID: cp2112: fix gpio-callback error handling
CVE-2017-8106 KVM: nVMX: Don't advertise single context invalidation for invept
CVE-2017-8240 pinctrl: qcom: Don't iterate past end of function array
CVE-2017-8242
CVE-2017-8244
CVE-2017-8245
CVE-2017-8246
CVE-2017-8797 nfsd: fix undefined behavior in nfsd4_layout_verify
CVE-2017-8824 dccp: CVE-2017-8824: use-after-free in DCCP code
CVE-2017-8831 [media] saa7164: fix double fetch PCIe access condition
CVE-2017-8890 dccp/tcp: do not inherit mc_list from parent
CVE-2017-8924 USB: serial: io_ti: fix information leak in completion handler
CVE-2017-8925 USB: serial: omninet: fix reference leaks at open
CVE-2017-9059 NFSv4: Fix callback server shutdown
CVE-2017-9074 ipv6: Prevent overrun when parsing v6 header options
CVE-2017-9075 sctp: do not inherit ipv6_{mc|ac|fl}_list from parent
CVE-2017-9076 ipv6/dccp: do not inherit ipv6_mc_list from parent
CVE-2017-9077 ipv6/dccp: do not inherit ipv6_mc_list from parent
CVE-2017-9150 bpf: don't let ldimm64 leak map addresses on unprivileged
CVE-2017-9211 crypto: skcipher - Add missing API setkey checks
CVE-2017-9242 ipv6: fix out of bound writes in __ip6_append_data()
CVE-2017-9605 drm/vmwgfx: Make sure backup_handle is always valid
CVE-2017-9725 mm: cma: fix incorrect type conversion for size during dma allocation
CVE-2017-9984 ALSA: msnd: Optimize / harden DSP and MIDI loops
CVE-2017-9985 ALSA: msnd: Optimize / harden DSP and MIDI loops
CVE-2017-9986 sound: Retire OSS
CVE-2018-1000004 ALSA: seq: Make ioctls race-free
CVE-2018-1000026 bnx2x: disable GSO where gso_size is too big for hardware
CVE-2018-1000028 nfsd: auth: Fix gid sorting when rootsquash enabled
CVE-2018-1000199 perf/hwbp: Simplify the perf-hwbp code, fix documentation
CVE-2018-1000200 mm, oom: fix concurrent munlock and oom reaper unmap, v3
CVE-2018-1000204 scsi: sg: allocate with __GFP_ZERO in sg_build_indirect()
CVE-2018-10021 scsi: libsas: defer ata device eh commands to libata
CVE-2018-10074
CVE-2018-10087 kernel/exit.c: avoid undefined behaviour when calling wait4()
CVE-2018-10124 kernel/signal.c: avoid undefined behaviour in kill_something_info
CVE-2018-10322 xfs: enhance dinode verifier
CVE-2018-10323 xfs: set format back to extents if xfs_bmap_extents_to_btree
CVE-2018-1065 netfilter: add back stackpointer size checks
CVE-2018-1066 CIFS: Enable encryption during session setup phase
CVE-2018-10675 mm/mempolicy: fix use after free when calling get_mempolicy
CVE-2018-1068 netfilter: ebtables: CONFIG_COMPAT: don't trust userland offsets
CVE-2018-10840 ext4: correctly handle a zero-length xattr with a non-zero e_value_offs
CVE-2018-10853 kvm: x86: use correct privilege level for sgdt/sidt/fxsave/fxrstor access
CVE-2018-1087 kvm/x86: fix icebp instruction handling
CVE-2018-10872
CVE-2018-10876 ext4: only look at the bg_flags field if it is valid
CVE-2018-10877 ext4: verify the depth of extent tree in ext4_find_extent()
CVE-2018-10878 ext4: always check block group bounds in ext4_init_block_bitmap()
CVE-2018-10879 ext4: make sure bitmaps and the inode table don't overlap with bg descriptors
CVE-2018-10880 ext4: never move the system.data xattr out of the inode body
CVE-2018-10881 ext4: clear i_data in ext4_inode_info when removing inline data
CVE-2018-10882 ext4: add more inode number paranoia checks
CVE-2018-10883 jbd2: don't mark block as modified if the handle is out of credits
CVE-2018-10901
CVE-2018-10902 ALSA: rawmidi: Change resized buffers atomically
CVE-2018-1091 powerpc/tm: Flush TM only if CPU has TM feature
CVE-2018-1092 ext4: fail ext4_iget for root directory if unallocated
CVE-2018-1093 ext4: add validity checks for bitmap block numbers
CVE-2018-10938 Cipso: cipso_v4_optptr enter infinite loop
CVE-2018-1094 ext4: always initialize the crc32c checksum driver
CVE-2018-10940 cdrom: information leak in cdrom_ioctl_media_changed()
CVE-2018-1095 ext4: limit xattr size to INT_MAX
CVE-2018-1108 random: fix crng_ready() test
CVE-2018-1118 vhost: fix info leak due to uninitialized memory
CVE-2018-1120 proc: do not access cmdline nor environ from file-backed areas
CVE-2018-1121
CVE-2018-11232 coresight: fix kernel panic caused by invalid CPU
CVE-2018-1128 libceph: add authorizer challenge
CVE-2018-1129 libceph: implement CEPHX_V2 calculation mode
CVE-2018-1130 dccp: check sk for closed state in dccp_sendmsg()
CVE-2018-11412 ext4: do not allow external inodes for inline data
CVE-2018-11506 sr: pass down correctly sized SCSI sense buffer
CVE-2018-11508 compat: fix 4-byte infoleak via uninitialized struct field
CVE-2018-11987
CVE-2018-12126 s390/speculation: Support 'mitigations=' cmdline option
CVE-2018-12127 s390/speculation: Support 'mitigations=' cmdline option
CVE-2018-12130 s390/speculation: Support 'mitigations=' cmdline option
CVE-2018-12207 kvm: x86, powerpc: do not allow clearing largepages debugfs entry
CVE-2018-12232 socket: close race condition between sock_close() and sockfs_setattr()
CVE-2018-12233 jfs: Fix inconsistency between memory allocation and ea_buf->max_size
CVE-2018-12633 virt: vbox: Only copy_from_user the request-header once
CVE-2018-12714 tracing: Check for no filter when processing event filters
CVE-2018-12896 posix-timers: Sanitize overrun handling
CVE-2018-12904 kvm: nVMX: Enforce cpl=0 for VMX instructions
CVE-2018-12928
CVE-2018-12929
CVE-2018-12930
CVE-2018-12931
CVE-2018-13053 alarmtimer: Prevent overflow for relative nanosleep
CVE-2018-13093 xfs: validate cached inodes are free when allocated
CVE-2018-13094 xfs: don't call xfs_da_shrink_inode with NULL bp
CVE-2018-13095 xfs: More robust inode extent count validation
CVE-2018-13096 f2fs: fix to do sanity check with node footer and iblocks
CVE-2018-13097 f2fs: fix to do sanity check with user_block_count
CVE-2018-13098 f2fs: fix to do sanity check with extra_attr feature
CVE-2018-13099 f2fs: fix to do sanity check with reserved blkaddr of inline inode
CVE-2018-13100 f2fs: fix to do sanity check with secs_per_zone
CVE-2018-13405 Fix up non-directory creation in SGID directories
CVE-2018-13406 video: uvesafb: Fix integer overflow in allocation
CVE-2018-14609 btrfs: relocation: Only remove reloc rb_trees if reloc control has been initialized
CVE-2018-14610 btrfs: Check that each block group has corresponding chunk at mount time
CVE-2018-14611 btrfs: validate type when reading a chunk
CVE-2018-14612 btrfs: tree-checker: Detect invalid and empty essential trees
CVE-2018-14613 btrfs: tree-checker: Verify block_group_item
CVE-2018-14614 f2fs: fix to do sanity check with cp_pack_start_sum
CVE-2018-14615 f2fs: fix to do sanity check with i_extra_isize
CVE-2018-14616 f2fs: fix to do sanity check with block address in main area v2
CVE-2018-14617 hfsplus: fix NULL dereference in hfsplus_lookup()
CVE-2018-14619 crypto: algif_aead - fix reference counting of null skcipher
CVE-2018-14625 vhost/vsock: fix use-after-free in network stack callers
CVE-2018-14633 scsi: target: iscsi: Use hex2bin instead of a re-implementation
CVE-2018-14634 exec: Limit arg stack to at most 75% of _STK_LIM
CVE-2018-14641
CVE-2018-14646 rtnetlink: give a user socket to get_target_net()
CVE-2018-14656 x86/dumpstack: Don't dump kernel memory based on usermode RIP
CVE-2018-14678 x86/entry/64: Remove %ebx handling from error_entry/exit
CVE-2018-14734 infiniband: fix a possible use-after-free bug
CVE-2018-15471 xen-netback: fix input validation in xenvif_set_hash_mapping()
CVE-2018-15572 x86/speculation: Protect against userspace-userspace spectreRSB
CVE-2018-15594 x86/paravirt: Fix spectre-v2 mitigations for paravirt guests
CVE-2018-16276 USB: yurex: fix out-of-bounds uaccess in read handler
CVE-2018-16597 ovl: modify ovl_permission() to do checks on two inodes
CVE-2018-16658 cdrom: Fix info leak/OOB read in cdrom_ioctl_drive_status
CVE-2018-16862 mm: cleancache: fix corruption on missed inode invalidation
CVE-2018-16871 nfsd: COPY and CLONE operations require the saved filehandle to be set
CVE-2018-16880 vhost: fix OOB in get_rx_bufs()
CVE-2018-16882 KVM: Fix UAF in nested posted interrupt processing
CVE-2018-16884 sunrpc: use-after-free in svc_process_common()
CVE-2018-16885
CVE-2018-17182 mm: get rid of vmacache_flush_all() entirely
CVE-2018-17972 proc: restrict kernel stack dumps to root
CVE-2018-17977
CVE-2018-18021 arm64: KVM: Tighten guest core register access from userspace
CVE-2018-18281 mremap: properly flush TLB before releasing the page
CVE-2018-18386 n_tty: fix EXTPROC vs ICANON interaction with TIOCINQ (aka FIONREAD)
CVE-2018-18397 userfaultfd: use ENOENT instead of EFAULT if the atomic copy user fails
CVE-2018-18445 bpf: 32-bit RSH verification must truncate input before the ALU op
CVE-2018-18559 net/packet: fix a race in packet_bind() and packet_notifier()
CVE-2018-18653
CVE-2018-18690 xfs: don't fail when converting shortform attr to long form during ATTR_REPLACE
CVE-2018-18710 cdrom: fix improper type cast, which can leat to information leak.
CVE-2018-18955 userns: also map extents in the reverse map to kernel IDs
CVE-2018-19406 KVM: LAPIC: Fix pv ipis use-before-initialization
CVE-2018-19407 KVM: X86: Fix scan ioapic use-before-initialization
CVE-2018-19824 ALSA: usb-audio: Fix UAF decrement if card has no live interfaces in card.c
CVE-2018-19854 crypto: user - fix leaking uninitialized memory to userspace
CVE-2018-19985 USB: hso: Fix OOB memory access in hso_probe/hso_get_config_data
CVE-2018-20169 USB: check usb_get_extra_descriptor for proper size
CVE-2018-20449 printk: hash addresses printed with %p
CVE-2018-20509 binder: refactor binder ref inc/dec for thread safety
CVE-2018-20510 binder: replace "%p" with "%pK"
CVE-2018-20511 net/appletalk: fix minor pointer leak to userspace in SIOCFINDIPDDPRT
CVE-2018-20669 make 'user_access_begin()' do 'access_ok()'
CVE-2018-20784 sched/fair: Fix infinite loop in update_blocked_averages() by reverting a9e7f6544b9c
CVE-2018-20836 scsi: libsas: fix a race condition when smp task timeout
CVE-2018-20854 phy: ocelot-serdes: fix out-of-bounds read
CVE-2018-20855 IB/mlx5: Fix leaking stack memory to userspace
CVE-2018-20856 block: blk_init_allocated_queue() set q->fq as NULL in the fail case
CVE-2018-20961 USB: gadget: f_midi: fixing a possible double-free in f_midi
CVE-2018-20976 xfs: clear sb->s_fs_info on mount failure
CVE-2018-21008 rsi: add fix for crash during assertions
CVE-2018-25015 sctp: return error if the asoc has been peeled off in sctp_wait_for_sndbuf
CVE-2018-25020 bpf: fix truncated jump targets on heavy expansions
CVE-2018-3574
CVE-2018-3620 x86/microcode: Allow late microcode loading with SMT disabled
CVE-2018-3639 x86/nospec: Simplify alternative_msr_write()
CVE-2018-3646 x86/microcode: Allow late microcode loading with SMT disabled
CVE-2018-3665 x86, fpu: decouple non-lazy/eager fpu restore from xsave
CVE-2018-3693 ext4: fix spectre gadget in ext4_mb_regular_allocator()
CVE-2018-5332 RDS: Heap OOB write in rds_message_alloc_sgs()
CVE-2018-5333 RDS: null pointer dereference in rds_atomic_free_op
CVE-2018-5344 loop: fix concurrent lo_open/lo_release
CVE-2018-5390 tcp: free batches of packets in tcp_prune_ofo_queue()
CVE-2018-5391 ip: discard IPv4 datagrams with overlapping segments.
CVE-2018-5703 tls: Use correct sk->sk_prot for IPV6
CVE-2018-5750 ACPI: sbshc: remove raw pointer from printk() message
CVE-2018-5803 sctp: verify size of a new chunk in _sctp_make_chunk()
CVE-2018-5814 usbip: usbip_host: fix NULL-ptr deref and use-after-free errors
CVE-2018-5848 wil6210: missing length check in wmi_set_ie
CVE-2018-5856
CVE-2018-5873 nsfs: mark dentry with DCACHE_RCUACCESS
CVE-2018-5953 printk: hash addresses printed with %p
CVE-2018-5995 printk: hash addresses printed with %p
CVE-2018-6412 fbdev: Fixing arbitrary kernel leak in case FBIOGETCMAP_SPARC in sbusfb_ioctl_helper().
CVE-2018-6554 staging: irda: remove the irda network stack and drivers
CVE-2018-6555 staging: irda: remove the irda network stack and drivers
CVE-2018-6559
CVE-2018-6927 futex: Prevent overflow by strengthen input validation
CVE-2018-7191 tun: call dev_get_valid_name() before register_netdevice()
CVE-2018-7273 printk: hash addresses printed with %p
CVE-2018-7480 blkcg: fix double free of new_blkg in blkcg_init_queue
CVE-2018-7492 rds: Fix NULL pointer dereference in __rds_rdma_map
CVE-2018-7566 ALSA: seq: Fix racy pool initializations
CVE-2018-7740 hugetlbfs: check for pgoff value overflow
CVE-2018-7754 printk: hash addresses printed with %p
CVE-2018-7755 floppy: Do not copy a kernel pointer to user memory in FDGETPRM ioctl
CVE-2018-7757 scsi: libsas: fix memory leak in sas_smp_get_phy_events()
CVE-2018-7995 x86/MCE: Serialize sysfs changes
CVE-2018-8043 net: phy: mdio-bcm-unimac: fix potential NULL dereference in unimac_mdio_probe()
CVE-2018-8087 mac80211_hwsim: fix possible memory leak in hwsim_new_radio_nl()
CVE-2018-8781 drm: udl: Properly check framebuffer mmap offsets
CVE-2018-8822 staging: ncpfs: memory corruption in ncp_read_kernel()
CVE-2018-8897 x86/entry/64: Don't use IST entry for #BP stack
CVE-2018-9363 Bluetooth: hidp: buffer overflow in hidp_process_report
CVE-2018-9385 ARM: amba: Don't read past the end of sysfs "driver_override" buffer
CVE-2018-9415 ARM: amba: Fix race condition with driver_override
CVE-2018-9422 futex: Remove requirement for lock_page() in get_futex_key()
CVE-2018-9465 binder: fix proc->files use-after-free
CVE-2018-9516 HID: debug: check length before copy_to_user()
CVE-2018-9517 l2tp: pass tunnel pointer to ->session_create()
CVE-2018-9518 NFC: llcp: Limit size of SDP URI
CVE-2018-9568 net: Set sk_prot_creator when cloning sockets to the right proto
CVE-2019-0136 mac80211: drop robust management frames from unknown TA
CVE-2019-0145 i40e: add num_vectors checker in iwarp handler
CVE-2019-0146 i40e: add num_vectors checker in iwarp handler
CVE-2019-0147 i40e: add num_vectors checker in iwarp handler
CVE-2019-0148 i40e: Wrong truncation from u16 to u8
CVE-2019-0149 i40e: Add bounds check for ch[] array
CVE-2019-0154 drm/i915: Lower RM timeout to avoid DSI hard hangs
CVE-2019-0155 drm/i915: Rename gen7 cmdparser tables
CVE-2019-10124 mm: hwpoison: fix thp split handing in soft_offline_in_use_page()
CVE-2019-10125 aio: simplify - and fix - fget/fput for io_submit()
CVE-2019-10126 mwifiex: Fix heap overflow in mwifiex_uap_parse_tail_ies()
CVE-2019-10140
CVE-2019-10142 drivers/virt/fsl_hypervisor.c: prevent integer overflow in ioctl
CVE-2019-10207 Bluetooth: hci_uart: check for missing tty operations
CVE-2019-10220 Convert filldir[64]() from __put_user() to unsafe_put_user()
CVE-2019-10638 inet: switch IP ID generator to siphash
CVE-2019-10639 netns: provide pure entropy for net_hash_mix()
CVE-2019-11085 drm/i915/gvt: Fix mmap range check
CVE-2019-11091 s390/speculation: Support 'mitigations=' cmdline option
CVE-2019-11135 x86/msr: Add the IA32_TSX_CTRL MSR
CVE-2019-11190 binfmt_elf: switch to new creds when switching to new mm
CVE-2019-11191 x86: Deprecate a.out support
CVE-2019-1125 x86/speculation: Prepare entry code for Spectre v1 swapgs mitigations
CVE-2019-11477 tcp: limit payload size of sacked skbs
CVE-2019-11478 tcp: tcp_fragment() should apply sane memory limits
CVE-2019-11479 tcp: add tcp_min_snd_mss sysctl
CVE-2019-11486 tty: mark Siemens R3964 line discipline as BROKEN
CVE-2019-11487 fs: prevent page refcount overflow in pipe_buf_get
CVE-2019-11599 coredump: fix race condition between mmget_not_zero()/get_task_mm() and core dumping
CVE-2019-11683 udp: fix GRO packet of death
CVE-2019-11810 scsi: megaraid_sas: return error when create DMA pool failed
CVE-2019-11811 ipmi_si: fix use-after-free of resource->name
CVE-2019-11815 net: rds: force to destroy connection if t_sock is NULL in rds_tcp_kill_sock().
CVE-2019-11833 ext4: zero out the unused memory region in the extent tree block
CVE-2019-11884 Bluetooth: hidp: fix buffer overflow
CVE-2019-12378 ipv6_sockglue: Fix a missing-check bug in ip6_ra_control()
CVE-2019-12379 consolemap: Fix a memory leaking bug in drivers/tty/vt/consolemap.c
CVE-2019-12380 efi/x86/Add missing error handling to old_memmap 1:1 mapping code
CVE-2019-12381 ip_sockglue: Fix missing-check bug in ip_ra_control()
CVE-2019-12382 drm/edid: Fix a missing-check bug in drm_load_edid_firmware()
CVE-2019-12454 wcd9335: fix a incorrect use of kstrndup()
CVE-2019-12455 clk-sunxi: fix a missing-check bug in sunxi_divs_clk_setup()
CVE-2019-12456
CVE-2019-12614 powerpc/pseries/dlpar: Fix a missing check in dlpar_parse_cc_property()
CVE-2019-12615 mdesc: fix a missing-check bug in get_vdev_port_node_info()
CVE-2019-12817 powerpc/mm/64s/hash: Reallocate context ids on fork
CVE-2019-12818 net: nfc: Fix NULL dereference on nfc_llcp_build_tlv fails
CVE-2019-12819 mdio_bus: Fix use-after-free on device_register fails
CVE-2019-12881 drm/i915/userptr: reject zero user_size
CVE-2019-12984 nfc: Ensure presence of required attributes in the deactivate_target handler
CVE-2019-13233 x86/insn-eval: Fix use-after-free access to LDT entry
CVE-2019-13272 ptrace: Fix ->ptracer_cred handling for PTRACE_TRACEME
CVE-2019-13631 Input: gtco - bounds check collection indent level
CVE-2019-13648 powerpc/tm: Fix oops on sigreturn on systems without TM
CVE-2019-14283 floppy: fix out-of-bounds read in copy_buffer
CVE-2019-14284 floppy: fix div-by-zero in setup_format_params
CVE-2019-14615 drm/i915/gen9: Clear residual context state on context switch
CVE-2019-14763 usb: dwc3: gadget: never call ->complete() from ->ep_queue()
CVE-2019-14814 mwifiex: Fix three heap overflow at parsing element in cfg80211_ap_settings
CVE-2019-14815 mwifiex: Fix three heap overflow at parsing element in cfg80211_ap_settings
CVE-2019-14816 mwifiex: Fix three heap overflow at parsing element in cfg80211_ap_settings
CVE-2019-14821 KVM: coalesced_mmio: add bounds checking
CVE-2019-14835 vhost: make sure log_num < in_num
CVE-2019-14895 mwifiex: fix possible heap overflow in mwifiex_process_country_ie()
CVE-2019-14896 libertas: Fix two buffer overflows at parsing bss descriptor
CVE-2019-14897 libertas: Fix two buffer overflows at parsing bss descriptor
CVE-2019-14898
CVE-2019-14901 mwifiex: Fix heap overflow in mmwifiex_process_tdls_action_frame()
CVE-2019-15030 powerpc/tm: Fix FP/VMX unavailable exceptions inside a transaction
CVE-2019-15031 powerpc/tm: Fix restoring FP/VMX facility incorrectly on interrupts
CVE-2019-15090 scsi: qedi: remove memset/memcpy to nfunc and use func instead
CVE-2019-15098 ath6kl: fix a NULL-ptr-deref bug in ath6kl_usb_alloc_urb_from_pipe()
CVE-2019-15099 ath6kl: fix a NULL-ptr-deref bug in ath6kl_usb_alloc_urb_from_pipe()
CVE-2019-15117 ALSA: usb-audio: Fix an OOB bug in parse_audio_mixer_unit
CVE-2019-15118 ALSA: usb-audio: Fix a stack buffer overflow bug in check_input_term
CVE-2019-15211 media: radio-raremono: change devm_k*alloc to k*alloc
CVE-2019-15212 USB: rio500: refuse more than one device at a time
CVE-2019-15213 media: dvb: usb: fix use after free in dvb_usb_device_exit
CVE-2019-15214 ALSA: core: Fix card races between register and disconnect
CVE-2019-15215 media: cpia2_usb: first wake up, then free in disconnect
CVE-2019-15216 USB: yurex: Fix protection fault after device removal
CVE-2019-15217 media: usb:zr364xx:Fix KASAN:null-ptr-deref Read in zr364xx_vidioc_querycap
CVE-2019-15218 media: usb: siano: Fix general protection fault in smsusb
CVE-2019-15219 USB: sisusbvga: fix oops in error path of sisusb_probe
CVE-2019-15220 p54usb: Fix race between disconnect and firmware loading
CVE-2019-15221 ALSA: line6: Fix write on zero-sized buffer
CVE-2019-15222 ALSA: usb-audio: Fix gpf in snd_usb_pipe_sanity_check
CVE-2019-15223 ALSA: line6: Assure canceling delayed work at disconnection
CVE-2019-15239
CVE-2019-15290
CVE-2019-15291 media: b2c2-flexcop-usb: add sanity checking
CVE-2019-15292 appletalk: Fix use-after-free in atalk_proc_exit
CVE-2019-15504 rsi: fix a double free bug in rsi_91x_deinit()
CVE-2019-15505 media: technisat-usb2: break out of loop at end of buffer
CVE-2019-15538 xfs: fix missing ILOCK unlock when xfs_setattr_nonsize fails due to EDQUOT
CVE-2019-15666 xfrm: policy: Fix out-of-bound array accesses in __xfrm_policy_unlink
CVE-2019-15791
CVE-2019-15792
CVE-2019-15793
CVE-2019-15794 ovl: fix reference counting in ovl_mmap error path
CVE-2019-15807 scsi: libsas: delete sas port if expander discover failed
CVE-2019-15902
CVE-2019-15916 net-sysfs: Fix mem leak in netdev_register_kobject
CVE-2019-15917 Bluetooth: hci_ldisc: Postpone HCI_UART_PROTO_READY bit set in hci_uart_set_proto()
CVE-2019-15918 cifs: Fix lease buffer length error
CVE-2019-15919 cifs: Fix use-after-free in SMB2_write
CVE-2019-15920 cifs: Fix use-after-free in SMB2_read
CVE-2019-15921 genetlink: Fix a memory leak on error path
CVE-2019-15922 paride/pf: Fix potential NULL pointer dereference
CVE-2019-15923 paride/pcd: Fix potential NULL pointer dereference and mem leak
CVE-2019-15924 fm10k: Fix a potential NULL pointer dereference
CVE-2019-15925 net: hns3: add some error checking in hclge_tm module
CVE-2019-15926 ath6kl: add some bounds checking
CVE-2019-15927 ALSA: usb-audio: Avoid access before bLength check in build_audio_procunit()
CVE-2019-16089
CVE-2019-16229 drm/amdkfd: fix a potential NULL pointer dereference (v2)
CVE-2019-16230 drm/amdkfd: fix a potential NULL pointer dereference (v2)
CVE-2019-16231 fjes: Handle workqueue allocation failure
CVE-2019-16232 libertas: fix a potential NULL pointer dereference
CVE-2019-16233 scsi: qla2xxx: fix a potential NULL pointer dereference
CVE-2019-16234 iwlwifi: pcie: fix rb_allocator workqueue allocation
CVE-2019-16413 9p: use inode->i_lock to protect i_size_write() under 32-bit
CVE-2019-16714 net/rds: Fix info leak in rds6_inc_info_copy()
CVE-2019-16746 nl80211: validate beacon head
CVE-2019-16921 RDMA/hns: Fix init resp when alloc ucontext
CVE-2019-16994 net: sit: fix memory leak in sit_init_net()
CVE-2019-16995 net: hsr: fix memory leak in hsr_dev_finalize()
CVE-2019-17052 ax25: enforce CAP_NET_RAW for raw sockets
CVE-2019-17053 ieee802154: enforce CAP_NET_RAW for raw sockets
CVE-2019-17054 appletalk: enforce CAP_NET_RAW for raw sockets
CVE-2019-17055 mISDN: enforce CAP_NET_RAW for raw sockets
CVE-2019-17056 nfc: enforce CAP_NET_RAW for raw sockets
CVE-2019-17075 RDMA/cxgb4: Do not dma memory off of the stack
CVE-2019-17133 cfg80211: wext: avoid copying malformed SSIDs
CVE-2019-17351 xen: let alloc_xenballooned_pages() fail if not enough memory free
CVE-2019-17666 rtlwifi: Fix potential overflow on P2P code
CVE-2019-18198 ipv6: do not free rt if FIB_LOOKUP_NOREF is set on suppress rule
CVE-2019-18282 net/flow_dissector: switch to siphash
CVE-2019-18660 powerpc/book3s64: Fix link stack flush on context switch
CVE-2019-18675 mmap: introduce sane default mmap limits
CVE-2019-18680
CVE-2019-18683 media: vivid: Fix wrong locking that causes race conditions on streaming stop
CVE-2019-18786 media: rcar_drif: fix a memory disclosure
CVE-2019-18805 ipv4: set the tcp_min_rtt_wlen range from 0 to one day
CVE-2019-18806 net: qlogic: Fix memory leak in ql_alloc_large_buffers
CVE-2019-18807 net: dsa: sja1105: Prevent leaking memory
CVE-2019-18808 crypto: ccp - Release all allocated memory if sha type is invalid
CVE-2019-18809 media: usb: fix memory leak in af9005_identify_state
CVE-2019-18810 drm/komeda: prevent memory leak in komeda_wb_connector_add
CVE-2019-18811 ASoC: SOF: ipc: Fix memory leak in sof_set_get_large_ctrl_data
CVE-2019-18812 ASoC: SOF: Fix memory leak in sof_dfsentry_write
CVE-2019-18813 usb: dwc3: pci: prevent memory leak in dwc3_pci_probe
CVE-2019-18814 apparmor: Fix use-after-free in aa_audit_rule_init
CVE-2019-18885 btrfs: merge btrfs_find_device and find_device
CVE-2019-19036 btrfs: Detect unbalanced tree with empty leaf before crashing btree operations
CVE-2019-19037 ext4: fix ext4_empty_dir() for directories with holes
CVE-2019-19039 btrfs: Don't submit any btree write bio if the fs has errors
CVE-2019-19043 i40e: prevent memory leak in i40e_setup_macvlans
CVE-2019-19044 drm/v3d: Fix memory leak in v3d_submit_cl_ioctl
CVE-2019-19045 net/mlx5: prevent memory leak in mlx5_fpga_conn_create_cq
CVE-2019-19046 ipmi: Fix memory leak in __ipmi_bmc_register
CVE-2019-19047 net/mlx5: fix memory leak in mlx5_fw_fatal_reporter_dump
CVE-2019-19048 virt: vbox: fix memory leak in hgcm_call_preprocess_linaddr
CVE-2019-19049 of: unittest: fix memory leak in unittest_data_add
CVE-2019-19050 crypto: user - fix memory leak in crypto_reportstat
CVE-2019-19051 wimax: i2400: Fix memory leak in i2400m_op_rfkill_sw_toggle
CVE-2019-19052 can: gs_usb: gs_can_open(): prevent memory leak
CVE-2019-19053 rpmsg: char: release allocated memory
CVE-2019-19054 media: rc: prevent memory leak in cx23888_ir_probe
CVE-2019-19055 nl80211: fix memory leak in nl80211_get_ftm_responder_stats
CVE-2019-19056 mwifiex: pcie: Fix memory leak in mwifiex_pcie_alloc_cmdrsp_buf
CVE-2019-19057 mwifiex: pcie: Fix memory leak in mwifiex_pcie_init_evt_ring
CVE-2019-19058 iwlwifi: dbg_ini: fix memory leak in alloc_sgtable
CVE-2019-19059 iwlwifi: pcie: fix memory leaks in iwl_pcie_ctxt_info_gen3_init
CVE-2019-19060 iio: imu: adis16400: release allocated memory on failure
CVE-2019-19061 iio: imu: adis16400: fix memory leak
CVE-2019-19062 crypto: user - fix memory leak in crypto_report
CVE-2019-19063 rtlwifi: prevent memory leak in rtl_usb_probe
CVE-2019-19064 spi: lpspi: fix memory leak in fsl_lpspi_probe
CVE-2019-19065 RDMA/hfi1: Prevent memory leak in sdma_init
CVE-2019-19066 scsi: bfa: release allocated memory in case of error
CVE-2019-19067 drm/amdgpu: fix multiple memory leaks in acp_hw_init
CVE-2019-19068 rtl8xxxu: prevent leaking urb
CVE-2019-19069 misc: fastrpc: prevent memory leak in fastrpc_dma_buf_attach
CVE-2019-19070 spi: gpio: prevent memory leak in spi_gpio_probe
CVE-2019-19071 rsi: release skb if rsi_prepare_beacon fails
CVE-2019-19072 tracing: Have error path in predicate_parse() free its allocated memory
CVE-2019-19073 ath9k_htc: release allocated buffer if timed out
CVE-2019-19074 ath9k: release allocated buffer if timed out
CVE-2019-19075 ieee802154: ca8210: prevent memory leak
CVE-2019-19076 nfp: abm: fix memory leak in nfp_abm_u32_knode_replace
CVE-2019-19077 RDMA: Fix goto target to release the allocated memory
CVE-2019-19078 ath10k: fix memory leak
CVE-2019-19079 net: qrtr: fix memort leak in qrtr_tun_write_iter
CVE-2019-19080 nfp: flower: prevent memory leak in nfp_flower_spawn_phy_reprs
CVE-2019-19081 nfp: flower: fix memory leak in nfp_flower_spawn_vnic_reprs
CVE-2019-19082 drm/amd/display: prevent memory leak
CVE-2019-19083 drm/amd/display: memory leak
CVE-2019-19227 appletalk: Fix potential NULL pointer dereference in unregister_snap_client
CVE-2019-19241 io_uring: async workers should inherit the user creds
CVE-2019-19252 vcs: prevent write access to vcsu devices
CVE-2019-19318 Btrfs: fix selftests failure due to uninitialized i_mode in test inodes
CVE-2019-19319 ext4: protect journal inode's blocks using block_validity
CVE-2019-19332 KVM: x86: fix out-of-bounds write in KVM_GET_EMULATED_CPUID (CVE-2019-19332)
CVE-2019-19338 KVM: x86: fix presentation of TSX feature in ARCH_CAPABILITIES
CVE-2019-19377 btrfs: Don't submit any btree write bio if the fs has errors
CVE-2019-19378
CVE-2019-19447 ext4: work around deleting a file with i_nlink == 0 safely
CVE-2019-19448 btrfs: only search for left_info if there is no right_info in try_merge_free_space
CVE-2019-19449 f2fs: fix to do sanity check on segment/section count
CVE-2019-19462 kernel/relay.c: handle alloc_percpu returning NULL in relay_open
CVE-2019-19523 USB: adutux: fix use-after-free on disconnect
CVE-2019-19524 Input: ff-memless - kill timer in destroy()
CVE-2019-19525 ieee802154: atusb: fix use-after-free at disconnect
CVE-2019-19526 NFC: pn533: fix use-after-free and memleaks
CVE-2019-19527 HID: hiddev: do cleanup in failure of opening a device
CVE-2019-19528 USB: iowarrior: fix use-after-free on disconnect
CVE-2019-19529 can: mcba_usb: fix use-after-free on disconnect
CVE-2019-19530 usb: cdc-acm: make sure a refcount is taken early enough
CVE-2019-19531 usb: yurex: Fix use-after-free in yurex_delete
CVE-2019-19532 HID: Fix assumption that devices have inputs
CVE-2019-19533 media: ttusb-dec: Fix info-leak in ttusb_dec_send_command()
CVE-2019-19534 can: peak_usb: fix slab info leak
CVE-2019-19535 can: peak_usb: pcan_usb_fd: Fix info-leaks to USB devices
CVE-2019-19536 can: peak_usb: pcan_usb_pro: Fix info-leaks to USB devices
CVE-2019-19537 USB: core: Fix races in character device registration and deregistraion
CVE-2019-19543 media: serial_ir: Fix use-after-free in serial_ir_init_module
CVE-2019-19602 x86/fpu: Don't cache access to fpu_fpregs_owner_ctx
CVE-2019-19767 ext4: add more paranoia checking in ext4_expand_extra_isize handling
CVE-2019-19768 blktrace: Protect q->blk_trace with RCU
CVE-2019-19769 locks: fix a potential use-after-free problem when wakeup a waiter
CVE-2019-19770 blktrace: fix debugfs use after free
CVE-2019-19807 ALSA: timer: Fix incorrectly assigned timer instance
CVE-2019-19813 btrfs: inode: Verify inode mode to avoid NULL pointer dereference
CVE-2019-19814
CVE-2019-19815 f2fs: support swap file w/ DIO
CVE-2019-19816 btrfs: inode: Verify inode mode to avoid NULL pointer dereference
CVE-2019-19922 sched/fair: Fix low cpu usage with high throttling by removing expiration of cpu-local slices
CVE-2019-19927 drm/ttm: fix incrementing the page pointer for huge pages
CVE-2019-19947 can: kvaser_usb: kvaser_usb_leaf: Fix some info-leaks to USB devices
CVE-2019-19965 scsi: libsas: stop discovering if oob mode is disconnected
CVE-2019-19966 media: cpia2: Fix use-after-free in cpia2_exit
CVE-2019-1999 binder: fix race between munmap() and direct reclaim
CVE-2019-20054 fs/proc/proc_sysctl.c: fix NULL pointer dereference in put_links
CVE-2019-20095 mwifiex: Fix mem leak in mwifiex_tm_cmd
CVE-2019-20096 dccp: Fix memleak in __feat_register_sp
CVE-2019-2024 media: em28xx: Fix use-after-free when disconnecting
CVE-2019-2025 binder: fix race that allows malicious free of live buffer
CVE-2019-20422 ipv6: fix a typo in fib6_rule_lookup()
CVE-2019-2054 arm/ptrace: run seccomp after ptrace
CVE-2019-20636 Input: add safety guards to input_set_keycode()
CVE-2019-20794
CVE-2019-20806 media: tw5864: Fix possible NULL pointer dereference in tw5864_handle_frame
CVE-2019-20810 media: go7007: fix a miss of snd_card_free
CVE-2019-20811 net-sysfs: call dev_hold if kobject_init_and_add success
CVE-2019-20812 af_packet: set defaule value for tmo
CVE-2019-20908 efi: Restrict efivar_ssdt_load when the kernel is locked down
CVE-2019-20934 sched/fair: Don't free p->numa_faults with concurrent readers
CVE-2019-2101 media: uvcvideo: Fix 'type' check leading to overflow
CVE-2019-2181 binder: check for overflow when alloc for security context
CVE-2019-2182 arm64: Enforce BBM for huge IO/VMAP mappings
CVE-2019-2213 binder: fix possible UAF when freeing buffer
CVE-2019-2214 binder: Set end of SG buffer area properly.
CVE-2019-2215 ANDROID: binder: remove waitqueue when thread exits.
CVE-2019-25044 block: free sched's request pool in blk_cleanup_queue
CVE-2019-25045 xfrm: clean up xfrm protocol checks
CVE-2019-3016 x86/kvm: Be careful not to clear KVM_VCPU_FLUSH_TLB bit
CVE-2019-3459 Bluetooth: Verify that l2cap_get_conf_opt provides large enough buffer
CVE-2019-3460 Bluetooth: Check L2CAP option sizes returned from l2cap_get_conf_opt
CVE-2019-3701 can: gw: ensure DLC boundaries after CAN frame modification
CVE-2019-3819 HID: debug: fix the ring buffer implementation
CVE-2019-3837 net_dma: simple removal
CVE-2019-3846 mwifiex: Fix possible buffer overflows at parsing bss descriptor
CVE-2019-3874 sctp: implement memory accounting on tx path
CVE-2019-3882 vfio/type1: Limit DMA mappings per container
CVE-2019-3887 KVM: x86: nVMX: close leak of L0's x2APIC MSRs (CVE-2019-3887)
CVE-2019-3892 coredump: fix race condition between mmget_not_zero()/get_task_mm() and core dumping
CVE-2019-3896
CVE-2019-3900 vhost_net: fix possible infinite loop
CVE-2019-3901 perf/core: Fix perf_event_open() vs. execve() race
CVE-2019-5108 mac80211: Do not send Layer 2 Update frame before authorization
CVE-2019-5489 Change mincore() to count "mapped" pages rather than "cached" pages
CVE-2019-6133 fork: record start_time late
CVE-2019-6974 kvm: fix kvm_ioctl_create_device() reference counting (CVE-2019-6974)
CVE-2019-7221 KVM: nVMX: unconditionally cancel preemption timer in free_nested (CVE-2019-7221)
CVE-2019-7222 KVM: x86: work around leak of uninitialized stack contents (CVE-2019-7222)
CVE-2019-7308 bpf: fix sanitation of alu op with pointer / scalar type from different paths
CVE-2019-8912 net: crypto set sk to NULL when af_alg_release.
CVE-2019-8956 sctp: walk the list of asoc safely
CVE-2019-8980 exec: Fix mem leak in kernel_read_file
CVE-2019-9003 ipmi: fix use-after-free of user->release_barrier.rda
CVE-2019-9162 netfilter: nf_nat_snmp_basic: add missing length checks in ASN.1 cbs
CVE-2019-9213 mm: enforce min addr even if capable() in expand_downwards()
CVE-2019-9245 f2fs: sanity check of xattr entry size
CVE-2019-9444 printk: hash addresses printed with %p
CVE-2019-9445 f2fs: check if file namelen exceeds max value
CVE-2019-9453 f2fs: fix to avoid accessing xattr across the boundary
CVE-2019-9454 i2c: core-smbus: prevent stack corruption on read I2C_BLOCK_DATA
CVE-2019-9455 media: videobuf2-v4l2: drop WARN_ON in vb2_warn_zero_bytesused()
CVE-2019-9456 usb: usbmon: Read text within supplied buffer size
CVE-2019-9457 exec: Limit arg stack to at most 75% of _STK_LIM
CVE-2019-9458 media: v4l: event: Prevent freeing event subscriptions while accessed
CVE-2019-9466 brcmfmac: add subtype check for event handling in data path
CVE-2019-9500 brcmfmac: assure SSID length from firmware is limited
CVE-2019-9503 brcmfmac: add subtype check for event handling in data path
CVE-2019-9506 Bluetooth: Fix faulty expression for minimum encryption key size check
CVE-2019-9857 inotify: Fix fsnotify_mark refcount leak in inotify_update_existing_watch()
CVE-2020-0009 staging: android: ashmem: Disallow ashmem memory from being remapped
CVE-2020-0030 ANDROID: binder: synchronize_rcu() when using POLLFREE.
CVE-2020-0041 binder: fix incorrect calculation for num_valid
CVE-2020-0066 netlink: Trim skb to alloc size to avoid MSG_TRUNC
CVE-2020-0067 f2fs: fix to avoid memory leakage in f2fs_listxattr
CVE-2020-0110 sched/psi: Fix OOB write when writing 0 bytes to PSI files
CVE-2020-0255 selinux: properly handle multiple messages in selinux_netlink_send()
CVE-2020-0305 chardev: Avoid potential use-after-free in 'chrdev_open()'
CVE-2020-0347
CVE-2020-0404 media: uvcvideo: Avoid cyclic entity chains due to malformed USB descriptors
CVE-2020-0423 binder: fix UAF when releasing todo list
CVE-2020-0427 pinctrl: devicetree: Avoid taking direct reference to device name string
CVE-2020-0429 l2tp: fix race between l2tp_session_delete() and l2tp_tunnel_closeall()
CVE-2020-0430 bpf: reject passing modified ctx to helper functions
CVE-2020-0431 HID: hid-input: clear unmapped usages
CVE-2020-0432 staging: most: net: fix buffer overflow
CVE-2020-0433 blk-mq: sync the update nr_hw_queues with blk_mq_queue_tag_busy_iter
CVE-2020-0435 f2fs: fix to do sanity check with i_extra_isize
CVE-2020-0444 audit: fix error handling in audit_data_to_entry()
CVE-2020-0465 HID: core: Sanitize event code and type when mapping input
CVE-2020-0466 do_epoll_ctl(): clean the failure exits up a bit
CVE-2020-0543 x86/cpu: Add 'table' argument to cpu_matches()
CVE-2020-10135 Bluetooth: Consolidate encryption handling in hci_encrypt_cfm
CVE-2020-10690 ptp: fix the race between the release of ptp_clock and cdev
CVE-2020-10708
CVE-2020-10711 netlabel: cope with NULL catmap
CVE-2020-10720 net-gro: fix use-after-free read in napi_gro_frags()
CVE-2020-10732 fs/binfmt_elf.c: allocate initialized memory in fill_thread_core_info()
CVE-2020-10742 new helper: iov_iter_get_pages_alloc()
CVE-2020-10751 selinux: properly handle multiple messages in selinux_netlink_send()
CVE-2020-10757 mm: Fix mremap not considering huge pmd devmap
CVE-2020-10766 x86/speculation: Prevent rogue cross-process SSBD shutdown
CVE-2020-10767 x86/speculation: Avoid force-disabling IBPB based on STIBP and enhanced IBRS.
CVE-2020-10768 x86/speculation: PR_SPEC_FORCE_DISABLE enforcement for indirect branches.
CVE-2020-10769 crypto: authenc - fix parsing key with misaligned rta_len
CVE-2020-10773 s390/cmm: fix information leak in cmm_timeout_handler()
CVE-2020-10774
CVE-2020-10781 Revert "zram: convert remaining CLASS_ATTR() to CLASS_ATTR_RO()"
CVE-2020-10942 vhost: Check docket sk_family instead of call getname
CVE-2020-11494 slcan: Don't transmit uninitialized stack data in padding
CVE-2020-11565 mm: mempolicy: require at least one nodeid for MPOL_PREFERRED
CVE-2020-11608 media: ov519: add missing endpoint sanity checks
CVE-2020-11609 media: stv06xx: add missing descriptor sanity checks
CVE-2020-11668 media: xirlink_cit: add missing descriptor sanity checks
CVE-2020-11669 powerpc/powernv/idle: Restore AMR/UAMOR/AMOR after idle
CVE-2020-11725
CVE-2020-11884 s390/mm: fix page table upgrade vs 2ndary address mode accesses
CVE-2020-11935
CVE-2020-12114 make struct mountpoint bear the dentry reference to mountpoint, not struct mount
CVE-2020-12351 Bluetooth: L2CAP: Fix calling sk_filter on non-socket based channel
CVE-2020-12352 Bluetooth: A2MP: Fix not initializing all members
CVE-2020-12362 drm/i915/guc: Update to use firmware v49.0.1
CVE-2020-12363 drm/i915/guc: Update to use firmware v49.0.1
CVE-2020-12364 drm/i915/guc: Update to use firmware v49.0.1
CVE-2020-12464 USB: core: Fix free-while-in-use bug in the USB S-Glibrary
CVE-2020-12465 mt76: fix array overflow on receiving too many fragments for a packet
CVE-2020-12652 scsi: mptfusion: Fix double fetch bug in ioctl
CVE-2020-12653 mwifiex: Fix possible buffer overflows in mwifiex_cmd_append_vsie_tlv()
CVE-2020-12654 mwifiex: Fix possible buffer overflows in mwifiex_ret_wmm_get_status()
CVE-2020-12655 xfs: add agf freeblocks verify in xfs_agf_verify
CVE-2020-12656 sunrpc: check that domain table is empty at module unload.
CVE-2020-12657 block, bfq: fix use-after-free in bfq_idle_slice_timer_body
CVE-2020-12659 xsk: Add missing check on user supplied headroom size
CVE-2020-12768 KVM: SVM: Fix potential memory leak in svm_cpu_init()
CVE-2020-12769 spi: spi-dw: Add lock protect dw_spi rx/tx to prevent concurrent calls
CVE-2020-12770 scsi: sg: add sg_remove_request in sg_write
CVE-2020-12771 bcache: fix potential deadlock problem in btree_gc_coalesce
CVE-2020-12826 signal: Extend exec_id to 64bits
CVE-2020-12888 vfio-pci: Invalidate mmaps and block MMIO access on disabled memory
CVE-2020-12912 hwmon: (amd_energy) modify the visibility of the counters
CVE-2020-13143 USB: gadget: fix illegal array access in binding with UDC
CVE-2020-13974 vt: keyboard: avoid signed integer overflow in k_ascii
CVE-2020-14304
CVE-2020-14305 netfilter: helpers: remove data_len usage for inkernel helpers
CVE-2020-14314 ext4: fix potential negative array index in do_split()
CVE-2020-14331 vgacon: Fix for missing check in scrollback handling
CVE-2020-14351 perf/core: Fix race in the perf_mmap_close() function
CVE-2020-14353 KEYS: prevent creating a different user's keyrings
CVE-2020-14356 cgroup: fix cgroup_sk_alloc() for sk_clone_lock()
CVE-2020-14381 futex: Fix inode life-time issue
CVE-2020-14385 xfs: fix boundary test in xfs_attr_shortform_verify
CVE-2020-14386 net/packet: fix overflow in tpacket_rcv
CVE-2020-14390 fbcon: remove soft scrollback code
CVE-2020-14416 can, slip: Protect tty->disc_data in write_wakeup and close with RCU
CVE-2020-15393 usb: usbtest: fix missing kfree(dev->buf) in usbtest_disconnect
CVE-2020-15436 block: Fix use-after-free in blkdev_get()
CVE-2020-15437 serial: 8250: fix null-ptr-deref in serial8250_start_tx()
CVE-2020-15780 ACPI: configfs: Disallow loading ACPI tables when locked down
CVE-2020-15802
CVE-2020-15852 x86/ioperm: Fix io bitmap invalidation on Xen PV
CVE-2020-16119 dccp: don't duplicate ccid when cloning dccp sock
CVE-2020-16120 ovl: switch to mounter creds in readdir
CVE-2020-16166 random32: update the net random state on interrupt and activity
CVE-2020-1749 net: ipv6_stub: use ip6_dst_lookup_flow instead of ip6_dst_lookup
CVE-2020-24394 nfsd: apply umask on fs without ACL support
CVE-2020-24490 Bluetooth: fix kernel oops in store_pending_adv_report
CVE-2020-24502
CVE-2020-24503
CVE-2020-24504 ice: create scheduler aggregator node config and move VSIs
CVE-2020-24586 mac80211: prevent mixed key and fragment cache attacks
CVE-2020-24587 mac80211: prevent mixed key and fragment cache attacks
CVE-2020-24588 cfg80211: mitigate A-MSDU aggregation attacks
CVE-2020-25211 netfilter: ctnetlink: add a range check for l3/l4 protonum
CVE-2020-25212 nfs: Fix getxattr kernel panic and memory overflow
CVE-2020-25220
CVE-2020-25221 mm: fix pin vs. gup mismatch with gate pages
CVE-2020-25284 rbd: require global CAP_SYS_ADMIN for mapping and unmapping
CVE-2020-25285 mm/hugetlb: fix a race between hugetlb sysctl handlers
CVE-2020-25639 drm/nouveau: bail out of nouveau_channel_new if channel init fails
CVE-2020-25641 block: allow for_each_bvec to support zero len bvec
CVE-2020-25643 hdlc_ppp: add range checks in ppp_cp_parse_cr()
CVE-2020-25645 geneve: add transport ports in route lookup for geneve
CVE-2020-25656 vt: keyboard, extend func_buf_lock to readers
CVE-2020-25661
CVE-2020-25662
CVE-2020-25668 tty: make FONTX ioctl use the tty pointer they were actually passed
CVE-2020-25669 Input: sunkbd - avoid use-after-free in teardown paths
CVE-2020-25670 nfc: fix refcount leak in llcp_sock_bind()
CVE-2020-25671 nfc: fix refcount leak in llcp_sock_connect()
CVE-2020-25672 nfc: fix memory leak in llcp_sock_connect()
CVE-2020-25673 nfc: Avoid endless loops caused by repeated llcp_sock_connect()
CVE-2020-25704 perf/core: Fix a memory leak in perf_event_parse_addr_filter()
CVE-2020-25705 icmp: randomize the global rate limiter
CVE-2020-26088 net/nfc/rawsock.c: add CAP_NET_RAW check.
CVE-2020-26139 mac80211: do not accept/forward invalid EAPOL frames
CVE-2020-26140
CVE-2020-26141 ath10k: Fix TKIP Michael MIC verification for PCIe
CVE-2020-26142
CVE-2020-26143
CVE-2020-26145 ath10k: drop fragments with multicast DA for PCIe
CVE-2020-26147 mac80211: assure all fragments are encrypted
CVE-2020-26541 certs: Add EFI_CERT_X509_GUID support for dbx entries
CVE-2020-26555 Bluetooth: SMP: Fail if remote and local public keys are identical
CVE-2020-26556
CVE-2020-26557
CVE-2020-26558 Bluetooth: SMP: Fail if remote and local public keys are identical
CVE-2020-26559
CVE-2020-26560
CVE-2020-27066 xfrm: policy: Fix doulbe free in xfrm_policy_timer
CVE-2020-27067 l2tp: fix l2tp_eth module loading
CVE-2020-27068 cfg80211: add missing policy for NL80211_ATTR_STATUS_CODE
CVE-2020-27152 KVM: ioapic: break infinite recursion on lazy EOI
CVE-2020-27170 bpf: Prohibit alu ops for pointer types not defining ptr_limit
CVE-2020-27171 bpf: Fix off-by-one for area size in creating mask to left
CVE-2020-27194 bpf: Fix scalar32_min_max_or bounds tracking
CVE-2020-2732 KVM: nVMX: Don't emulate instructions in guest mode
CVE-2020-27418 vgacon: Fix a UAF in vgacon_invert_region
CVE-2020-27673 xen/events: add a proper barrier to 2-level uevent unmasking
CVE-2020-27675 xen/events: avoid removing an event channel while handling it
CVE-2020-27777 powerpc/rtas: Restrict RTAS requests from userspace
CVE-2020-27784 usb: gadget: function: printer: fix use-after-free in __lock_acquire
CVE-2020-27786 ALSA: rawmidi: Fix racy buffer resize under concurrent accesses
CVE-2020-27815 jfs: Fix array index bounds check in dbAdjTree
CVE-2020-27820 drm/nouveau: use drm_dev_unplug() during device removal
CVE-2020-27825 tracing: Fix race in trace_open and buffer resize call
CVE-2020-27830 speakup: Reject setting the speakup line discipline outside of speakup
CVE-2020-27835 IB/hfi1: Ensure correct mm is used at all times
CVE-2020-28097 vgacon: remove software scrollback support
CVE-2020-28374 scsi: target: Fix XCOPY NAA identifier lookup
CVE-2020-28588 lib/syscall: fix syscall registers retrieval on 32-bit platforms
CVE-2020-28915 fbcon: Fix global-out-of-bounds read in fbcon_get_font()
CVE-2020-28941 speakup: Do not let the line discipline be used several times
CVE-2020-28974 vt: Disable KD_FONT_OP_COPY
CVE-2020-29368 mm: thp: make the THP mapcount atomic against __split_huge_pmd_locked()
CVE-2020-29369 mm/mmap.c: close race between munmap() and expand_upwards()/downwards()
CVE-2020-29370 mm: slub: add missing TID bump in kmem_cache_alloc_bulk()
CVE-2020-29371 romfs: fix uninitialized memory leak in romfs_dev_read()
CVE-2020-29372 mm: check that mm is still valid in madvise()
CVE-2020-29373 io_uring: grab ->fs as part of async preparation
CVE-2020-29374 gup: document and work around "COW can break either way" issue
CVE-2020-29534 io_uring: don't rely on weak ->files references
CVE-2020-29568 xen/xenbus: Allow watches discard events before queueing
CVE-2020-29569 xen-blkback: set ring->xenblkd to NULL after kthread_stop()
CVE-2020-29660 tty: Fix ->session locking
CVE-2020-29661 tty: Fix ->pgrp locking in tiocspgrp()
CVE-2020-35499 Bluetooth: sco: Fix crash when using BT_SNDMTU/BT_RCVMTU option
CVE-2020-35501
CVE-2020-35508 fork: fix copy_process(CLONE_PARENT) race with the exiting ->real_parent
CVE-2020-35513 nfsd: fix incorrect umasks
CVE-2020-35519 net/x25: prevent a couple of overflows
CVE-2020-36158 mwifiex: Fix possible buffer overflows in mwifiex_cmd_802_11_ad_hoc_start
CVE-2020-36310 KVM: SVM: avoid infinite loop on NPF from bad address
CVE-2020-36311 KVM: SVM: Periodically schedule when unregistering regions on destroy
CVE-2020-36312 KVM: fix memory leak in kvm_io_bus_unregister_dev()
CVE-2020-36313 KVM: Fix out of range accesses to memslots
CVE-2020-36322 fuse: fix bad inode
CVE-2020-36385 RDMA/ucma: Rework ucma_migrate_id() to avoid races with destroy
CVE-2020-36386 Bluetooth: Fix slab-out-of-bounds read in hci_extended_inquiry_result_evt()
CVE-2020-36387 io_uring: hold 'ctx' reference around task_work queue + execute
CVE-2020-36516 ipv4: avoid using shared IP generator for connected sockets
CVE-2020-36557 vt: vt_ioctl: fix VT_DISALLOCATE freeing in-use virtual console
CVE-2020-36558 vt: vt_ioctl: fix race in VT_RESIZEX
CVE-2020-36691 netlink: limit recursion depth in policy validation
CVE-2020-36694 netfilter: x_tables: Switch synchronization to RCU
CVE-2020-36766 cec-api: prevent leaking memory through hole in structure
CVE-2020-3702 ath: Use safer key clearing with key cache entries
CVE-2020-4788 powerpc/64s: flush L1D on kernel entry
CVE-2020-7053 drm/i915: Introduce a mutex for file_priv->context_idr
CVE-2020-8428 do_last(): fetch directory ->i_mode and ->i_uid before it's too late
CVE-2020-8647 vgacon: Fix a UAF in vgacon_invert_region
CVE-2020-8648 vt: selection, close sel_buffer race
CVE-2020-8649 vgacon: Fix a UAF in vgacon_invert_region
CVE-2020-8694 powercap: restrict energy meter to root access
CVE-2020-8832 drm/i915: Record the default hw state after reset upon load
CVE-2020-8834 KVM: PPC: Book3S HV: Factor fake-suspend handling out of kvmppc_save/restore_tm
CVE-2020-8835 bpf: Undo incorrect __reg_bound_offset32 handling
CVE-2020-8992 ext4: add cond_resched() to ext4_protect_reserved_inode
CVE-2020-9383 floppy: check FDC index for errors before assigning it
CVE-2020-9391 mm: Avoid creating virtual address aliases in brk()/mmap()/mremap()
CVE-2021-0129 Bluetooth: SMP: Fail if remote and local public keys are identical
CVE-2021-0342 tun: correct header offsets in napi frags mode
CVE-2021-0399
CVE-2021-0447 l2tp: protect sock pointer of struct pppol2tp_session with RCU
CVE-2021-0448 netfilter: ctnetlink: add a range check for l3/l4 protonum
CVE-2021-0512 HID: make arrays usage and value to be the same
CVE-2021-0605 af_key: pfkey_dump needs parameter validation
CVE-2021-0606
CVE-2021-0695
CVE-2021-0707 dmabuf: fix use-after-free of dmabuf's file->f_inode
CVE-2021-0920 af_unix: fix garbage collect vs MSG_PEEK
CVE-2021-0924
CVE-2021-0929 staging/android/ion: delete dma_buf->kmap/unmap implemenation
CVE-2021-0935 net: ipv6: keep sk status consistent after datagram connect failure
CVE-2021-0936
CVE-2021-0937 netfilter: x_tables: fix compat match/target pad out-of-bound write
CVE-2021-0938 compiler.h: fix barrier_data() on clang
CVE-2021-0941 bpf: Remove MTU check in __bpf_skb_max_len
CVE-2021-0961
CVE-2021-1048 fix regression in "epoll: Keep a reference on files added to the check list"
CVE-2021-20177 netfilter: add and use nf_hook_slow_list()
CVE-2021-20194 io_uring: don't rely on weak ->files references
CVE-2021-20219
CVE-2021-20226 io_uring: don't rely on weak ->files references
CVE-2021-20239 net: pass a sockptr_t into ->setsockopt
CVE-2021-20261 floppy: fix lock_fdc() signal handling
CVE-2021-20265 af_unix: fix struct pid memory leak
CVE-2021-20268 bpf: Fix signed_{sub,add32}_overflows type handling
CVE-2021-20292 drm/ttm/nouveau: don't call tt destroy callback on alloc failure.
CVE-2021-20317 lib/timerqueue: Rely on rbtree semantics for next timer
CVE-2021-20320 s390/bpf: Fix optimizing out zero-extensions
CVE-2021-20321 ovl: fix missing negative dentry check in ovl_rename()
CVE-2021-20322 ipv6: make exception cache less predictible
CVE-2021-21781 ARM: ensure the signal page contains defined contents
CVE-2021-22543 KVM: do not allow mapping valid but non-reference-counted pages
CVE-2021-22555 netfilter: x_tables: fix compat match/target pad out-of-bound write
CVE-2021-22600 net/packet: rx_owner_map depends on pg_vec
CVE-2021-23133 net/sctp: fix race condition in sctp_destroy_sock
CVE-2021-23134 net/nfc: fix use-after-free llcp_sock_bind/connect
CVE-2021-26401 x86/speculation: Use generic retpoline by default on AMD
CVE-2021-26708 vsock: fix the race conditions in multi-transport support
CVE-2021-26930 xen-blkback: fix error handling in xen_blkbk_map()
CVE-2021-26931 xen-blkback: don't "handle" error by BUG()
CVE-2021-26932 Xen/x86: don't bail early from clear_foreign_p2m_mapping()
CVE-2021-26934
CVE-2021-27363 scsi: iscsi: Restrict sessions and handles to admin capabilities
CVE-2021-27364 scsi: iscsi: Restrict sessions and handles to admin capabilities
CVE-2021-27365 scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE
CVE-2021-28038 Xen/gnttab: handle p2m update errors on a per-slot basis
CVE-2021-28039 xen: fix p2m size in dom0 for disabled memory hotplug case
CVE-2021-28375 misc: fastrpc: restrict user apps from sending kernel RPC messages
CVE-2021-28660 staging: rtl8188eu: prevent ->ssid overflow in rtw_wx_set_scan()
CVE-2021-28688 xen-blkback: don't leak persistent grants from xen_blkbk_map()
CVE-2021-28691 xen-netback: take a reference to the RX task thread
CVE-2021-28711 xen/blkfront: harden blkfront against event channel storms
CVE-2021-28712 xen/netfront: harden netfront against event channel storms
CVE-2021-28713 xen/console: harden hvc_xen against event channel storms
CVE-2021-28714 xen/netback: fix rx queue stall detection
CVE-2021-28715 xen/netback: don't queue unlimited number of packages
CVE-2021-28950 fuse: fix live lock in fuse_iget()
CVE-2021-28951 io_uring: ensure that SQPOLL thread is started for exit
CVE-2021-28952 ASoC: qcom: sdm845: Fix array out of bounds access
CVE-2021-28964 btrfs: fix race when cloning extent buffer during rewind of an old root
CVE-2021-28971 perf/x86/intel: Fix a crash caused by zero PEBS status
CVE-2021-28972 PCI: rpadlpar: Fix potential drc_name corruption in store functions
CVE-2021-29154 bpf, x86: Validate computation of branch displacements for x86-64
CVE-2021-29155 bpf: Use correct permission flag for mixed signed bounds arithmetic
CVE-2021-29264 gianfar: fix jumbo packets+napi+rx overrun crash
CVE-2021-29265 usbip: fix stub_dev usbip_sockfd_store() races leading to gpf
CVE-2021-29266 vhost-vdpa: fix use-after-free of v->config_ctx
CVE-2021-29646 tipc: better validate user input in tipc_nl_retrieve_key()
CVE-2021-29647 net: qrtr: fix a kernel-infoleak in qrtr_recvmsg()
CVE-2021-29648 bpf: Dont allow vmlinux BTF to be used in map_create and prog_load.
CVE-2021-29649 bpf: Fix umd memory leak in copy_process()
CVE-2021-29650 netfilter: x_tables: Use correct memory barriers.
CVE-2021-29657 KVM: SVM: load control fields from VMCB12 before checking them
CVE-2021-30002 media: v4l: ioctl: Fix memory leak in video_usercopy
CVE-2021-30178 KVM: x86: hyper-v: Fix Hyper-V context null-ptr-deref
CVE-2021-31440 bpf: Fix propagation of 32 bit unsigned bounds from 64 bit bounds
CVE-2021-3178 nfsd4: readdirplus shouldn't return parent of export
CVE-2021-31829 bpf: Fix masking negation logic upon negative dst register
CVE-2021-31916 dm ioctl: fix out of bounds array access when no devices
CVE-2021-32078 ARM: footbridge: remove personal server platform
CVE-2021-32399 bluetooth: eliminate the potential race condition when removing the HCI controller
CVE-2021-32606 can: isotp: prevent race between isotp_bind() and isotp_setsockopt()
CVE-2021-33033 cipso,calipso: resolve a number of problems with the DOI refcounts
CVE-2021-33034 Bluetooth: verify AMP hci_chan before amp_destroy
CVE-2021-33061 ixgbe: add improvement for MDD response functionality
CVE-2021-33098 ixgbe: fix large MTU request from VF
CVE-2021-33135 x86/sgx: Free backing memory after faulting the enclave page
CVE-2021-33200 bpf: Wrap aux data inside bpf_sanitize_info container
CVE-2021-3347 futex: Ensure the correct return value from futex_lock_pi()
CVE-2021-3348 nbd: freeze the queue while we're adding connections
CVE-2021-33624 bpf: Inherit expanded/patched seen count from old aux data
CVE-2021-33630 net/sched: cbs: Fix not adding cbs instance to list
CVE-2021-33631 ext4: fix kernel BUG in 'ext4_write_inline_data_end()'
CVE-2021-33655 fbcon: Disallow setting font bigger than screen size
CVE-2021-33656 vt: drop old FONT ioctls
CVE-2021-33909 seq_file: disallow extremely large seq buffer allocations
CVE-2021-3411 x86/kprobes: Fix optprobe to detect INT3 padding correctly
CVE-2021-3428 ext4: handle error of ext4_setup_system_zone() on remount
CVE-2021-3444 bpf: Fix truncation handling for mod32 dst reg wrt zero
CVE-2021-34556 bpf: Introduce BPF nospec instruction for mitigating Spectre v4
CVE-2021-34693 can: bcm: fix infoleak in struct bcm_msg_head
CVE-2021-3483 firewire: nosy: Fix a use-after-free bug in nosy_ioctl()
CVE-2021-34866 bpf: Fix ringbuf helper function compatibility
CVE-2021-3489 bpf, ringbuf: Deny reserve of buffers larger than ringbuf
CVE-2021-3490 bpf: Fix alu32 const subreg bound tracking on bitwise operations
CVE-2021-3491 io_uring: truncate lengths larger than MAX_RW_COUNT on provide buffers
CVE-2021-3492
CVE-2021-3493 vfs: move cap_convert_nscap() call into vfs_setxattr()
CVE-2021-34981 Bluetooth: cmtp: fix file refcount when cmtp_attach_device fails
CVE-2021-3501 KVM: VMX: Don't use vcpu->run->internal.ndata as an array index
CVE-2021-35039 module: limit enabling module.sig_enforce
CVE-2021-3506 f2fs: fix to avoid out-of-bounds memory access
CVE-2021-3542
CVE-2021-3543 nitro_enclaves: Fix stale file descriptors on failed usercopy
CVE-2021-35477 bpf: Introduce BPF nospec instruction for mitigating Spectre v4
CVE-2021-3564 Bluetooth: fix the erroneous flush_work() order
CVE-2021-3573 Bluetooth: use correct lock to prevent UAF of hdev object
CVE-2021-3587 nfc: fix NULL ptr dereference in llcp_sock_getname() after failed connect
CVE-2021-3600 bpf: Fix 32 bit src register truncation on div/mod
CVE-2021-3609 can: bcm: delay release of struct bcm_op after synchronize_rcu()
CVE-2021-3612 Input: joydev - prevent potential read overflow in ioctl
CVE-2021-3635 netfilter: nf_tables: fix flowtable list del corruption
CVE-2021-3640 Bluetooth: sco: Fix lock_sock() blockage by memcpy_from_msg()
CVE-2021-3653 KVM: nSVM: avoid picking up unsupported bits from L2 in int_ctl (CVE-2021-3653)
CVE-2021-3655 sctp: validate from_addr_param return
CVE-2021-3656 KVM: nSVM: always intercept VMLOAD/VMSAVE when nested (CVE-2021-3656)
CVE-2021-3659 net: mac802154: Fix general protection fault
CVE-2021-3669 ipc: replace costly bailout check in sysvipc_find_ipc()
CVE-2021-3679 tracing: Fix bug in rb_per_cpu_empty() that might cause deadloop.
CVE-2021-3714
CVE-2021-3715 net_sched: cls_route: remove the right filter from hashtable
CVE-2021-37159 usb: hso: fix error handling code of hso_create_net_device
CVE-2021-3732 ovl: prevent private clone if bind mount is not allowed
CVE-2021-3736 vfio/mbochs: Fix missing error unwind of mbochs_used_mbytes
CVE-2021-3739 btrfs: fix NULL pointer dereference when deleting device by invalid id
CVE-2021-3743 net: qrtr: fix OOB Read in qrtr_endpoint_post
CVE-2021-3744 crypto: ccp - fix resource leaks in ccp_run_aes_gcm_cmd()
CVE-2021-3752 Bluetooth: fix use-after-free error in lock_sock_nested()
CVE-2021-3753 vt_kdsetmode: extend console locking
CVE-2021-37576 KVM: PPC: Book3S: Fix H_RTAS rets buffer overflow
CVE-2021-3759 memcg: enable accounting of ipc resources
CVE-2021-3760 nfc: nci: fix the UAF of rf_conn_info object
CVE-2021-3764 crypto: ccp - fix resource leaks in ccp_run_aes_gcm_cmd()
CVE-2021-3772 sctp: use init_tag from inithdr for ABORT chunk
CVE-2021-38160 virtio_console: Assure used length from device is limited
CVE-2021-38166 bpf: Fix integer overflow involving bucket_size
CVE-2021-38198 KVM: X86: MMU: Use the correct inherited permissions to get shadow page
CVE-2021-38199 NFSv4: Initialise connection to the server in nfs4_alloc_client()
CVE-2021-38200 powerpc/perf: Fix crash in perf_instruction_pointer() when ppmu is not set
CVE-2021-38201 sunrpc: Avoid a KASAN slab-out-of-bounds bug in xdr_set_page_base()
CVE-2021-38202 NFSD: Prevent a possible oops in the nfs_dirent() tracepoint
CVE-2021-38203 btrfs: fix deadlock with concurrent chunk allocations involving system chunks
CVE-2021-38204 usb: max-3421: Prevent corruption of freed memory
CVE-2021-38205 net: xilinx_emaclite: Do not print real IOMEM pointer
CVE-2021-38206 mac80211: Fix NULL ptr deref for injected rate info
CVE-2021-38207 net: ll_temac: Fix TX BD buffer overwrite
CVE-2021-38208 nfc: fix NULL ptr dereference in llcp_sock_getname() after failed connect
CVE-2021-38209 netfilter: conntrack: Make global sysctls readonly in non-init netns
CVE-2021-38300 bpf, mips: Validate conditional branch offsets
CVE-2021-3847
CVE-2021-3864
CVE-2021-3892
CVE-2021-3894 sctp: account stream padding length for reconf chunk
CVE-2021-3896 isdn: cpai: check ctr->cnr to avoid array index out of bound
CVE-2021-3923 RDMA/core: Don't infoleak GRH fields
CVE-2021-39633 ip_gre: add validation for csum_start
CVE-2021-39634 epoll: do not insert into poll queues until all sanity checks are done
CVE-2021-39636 netfilter: x_tables: fix pointer leaks to userspace
CVE-2021-39648 usb: gadget: configfs: Fix use-after-free issue with udc_name
CVE-2021-39656 configfs: fix a use-after-free in __configfs_open_file
CVE-2021-39657 scsi: ufs: Correct the LUN used in eh_device_reset_handler() callback
CVE-2021-39685 USB: gadget: detect too-big endpoint 0 requests
CVE-2021-39686 binder: use euid from cred instead of using task
CVE-2021-39698 wait: add wake_up_pollfree()
CVE-2021-39711 bpf: fix panic due to oob in bpf_prog_test_run_skb
CVE-2021-39713 net: sched: use Qdisc rcu API instead of relying on rtnl lock
CVE-2021-39714 staging: android: ion: Drop ion_map_kernel interface
CVE-2021-39800
CVE-2021-39801
CVE-2021-39802
CVE-2021-4001 bpf: Fix toctou on read-only map's constant scalar tracking
CVE-2021-4002 hugetlbfs: flush TLBs correctly after huge_pmd_unshare
CVE-2021-4023 io-wq: fix cancellation on create-worker failure
CVE-2021-4028 RDMA/cma: Do not change route.addr.src_addr.ss_family
CVE-2021-4032 Revert "KVM: x86: Open code necessary bits of kvm_lapic_set_base() at vCPU RESET"
CVE-2021-4037 xfs: fix up non-directory creation in SGID directories
CVE-2021-40490 ext4: fix race writing to an inline_data file while its xattrs are changing
CVE-2021-4083 fget: check that the fd still exists after getting a ref to it
CVE-2021-4090 NFSD: Fix exposure in nfsd4_decode_bitmap()
CVE-2021-4093 KVM: SEV-ES: go over the sev_pio_data buffer in multiple passes if needed
CVE-2021-4095 KVM: x86: Fix wall clock writes in Xen shared_info not to mark page dirty
CVE-2021-41073 io_uring: ensure symmetry in handling iter types in loop_rw_iter()
CVE-2021-4135 netdevsim: Zero-initialize memory for new map's value in function nsim_bpf_map_alloc
CVE-2021-4148 mm: khugepaged: skip huge page collapse for special files
CVE-2021-4149 btrfs: unlock newly allocated extent buffer after error
CVE-2021-4150 block: fix incorrect references to disk objects
CVE-2021-4154 cgroup: verify that source is a string
CVE-2021-4155 xfs: map unwritten blocks in XFS_IOC_{ALLOC,FREE}SP just like fallocate
CVE-2021-4157 pNFS/flexfiles: fix incorrect size check in decode_nfs_fh()
CVE-2021-4159 bpf: Verifer, adjust_scalar_min_max_vals to always call update_reg_bounds()
CVE-2021-41864 bpf: Fix integer overflow in prealloc_elems_and_freelist()
CVE-2021-4197 cgroup: Use open-time credentials for process migraton perm checks
CVE-2021-42008 net: 6pack: fix slab-out-of-bounds in decode_data
CVE-2021-4202 NFC: reorganize the functions in nci_request
CVE-2021-4203 af_unix: fix races in sk_peer_pid and sk_peer_cred accesses
CVE-2021-4204 bpf: Generalize check_ctx_reg for reuse with other types
CVE-2021-4218 sysctl: pass kernel pointers to ->proc_handler
CVE-2021-42252 soc: aspeed: lpc-ctrl: Fix boundary check for mmap
CVE-2021-42327 drm/amdgpu: fix out of bounds write
CVE-2021-42739 media: firewire: firedtv-avc: fix a buffer overflow in avc_ca_pmt()
CVE-2021-43056 KVM: PPC: Book3S HV: Make idle_kvm_start_guest() return 0 if it went to guest
CVE-2021-43057 selinux,smack: fix subjective/objective credential use mixups
CVE-2021-43267 tipc: fix size validations for the MSG_CRYPTO type
CVE-2021-43389 isdn: cpai: check ctr->cnr to avoid array index out of bound
CVE-2021-43975 atlantic: Fix OOB read and write in hw_atl_utils_fw_rpc_wait
CVE-2021-43976 mwifiex: Fix skb_over_panic in mwifiex_usb_recv()
CVE-2021-44733 tee: handle lookup of shm with reference count 0
CVE-2021-44879 f2fs: fix to do sanity check on inode type during garbage collection
CVE-2021-45095 phonet: refcount leak in pep_sock_accep
CVE-2021-45100 ksmbd: disable SMB2_GLOBAL_CAP_ENCRYPTION for SMB 3.1.1
CVE-2021-45402 bpf: Fix signed bounds propagation after mov32
CVE-2021-45469 f2fs: fix to do sanity check on last xattr entry in __f2fs_setxattr()
CVE-2021-45480 rds: memory leak in __rds_conn_create()
CVE-2021-45485 ipv6: use prandom_u32() for ID generation
CVE-2021-45486 inet: use bigger hash table for IP ID generation
CVE-2021-45868 quota: check block number when reading the block in quota file
CVE-2021-46283 netfilter: nf_tables: initialize set before expression setup
CVE-2022-0001 x86/speculation: Rename RETPOLINE_AMD to RETPOLINE_LFENCE
CVE-2022-0002 x86/speculation: Rename RETPOLINE_AMD to RETPOLINE_LFENCE
CVE-2022-0168 cifs: fix NULL ptr dereference in smb2_ioctl_query_info()
CVE-2022-0171 KVM: SEV: add cache flush to solve SEV cache incoherency issues
CVE-2022-0185 vfs: fs_context: fix up param length parsing in legacy_parse_param
CVE-2022-0264 bpf: Fix kernel address leakage in atomic fetch
CVE-2022-0286 bonding: fix null dereference in bond_ipsec_add_sa()
CVE-2022-0322 sctp: account stream padding length for reconf chunk
CVE-2022-0330 drm/i915: Flush TLBs before releasing backing store
CVE-2022-0382 net ticp:fix a kernel-infoleak in __tipc_sendmsg()
CVE-2022-0400
CVE-2022-0433 bpf: Add missing map_get_next_key method to bloom filter map.
CVE-2022-0435 tipc: improve size validations for received domain records
CVE-2022-0480 memcg: enable accounting for file lock caches
CVE-2022-0487 moxart: fix potential use-after-free on remove path
CVE-2022-0492 cgroup-v1: Require capabilities to set release_agent
CVE-2022-0494 block-map: add __GFP_ZERO flag for alloc_page in function bio_copy_kern
CVE-2022-0500 bpf: Introduce MEM_RDONLY flag
CVE-2022-0516 KVM: s390: Return error on SIDA memop on normal guest
CVE-2022-0617 udf: Fix NULL ptr deref when converting from inline format
CVE-2022-0644 vfs: check fd has read access in kernel_read_file_from_fd()
CVE-2022-0646
CVE-2022-0742 ipv6: fix skb drops in igmp6_event_query() and igmp6_event_report()
CVE-2022-0812 xprtrdma: fix incorrect header size calculations
CVE-2022-0847 lib/iov_iter: initialize "flags" in new pipe_buffer
CVE-2022-0850 ext4: fix kernel infoleak via ext4_extent_header
CVE-2022-0854 swiotlb: rework "fix info leak with DMA_FROM_DEVICE"
CVE-2022-0995 watch_queue: Fix filter limit check
CVE-2022-0998 vdpa: clean up get_config_size ret value handling
CVE-2022-1011 fuse: fix pipe buffer lifetime for direct_io
CVE-2022-1012 secure_seq: use the 64 bits of the siphash for port offset calculation
CVE-2022-1015 netfilter: nf_tables: validate registers coming from userspace.
CVE-2022-1016 netfilter: nf_tables: initialize registers in nft_do_chain()
CVE-2022-1043 io_uring: fix xa_alloc_cycle() error return value check
CVE-2022-1048 ALSA: pcm: Fix races among concurrent hw_params and hw_free calls
CVE-2022-1055 net: sched: fix use-after-free in tc_new_tfilter()
CVE-2022-1116
CVE-2022-1158 KVM: x86/mmu: do compare-and-exchange of gPTE via the user address
CVE-2022-1184 ext4: verify dir block before splitting it
CVE-2022-1195 hamradio: improve the incomplete fix to avoid NPD
CVE-2022-1198 drivers: hamradio: 6pack: fix UAF bug caused by mod_timer()
CVE-2022-1199 ax25: Fix NULL pointer dereference in ax25_kill_by_device
CVE-2022-1204 ax25: Fix refcount leaks caused by ax25_cb_del()
CVE-2022-1205 ax25: Fix NULL pointer dereferences in ax25 timers
CVE-2022-1247
CVE-2022-1263 KVM: avoid NULL pointer dereference in kvm_dirty_ring_push
CVE-2022-1280 drm: avoid circular locks in drm_mode_getconnector
CVE-2022-1353 af_key: add __GFP_ZERO flag for compose_sadb_supported in function pfkey_register
CVE-2022-1419 drm/vgem: Close use-after-free race in vgem_gem_create
CVE-2022-1462 tty: use new tty_insert_flip_string_and_push_buffer() in pty_write()
CVE-2022-1508 io_uring: reexpand under-reexpanded iters
CVE-2022-1516 net/x25: Fix null-ptr-deref caused by x25_disconnect
CVE-2022-1651 virt: acrn: fix a memory leak in acrn_dev_ioctl()
CVE-2022-1652 floppy: use a statically allocated error counter
CVE-2022-1671 rxrpc: fix some null-ptr-deref bugs in server_key.c
CVE-2022-1678 tcp: optimize tcp internal pacing
CVE-2022-1679 ath9k: fix use-after-free in ath9k_hif_usb_rx_cb
CVE-2022-1729 perf: Fix sys_perf_event_open() race against self
CVE-2022-1734 nfc: nfcmrvl: main: reorder destructive operations in nfcmrvl_nci_unregister_dev to avoid bugs
CVE-2022-1786 io_uring: remove io_identity
CVE-2022-1789 KVM: x86/mmu: fix NULL pointer dereference on guest INVPCID
CVE-2022-1836 floppy: disable FDRAWCMD by default
CVE-2022-1852 KVM: x86: avoid calling x86 emulator without a decoded instruction
CVE-2022-1882 watchqueue: make sure to serialize 'wqueue->defunct' properly
CVE-2022-1943 udf: Avoid using stale lengthOfImpUse
CVE-2022-1966 netfilter: nf_tables: disallow non-stateful expression in sets earlier
CVE-2022-1972 netfilter: nf_tables: sanitize nft_set_desc_concat_parse()
CVE-2022-1973 fs/ntfs3: Fix invalid free in log_replay
CVE-2022-1974 nfc: replace improper check device_is_registered() in netlink related functions
CVE-2022-1975 NFC: netlink: fix sleep in atomic bug when firmware download timeout
CVE-2022-1976 io_uring: reinstate the inflight tracking
CVE-2022-1998 fanotify: Fix stale file descriptor in copy_event_to_user()
CVE-2022-20008 mmc: block: fix read single on recovery logic
CVE-2022-20132 HID: add hid_is_usb() function to make it simpler for USB detection
CVE-2022-20141 igmp: Add ip_mc_list lock in ip_check_mc_rcu
CVE-2022-20148 f2fs: fix UAF in f2fs_available_free_memory
CVE-2022-20153 io_uring: return back safer resurrect
CVE-2022-20154 sctp: use call_rcu to free endpoint
CVE-2022-20158 net/packet: fix slab-out-of-bounds access in packet_recvmsg()
CVE-2022-20166 drivers core: Use sysfs_emit and sysfs_emit_at for show(device *...) functions
CVE-2022-20368 net/packet: fix slab-out-of-bounds access in packet_recvmsg()
CVE-2022-20369 media: v4l2-mem2mem: Apply DST_QUEUE_OFF_BASE on MMAP buffers across ioctls
CVE-2022-20409 io_uring: remove io_identity
CVE-2022-20421 binder: fix UAF of ref->proc caused by race condition
CVE-2022-20422 arm64: fix oops in concurrently setting insn_emulation sysctls
CVE-2022-20423 usb: gadget: rndis: prevent integer overflow in rndis_set_response()
CVE-2022-20424 io_uring: remove io_identity
CVE-2022-20565 HID: core: Correctly handle ReportSize being zero
CVE-2022-20566 Bluetooth: L2CAP: Fix use-after-free caused by l2cap_chan_put
CVE-2022-20567 l2tp: fix race in pppol2tp_release with session object destroy
CVE-2022-20568 Merge tag 'io_uring-worker.v3-2021-02-25' of git://git.kernel.dk/linux-block
CVE-2022-20572 dm verity: set DM_TARGET_IMMUTABLE feature flag
CVE-2022-2078 netfilter: nf_tables: sanitize nft_set_desc_concat_parse()
CVE-2022-21123 x86/speculation/mmio: Add mitigation for Processor MMIO Stale Data
CVE-2022-21125 x86/speculation/mmio: Reuse SRBDS mitigation for SBDS
CVE-2022-21166 x86/speculation/mmio: Enable CPU Fill buffer clearing on idle
CVE-2022-21385 net/rds: fix warn in rds_message_alloc_sgs
CVE-2022-21499 lockdown: also lock down previous kgdb use
CVE-2022-21505 lockdown: Fix kexec lockdown bypass with ima policy
CVE-2022-2153 KVM: x86: Avoid theoretical NULL pointer dereference in kvm_irq_delivery_to_apic_fast()
CVE-2022-2196 KVM: VMX: Execute IBPB on emulated VM-exit when guest has IBRS
CVE-2022-2209
CVE-2022-22942 drm/vmwgfx: Fix stale file descriptors on failed usercopy
CVE-2022-23036 xen/grant-table: add gnttab_try_end_foreign_access()
CVE-2022-23037 xen/netfront: don't use gnttab_query_foreign_access() for mapped status
CVE-2022-23038 xen/grant-table: add gnttab_try_end_foreign_access()
CVE-2022-23039 xen/gntalloc: don't use gnttab_query_foreign_access()
CVE-2022-23040 xen/xenbus: don't let xenbus_grant_ring() remove grants in error case
CVE-2022-23041 xen/9p: use alloc/free_pages_exact()
CVE-2022-23042 xen/netfront: react properly to failing gnttab_end_foreign_access_ref()
CVE-2022-2308 vduse: prevent uninitialized memory accesses
CVE-2022-2318 net: rose: fix UAF bugs caused by timer handler
CVE-2022-23222 bpf: Replace PTR_TO_XXX_OR_NULL with PTR_TO_XXX | PTR_MAYBE_NULL
CVE-2022-2327 io_uring: remove any grabbing of context
CVE-2022-2380 video: fbdev: sm712fb: Fix crash in smtcfb_read()
CVE-2022-23816 x86/kvm/vmx: Make noinstr clean
CVE-2022-23825
CVE-2022-23960 ARM: report Spectre v2 status through sysfs
CVE-2022-24122 ucount: Make get_ucount a safe get_user replacement
CVE-2022-24448 NFSv4: Handle case where the lookup of a directory fails
CVE-2022-24958 usb: gadget: don't release an existing dev->buf
CVE-2022-24959 yam: fix a memory leak in yam_siocdevprivate()
CVE-2022-2503 dm verity: set DM_TARGET_IMMUTABLE feature flag
CVE-2022-25258 USB: gadget: validate interface OS descriptor requests
CVE-2022-25265
CVE-2022-25375 usb: gadget: rndis: check size of RNDIS_MSG_SET command
CVE-2022-25636 netfilter: nf_tables_offload: incorrect flow offload action array size
CVE-2022-2585 posix-cpu-timers: Cleanup CPU timers before freeing them during exec
CVE-2022-2586 netfilter: nf_tables: do not allow SET_ID to refer to another table
CVE-2022-2588 net_sched: cls_route: remove from list when handle is 0
CVE-2022-2590 mm/gup: fix FOLL_FORCE COW security issue and remove FOLL_COW
CVE-2022-2602 io_uring/af_unix: defer registered files gc to io_uring release
CVE-2022-26365 xen/blkfront: fix leaking data in shared pages
CVE-2022-26373 x86/speculation: Add RSB VM Exit protections
CVE-2022-2639 openvswitch: fix OOB access in reserve_sfa_size()
CVE-2022-26490 nfc: st21nfca: Fix potential buffer overflows in EVT_TRANSACTION
CVE-2022-2663 netfilter: nf_conntrack_irc: Fix forged IP logic
CVE-2022-26878
CVE-2022-26966 sr9700: sanity check for packet length
CVE-2022-27223 USB: gadget: validate endpoint index for xilinx udc
CVE-2022-27666 esp: Fix possible buffer overflow in ESP transformation
CVE-2022-27672 x86/speculation: Identify processors vulnerable to SMT RSB predictions
CVE-2022-2785 bpf: Disallow bpf programs call prog_run command.
CVE-2022-27950 HID: elo: fix memory leak in elo_probe
CVE-2022-28356 llc: fix netdevice reference leaks in llc_ui_bind()
CVE-2022-28388 can: usb_8dev: usb_8dev_start_xmit(): fix double dev_kfree_skb() in error path
CVE-2022-28389 can: mcba_usb: mcba_usb_start_xmit(): fix double dev_kfree_skb in error path
CVE-2022-28390 can: ems_usb: ems_usb_start_xmit(): fix double dev_kfree_skb() in error path
CVE-2022-2873 i2c: ismt: prevent memory corruption in ismt_access()
CVE-2022-28796 jbd2: fix use-after-free of transaction_t race
CVE-2022-28893 SUNRPC: Ensure we flush any closed sockets before xs_xprt_free()
CVE-2022-2905 bpf: Don't use tnum_range on array range checking for poke descriptors
CVE-2022-29156 RDMA/rtrs-clt: Fix possible double free in error case
CVE-2022-2938 psi: Fix uaf issue when psi trigger is destroyed while being polled
CVE-2022-29581 net/sched: cls_u32: fix netns refcount changes in u32_change()
CVE-2022-29582 io_uring: fix race between timeout flush and removal
CVE-2022-2959 pipe: Fix missing lock in pipe_resize_ring()
CVE-2022-2961
CVE-2022-2964 net: usb: ax88179_178a: Fix out-of-bounds accesses in RX fixup
CVE-2022-2977 tpm: fix reference counting for struct tpm_chip
CVE-2022-2978 fs: fix UAF/GPF bug in nilfs_mdt_destroy
CVE-2022-29900 x86/kvm/vmx: Make noinstr clean
CVE-2022-29901 x86/kvm/vmx: Make noinstr clean
CVE-2022-2991 remove the lightnvm subsystem
CVE-2022-29968 io_uring: fix uninitialized field in rw io_kiocb
CVE-2022-3028 af_key: Do not call xfrm_probe_algs in parallel
CVE-2022-30594 ptrace: Check PTRACE_O_SUSPEND_SECCOMP permission on PTRACE_SEIZE
CVE-2022-3061 video: fbdev: i740fb: Error out if 'pixclock' equals zero
CVE-2022-3077 i2c: ismt: prevent memory corruption in ismt_access()
CVE-2022-3078 media: vidtv: Check for null return of vzalloc
CVE-2022-3103 io_uring: fix off-by-one in sync cancelation file check
CVE-2022-3104 lkdtm/bugs: Check for the NULL pointer after calling kmalloc
CVE-2022-3105 RDMA/uverbs: Check for null return of kmalloc_array
CVE-2022-3106 sfc_ef100: potential dereference of null pointer
CVE-2022-3107 hv_netvsc: Add check for kvmalloc_array
CVE-2022-3108 drm/amdkfd: Check for null pointer after calling kmemdup
CVE-2022-3110 staging: r8188eu: add check for kzalloc
CVE-2022-3111 power: supply: wm8350-power: Add missing free in free_charger_irq
CVE-2022-3112 media: meson: vdec: potential dereference of null pointer
CVE-2022-3113 media: mtk-vcodec: potential dereference of null pointer
CVE-2022-3114 clk: imx: Add check for kcalloc
CVE-2022-3115 drm: mali-dp: potential dereference of null pointer
CVE-2022-3169 nvme: ensure subsystem reset is single threaded
CVE-2022-3170
CVE-2022-3176 io_uring: fix UAF due to missing POLLFREE handling
CVE-2022-3202 jfs: prevent NULL deref in diFree
CVE-2022-32250 netfilter: nf_tables: disallow non-stateful expression in sets earlier
CVE-2022-32296 tcp: increase source port perturb table to 2^16
CVE-2022-3238
CVE-2022-3239 media: em28xx: initialize refcount before kref_get
CVE-2022-32981 powerpc/32: Fix overread/overwrite of thread_struct via ptrace
CVE-2022-3303 ALSA: pcm: oss: Fix race at SNDCTL_DSP_SYNC
CVE-2022-3344 KVM: x86: nSVM: harden svm_free_nested against freeing vmcb02 while still in use
CVE-2022-33740 xen/netfront: fix leaking data in shared pages
CVE-2022-33741 xen/netfront: force data bouncing when backend is untrusted
CVE-2022-33742 xen/blkfront: force data bouncing when backend is untrusted
CVE-2022-33743 xen-netfront: restore __skb_queue_tail() positioning in xennet_get_responses()
CVE-2022-33744 xen/arm: Fix race in RB-tree based P2M accounting
CVE-2022-33981 floppy: disable FDRAWCMD by default
CVE-2022-3424 misc: sgi-gru: fix use-after-free error in gru_set_context_option, gru_fault and gru_handle_user_call_os
CVE-2022-3435 ipv4: Handle attempt to delete multipath route when fib_info contains an nh reference
CVE-2022-34494 rpmsg: virtio: Fix possible double free in rpmsg_virtio_add_ctrl_dev()
CVE-2022-34495 rpmsg: virtio: Fix possible double free in rpmsg_probe()
CVE-2022-34918 netfilter: nf_tables: stricter validation of element data
CVE-2022-3521 kcm: avoid potential race in kcm_tx_work
CVE-2022-3522 mm/hugetlb: use hugetlb_pte_stable in migration race check
CVE-2022-3523 mm/memory.c: fix race when faulting a device private page
CVE-2022-3524 tcp/udp: Fix memory leak in ipv6_renew_options().
CVE-2022-3526 macvlan: Fix leaking skb in source mode with nodst option
CVE-2022-3531 selftest/bpf: Fix memory leak in kprobe_multi_test
CVE-2022-3532 selftests/bpf: Fix memory leak caused by not destroying skeleton
CVE-2022-3533
CVE-2022-3534 libbpf: Fix use-after-free in btf_dump_name_dups
CVE-2022-3535 net: mvpp2: fix mvpp2 debugfs leak
CVE-2022-3541 eth: sp7021: fix use after free bug in spl2sw_nvmem_get_mac_address
CVE-2022-3542 bnx2x: fix potential memory leak in bnx2x_tpa_stop()
CVE-2022-3543 af_unix: Fix memory leaks of the whole sk due to OOB skb.
CVE-2022-3544
CVE-2022-3545 nfp: fix use-after-free in area_cache_get()
CVE-2022-3564 Bluetooth: L2CAP: Fix use-after-free caused by l2cap_reassemble_sdu
CVE-2022-3565 mISDN: fix use-after-free bugs in l1oip timer handlers
CVE-2022-3566 tcp: Fix data races around icsk->icsk_af_ops.
CVE-2022-3567 ipv6: Fix data races around sk->sk_prot.
CVE-2022-3577 HID: bigben: fix slab-out-of-bounds Write in bigben_probe
CVE-2022-3586 sch_sfb: Don't assume the skb is still around after enqueueing to child
CVE-2022-3594 r8152: Rate limit overflow messages
CVE-2022-3595 cifs: fix double-fault crash during ntlmssp
CVE-2022-3606
CVE-2022-36123 x86: Clear .brk area at early boot
CVE-2022-3619 Bluetooth: L2CAP: Fix memory leak in vhci_write
CVE-2022-3621 nilfs2: fix NULL pointer dereference at nilfs_bmap_lookup_at_level()
CVE-2022-3623 mm/hugetlb: fix races when looking up a CONT-PTE/PMD size hugetlb page
CVE-2022-3624 bonding: fix reference count leak in balance-alb mode
CVE-2022-3625 devlink: Fix use-after-free after a failed reload
CVE-2022-3628 wifi: brcmfmac: Fix potential buffer overflow in brcmf_fweh_event_worker()
CVE-2022-36280 drm/vmwgfx: Validate the box size for the snooped cursor
CVE-2022-3629 vsock: Fix memory leak in vsock_connect()
CVE-2022-3630 fscache: don't leak cookie access refs if invalidation is in progress or failed
CVE-2022-3633 can: j1939: j1939_session_destroy(): fix memory leak of skbs
CVE-2022-3635 atm: idt77252: fix use-after-free bugs caused by tst_timer
CVE-2022-3636 net: ethernet: mtk_eth_soc: use after free in __mtk_ppe_check_skb()
CVE-2022-3640 Bluetooth: L2CAP: fix use-after-free in l2cap_conn_del()
CVE-2022-36402 drm/vmwgfx: Fix shader stage validation
CVE-2022-3642
CVE-2022-3643 xen/netback: Ensure protocol headers don't fall in the non-linear area
CVE-2022-3646 nilfs2: fix leak of nilfs_root in case of writer thread creation failure
CVE-2022-3649 nilfs2: fix use-after-free bug of struct nilfs_root
CVE-2022-36879 xfrm: xfrm_policy: fix a possible double xfrm_pols_put() in xfrm_bundle_lookup()
CVE-2022-36946 netfilter: nf_queue: do not allow packet truncation below transport header offset
CVE-2022-3707 drm/i915/gvt: fix double free bug in split_2MB_gtt_entry
CVE-2022-38096
CVE-2022-38457 drm/vmwgfx: Remove rcu locks from user resources
CVE-2022-3903 media: mceusb: Use new usb_control_msg_*() routines
CVE-2022-3910 io_uring/msg_ring: check file type before putting
CVE-2022-39188 mmu_gather: Force tlb-flush VM_PFNMAP vmas
CVE-2022-39189 KVM: x86: do not report a vCPU as preempted outside instruction boundaries
CVE-2022-39190 netfilter: nf_tables: disallow binding to already bound chain
CVE-2022-3977 mctp: prevent double key removal and unref
CVE-2022-39842 video: fbdev: pxa3xx-gcu: Fix integer overflow in pxa3xx_gcu_write
CVE-2022-40133 drm/vmwgfx: Remove rcu locks from user resources
CVE-2022-40307 efi: capsule-loader: Fix use-after-free in efi_capsule_write
CVE-2022-40476
CVE-2022-40768 scsi: stex: Properly zero out the passthrough command structure
CVE-2022-4095 staging: rtl8712: fix use after free bugs
CVE-2022-40982 x86/speculation: Add Gather Data Sampling mitigation
CVE-2022-41218 media: dvb-core: Fix UAF due to refcount races at releasing
CVE-2022-41222 mm/mremap: hold the rmap lock in write mode when moving page table entries.
CVE-2022-4127 io_uring: check that we have a file table when allocating update slots
CVE-2022-4128 mptcp: fix subflow traversal at disconnect time
CVE-2022-4129 l2tp: Serialize access to sk_user_data with sk_callback_lock
CVE-2022-4139 drm/i915: fix TLB invalidation for Gen12 video and compute engines
CVE-2022-41674 wifi: cfg80211: fix u8 overflow in cfg80211_update_notlisted_nontrans()
CVE-2022-41848
CVE-2022-41849 fbdev: smscufx: Fix use-after-free in ufx_ops_open()
CVE-2022-41850 HID: roccat: Fix use-after-free in roccat_read()
CVE-2022-41858 drivers: net: slip: fix NPD bug in sl_tx_timeout()
CVE-2022-42328 xen/netback: don't call kfree_skb() with interrupts disabled
CVE-2022-42329 xen/netback: don't call kfree_skb() with interrupts disabled
CVE-2022-42432 netfilter: nfnetlink_osf: fix possible bogus match in nf_osf_find()
CVE-2022-4269 act_mirred: use the backlog for nested calls to mirred ingress
CVE-2022-42703 mm/rmap: Fix anon_vma->degree ambiguity leading to double-reuse
CVE-2022-42719 wifi: mac80211: fix MBSSID parsing use-after-free
CVE-2022-42720 wifi: cfg80211: fix BSS refcounting bugs
CVE-2022-42721 wifi: cfg80211: avoid nontransmitted BSS list corruption
CVE-2022-42722 wifi: mac80211: fix crash in beacon protection for P2P-device
CVE-2022-42895 Bluetooth: L2CAP: Fix attempting to access uninitialized memory
CVE-2022-42896 Bluetooth: L2CAP: Fix accepting connection request for invalid SPSM
CVE-2022-43750 usb: mon: make mmapped memory read only
CVE-2022-4378 proc: proc_skip_spaces() shouldn't think it is working on C strings
CVE-2022-4379 NFSD: fix use-after-free in __nfs42_ssc_open()
CVE-2022-4382 USB: gadgetfs: Fix race between mounting and unmounting
CVE-2022-43945 NFSD: Protect against send buffer overflow in NFSv2 READDIR
CVE-2022-44032 char: pcmcia: remove all the drivers
CVE-2022-44033 char: pcmcia: remove all the drivers
CVE-2022-44034 char: pcmcia: remove all the drivers
CVE-2022-4543
CVE-2022-45869 KVM: x86/mmu: Fix race condition in direct_page_fault
CVE-2022-45884
CVE-2022-45885
CVE-2022-45886 media: dvb-core: Fix use-after-free due on race condition at dvb_net
CVE-2022-45887 media: ttusb-dec: fix memory leak in ttusb_dec_exit_dvb()
CVE-2022-45888 char: xillybus: Prevent use-after-free due to race condition
CVE-2022-45919 media: dvb-core: Fix use-after-free due to race condition at dvb_ca_en50221
CVE-2022-45934 Bluetooth: L2CAP: Fix u8 overflow
CVE-2022-4662 USB: core: Prevent nested device-reset calls
CVE-2022-4696 io_uring: remove any grabbing of context
CVE-2022-4744 tun: avoid double free in tun_free_netdev
CVE-2022-47518 wifi: wilc1000: validate number of channels
CVE-2022-47519 wifi: wilc1000: validate length of IEEE80211_P2P_ATTR_OPER_CHANNEL attribute
CVE-2022-47520 wifi: wilc1000: validate pairwise and authentication suite offsets
CVE-2022-47521 wifi: wilc1000: validate length of IEEE80211_P2P_ATTR_CHANNEL_LIST attribute
CVE-2022-47929 net: sched: disallow noqueue for qdisc classes
CVE-2022-47938 ksmbd: prevent out of bound read for SMB2_TREE_CONNNECT
CVE-2022-47939 ksmbd: fix use-after-free bug in smb2_tree_disconect
CVE-2022-47940 ksmbd: validate length in smb2_write()
CVE-2022-47941 ksmbd: fix memory leak in smb2_handle_negotiate
CVE-2022-47942 ksmbd: fix heap-based overflow in set_ntacl_dacl()
CVE-2022-47943 ksmbd: prevent out of bound read for SMB2_WRITE
CVE-2022-47946 io_uring: kill sqo_dead and sqo submission halting
CVE-2022-4842 fs/ntfs3: Fix attr_punch_hole() null pointer derenference
CVE-2022-48423 fs/ntfs3: Validate resident attribute name
CVE-2022-48424 fs/ntfs3: Validate attribute name offset
CVE-2022-48425 fs/ntfs3: Validate MFT flags before replaying logs
CVE-2022-48502 fs/ntfs3: Check fields while reading
CVE-2022-48619 Input: add bounds checking to input_set_capability()
CVE-2023-0030 drm/nouveau/mmu: add more general vmm free/node handling functions
CVE-2023-0045 x86/bugs: Flush IBP in ib_prctl_set()
CVE-2023-0047 mm, oom: do not trigger out_of_memory from the #PF
CVE-2023-0122
CVE-2023-0160 bpf, sockmap: fix deadlocks in the sockhash and sockmap
CVE-2023-0179 netfilter: nft_payload: incorrect arithmetics when fetching VLAN header bits
CVE-2023-0210 ksmbd: check nt_len to be at least CIFS_ENCPWD_SIZE in ksmbd_decode_ntlmssp_auth_blob
CVE-2023-0240 io_uring: COW io_identity on mismatch
CVE-2023-0266 ALSA: pcm: Move rwsem lock inside snd_ctl_elem_read to prevent UAF
CVE-2023-0386 ovl: fail on invalid uid/gid mapping at copy up
CVE-2023-0394 ipv6: raw: Deduct extension header length in rawv6_push_pending_frames
CVE-2023-0458 prlimit: do_prlimit needs to have a speculation check
CVE-2023-0459 uaccess: Add speculation barrier to copy_from_user()
CVE-2023-0461 net/ulp: prevent ULP without clone op from entering the LISTEN status
CVE-2023-0468 io_uring: make poll refs more robust
CVE-2023-0469 io_uring/filetable: fix file reference underflow
CVE-2023-0590 net: sched: fix race condition in qdisc_graft()
CVE-2023-0597 x86/mm: Randomize per-cpu entry area
CVE-2023-0615 media: vivid: dev->bitmap_cap wasn't freed in all cases
CVE-2023-1032 net: avoid double iput when sock_alloc_file fails
CVE-2023-1073 HID: check empty report_list in hid_validate_values()
CVE-2023-1074 sctp: fail if no bound addresses can be used for a given scope
CVE-2023-1075 net/tls: tls_is_tx_ready() checked list_entry
CVE-2023-1076 tun: tun_chr_open(): correctly initialize socket uid
CVE-2023-1077 sched/rt: pick_next_rt_entity(): check list_entry
CVE-2023-1078 rds: rds_rm_zerocopy_callback() use list_first_entry()
CVE-2023-1079 HID: asus: use spinlock to safely schedule workers
CVE-2023-1095 netfilter: nf_tables: fix null deref due to zeroed list head
CVE-2023-1118 media: rc: Fix use-after-free bugs caused by ene_tx_irqsim()
CVE-2023-1192 fs/ntfs3: Validate MFT flags before replaying logs
CVE-2023-1193 ksmbd: delete asynchronous work from list
CVE-2023-1194 ksmbd: fix out-of-bound read in parse_lease_state()
CVE-2023-1195 cifs: fix use-after-free caused by invalid pointer `hostname`
CVE-2023-1206 tcp: Reduce chance of collisions in inet6_hashfn().
CVE-2023-1249 coredump: Use the vma snapshot in fill_files_note
CVE-2023-1252 ovl: fix use after free in struct ovl_aio_req
CVE-2023-1281 net/sched: tcindex: update imperfect hash filters respecting rcu
CVE-2023-1295 io_uring: get rid of intermediate IORING_OP_CLOSE stage
CVE-2023-1380 wifi: brcmfmac: slab-out-of-bounds read in brcmf_get_assoc_ies()
CVE-2023-1382 tipc: set con sock in tipc_conn_alloc
CVE-2023-1390 tipc: fix NULL deref in tipc_link_xmit()
CVE-2023-1476
CVE-2023-1513 kvm: initialize all of the kvm_debugregs structure before sending it to userspace
CVE-2023-1582 fs/proc: task_mmu.c: don't read mapcount for migration entry
CVE-2023-1583 io_uring/rsrc: fix null-ptr-deref in io_file_bitmap_get()
CVE-2023-1611 btrfs: fix race between quota disable and quota assign ioctls
CVE-2023-1637 x86/speculation: Restore speculation related MSRs during S3 resume
CVE-2023-1652 NFSD: fix use-after-free in nfsd4_ssc_setup_dul()
CVE-2023-1670 xirc2ps_cs: Fix use after free bug in xirc2ps_detach
CVE-2023-1829 net/sched: Retire tcindex classifier
CVE-2023-1838 Fix double fget() in vhost_net_set_backend()
CVE-2023-1855 hwmon: (xgene) Fix use after free bug in xgene_hwmon_remove due to race condition
CVE-2023-1859 9p/xen : Fix use after free bug in xen_9pfs_front_remove due to race condition
CVE-2023-1872 io_uring: propagate issue_flags state down to file assignment
CVE-2023-1989 Bluetooth: btsdio: fix use after free bug in btsdio_remove due to unfinished work
CVE-2023-1990 nfc: st-nci: Fix use after free bug in ndlc_remove due to race condition
CVE-2023-1998 x86/speculation: Allow enabling STIBP with legacy IBRS
CVE-2023-2002 bluetooth: Perform careful capability checks in hci_sock_ioctl()
CVE-2023-2006 rxrpc: Fix race between conn bundle lookup and bundle removal [ZDI-CAN-15975]
CVE-2023-2007 scsi: dpt_i2o: Remove obsolete driver
CVE-2023-2008 udmabuf: add back sanity check
CVE-2023-2019 netdevsim: fib: Fix reference count leak on route deletion failure
CVE-2023-20569 x86/bugs: Increase the x86 bugs vector size to two u32s
CVE-2023-20588 x86/CPU/AMD: Do not leak quotient data after a division by 0
CVE-2023-20593 x86/cpu/amd: Add a Zenbleed fix
CVE-2023-20928 android: binder: stop saving a pointer to the VMA
CVE-2023-20937
CVE-2023-20938 binder: Gracefully handle BINDER_TYPE_FDA objects with num_fds=0
CVE-2023-20941
CVE-2023-21102 efi: rt-wrapper: Add missing include
CVE-2023-21106 drm/msm/gpu: Fix potential double-free
CVE-2023-2124 xfs: verify buffer contents when we skip log replay
CVE-2023-21255 binder: fix UAF caused by faulty buffer cleanup
CVE-2023-21264 KVM: arm64: Prevent unconditional donation of unmapped regions from the host
CVE-2023-21400
CVE-2023-2156 net: rpl: fix rpl header size calculation
CVE-2023-2162 scsi: iscsi_tcp: Fix UAF during login when accessing the shost ipaddress
CVE-2023-2163 bpf: Fix incorrect verifier pruning due to missing register precision taints
CVE-2023-2166 can: af_can: fix NULL pointer dereference in can_rcv_filter
CVE-2023-2176 RDMA/core: Refactor rdma_bind_addr
CVE-2023-2177 sctp: leave the err path free in sctp_stream_init to sctp_stream_free
CVE-2023-2194 i2c: xgene-slimpro: Fix out-of-bounds bug in xgene_slimpro_i2c_xfer()
CVE-2023-2235 perf: Fix check before add_event_to_groups() in perf_group_detach()
CVE-2023-2236 io_uring/filetable: fix file reference underflow
CVE-2023-2248 net: sched: sch_qfq: prevent slab-out-of-bounds in qfq_activate_agg
CVE-2023-2269 dm ioctl: fix nested locking in table_clear() to remove deadlock concern
CVE-2023-22995 usb: dwc3: dwc3-qcom: Add missing platform_device_put() in dwc3_qcom_acpi_register_core
CVE-2023-22996 soc: qcom: aoss: Fix missing put_device call in qmp_get
CVE-2023-22997 module: Fix NULL vs IS_ERR checking for module_get_next_page
CVE-2023-22998 drm/virtio: Fix NULL vs IS_ERR checking in virtio_gpu_object_shmem_init
CVE-2023-22999 usb: dwc3: qcom: Fix NULL vs IS_ERR checking in dwc3_qcom_probe
CVE-2023-23000 phy: tegra: xusb: Fix return value of tegra_xusb_find_port_node function
CVE-2023-23001 scsi: ufs: ufs-mediatek: Fix error checking in ufs_mtk_init_va09_pwr_ctrl()
CVE-2023-23002 Bluetooth: hci_qca: Fix NULL vs IS_ERR_OR_NULL check in qca_serdev_probe
CVE-2023-23003
CVE-2023-23004 malidp: Fix NULL vs IS_ERR() checking
CVE-2023-23005 mm/demotion: fix NULL vs IS_ERR checking in memory_tier_init
CVE-2023-23006 net/mlx5: DR, Fix NULL vs IS_ERR checking in dr_domain_init_resources
CVE-2023-23039
CVE-2023-23454 net: sched: cbq: dont intepret cls results when asked to drop
CVE-2023-23455 net: sched: atm: dont intepret cls results when asked to drop
CVE-2023-23559 wifi: rndis_wlan: Prevent buffer overflow in rndis_query_oid
CVE-2023-23586 io_uring: remove io_identity
CVE-2023-2430 io_uring/msg_ring: fix missing lock on overflow for IOPOLL
CVE-2023-2483 net: qcom/emac: Fix use after free bug in emac_remove due to race condition
CVE-2023-25012 HID: bigben: use spinlock to safely schedule workers
CVE-2023-2513 ext4: fix use-after-free in ext4_xattr_set_entry
CVE-2023-25775 RDMA/irdma: Prevent zero-length STAG registration
CVE-2023-2598 io_uring/rsrc: check for nonconsecutive pages
CVE-2023-26242
CVE-2023-2640
CVE-2023-26544 fs/ntfs3: Fix slab-out-of-bounds read in run_unpack
CVE-2023-26545 net: mpls: fix stale pointer if allocation fails during device rename
CVE-2023-26605
CVE-2023-26606 fs/ntfs3: Fix slab-out-of-bounds read in ntfs_trim_fs
CVE-2023-26607 ntfs: fix out-of-bounds read in ntfs_attr_find()
CVE-2023-28327 af_unix: Get user_ns from in_skb in unix_diag_get_exact().
CVE-2023-28328 media: dvb-usb: az6027: fix null-ptr-deref in az6027_i2c_xfer()
CVE-2023-28410 drm/i915/gem: add missing boundary check in vm_access
CVE-2023-28464
CVE-2023-28466 net: tls: fix possible race condition between do_tls_getsockopt_conf() and do_tls_setsockopt_conf()
CVE-2023-2860 ipv6: sr: fix out-of-bounds read when setting HMAC data.
CVE-2023-28772 seq_buf: Fix overflow in seq_buf_putmem_hex()
CVE-2023-28866 Bluetooth: HCI: Fix global-out-of-bounds
CVE-2023-2898 f2fs: fix to avoid NULL pointer dereference f2fs_write_end_io()
CVE-2023-2985 fs: hfsplus: fix UAF issue in hfsplus_put_super
CVE-2023-3006 arm64: Add AMPERE1 to the Spectre-BHB affected list
CVE-2023-3022 ipv6: Use result arg in fib_lookup_arg consistently
CVE-2023-30456 KVM: nVMX: add missing consistency checks for CR0 and CR4
CVE-2023-30772 power: supply: da9150: Fix use after free bug in da9150_charger_remove due to race condition
CVE-2023-3090 ipvlan:Fix out-of-bounds caused by unclear skb->cb
CVE-2023-3106 xfrm: fix crash in XFRM_MSG_GETSA netlink handler
CVE-2023-3108 crypto: fix af_alg_make_sg() conversion to iov_iter
CVE-2023-31081
CVE-2023-31082
CVE-2023-31083 Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO
CVE-2023-31084 media: dvb-core: Fix kernel WARNING for blocking operation in wait_event*()
CVE-2023-31085 ubi: Refuse attaching if mtd's erasesize is 0
CVE-2023-3111 btrfs: unset reloc control if transaction commit fails in prepare_to_relocate()
CVE-2023-3117 netfilter: nf_tables: incorrect error path handling with NFT_MSG_NEWRULE
CVE-2023-31248 netfilter: nf_tables: do not ignore genmask when looking up chain by id
CVE-2023-3141 memstick: r592: Fix UAF bug in r592_remove due to race condition
CVE-2023-31436 net: sched: sch_qfq: prevent slab-out-of-bounds in qfq_activate_agg
CVE-2023-3159 firewire: fix potential uaf in outbound_phy_packet_callback()
CVE-2023-3161 fbcon: Check font dimension limits
CVE-2023-3212 gfs2: Don't deref jdesc in evict
CVE-2023-3220 drm/msm/dpu: Add check for pstates
CVE-2023-32233 netfilter: nf_tables: deactivate anonymous set from preparation phase
CVE-2023-32247 ksmbd: destroy expired sessions
CVE-2023-32248 ksmbd: fix NULL pointer dereference in smb2_get_info_filesystem()
CVE-2023-32250 ksmbd: fix racy issue from session setup and logoff
CVE-2023-32252 ksmbd: fix racy issue from session setup and logoff
CVE-2023-32254 ksmbd: fix racy issue under cocurrent smb2 tree disconnect
CVE-2023-32257 ksmbd: fix racy issue from session setup and logoff
CVE-2023-32258 ksmbd: fix racy issue from smb2 close and logoff with multichannel
CVE-2023-32269 netrom: Fix use-after-free caused by accept on already connected socket
CVE-2023-32629
CVE-2023-3268 relayfs: fix out-of-bounds access in relay_file_read
CVE-2023-3269 mm: introduce new 'lock_mm_and_find_vma()' page fault helper
CVE-2023-3312 cpufreq: qcom-cpufreq-hw: fix double IO unmap and resource release on exit
CVE-2023-3317 wifi: mt76: mt7921: Fix use-after-free in fw features query.
CVE-2023-33203 net: qcom/emac: Fix use after free bug in emac_remove due to race condition
CVE-2023-33250 iommufd: Call iopt_area_contig_done() under the lock
CVE-2023-33288 power: supply: bq24190: Fix use after free bug in bq24190_remove due to race condition
CVE-2023-3338 Remove DECnet support from kernel
CVE-2023-3355 drm/msm/gem: Add check for kmalloc
CVE-2023-3357 HID: amd_sfh: Add missing check for dma_alloc_coherent
CVE-2023-3358 HID: intel_ish-hid: Add check for ishtp_dma_tx_map
CVE-2023-3359 nvmem: brcm_nvram: Add check for kzalloc
CVE-2023-3389 io_uring: mutex locked poll hashing
CVE-2023-3390 netfilter: nf_tables: incorrect error path handling with NFT_MSG_NEWRULE
CVE-2023-33951 drm/vmwgfx: Do not drop the reference to the handle too soon
CVE-2023-33952 drm/vmwgfx: Do not drop the reference to the handle too soon
CVE-2023-3397
CVE-2023-34255 xfs: verify buffer contents when we skip log replay
CVE-2023-34256 ext4: avoid a potential slab-out-of-bounds in ext4_group_desc_csum
CVE-2023-34319 xen/netback: Fix buffer overrun triggered by unusual packet
CVE-2023-34324 xen/events: replace evtchn_rwlock with RCU
CVE-2023-3439 mctp: defer the kfree of object mdev->addrs
CVE-2023-35001 netfilter: nf_tables: prevent OOB access in nft_byteorder_eval
CVE-2023-3567 vc_screen: move load of struct vc_data pointer in vcs_read() to avoid UAF
CVE-2023-35693
CVE-2023-35788 net/sched: flower: fix possible OOB write in fl_set_geneve_opt()
CVE-2023-35823 media: saa7134: fix use after free bug in saa7134_finidev due to race condition
CVE-2023-35824 media: dm1105: Fix use after free bug in dm1105_remove due to race condition
CVE-2023-35826 media: cedrus: fix use after free bug in cedrus_remove due to race condition
CVE-2023-35827 ravb: Fix use-after-free issue in ravb_tx_timeout_work()
CVE-2023-35828 usb: gadget: udc: renesas_usb3: Fix use after free bug in renesas_usb3_remove due to race condition
CVE-2023-35829 media: rkvdec: fix use after free bug in rkvdec_remove
CVE-2023-3609 net/sched: cls_u32: Fix reference counter leak leading to overflow
CVE-2023-3610 netfilter: nf_tables: fix chain binding transaction logic
CVE-2023-3611 net/sched: sch_qfq: account for stab overhead in qfq_enqueue
CVE-2023-3640
CVE-2023-37453 USB: core: Fix race by not overwriting udev->descriptor in hub_port_init()
CVE-2023-37454
CVE-2023-3772 xfrm: add NULL check in xfrm_update_ae_params
CVE-2023-3773 xfrm: add forgotten nla_policy for XFRMA_MTIMER_THRESH
CVE-2023-3776 net/sched: cls_fw: Fix improper refcount update leads to use-after-free
CVE-2023-3777 netfilter: nf_tables: skip bound chain on rule flush
CVE-2023-3812 net: tun: fix bugs for oversize packet when napi frags enabled
CVE-2023-38409 fbcon: set_con2fb_map needs to set con2fb_map!
CVE-2023-38426 ksmbd: fix global-out-of-bounds in smb2_find_context_vals
CVE-2023-38427 ksmbd: fix out-of-bound read in deassemble_neg_contexts()
CVE-2023-38428 ksmbd: fix wrong UserName check in session_user
CVE-2023-38429 ksmbd: allocate one more byte for implied bcc[0]
CVE-2023-38430 ksmbd: validate smb request protocol id
CVE-2023-38431 ksmbd: check the validation of pdu_size in ksmbd_conn_handler_loop
CVE-2023-38432 ksmbd: validate command payload size
CVE-2023-3863 net: nfc: Fix use-after-free caused by nfc_llcp_find_local
CVE-2023-3865 ksmbd: fix out-of-bound read in smb2_write
CVE-2023-3866 ksmbd: validate session id and tree id in the compound request
CVE-2023-3867 ksmbd: add missing compound request handing in some commands
CVE-2023-39189 netfilter: nfnetlink_osf: avoid OOB read
CVE-2023-39191 bpf: Fix state pruning for STACK_DYNPTR stack slots
CVE-2023-39192 netfilter: xt_u32: validate user space input
CVE-2023-39193 netfilter: xt_sctp: validate the flag_info count
CVE-2023-39194 net: xfrm: Fix xfrm_address_filter OOB read
CVE-2023-39197 netfilter: conntrack: dccp: copy entire header to stack buffer, not just basic one
CVE-2023-39198 drm/qxl: fix UAF on handle creation
CVE-2023-4004 netfilter: nft_set_pipapo: fix improper element removal
CVE-2023-4010
CVE-2023-4015 netfilter: nf_tables: skip immediate deactivate in _PREPARE_ERROR
CVE-2023-40283 Bluetooth: L2CAP: Fix use-after-free in l2cap_sock_ready_cb
CVE-2023-40791 crypto, cifs: fix error handling in extract_iter_to_sg()
CVE-2023-4128 net/sched: cls_u32: No longer copy tcf_result on update to avoid use-after-free
CVE-2023-4132 media: usb: siano: Fix warning due to null work_func_t function pointer
CVE-2023-4133 cxgb4: fix use after free bugs caused by circular dependency problem
CVE-2023-4134 Input: cyttsp4_core - change del_timer_sync() to timer_shutdown_sync()
CVE-2023-4147 netfilter: nf_tables: disallow rule addition to bound chain via NFTA_RULE_CHAIN_ID
CVE-2023-4155 KVM: SEV: only access GHCB fields once
CVE-2023-4194 net: tun_chr_open(): set sk_uid from current_fsuid()
CVE-2023-4206 net/sched: cls_route: No longer copy tcf_result on update to avoid use-after-free
CVE-2023-4207 net/sched: cls_fw: No longer copy tcf_result on update to avoid use-after-free
CVE-2023-4208 net/sched: cls_u32: No longer copy tcf_result on update to avoid use-after-free
CVE-2023-4244 netfilter: nf_tables: fix GC transaction races with netns and netlink event exit path
CVE-2023-4273 exfat: check if filename entries exceeds max filename length
CVE-2023-42752 igmp: limit igmpv3_newpack() packet size to IP_MAX_MTU
CVE-2023-42753 netfilter: ipset: add the missing IP_SET_HASH_WITH_NET0 macro for ip_set_hash_netportnet.c
CVE-2023-42754 ipv4: fix null-deref in ipv4_link_failure
CVE-2023-42755 net/sched: Retire rsvp classifier
CVE-2023-42756 netfilter: ipset: Fix race between IPSET_CMD_CREATE and IPSET_CMD_SWAP
CVE-2023-4385 fs: jfs: fix possible NULL pointer dereference in dbFree()
CVE-2023-4387 net: vmxnet3: fix possible use-after-free bugs in vmxnet3_rq_alloc_rx_buf()
CVE-2023-4389 btrfs: fix root ref counts in error handling in btrfs_get_root_ref
CVE-2023-4394 btrfs: fix possible memory leak in btrfs_get_dev_args_from_path()
CVE-2023-44466 libceph: harden msgr2.1 frame segment length checks
CVE-2023-4459 net: vmxnet3: fix possible NULL pointer dereference in vmxnet3_rq_cleanup()
CVE-2023-4563 netfilter: nf_tables: don't skip expired elements during walk
CVE-2023-4569 netfilter: nf_tables: deactivate catchall elements in next generation
CVE-2023-45862 USB: ene_usb6250: Allocate enough memory for full object
CVE-2023-45863 kobject: Fix slab-out-of-bounds in fill_kobj_path()
CVE-2023-45871 igb: set max size RX buffer when store bad packet is enabled
CVE-2023-45898 ext4: fix slab-use-after-free in ext4_es_insert_extent()
CVE-2023-4610 Revert "mm: vmscan: make global slab shrink lockless"
CVE-2023-4611 mm/mempolicy: Take VMA lock before replacing policy
CVE-2023-4622 unix: Convert unix_stream_sendpage() to use MSG_SPLICE_PAGES
CVE-2023-4623 net/sched: sch_hfsc: Ensure inner classes have fsc curve
CVE-2023-46343 nfc: nci: fix possible NULL pointer dereference in send_acknowledge()
CVE-2023-46813 x86/sev: Check for user-space IOIO pointing to kernel space
CVE-2023-46838 xen-netback: don't produce zero-size SKB frags
CVE-2023-46862 io_uring/fdinfo: lock SQ thread while retrieving thread cpu/pid
CVE-2023-47233
CVE-2023-4732 mm/userfaultfd: fix uffd-wp special cases for fork()
CVE-2023-4881 netfilter: nftables: exthdr: fix 4-byte stack OOB write
CVE-2023-4921 net: sched: sch_qfq: Fix UAF in qfq_dequeue()
CVE-2023-50431 accel/habanalabs: fix information leak in sec_attest_info()
CVE-2023-5090 x86: KVM: SVM: always update the x2avic msr interception
CVE-2023-51042 drm/amdgpu: Fix potential fence use-after-free v2
CVE-2023-51043 drm/atomic: Fix potential use-after-free in nonblocking commits
CVE-2023-5158 vringh: don't use vringh_kiov_advance() in vringh_iov_xfer()
CVE-2023-51779 Bluetooth: af_bluetooth: Fix Use-After-Free in bt_sock_recvmsg
CVE-2023-5178 nvmet-tcp: Fix a possible UAF in queue intialization setup
CVE-2023-51780 atm: Fix Use-After-Free in do_vcc_ioctl
CVE-2023-51781 appletalk: Fix Use-After-Free in atalk_ioctl
CVE-2023-51782 net/rose: Fix Use-After-Free in rose_ioctl
CVE-2023-5197 netfilter: nf_tables: disallow rule removal from chain binding
CVE-2023-52340 ipv6: remove max_size check inline with ipv4
CVE-2023-52429 dm: limit the number of targets and parameter size area
CVE-2023-52433 netfilter: nft_set_rbtree: skip sync GC for new elements in this transaction
CVE-2023-52434 smb: client: fix potential OOBs in smb2_parse_contexts()
CVE-2023-52435 net: prevent mss overflow in skb_segment()
CVE-2023-52436 f2fs: explicitly null-terminate the xattr list
CVE-2023-52438 binder: fix use-after-free in shinker's callback
CVE-2023-52439 uio: Fix use-after-free in uio_open
CVE-2023-52440 ksmbd: fix slub overflow in ksmbd_decode_ntlmssp_auth_blob()
CVE-2023-52441 ksmbd: fix out of bounds in init_smb2_rsp_hdr()
CVE-2023-52442 ksmbd: validate session id and tree id in compound request
CVE-2023-52443 apparmor: avoid crash when parsed profile name is empty
CVE-2023-52444 f2fs: fix to avoid dirent corruption
CVE-2023-52445 media: pvrusb2: fix use after free on context disconnection
CVE-2023-52446 bpf: Fix a race condition between btf_put() and map_free()
CVE-2023-52447 bpf: Defer the free of inner map when necessary
CVE-2023-52448 gfs2: Fix kernel NULL pointer dereference in gfs2_rgrp_dump
CVE-2023-52449 mtd: Fix gluebi NULL pointer dereference caused by ftl notifier
CVE-2023-52450 perf/x86/intel/uncore: Fix NULL pointer dereference issue in upi_fill_topology()
CVE-2023-52451 powerpc/pseries/memhp: Fix access beyond end of drmem array
CVE-2023-52452 bpf: Fix accesses to uninit stack slots
CVE-2023-52453 hisi_acc_vfio_pci: Update migration data pointer correctly on saving/resume
CVE-2023-52454 nvmet-tcp: Fix a kernel panic when host sends an invalid H2C PDU length
CVE-2023-52455 iommu: Don't reserve 0-length IOVA region
CVE-2023-52456 serial: imx: fix tx statemachine deadlock
CVE-2023-52457 serial: 8250: omap: Don't skip resource freeing if pm_runtime_resume_and_get() failed
CVE-2023-52458 block: add check that partition length needs to be aligned with block size
CVE-2023-52459 media: v4l: async: Fix duplicated list deletion
CVE-2023-52460 drm/amd/display: Fix NULL pointer dereference at hibernate
CVE-2023-52461 drm/sched: Fix bounds limiting when given a malformed entity
CVE-2023-52462 bpf: fix check for attempt to corrupt spilled pointer
CVE-2023-52463 efivarfs: force RO when remounting if SetVariable is not supported
CVE-2023-52464 EDAC/thunderx: Fix possible out-of-bounds string access
CVE-2023-5345 fs/smb/client: Reset password pointer to NULL
CVE-2023-5633 drm/vmwgfx: Keep a gem reference to user bos in surfaces
CVE-2023-5717 perf: Disallow mis-matched inherited group reads
CVE-2023-5972 nf_tables: fix NULL pointer dereference in nft_expr_inner_parse()
CVE-2023-6039 net: usb: lan78xx: reorder cleanup operations to avoid UAF bugs
CVE-2023-6040 netfilter: nf_tables: Reject tables of unsupported family
CVE-2023-6111 netfilter: nf_tables: remove catchall element in GC sync path
CVE-2023-6121 nvmet: nul-terminate the NQNs passed in the connect command
CVE-2023-6176 net/tls: do not free tls_rec on async operation in bpf_exec_tx_verdict()
CVE-2023-6200 net/ipv6: Revert remove expired routes with a separated list of routes
CVE-2023-6238
CVE-2023-6240
CVE-2023-6270
CVE-2023-6356
CVE-2023-6531 io_uring/af_unix: disable sending io_uring over sockets
CVE-2023-6535
CVE-2023-6536
CVE-2023-6546 tty: n_gsm: fix the UAF caused by race condition in gsm_cleanup_mux
CVE-2023-6560 io_uring: don't allow discontig pages for IORING_SETUP_NO_MMAP
CVE-2023-6606 smb: client: fix OOB in smbCalcSize()
CVE-2023-6610 smb: client: fix potential OOB in smb2_dump_detail()
CVE-2023-6622 netfilter: nf_tables: bail out on mismatching dynset and set expressions
CVE-2023-6679 dpll: sanitize possible null pointer dereference in dpll_pin_parent_pin_set()
CVE-2023-6817 netfilter: nft_set_pipapo: skip inactive elements during set walk
CVE-2023-6915 ida: Fix crash in ida_free when the bitmap is empty
CVE-2023-6931 perf: Fix perf_event_validate_size()
CVE-2023-6932 ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet
CVE-2023-7042
CVE-2023-7192 netfilter: ctnetlink: fix possible refcount leak in ctnetlink_create_conntrack()
CVE-2024-0193 netfilter: nf_tables: skip set commit for deleted/destroyed sets
CVE-2024-0340 vhost: use kzalloc() instead of kmalloc() followed by memset()
CVE-2024-0443 blk-cgroup: Flush stats before releasing blkcg_gq
CVE-2024-0562 writeback: avoid use-after-free after removing device
CVE-2024-0564
CVE-2024-0565 smb: client: fix OOB in receive_encrypted_standard()
CVE-2024-0582 io_uring/kbuf: defer release of mapped buffer rings
CVE-2024-0584 ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet
CVE-2024-0607 netfilter: nf_tables: fix pointer math issue in nft_byteorder_eval()
CVE-2024-0639 sctp: fix potential deadlock on &net->sctp.addr_wq_lock
CVE-2024-0641 tipc: fix a potential deadlock on &tx->lock
CVE-2024-0646 net: tls, update curr on splice as well
CVE-2024-0775 ext4: improve error recovery code paths in __ext4_remount()
CVE-2024-0841
CVE-2024-1085 netfilter: nf_tables: check if catch-all set element is active in next generation
CVE-2024-1086 netfilter: nf_tables: reject QUEUE/DROP verdict parameters
CVE-2024-1151 net: openvswitch: limit the number of recursions from action sets
CVE-2024-1312 mm: lock_vma_under_rcu() must check vma->anon_vma under vma lock
CVE-2024-21803
CVE-2024-22099
CVE-2024-22386
CVE-2024-22705 ksmbd: fix slab-out-of-bounds in smb_strndup_from_utf16()
CVE-2024-23196
CVE-2024-23307
CVE-2024-23848
CVE-2024-23849 net/rds: Fix UBSAN: array-index-out-of-bounds in rds_cmsg_recv
CVE-2024-23850 btrfs: do not ASSERT() if the newly created subvolume already got read
CVE-2024-23851 dm: limit the number of targets and parameter size area
CVE-2024-24855 scsi: lpfc: Fix a possible data race in lpfc_unregister_fcf_rescan()
CVE-2024-24857
CVE-2024-24858
CVE-2024-24859
CVE-2024-24860 Bluetooth: Fix atomicity violation in {min,max}_key_size_set
CVE-2024-24861
CVE-2024-24864
CVE-2024-25739
CVE-2024-25740
CVE-2024-25741
CVE-2024-25744 x86/coco: Disable 32-bit emulation by default on TDX and SEV
CVE-2024-26581 netfilter: nft_set_rbtree: skip end interval element from gc
CVE-2024-26582 net: tls: fix use-after-free with partial reads and async decrypt
CVE-2024-26583 tls: fix race between async notify and socket close
CVE-2024-26584 net: tls: handle backlogging of crypto requests
CVE-2024-26585 tls: fix race between tx work scheduling and socket close
CVE-2024-26586 mlxsw: spectrum_acl_tcam: Fix stack corruption
CVE-2024-26587 net: netdevsim: don't try to destroy PHC on VFs
CVE-2024-26588 LoongArch: BPF: Prevent out-of-bounds memory access
CVE-2024-26589 bpf: Reject variable offset alu on PTR_TO_FLOW_KEYS
CVE-2024-26590 erofs: fix inconsistent per-file compression format
CVE-2024-26591 bpf: Fix re-attachment branch in bpf_tracing_prog_attach
CVE-2024-26592 ksmbd: fix UAF issue in ksmbd_tcp_new_connection()
CVE-2024-26593 i2c: i801: Fix block process call transactions
CVE-2024-26594 ksmbd: validate mech token in session setup
CVE-2024-26595 mlxsw: spectrum_acl_tcam: Fix NULL pointer dereference in error path
CVE-2024-26596 net: dsa: fix netdev_priv() dereference before check on non-DSA netdevice events
CVE-2024-26597 net: qualcomm: rmnet: fix global oob in rmnet_policy
CVE-2024-26598 KVM: arm64: vgic-its: Avoid potential UAF in LPI translation cache
CVE-2024-26599 pwm: Fix out-of-bounds access in of_pwm_single_xlate()