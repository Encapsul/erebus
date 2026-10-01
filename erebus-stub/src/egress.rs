//! Outbound network confinement requested at launch with `ERE_EGRESS`.
//!
//! `ERE_EGRESS=PORT[,PORT…]` lets the payload open TCP connections to those
//! ports only, `ERE_EGRESS=none` forbids egress. The intended value is the
//! port of an `erebus attest-tool http` boundary: the payload can then reach
//! its tools only through the boundary that signs every execution. The
//! policy is signed into the receipt (`execution.egress`).
//!
//! - macOS: Seatbelt `network-outbound` limited to `localhost:<port>`
//!   (see `macos_sandbox`); scope `loopback`.
//! - Linux: a Landlock ruleset handling `CONNECT_TCP` (ABI ≥ 4, Linux 6.7)
//!   allows the ports on any address (Landlock has no address rules), and a
//!   seccomp filter refuses what Landlock does not see: non-stream IPv4/IPv6
//!   sockets (UDP, QUIC, raw), packet sockets, `io_uring` and foreign or x32
//!   syscall ABIs; scope `any_address`.
//!
//! Unix-domain sockets (local IPC) stay open on both. Fail-closed: an
//! unparsable value or a kernel that cannot enforce it stops the launch.

use std::io;

use erebus_core::attest::{EgressPolicy, EGRESS_ANY_ADDRESS, EGRESS_LOOPBACK};

pub const ENV: &str = "ERE_EGRESS";

/// TCP ports the payload may connect to; empty means no egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub ports: Vec<u16>,
}

impl Policy {
    /// `None` when `ERE_EGRESS` is unset; an error when it is set but invalid.
    pub fn from_env() -> io::Result<Option<Self>> {
        match std::env::var(ENV) {
            Ok(v) => Self::parse(&v).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(invalid("not valid UTF-8")),
        }
    }

    pub fn parse(spec: &str) -> io::Result<Self> {
        if spec.trim() == "none" {
            return Ok(Self { ports: Vec::new() });
        }
        let mut ports = Vec::new();
        for part in spec.split(',') {
            let port = part
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| invalid(&format!("invalid port {part:?}")))?;
            ports.push(port);
        }
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { ports })
    }

    /// What the receipt signs, with the scope this platform enforces.
    pub fn signed(&self) -> EgressPolicy {
        let scope = if cfg!(target_os = "macos") {
            EGRESS_LOOPBACK
        } else {
            EGRESS_ANY_ADDRESS
        };
        EgressPolicy {
            tcp_ports: self.ports.clone(),
            scope: scope.to_string(),
        }
    }
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{ENV}: {why} (expected PORT[,PORT...] or none)"),
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;

    use crate::landlock::sys;
    use crate::seccomp::AUDIT_ARCH;

    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const LANDLOCK_RULE_NET_PORT: i64 = 2;
    const MIN_NET_ABI: i64 = 4;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C)]
    struct NetPortAttr {
        allowed_access: u64,
        port: u64,
    }

    /// Landlock ABI version of the running kernel; 0 when unavailable.
    pub fn landlock_abi() -> i64 {
        // SAFETY: with a null attr, size 0 and the VERSION flag the syscall
        // reads no memory and only returns the ABI version (or -1).
        let v = unsafe {
            libc::syscall(
                sys::LANDLOCK_CREATE_RULESET,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        // `syscall` returns `c_long` (i32 on arm/x86, i64 on aarch64/x86_64).
        (v as i64).max(0)
    }

    /// Everything [`Prepared::apply`] needs, built beforehand so that applying
    /// it after `fork` performs syscalls only.
    pub struct Prepared {
        ports: Vec<u16>,
        filter: Vec<libc::sock_filter>,
    }

    impl super::Policy {
        pub fn prepare(&self) -> Prepared {
            Prepared {
                ports: self.ports.clone(),
                filter: socket_filter(),
            }
        }
    }

    impl Prepared {
        /// Confine the calling thread and everything it execs.
        pub fn apply(&self) -> io::Result<()> {
            let abi = landlock_abi();
            if abi < MIN_NET_ABI {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "Landlock ABI {abi} cannot confine TCP connections \
                         (needs ABI {MIN_NET_ABI}, Linux 6.7+)"
                    ),
                ));
            }
            no_new_privs()?;
            restrict_tcp_connect(&self.ports)?;
            install_filter(&self.filter)
        }
    }

    fn check(rc: libc::c_long) -> io::Result<libc::c_long> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn no_new_privs() -> io::Result<()> {
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) takes no pointers; it is
        // required before an unprivileged landlock_restrict_self or seccomp.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        check(libc::c_long::from(rc)).map(drop)
    }

    fn restrict_tcp_connect(ports: &[u16]) -> io::Result<()> {
        let attr = RulesetAttr {
            handled_access_fs: 0,
            handled_access_net: LANDLOCK_ACCESS_NET_CONNECT_TCP,
        };
        // SAFETY: `attr` is a valid ABI-4 ruleset attribute that outlives the
        // call, and its exact size is passed; returns a new fd or -1.
        let fd = check(unsafe {
            libc::syscall(
                sys::LANDLOCK_CREATE_RULESET,
                std::ptr::from_ref(&attr).cast::<libc::c_void>(),
                core::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        })?;
        let result = ports
            .iter()
            .try_for_each(|p| add_port(fd, *p))
            .and_then(|()| {
                // SAFETY: `fd` is the ruleset created above; flags must be 0.
                check(unsafe { libc::syscall(sys::LANDLOCK_RESTRICT_SELF, fd, 0u32) }).map(drop)
            });
        // SAFETY: `fd` is owned here and not used after this point.
        unsafe { libc::close(fd as libc::c_int) };
        result
    }

    fn add_port(ruleset: libc::c_long, port: u16) -> io::Result<()> {
        let attr = NetPortAttr {
            allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
            port: u64::from(port),
        };
        // SAFETY: `ruleset` is a live Landlock fd and `attr` a valid
        // `landlock_net_port_attr` that outlives the call; flags must be 0.
        check(unsafe {
            libc::syscall(
                sys::LANDLOCK_ADD_RULE,
                ruleset,
                LANDLOCK_RULE_NET_PORT,
                std::ptr::from_ref(&attr).cast::<libc::c_void>(),
                0u32,
            )
        })
        .map(drop)
    }

    fn install_filter(filter: &[libc::sock_filter]) -> io::Result<()> {
        let prog = libc::sock_fprog {
            len: u16::try_from(filter.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filter too long"))?,
            filter: filter.as_ptr().cast_mut(),
        };
        // SAFETY: `prog` points to `filter`, which outlives the call; the
        // kernel copies the program and never writes through the pointer.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                std::ptr::from_ref(&prog) as usize,
                0,
                0,
            )
        };
        check(libc::c_long::from(rc)).map(drop)
    }

    #[derive(Clone, Copy)]
    enum To {
        Next,
        Deny,
        Allow,
        L(Label),
    }

    #[derive(Clone, Copy)]
    enum Label {
        SocketType,
        FlagsArg2,
        FlagsArg3,
    }

    const LD_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const JSET: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
    #[cfg(target_arch = "x86_64")]
    const JGE: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const AND: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
    const RET: u16 = 0x06; // BPF_RET | BPF_K
    const OFF_NR: u32 = 0;
    const OFF_ARCH: u32 = 4;
    // Low 32 bits of args[0] and args[1]: every supported target is
    // little-endian.
    const OFF_ARG0: u32 = 16;
    const OFF_ARG1: u32 = 24;
    const OFF_ARG2: u32 = 32;
    const OFF_ARG3: u32 = 40;
    const SOCK_TYPE_MASK: u32 = 0xf;
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    type Insn = (u16, To, To, u32);

    /// Refuses (EACCES) what Landlock's TCP rules do not cover: non-stream
    /// IPv4/IPv6 and packet sockets, TCP Fast Open (it connects from
    /// `sendto`/`sendmsg`, which Landlock does not check), and every path
    /// around this filter: a foreign syscall ABI, x32, `socketcall` (i386)
    /// and `io_uring` (which creates sockets and sends without syscalls).
    fn socket_filter() -> Vec<libc::sock_filter> {
        let mut p: Vec<Insn> = vec![
            (LD_ABS, To::Next, To::Next, OFF_ARCH),
            (JEQ, To::Next, To::Deny, AUDIT_ARCH),
            (LD_ABS, To::Next, To::Next, OFF_NR),
        ];
        #[cfg(target_arch = "x86_64")]
        p.push((JGE, To::Deny, To::Next, X32_SYSCALL_BIT));
        #[cfg(target_arch = "x86")]
        p.push((JEQ, To::Deny, To::Next, libc::SYS_socketcall as u32));
        let flags3 = To::L(Label::FlagsArg3);
        p.extend([
            (JEQ, To::Deny, To::Next, libc::SYS_io_uring_setup as u32),
            (JEQ, flags3, To::Next, libc::SYS_sendto as u32),
            (JEQ, flags3, To::Next, libc::SYS_sendmmsg as u32),
            (
                JEQ,
                To::L(Label::FlagsArg2),
                To::Next,
                libc::SYS_sendmsg as u32,
            ),
            (JEQ, To::Next, To::Allow, libc::SYS_socket as u32),
            (LD_ABS, To::Next, To::Next, OFF_ARG0),
            (JEQ, To::Deny, To::Next, libc::AF_PACKET as u32),
            (
                JEQ,
                To::L(Label::SocketType),
                To::Next,
                libc::AF_INET as u32,
            ),
            (JEQ, To::Next, To::Allow, libc::AF_INET6 as u32),
        ]);
        let fast_open = |off| -> [Insn; 2] {
            [
                (LD_ABS, To::Next, To::Next, off),
                (JSET, To::Deny, To::Allow, libc::MSG_FASTOPEN as u32),
            ]
        };
        let mut labels = [0usize; 3];
        labels[Label::SocketType as usize] = p.len();
        p.extend([
            (LD_ABS, To::Next, To::Next, OFF_ARG1),
            (AND, To::Next, To::Next, SOCK_TYPE_MASK),
            (JEQ, To::Allow, To::Deny, libc::SOCK_STREAM as u32),
        ]);
        labels[Label::FlagsArg2 as usize] = p.len();
        p.extend(fast_open(OFF_ARG2));
        labels[Label::FlagsArg3 as usize] = p.len();
        p.extend(fast_open(OFF_ARG3));
        assemble(&p, labels)
    }

    /// Resolve symbolic jumps (always forward); `Deny` and `Allow` are the
    /// two final returns.
    fn assemble(p: &[Insn], labels: [usize; 3]) -> Vec<libc::sock_filter> {
        let deny = p.len();
        let rel = |at: usize, to: To| -> u8 {
            let target = match to {
                To::Next => at + 1,
                To::Deny => deny,
                To::Allow => deny + 1,
                To::L(l) => labels[l as usize],
            };
            u8::try_from(target.saturating_sub(at + 1)).unwrap_or(0)
        };
        let mut out: Vec<libc::sock_filter> = p
            .iter()
            .enumerate()
            .map(|(at, &(code, jt, jf, k))| libc::sock_filter {
                code,
                jt: rel(at, jt),
                jf: rel(at, jf),
                k,
            })
            .collect();
        let errno = libc::SECCOMP_RET_ERRNO | (libc::EACCES as u32 & libc::SECCOMP_RET_DATA);
        for k in [errno, libc::SECCOMP_RET_ALLOW] {
            out.push(libc::sock_filter {
                code: RET,
                jt: 0,
                jf: 0,
                k,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_ports_and_none_and_refuses_anything_else() {
        assert_eq!(Policy::parse("8931").unwrap().ports, vec![8931]);
        assert_eq!(
            Policy::parse(" 443, 8931,443 ").unwrap().ports,
            vec![443, 8931]
        );
        assert!(Policy::parse("none").unwrap().ports.is_empty());
        for bad in ["", "0", "70000", "80,", "localhost:80", "all"] {
            assert!(Policy::parse(bad).is_err(), "{bad:?} accepted");
        }
    }

    /// Child half of the Linux test: confines its own thread (Landlock and
    /// seccomp apply per thread) and reports what still gets through.
    #[cfg(target_os = "linux")]
    #[test]
    fn egress_probe_child() {
        let Ok(spec) = std::env::var("EREBUS_EGRESS_PROBE") else {
            return;
        };
        let (allowed, blocked) = spec.split_once(',').unwrap();
        let (allowed, blocked): (u16, u16) = (allowed.parse().unwrap(), blocked.parse().unwrap());
        if let Err(e) = Policy::parse(&allowed.to_string())
            .unwrap()
            .prepare()
            .apply()
        {
            println!("REFUSED: {e}");
            return;
        }
        let errno = |r: io::Result<()>| r.err().and_then(|e| e.raw_os_error()).unwrap_or(0);
        let tcp = |port: u16| errno(std::net::TcpStream::connect(("127.0.0.1", port)).map(drop));
        let udp = errno(std::net::UdpSocket::bind("127.0.0.1:0").map(drop));
        let send = errno(
            std::net::TcpStream::connect(("127.0.0.1", allowed))
                .and_then(|mut s| std::io::Write::write_all(&mut s, b"ping")),
        );
        println!(
            "ALLOWED={} SEND={send} BLOCKED={} UDP={udp} TFO={}",
            tcp(allowed),
            tcp(blocked),
            fast_open(blocked)
        );
    }

    /// TCP Fast Open connects from `sendto`, not `connect`.
    #[cfg(target_os = "linux")]
    fn fast_open(port: u16) -> i32 {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: plain socket/sendto/close on a fresh fd; `addr` and the
        // one-byte buffer outlive the calls and their sizes are exact.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let rc = libc::sendto(
                fd,
                b"x".as_ptr().cast(),
                1,
                libc::MSG_FASTOPEN,
                std::ptr::from_ref(&addr).cast(),
                core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            let err = if rc < 0 {
                io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                0
            };
            libc::close(fd);
            err
        }
    }

    /// The real kernel check: only the listed port is reachable, UDP and
    /// Fast Open are refused. On kernels without Landlock ABI 4 the launch
    /// must be refused instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn egress_confines_tcp_to_the_listed_ports_or_refuses_to_run() {
        if std::env::var_os("EREBUS_EGRESS_PROBE").is_some() {
            return;
        }
        let _guard = crate::FORK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ports = format!(
            "{},{}",
            a.local_addr().unwrap().port(),
            b.local_addr().unwrap().port()
        );
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "egress::tests::egress_probe_child",
                "--nocapture",
            ])
            .args(["--test-threads", "1"])
            .env("EREBUS_EGRESS_PROBE", ports)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let abi = linux::landlock_abi();
        if abi < 4 {
            assert!(stdout.contains("REFUSED: Landlock ABI"), "{stdout}");
            eprintln!("Landlock ABI {abi} < 4: refusal path only");
            return;
        }
        let eacces = libc::EACCES;
        let want = format!("ALLOWED=0 SEND=0 BLOCKED={eacces} UDP={eacces} TFO={eacces}");
        assert!(stdout.contains(&want), "want {want}: {stdout}");
    }
}
