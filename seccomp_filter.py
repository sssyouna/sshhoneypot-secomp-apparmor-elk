try:
    import seccomp
    SECCOMP_AVAILABLE = True
except ImportError:
    SECCOMP_AVAILABLE = False




def setup_no_new_privs():
    try:
        import prctl
        prctl.set_no_new_privs(True)
        print("[OK] no_new_privs enabled")
    except ImportError:
        print("[WARN] python-prctl not installed")
    except PermissionError:
        print("[WARN] no_new_privs not permitted")


def apply_ssh_seccomp_filter():
    if not SECCOMP_AVAILABLE:
        print("Seccomp non disponible pour SSH.")
        return

    print("Application du filtre Seccomp SSH (process-wide)...")

    try:
        # DEFAULT: KILL / ERRNO
        filt = seccomp.SyscallFilter(defaction=seccomp.ERRNO(1))

        # ===== Allow required syscalls =====
        allowed_calls = [
            # IO
    "read", "write", "close",

    # Network
    "socket", "accept", "accept4", "bind", "listen",
    "recvfrom", "sendto", "setsockopt", "getsockopt",

    # Multiplexing
    "poll", "ppoll", "select", "pselect6",
    "epoll_create1", "epoll_ctl", "epoll_wait",

    # Threads & sync
    "clone",  # <-- THIS IS REQUIRED FOR threading!
    "futex",

    # Memory
    "mmap", "munmap", "brk",

    # Time / random
    "clock_gettime", "nanosleep", "getrandom",

    # Signals & exit
    "rt_sigaction", "rt_sigreturn",
    "exit", "exit_group",

    # Python internals
    "arch_prctl", "prlimit64", "getpid", "gettid",
        ]

        for call in allowed_calls:
            filt.add_rule(seccomp.ALLOW, call)

        filt.load()
        print("Filtre Seccomp SSH chargé (process-wide).")

    except Exception as e:
        print("Erreur lors de l'application du filtre Seccomp:", e)
