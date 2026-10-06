/* seccomp-bpf user-space API under lk_/LK_ names (design.md section 10):
 * classic BPF instructions, struct seccomp_data offsets, return actions,
 * filter flags, AUDIT_ARCH values and the seccomp() syscall number.
 * Values are from include/uapi/linux/{seccomp,filter,bpf_common,audit,
 * elf-em}.h, GPL-2.0 WITH Linux-syscall-note (see inst/COPYRIGHTS). */
#ifndef LK_SECCOMP_COMPAT_H
#define LK_SECCOMP_COMPAT_H

#ifdef __linux__
#include <stdint.h>
#include <sys/syscall.h>

struct lk_sock_filter {   /* struct sock_filter */
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct lk_sock_fprog {    /* struct sock_fprog */
    unsigned short len;
    struct lk_sock_filter *filter;
};

/* Classic BPF opcodes. */
#define LK_BPF_LD   0x00
#define LK_BPF_JMP  0x05
#define LK_BPF_RET  0x06
#define LK_BPF_W    0x00
#define LK_BPF_ABS  0x20
#define LK_BPF_JEQ  0x10
#define LK_BPF_JGE  0x30
#define LK_BPF_JSET 0x40
#define LK_BPF_K    0x00

/* struct seccomp_data: int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; */
#define LK_SECCOMP_DATA_NR    0
#define LK_SECCOMP_DATA_ARCH  4
#define LK_SECCOMP_DATA_ARGS  16

/* clone()'s flags argument: args[1] on s390x, args[0] elsewhere; the low 32
 * bits hold every CLONE_NEW* flag and sit at +4 on big-endian. */
#if defined(__s390x__)
#define LK_CLONE_FLAGS_OFF (LK_SECCOMP_DATA_ARGS + 8 + 4)
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define LK_CLONE_FLAGS_OFF (LK_SECCOMP_DATA_ARGS + 4)
#else
#define LK_CLONE_FLAGS_OFF LK_SECCOMP_DATA_ARGS
#endif

/* Offset of the low 32 bits of args[i]: +4 within the 64-bit slot on
 * big-endian. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define LK_SECCOMP_ARG_LO(i) (LK_SECCOMP_DATA_ARGS + 8 * (uint32_t) (i) + 4)
#else
#define LK_SECCOMP_ARG_LO(i) (LK_SECCOMP_DATA_ARGS + 8 * (uint32_t) (i))
#endif

/* CLONE_NEWTIME | NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET */
#define LK_CLONE_NEW_MASK 0x7E020080U

#define LK_SECCOMP_SET_MODE_FILTER   1
#define LK_SECCOMP_MODE_FILTER       2
#define LK_SECCOMP_FILTER_FLAG_TSYNC (1U << 0)

#define LK_SECCOMP_RET_KILL_PROCESS  0x80000000U
#define LK_SECCOMP_RET_TRAP          0x00030000U
#define LK_SECCOMP_RET_ERRNO         0x00050000U
#define LK_SECCOMP_RET_LOG           0x7ffc0000U
#define LK_SECCOMP_RET_ALLOW         0x7fff0000U
#define LK_SECCOMP_RET_DATA          0x0000ffffU

#define LK_X32_SYSCALL_BIT 0x40000000U

/* AUDIT_ARCH_* = EM_* | 64-bit flag 0x80000000 | little-endian flag 0x40000000. */
#if defined(__x86_64__) && !defined(__ILP32__)
#define LK_AUDIT_ARCH 0xC000003EU      /* AUDIT_ARCH_X86_64 */
#define LK_HAVE_X32_GUARD 1
#elif defined(__i386__)
#define LK_AUDIT_ARCH 0x40000003U      /* AUDIT_ARCH_I386 */
#elif defined(__aarch64__) && !defined(__AARCH64EB__)
#define LK_AUDIT_ARCH 0xC00000B7U      /* AUDIT_ARCH_AARCH64 */
#elif defined(__arm__) && !defined(__ARMEB__)
#define LK_AUDIT_ARCH 0x40000028U      /* AUDIT_ARCH_ARM */
#elif defined(__riscv) && __riscv_xlen == 64
#define LK_AUDIT_ARCH 0xC00000F3U      /* AUDIT_ARCH_RISCV64 */
#elif defined(__powerpc64__) && defined(__LITTLE_ENDIAN__)
#define LK_AUDIT_ARCH 0xC0000015U      /* AUDIT_ARCH_PPC64LE */
#elif defined(__s390x__)
#define LK_AUDIT_ARCH 0x80000016U      /* AUDIT_ARCH_S390X */
#elif defined(__loongarch64)
#define LK_AUDIT_ARCH 0xC0000102U      /* AUDIT_ARCH_LOONGARCH64 */
#endif
/* Any other architecture: LK_AUDIT_ARCH stays undefined and lk_sc_deny()
 * returns -ENOTSUP rather than build a filter without an arch check. */

/* seccomp() syscall number when <sys/syscall.h> is too old to name it. */
#if defined(SYS_seccomp)
#define LK_NR_SECCOMP SYS_seccomp
#elif defined(__x86_64__) && !defined(__ILP32__)
#define LK_NR_SECCOMP 317
#elif defined(__aarch64__)
#define LK_NR_SECCOMP 277
#elif defined(__i386__)
#define LK_NR_SECCOMP 354
#elif defined(__arm__)
#define LK_NR_SECCOMP 383
#endif
/* Otherwise the prctl(PR_SET_SECCOMP) path is used. */

#endif /* __linux__ */
#endif /* LK_SECCOMP_COMPAT_H */
