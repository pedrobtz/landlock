/* .Call adapters over the C core. The only file in src/ that includes R
 * headers (design.md section 3). Uses the R API only: no R internals, no
 * console hooks. */
#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sched.h>
#include <sys/syscall.h>
#endif

#include "lk.h"

static void fail(const char *what, int err)
{
    Rf_error("%s: %s", what, strerror(err < 0 ? -err : err));
}

/* ---- Landlock ---------------------------------------------------------- */

SEXP C_ll_abi(void)
{
    return Rf_ScalarInteger(lk_ll_abi());
}

/* paths: character; modes: integer (LK_LL_* bits); bind, connect: integer
 * ports; flags: integer c(handle_fs, handle_net, scope_signal,
 * scope_abstract_unix, log, best_effort, force_abi). Returns integer
 * c(abi, fs, net, scope, log). Errors name the path that failed. */
SEXP C_ll_restrict(SEXP paths, SEXP modes, SEXP bind, SEXP connect, SEXP flags)
{
    R_xlen_t np = XLENGTH(paths), nb = XLENGTH(bind), nc = XLENGTH(connect);
    struct lk_ll_path *pp = (struct lk_ll_path *) R_alloc((size_t) np + 1, sizeof *pp);
    uint16_t *bp = (uint16_t *) R_alloc((size_t) nb + 1, sizeof *bp);
    uint16_t *cp = (uint16_t *) R_alloc((size_t) nc + 1, sizeof *cp);
    for (R_xlen_t i = 0; i < np; i++) {
        pp[i].path = Rf_translateChar(STRING_ELT(paths, i));
        pp[i].mode = (unsigned) INTEGER(modes)[i];
    }
    for (R_xlen_t i = 0; i < nb; i++)
        bp[i] = (uint16_t) INTEGER(bind)[i];
    for (R_xlen_t i = 0; i < nc; i++)
        cp[i] = (uint16_t) INTEGER(connect)[i];

    const int *f = INTEGER(flags);
    struct lk_ll_policy p;
    memset(&p, 0, sizeof p);
    p.handle_fs = f[0];
    p.paths = pp;
    p.npaths = (size_t) np;
    p.handle_net = f[1];
    p.bind_ports = bp;
    p.nbind = (size_t) nb;
    p.connect_ports = cp;
    p.nconnect = (size_t) nc;
    p.scope_signal = f[2];
    p.scope_abstract_unix = f[3];
    p.log = (unsigned) f[4];
    p.best_effort = f[5];
    p.force_abi = f[6];

    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    if (rc != 0) {
        if (r.failed_path >= 0)
            Rf_error("Landlock rule for '%s': %s", pp[r.failed_path].path, strerror(-rc));
        if (rc == -EOPNOTSUPP)
            Rf_error("Landlock: the kernel lacks a requested feature (ABI %d) and strict mode is on", r.abi);
        fail("Landlock", rc);
    }
    SEXP out = Rf_allocVector(INTSXP, 5);
    INTEGER(out)[0] = r.abi;
    INTEGER(out)[1] = r.fs;
    INTEGER(out)[2] = r.net;
    INTEGER(out)[3] = r.scope;
    INTEGER(out)[4] = r.log;
    return out;
}

/* ---- seccomp ----------------------------------------------------------- */

/* data.frame-ready list(name, nr) of the calls this architecture has. */
SEXP C_sc_table(void)
{
    size_t n = lk_sc_count(), k = 0;
    for (size_t i = 0; i < n; i++) {
        int nr;
        lk_sc_name_at(i, &nr);
        if (nr >= 0)
            k++;
    }
    SEXP names = PROTECT(Rf_allocVector(STRSXP, (R_xlen_t) k));
    SEXP nrs = PROTECT(Rf_allocVector(INTSXP, (R_xlen_t) k));
    k = 0;
    for (size_t i = 0; i < n; i++) {
        int nr;
        const char *name = lk_sc_name_at(i, &nr);
        if (nr < 0)
            continue;
        SET_STRING_ELT(names, (R_xlen_t) k, Rf_mkChar(name));
        INTEGER(nrs)[k++] = nr;
    }
    SEXP out = PROTECT(Rf_allocVector(VECSXP, 2));
    SET_VECTOR_ELT(out, 0, names);
    SET_VECTOR_ELT(out, 1, nrs);
    UNPROTECT(3);
    return out;
}

/* Per name: the number, -1 when this architecture lacks the call, -2 when
 * the name is unknown. */
SEXP C_sc_lookup(SEXP names)
{
    R_xlen_t n = XLENGTH(names);
    SEXP out = PROTECT(Rf_allocVector(INTSXP, n));
    for (R_xlen_t i = 0; i < n; i++) {
        int r = lk_sc_lookup(CHAR(STRING_ELT(names, i)));
        INTEGER(out)[i] = r >= 0 ? r : r == -ENOSYS ? -1 : -2;
    }
    UNPROTECT(1);
    return out;
}

/* nrs, actions, errnums: one per rule. Returns c(rc, tsync): rc 0, or
 * -errno for the R side to report. */
SEXP C_sc_install(SEXP nrs, SEXP actions, SEXP errnums, SEXP deny_clone_ns)
{
    R_xlen_t n = XLENGTH(nrs);
    struct lk_sc_rule *rules = (struct lk_sc_rule *) R_alloc((size_t) n + 1, sizeof *rules);
    for (R_xlen_t i = 0; i < n; i++) {
        rules[i].nr = INTEGER(nrs)[i];
        rules[i].action = INTEGER(actions)[i];
        rules[i].errnum = INTEGER(errnums)[i];
    }
    int tsync = 0;
    int rc = lk_sc_install(rules, (size_t) n, Rf_asLogical(deny_clone_ns) == TRUE, &tsync);
    SEXP out = Rf_allocVector(INTSXP, 2);
    INTEGER(out)[0] = rc;
    INTEGER(out)[1] = tsync;
    return out;
}

SEXP C_sc_status(void)
{
    return Rf_ScalarInteger(lk_sc_status());
}

SEXP C_errno_value(SEXP name)
{
    static const struct { const char *name; int value; } tbl[] = {
        { "EPERM", EPERM }, { "EACCES", EACCES }, { "ENOSYS", ENOSYS },
        { "EINVAL", EINVAL }, { "ENOTSUP", ENOTSUP }, { "EOPNOTSUPP", EOPNOTSUPP },
        { "EAGAIN", EAGAIN }, { "ENOMEM", ENOMEM }, { "EIO", EIO },
        { "EFAULT", EFAULT },
    };
    const char *s = CHAR(STRING_ELT(name, 0));
    for (size_t i = 0; i < sizeof tbl / sizeof tbl[0]; i++)
        if (strcmp(tbl[i].name, s) == 0)
            return Rf_ScalarInteger(tbl[i].value);
    return Rf_ScalarInteger(NA_INTEGER);
}

/* ---- capabilities and no_new_privs -------------------------------------- */

SEXP C_cap_last(void)
{
    return Rf_ScalarInteger(lk_cap_last());
}

/* These return 0 or -errno; the R side decides between skip and error. */
SEXP C_caps_drop_bounding(SEXP keep)
{
    return Rf_ScalarInteger(lk_caps_drop_bounding(INTEGER(keep), (size_t) XLENGTH(keep)));
}

SEXP C_caps_clear(SEXP keep)
{
    return Rf_ScalarInteger(lk_caps_clear(INTEGER(keep), (size_t) XLENGTH(keep)));
}

SEXP C_nnp_set(void)
{
    int rc = lk_nnp_set();
    if (rc != 0)
        fail("prctl(PR_SET_NO_NEW_PRIVS)", rc);
    return Rf_ScalarLogical(TRUE);
}

SEXP C_nnp_get(void)
{
    int r = lk_nnp_get();
    return Rf_ScalarLogical(r < 0 ? NA_LOGICAL : r);
}

SEXP C_strerror(SEXP err)
{
    int e = Rf_asInteger(err);
    return Rf_mkString(strerror(e < 0 ? -e : e));
}

/* ---- rlimits ----------------------------------------------------------- */

static double u64_to_real(uint64_t v)
{
    return v == UINT64_MAX ? R_PosInf : (double) v;
}

static uint64_t real_to_u64(double v)
{
    if (!R_FINITE(v) || v >= 18446744073709551615.0)
        return UINT64_MAX;
    if (v < 0)
        Rf_error("resource limits cannot be negative");
    return (uint64_t) v;
}

static int rlimit_res(SEXP name)
{
    return lk_rlimit_lookup(CHAR(STRING_ELT(name, 0)));
}

/* c(cur, max), Inf for unlimited; c(NA, NA) when the platform lacks it. */
SEXP C_rlimit_get(SEXP name)
{
    int res = rlimit_res(name);
    SEXP out = Rf_allocVector(REALSXP, 2);
    if (res == -ENOTSUP) {
        REAL(out)[0] = REAL(out)[1] = NA_REAL;
        return out;
    }
    if (res < 0)
        Rf_error("unknown resource limit '%s'", CHAR(STRING_ELT(name, 0)));
    uint64_t soft, hard;
    int rc = lk_rlimit_get(res, &soft, &hard);
    if (rc != 0)
        fail("getrlimit()", rc);
    REAL(out)[0] = u64_to_real(soft);
    REAL(out)[1] = u64_to_real(hard);
    return out;
}

SEXP C_rlimit_set(SEXP name, SEXP cur, SEXP max)
{
    int res = rlimit_res(name);
    if (res < 0)
        Rf_error("resource limit '%s' is not available on this system", CHAR(STRING_ELT(name, 0)));
    int rc = lk_rlimit_set(res, real_to_u64(Rf_asReal(cur)), real_to_u64(Rf_asReal(max)));
    if (rc != 0)
        fail("setrlimit()", rc);
    return R_NilValue;
}

/* ---- ids, process, priority -------------------------------------------- */

SEXP C_getid(SEXP which)
{
    switch (Rf_asInteger(which)) {
    case LK_ID_UID:  return Rf_ScalarInteger((int) getuid());
    case LK_ID_EUID: return Rf_ScalarInteger((int) geteuid());
    case LK_ID_GID:  return Rf_ScalarInteger((int) getgid());
    case LK_ID_EGID: return Rf_ScalarInteger((int) getegid());
    }
    Rf_error("unknown id kind");
}

static const char *setid_name[] = { "setuid()", "seteuid()", "setgid()", "setegid()" };

SEXP C_setid(SEXP which, SEXP id)
{
    int w = Rf_asInteger(which);
    int v = Rf_asInteger(id);
    if (v == NA_INTEGER || v < 0)
        Rf_error("invalid id");
    int rc = lk_setid(w, (unsigned) v);
    if (rc != 0)
        fail(w >= 0 && w <= 3 ? setid_name[w] : "set id", rc);
    return C_getid(which);
}

SEXP C_setids(SEXP uid, SEXP gid)
{
    int u = Rf_asInteger(uid), g = Rf_asInteger(gid);
    int rc = lk_setids(u == NA_INTEGER ? (uid_t) -1 : (uid_t) u,
                       g == NA_INTEGER ? (gid_t) -1 : (gid_t) g);
    if (rc != 0)
        fail("setting user and group ids", rc);
    return R_NilValue;
}

SEXP C_getpid(void)
{
    return Rf_ScalarInteger((int) getpid());
}

SEXP C_getppid(void)
{
    return Rf_ScalarInteger((int) getppid());
}

SEXP C_getpgid(void)
{
    return Rf_ScalarInteger((int) getpgid(0));
}

SEXP C_setpgid(SEXP pgid)
{
    int rc = lk_setpgid(0, (pid_t) Rf_asInteger(pgid));
    if (rc != 0)
        fail("setpgid()", rc);
    return C_getpgid();
}

SEXP C_getpriority(void)
{
    int p;
    int rc = lk_priority_get(&p);
    if (rc != 0)
        fail("getpriority()", rc);
    return Rf_ScalarInteger(p);
}

SEXP C_setpriority(SEXP prio)
{
    int rc = lk_priority_set(Rf_asInteger(prio));
    if (rc != 0)
        fail("setpriority()", rc);
    return C_getpriority();
}

SEXP C_kill(SEXP pid, SEXP sig)
{
    int rc = lk_kill((pid_t) Rf_asInteger(pid), Rf_asInteger(sig));
    if (rc != 0)
        fail("kill()", rc);
    return R_NilValue;
}

SEXP C_chroot(SEXP path)
{
    int rc = lk_chroot(Rf_translateChar(STRING_ELT(path, 0)));
    if (rc != 0)
        fail("chroot()", rc);
    return path;
}

SEXP C_aa_change_profile(SEXP profile)
{
    const char *name = Rf_translateChar(STRING_ELT(profile, 0));
    int rc = lk_aa_change_profile(name);
    if (rc != 0)
        Rf_error("AppArmor profile change to '%s': %s", name, strerror(-rc));
    return R_NilValue;
}

SEXP C_userns_works(void)
{
    int r = lk_userns_works();
    return Rf_ScalarLogical(r < 0 ? NA_LOGICAL : r);
}

/* ---- user and group database ------------------------------------------- */

static SEXP str_or_na(const char *s)
{
    return s ? Rf_mkString(s) : Rf_ScalarString(NA_STRING);
}

SEXP C_user_info(SEXP input)
{
    errno = 0;
    struct passwd *pw = TYPEOF(input) == STRSXP
        ? getpwnam(Rf_translateChar(STRING_ELT(input, 0)))
        : getpwuid((uid_t) Rf_asInteger(input));
    if (!pw) {
        if (errno)
            fail("getpwuid() / getpwnam()", errno);
        Rf_error("user not found");
    }
    SEXP out = PROTECT(Rf_allocVector(VECSXP, 7));
    SET_VECTOR_ELT(out, 0, str_or_na(pw->pw_name));
    SET_VECTOR_ELT(out, 1, str_or_na(pw->pw_passwd));
    SET_VECTOR_ELT(out, 2, Rf_ScalarInteger((int) pw->pw_uid));
    SET_VECTOR_ELT(out, 3, Rf_ScalarInteger((int) pw->pw_gid));
    SET_VECTOR_ELT(out, 4, str_or_na(pw->pw_gecos));
    SET_VECTOR_ELT(out, 5, str_or_na(pw->pw_dir));
    SET_VECTOR_ELT(out, 6, str_or_na(pw->pw_shell));
    UNPROTECT(1);
    return out;
}

SEXP C_group_info(SEXP input)
{
    errno = 0;
    struct group *gr = TYPEOF(input) == STRSXP
        ? getgrnam(Rf_translateChar(STRING_ELT(input, 0)))
        : getgrgid((gid_t) Rf_asInteger(input));
    if (!gr) {
        if (errno)
            fail("getgrgid() / getgrnam()", errno);
        Rf_error("group not found");
    }
    int n = 0;
    while (gr->gr_mem[n])
        n++;
    SEXP out = PROTECT(Rf_allocVector(VECSXP, 4));
    SET_VECTOR_ELT(out, 0, str_or_na(gr->gr_name));
    SET_VECTOR_ELT(out, 1, str_or_na(gr->gr_passwd));
    SET_VECTOR_ELT(out, 2, Rf_ScalarInteger((int) gr->gr_gid));
    SEXP mem = PROTECT(Rf_allocVector(STRSXP, n));
    for (int i = 0; i < n; i++)
        SET_STRING_ELT(mem, i, Rf_mkChar(gr->gr_mem[i]));
    SET_VECTOR_ELT(out, 3, mem);
    UNPROTECT(2);
    return out;
}

/* ---- fork, evaluate, collect (design.md section 6.3) ------------------- */

/* The child's end of the result pipe; set only in a forked child. */
static int child_result_fd = -1;

static double monotonic(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

/* Child side. The R function returns a raw vector (the serialized result)
 * or NULL; the bytes go to the result pipe behind an 8-byte length. Any
 * jump out of the evaluation (an error that escaped, an interrupt, an
 * abort restart) lands in child_cleanup, which ends the child: a forked
 * child must never return into the parent's toplevel. */
struct child_data {
    SEXP fun;
    int fd;
};

/* Result-pipe frames: one type byte, an 8-byte native double length, the
 * bytes. 'P' payload (the serialized result), 'R' report (sent by run()
 * before exec), 'X' exec attempted. R parses them (parse_frames()). */
static int write_frame(int fd, char type, const void *data, size_t len)
{
    double n = (double) len;
    int rc = lk_write_all(fd, &type, 1);
    if (rc == 0)
        rc = lk_write_all(fd, &n, sizeof n);
    if (rc == 0 && len)
        rc = lk_write_all(fd, data, len);
    return rc;
}

static SEXP child_body(void *data)
{
    struct child_data *d = data;
    SEXP call = PROTECT(Rf_lang1(d->fun));
    SEXP val = PROTECT(Rf_eval(call, R_GlobalEnv));
    if (TYPEOF(val) == RAWSXP)
        write_frame(d->fd, 'P', RAW(val), (size_t) XLENGTH(val));
    UNPROTECT(2);
    return R_NilValue;
}

static void child_cleanup(void *data, Rboolean jump)
{
    struct child_data *d = data;
    if (jump)
        lk_child_exit(&d->fd, 1);
}

/* Parent side: the collect loop runs inside R_UnwindProtect so that an
 * interrupt (or an error in an output callback) kills and reaps the child
 * and frees the buffers before the jump continues. */
struct parent_state {
    pid_t pid;
    int fds[3];             /* result, stdout, stderr */
    struct lk_buf bufs[3];
    SEXP outfun, errfun;
    double timeout, t0;
    double max_result;      /* bytes allowed on the result pipe */
    int status, done, killed, timed_out, oversize, rc;
};

static void kill_child(struct parent_state *st)
{
    /* Never after reaping: the pid and group id may then be reused. */
    if (st->killed || st->done)
        return;
    kill(-st->pid, SIGKILL);  /* the child's process group: grandchildren too */
    kill(st->pid, SIGKILL);
    st->killed = 1;
}

static void close_and_reap(struct parent_state *st)
{
    for (int i = 0; i < 3; i++)
        if (st->fds[i] >= 0) {
            close(st->fds[i]);
            st->fds[i] = -1;
        }
    if (!st->done) {
        /* Killed (or about to be): the group is killed before reaping, while
         * the zombie still pins its id. */
        kill(-st->pid, SIGKILL);
        int s = 0;
        pid_t w;
        do {
            w = waitpid(st->pid, &s, 0);
        } while (w < 0 && errno == EINTR);
        st->status = w < 0 ? -1 : s;
        st->done = 1;
    }
}

static void free_bufs(struct parent_state *st)
{
    for (int i = 0; i < 3; i++)
        lk_buf_free(&st->bufs[i]);
}

static void deliver(SEXP fun, struct lk_buf *b)
{
    if (b->len == 0)
        return;
    if (Rf_isFunction(fun)) {
        SEXP chunk = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) b->len));
        memcpy(RAW(chunk), b->data, b->len);
        SEXP call = PROTECT(Rf_lang2(fun, chunk));
        b->len = 0;
        Rf_eval(call, R_GlobalEnv);
        UNPROTECT(2);
    }
    b->len = 0;
}

static SEXP parent_body(void *data)
{
    struct parent_state *st = data;
    while (!st->done) {
        st->rc = lk_wait_collect(st->pid, st->fds, 3, 200, st->bufs, &st->status, &st->done);
        if (st->rc != 0) {
            kill_child(st);
            return R_NilValue;
        }
        if (!st->done && !st->killed && (double) st->bufs[0].len > st->max_result) {
            st->oversize = 1;  /* a child flooding the result pipe must not exhaust the session */
            kill_child(st);
        }
        deliver(st->outfun, &st->bufs[1]);
        deliver(st->errfun, &st->bufs[2]);
        if (st->done || st->killed)
            continue;
        if (st->timeout > 0 && monotonic() - st->t0 > st->timeout) {
            st->timed_out = 1;
            kill_child(st);
            continue;
        }
        R_CheckUserInterrupt();
    }
    return R_NilValue;
}

static void parent_cleanup(void *data, Rboolean jump)
{
    struct parent_state *st = data;
    if (!jump)
        return;
    kill_child(st);
    close_and_reap(st);
    free_bufs(st);
}

/* fun: R function evaluated in the child, returning a raw vector.
 * Returns list(buffer = raw result-pipe bytes (frames), status, signal,
 * exit_code, timed_out). */
SEXP C_fork_eval(SEXP fun, SEXP timeout, SEXP outfun, SEXP errfun, SEXP close_fds,
                 SEXP max_result)
{
    /* Allocate everything R before fork(): an allocation error after it
     * would longjmp the child into a copy of the parent's toplevel. */
    SEXP child_cont = PROTECT(R_MakeUnwindCont());
    SEXP parent_cont = PROTECT(R_MakeUnwindCont());
    int do_close = Rf_asLogical(close_fds) == TRUE;
    double limit = Rf_asReal(max_result);
    double tmo = Rf_asReal(timeout);

    int res[2], out[2], err[2];
    int rc = lk_pipe(res);
    if (rc != 0)
        fail("pipe()", rc);
    if ((rc = lk_pipe(out)) != 0) {
        close(res[0]);
        close(res[1]);
        fail("pipe()", rc);
    }
    if ((rc = lk_pipe(err)) != 0) {
        close(res[0]); close(res[1]); close(out[0]); close(out[1]);
        fail("pipe()", rc);
    }

    /* Unflushed parent output would otherwise be flushed a second time by
     * the child, into the captured stream. */
    fflush(NULL);

    pid_t pid = lk_fork();
    if (pid < 0) {
        close(res[0]); close(res[1]); close(out[0]); close(out[1]);
        close(err[0]); close(err[1]);
        fail("fork()", pid);
    }

    if (pid == 0) {
        setpgid(0, 0);  /* the terminal's SIGINT goes to the parent, which kills us */
        close(res[0]);
        close(out[0]);
        close(err[0]);
        /* Setup must not fail open: a child that keeps the parent's
         * terminal or inherited files ends here, before any user code. */
        const char *failed = NULL;
        if (lk_devnull_stdin() != 0)
            failed = "redirecting standard input to /dev/null";
        else if (lk_dup2(out[1], 1) != 0 || lk_dup2(err[1], 2) != 0)
            failed = "redirecting standard output and error";
        if (out[1] != 1)
            close(out[1]);
        if (err[1] != 2)
            close(err[1]);
        if (!failed && do_close) {
            int keep[1] = { res[1] };
            if (lk_fd_hygiene(3, keep, 1) != 0)
                failed = "replacing inherited file descriptors";
        }
        if (failed) {
            write_frame(res[1], 'F', failed, strlen(failed));
            lk_child_exit(&res[1], 1);
        }
        child_result_fd = res[1];
        struct child_data d = { fun, res[1] };
        R_UnwindProtect(child_body, &d, child_cleanup, &d, child_cont);
        lk_child_exit(&d.fd, 1);
    }

    setpgid(pid, pid);  /* also from this side, closing the race with the child */
    close(res[1]);
    close(out[1]);
    close(err[1]);

    struct parent_state st;
    memset(&st, 0, sizeof st);
    st.pid = pid;
    st.fds[0] = res[0];
    st.fds[1] = out[0];
    st.fds[2] = err[0];
    st.outfun = outfun;
    st.errfun = errfun;
    st.timeout = tmo;
    st.max_result = limit;
    st.t0 = monotonic();
    for (int i = 0; i < 3; i++)
        lk_set_nonblock(st.fds[i]);

    R_UnwindProtect(parent_body, &st, parent_cleanup, &st, parent_cont);
    close_and_reap(&st);

    if (st.rc != 0) {
        free_bufs(&st);
        fail("collecting child output", st.rc);
    }

    struct lk_buf *rb = &st.bufs[0];
    SEXP buffer = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) rb->len));
    if (rb->len)
        memcpy(RAW(buffer), rb->data, rb->len);

    SEXP ans = PROTECT(Rf_allocVector(VECSXP, 6));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, 6));
    const char *names[] = { "buffer", "status", "signal", "exit_code", "timed_out", "oversize" };
    for (int i = 0; i < 6; i++)
        SET_STRING_ELT(nms, i, Rf_mkChar(names[i]));
    Rf_setAttrib(ans, R_NamesSymbol, nms);
    SET_VECTOR_ELT(ans, 0, buffer);
    SET_VECTOR_ELT(ans, 1, Rf_ScalarInteger(st.status));
    SET_VECTOR_ELT(ans, 2, Rf_ScalarInteger(st.status >= 0 && WIFSIGNALED(st.status)
                                            ? WTERMSIG(st.status) : NA_INTEGER));
    SET_VECTOR_ELT(ans, 3, Rf_ScalarInteger(st.status >= 0 && WIFEXITED(st.status)
                                            ? WEXITSTATUS(st.status) : NA_INTEGER));
    SET_VECTOR_ELT(ans, 4, Rf_ScalarLogical(st.timed_out));
    SET_VECTOR_ELT(ans, 5, Rf_ScalarLogical(st.oversize));
    free_bufs(&st);
    UNPROTECT(5);  /* two conts, buffer, ans, nms */
    return ans;
}

/* In a forked child: end now. Used by the q() guard finalizer. */
SEXP C_child_abort(void)
{
    int fd = child_result_fd;
    lk_child_exit(&fd, fd >= 0 ? 1 : 0);
    return R_NilValue;
}

/* In a forked child: send a frame on the result pipe. */
SEXP C_write_frame(SEXP type, SEXP data)
{
    if (child_result_fd < 0)
        Rf_error("not in a landlock child process");
    int rc = write_frame(child_result_fd, CHAR(STRING_ELT(type, 0))[0], RAW(data),
                         (size_t) XLENGTH(data));
    if (rc != 0)
        fail("writing to the result pipe", rc);
    return R_NilValue;
}

/* In a forked child (run()): send the 'X' frame, then exec. Returns the
 * error message only if exec fails; the caller turns it into a condition. */
SEXP C_exec(SEXP cmd, SEXP args)
{
    R_xlen_t n = XLENGTH(args);
    const char **argv = (const char **) R_alloc((size_t) n + 2, sizeof(char *));
    argv[0] = Rf_translateChar(STRING_ELT(cmd, 0));
    for (R_xlen_t i = 0; i < n; i++)
        argv[i + 1] = Rf_translateChar(STRING_ELT(args, i));
    argv[n + 1] = NULL;
    if (child_result_fd >= 0)
        write_frame(child_result_fd, 'X', NULL, 0);
    fflush(NULL);
    execvp(argv[0], (char *const *) argv);
    int e = errno;
    char msg[512];
    snprintf(msg, sizeof msg, "cannot run '%s': %s", argv[0], strerror(e));
    return Rf_mkString(msg);
}

SEXP C_strsignal(SEXP sig)
{
    const char *s = strsignal(Rf_asInteger(sig));
    return Rf_mkString(s ? s : "unknown signal");
}

/* ---- test helpers (internal, used by tests/testthat) ------------------- */

SEXP C_test_open_fd(SEXP path)
{
    int fd = open(Rf_translateChar(STRING_ELT(path, 0)), O_RDONLY);
    if (fd < 0)
        fail("open()", errno);
    return Rf_ScalarInteger(fd);
}

/* Bytes read from fd (at most 16), or -errno. */
SEXP C_test_read_fd(SEXP fd)
{
    char buf[16];
    ssize_t n = read(Rf_asInteger(fd), buf, sizeof buf);
    return Rf_ScalarInteger(n < 0 ? -errno : (int) n);
}

SEXP C_test_close_fd(SEXP fd)
{
    close(Rf_asInteger(fd));
    return R_NilValue;
}

/* clone(CLONE_NEWUSER) like fork: 0 if a namespace child was created, else
 * -errno; NA where the argument order differs (s390x) or off Linux. */
SEXP C_test_clone_newuser(void)
{
#if defined(__linux__) && defined(SYS_clone) && !defined(__s390x__)
    long r = syscall(SYS_clone, (long) (CLONE_NEWUSER | SIGCHLD), 0L, 0L, 0L, 0L);
    if (r == 0)
        for (;;)
            raise(SIGKILL);
    if (r < 0)
        return Rf_ScalarInteger(-errno);
    while (waitpid((pid_t) r, NULL, 0) < 0 && errno == EINTR)
        ;
    return Rf_ScalarInteger(0);
#else
    return Rf_ScalarInteger(NA_INTEGER);
#endif
}

/* errno of clone3(NULL, 0): EFAULT or EINVAL normally, ENOSYS when the
 * filter refuses it; NA where the call does not exist. */
SEXP C_test_clone3_errno(void)
{
#if defined(__linux__) && defined(SYS_clone3)
    long r = syscall(SYS_clone3, NULL, (size_t) 0);
    return Rf_ScalarInteger(r < 0 ? errno : 0);
#else
    return Rf_ScalarInteger(NA_INTEGER);
#endif
}

/* A loop that ignores interrupts unless asked to check them: stands in for
 * long-running C code (unix's freeze()). */
SEXP C_freeze(SEXP interrupt)
{
    int check = Rf_asLogical(interrupt) == TRUE;
    volatile unsigned long spin = 0;
    for (;;) {
        spin++;
        if (check && (spin & 0xFFFFF) == 0)
            R_CheckUserInterrupt();
    }
    return R_NilValue;
}
