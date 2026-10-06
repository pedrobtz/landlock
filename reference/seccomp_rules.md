# The seccomp filter a policy produces

Lists the rules the
[`syscalls()`](https://pedrobtz.github.io/landlock/reference/policy.md)
layer of a policy installs on this architecture, in the order the filter
checks them, like 'libseccomp”s `seccomp_export_pfc()`. Every filter
also starts by killing calls made for another architecture (and, on
x86_64, x32 calls), and allows any call no rule matches.

## Usage

``` r
seccomp_rules(p)
```

## Arguments

- p:

  A
  [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  with a
  [`syscalls()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  layer.

## Value

A data frame with one row per rule: `call`, its number `nr` on this
architecture, the `condition` on its arguments (empty when every call is
matched), and the `result` (`"errno EPERM"`, `"kill"`, ...). Calls that
do not exist on this architecture are listed in the attribute `absent`.
Empty off Linux.

## Examples

``` r
seccomp_rules(preset("numeric"))
#>                       call  nr                condition       result
#> 1                    clone  56 flags include CLONE_NEW*  errno EPERM
#> 2                    ioctl  16 arg1 in {0x5412, 0x541c}  errno EPERM
#> 3                   ptrace 101                           errno EPERM
#> 4         process_vm_readv 310                           errno EPERM
#> 5        process_vm_writev 311                           errno EPERM
#> 6                     kcmp 312                           errno EPERM
#> 7          perf_event_open 298                           errno EPERM
#> 8              pidfd_getfd 438                           errno EPERM
#> 9           lookup_dcookie 212                           errno EPERM
#> 10                   mount 165                           errno EPERM
#> 11                 umount2 166                           errno EPERM
#> 12              pivot_root 155                           errno EPERM
#> 13           mount_setattr 442                           errno EPERM
#> 14              move_mount 429                           errno EPERM
#> 15               open_tree 428                           errno EPERM
#> 16                  fsopen 430                           errno EPERM
#> 17                 fsmount 432                           errno EPERM
#> 18                fsconfig 431                           errno EPERM
#> 19                  fspick 433                           errno EPERM
#> 20                   setns 308                           errno EPERM
#> 21                 unshare 272                           errno EPERM
#> 22                  clone3 435                          errno ENOSYS
#> 23                  keyctl 250                           errno EPERM
#> 24                 add_key 248                           errno EPERM
#> 25             request_key 249                           errno EPERM
#> 26             init_module 175                           errno EPERM
#> 27            finit_module 313                           errno EPERM
#> 28           delete_module 176                           errno EPERM
#> 29              kexec_load 246                           errno EPERM
#> 30         kexec_file_load 320                           errno EPERM
#> 31                  reboot 169                           errno EPERM
#> 32                  swapon 167                           errno EPERM
#> 33                 swapoff 168                           errno EPERM
#> 34            settimeofday 164                           errno EPERM
#> 35           clock_settime 227                           errno EPERM
#> 36                adjtimex 159                           errno EPERM
#> 37           clock_adjtime 305                           errno EPERM
#> 38                    acct 163                           errno EPERM
#> 39                quotactl 179                           errno EPERM
#> 40                  syslog 103                           errno EPERM
#> 41                 vhangup 153                           errno EPERM
#> 42                  ioperm 173                           errno EPERM
#> 43                    iopl 172                           errno EPERM
#> 44       open_by_handle_at 304                           errno EPERM
#> 45       name_to_handle_at 303                           errno EPERM
#> 46             sethostname 170                           errno EPERM
#> 47           setdomainname 171                           errno EPERM
#> 48             personality 135                           errno EPERM
#> 49             userfaultfd 323                           errno EPERM
#> 50                   mbind 237                           errno EPERM
#> 51           set_mempolicy 238                           errno EPERM
#> 52           migrate_pages 256                           errno EPERM
#> 53              move_pages 279                           errno EPERM
#> 54                     bpf 321                           errno EPERM
#> 55          io_uring_setup 425                           errno EPERM
#> 56          io_uring_enter 426                           errno EPERM
#> 57       io_uring_register 427                           errno EPERM
#> 58                  setsid 112                           errno EPERM
#> 59                 setpgid 109                           errno EPERM
#> 60 landlock_create_ruleset 444                           errno EPERM
#> 61       landlock_add_rule 445                           errno EPERM
#> 62  landlock_restrict_self 446                           errno EPERM
#> 63                 seccomp 317                           errno EPERM
#> 64                  execve  59                           errno EPERM
#> 65                execveat 322                           errno EPERM
#> 66                  socket  41                           errno EPERM
#> 67              socketpair  53                           errno EPERM
#> 68                 connect  42                           errno EPERM
#> 69                    bind  49                           errno EPERM
#> 70                  listen  50                           errno EPERM
#> 71                  accept  43                           errno EPERM
#> 72                 accept4 288                           errno EPERM
#> 73                  sendto  44                           errno EPERM
#> 74                recvfrom  45                           errno EPERM
#> 75                 sendmsg  46                           errno EPERM
#> 76                 recvmsg  47                           errno EPERM
#> 77                sendmmsg 307                           errno EPERM
#> 78                recvmmsg 299                           errno EPERM
```
