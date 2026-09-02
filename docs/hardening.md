---
title: Hardening the spool
nav_order: 8
---

# Hardening the spool

[← dsh-ocsf-forwarder docs](index.md)

[Tamper-evidence](integrity.md) detects a spool cut short *after* the fact, and only for a reader
holding records the SIEM already took. This page is the complementary move: making the file harder
to cut short in the first place, on Linux, with `chattr +a`.

Read [what it is not a boundary against](#what-it-does-not-buy) before deciding it is worth the
operational cost, because the cost is real: **an append-only spool cannot rotate.**

## What `chattr +a` buys

`chattr +a` sets the ext4/XFS/btrfs append-only attribute. Setting or clearing it needs
`CAP_LINUX_IMMUTABLE`; an unprivileged account cannot do either, and a *privileged* one must clear
it before any of the refused operations will work. These are the syscalls this plugin's spool path
makes, and what each does on a file carrying the attribute:

| Operation | On an append-only file | Who does it |
|---|---|---|
| `open(…, O_WRONLY\|O_APPEND\|O_CREAT)` | **succeeds** | the spool, on every open |
| `write` at the end | **succeeds** | the spool, per record |
| `fchmod` / `chmod` | `EPERM` | the spool, re-asserting `0640` after each open |
| `ftruncate` / `truncate` | `EPERM` | nobody here — this is the attack |
| `open(…, O_WRONLY)` / `O_RDWR` without `O_APPEND` | `EPERM` | nobody here — this is the attack |
| `rename` | `EPERM` | the spool, rotating |
| `unlink` | `EPERM` | the shipper, removing a drained generation |

`root` gets `EPERM` on every row above except `open`/`write`. It can lift the attribute first, and
then it can do anything; what the attribute buys is that destroying the spool takes a second,
separately auditable, privileged step rather than one `>` redirect.

## The supported combination

**Append-only and rotation are mutually exclusive, and rotation is the one that gives way.** A
spool made append-only is a spool that will grow without bound until an operator with
`CAP_LINUX_IMMUTABLE` intervenes. That is a deliberate trade and it is only correct where the
alternative — an agent that can silently truncate its own audit trail — is worse.

Use `chattr +a` on **the live spool file only**, and expect to manage its size by hand:

```sh
install -m 0640 -o dsh -g soc /dev/null /var/log/dsh/ocsf.jsonl   # create it at the mode you want
chattr +a /var/log/dsh/ocsf.jsonl                                  # then take away the ability to change it
lsattr /var/log/dsh/ocsf.jsonl                                     # -----a-------- …
```

Order matters. `chattr +a` blocks `chmod`, so the mode has to be right before the attribute goes
on; the plugin cannot fix it afterwards and neither can you. Do the same for `restricted.path` if
that lane is open — it is a second `SpoolSink` on the same code path.

Leave `spoolPath`'s **directory** writable and un-hardened. The `<spoolPath>.lock` file, the
shipper's cursor and the quarantine file all live there and all need to be created, rewritten and
removed. See [the directory trap](#the-directory-is-not-the-file).

## What the plugin does under it

**The mode re-assertion is skipped, loudly if it matters.** `open(…, 'a', mode)` applies a mode
only when it *creates* the file, so the spool re-states `0640` with `fchmod` after every open. On an
append-only file that call returns `EPERM`. The plugin tolerates it and keeps the descriptor: a
spool it cannot chmod but can append to is still a working spool. If the file is *wider* than the
configured mode it says so once, naming both modes, because that is the SOC lane readable by
accounts the configuration meant to exclude and no code here can fix it:

```
ocsf-forwarder: spool /var/log/dsh/ocsf.jsonl is mode 0644 and could not be changed to 0640
(EPERM); an append-only or foreign-owned spool cannot be chmod-ed, so records keep appending at
the wider mode
```

A file already at or inside the configured mode is what the `fchmod` would have produced, so
nothing is reported. Any *other* errno from that call is still fatal, because it is not a condition
this reasoning covers.

**Rotation stops, on the terms a refused rotation already had.** At `spoolMaxBytes` the spool
renames the live file, and the rename returns `EPERM`. That is the same failure
[Delivery and failure modes](operations.md#delivery-and-failure-modes) describes for a directory
whose permissions changed, and it is handled the same way: it reports it once, re-opens the live file
immediately so no record is dropped, stands off for a minute before trying again, and reports
`rotation_stopped: true` in the heartbeat for the life of the process.

```
ocsf-forwarder: spool /var/log/dsh/ocsf.jsonl could not be rotated (EPERM); growing past
spoolMaxBytes until the condition clears
```

The condition never clears while the attribute is set, so the practical reading of that line on an
append-only spool is *rotation is off, permanently, by your own configuration*. Set
`spoolMaxBytes` above the size you expect to reclaim at rather than leaving the default `268435456`
to produce a warning on day one, and keep `spoolHighWaterBytes` as the alarm that tells you the
live file needs attention.

**The shipper still delivers.** It reads the live file by byte offset and writes its cursor and
quarantine file beside the spool, never into it. Nothing about the attribute stops delivery to
Splunk or OTLP, and delivery does not shrink the file: the spool is not truncated once shipped, and
under `+a` it could not be.

## What breaks

**Reclaiming space is a privileged, manual job, and it needs the agent stopped.** There is no
rotation to hand it to:

```sh
# with the agent stopped, and after confirming the shipper's cursor reached the end
chattr -a /var/log/dsh/ocsf.jsonl                                   # needs CAP_LINUX_IMMUTABLE
mv /var/log/dsh/ocsf.jsonl /var/log/dsh/ocsf.jsonl.$(date -u +%FT%H-%M-%SZ)
install -m 0640 -o dsh -g soc /dev/null /var/log/dsh/ocsf.jsonl
chattr +a /var/log/dsh/ocsf.jsonl
```

Doing it under a running agent is not supported. The spool holds an open descriptor, and a `mv`
moves the inode that descriptor names: records keep landing in the moved file, not in the fresh
one, until the spool next takes a descriptor on the path. On a rotating spool that happens at the
next rotation; on an append-only spool rotation is exactly what does not happen, so the window has
no defined end.

**A rotated generation that is itself append-only stops delivery dead.** The shipper removes a
generation only once the collector has acknowledged every byte in it, and ordering forbids it from
stepping over one — a later generation must not overtake one the destination has not finished
taking. If that `unlink` returns `EPERM` the drain pass ends there and reports the error, and it
ends there again on every later pass: the live file is never reached and the cursor never moves.
Nothing is lost, and nothing is delivered either. This is why the recipe hardens the live file
only, where no generation can ever be created.

## The directory is not the file

`chattr +a` on the spool's **directory** is a different attribute with a different effect, and it
is the wrong one:

| Operation in an append-only directory | Result |
|---|---|
| create a file | succeeds |
| append to a file | succeeds |
| **`chmod` a file** | **succeeds** |
| **truncate a file, or open it `O_WRONLY` without `O_APPEND`** | **succeeds** |
| `unlink` a file | `EPERM` |
| `rename` a file | `EPERM` |

So it buys nothing against the truncation it looks like it should prevent — the files inside are
ordinary files — while breaking rotation, the shipper's unlink of a drained generation, *and* the
lock. The attribute is not inherited by files created in the directory, so a fresh generation would
not be protected either.

The lock is the sharpest edge. `acquireLock` takes over a lock left by a process that no longer
exists, by removing it; in an append-only directory that `unlink` returns `EPERM`, so the spool
cannot be constructed. A constructor that throws fails the whole plugin tree and `dsh` refuses to
start, which means one crash leaves the agent unable to boot until someone clears the attribute.

Do not set it on the directory.

## What it does not buy

The attribute constrains the *file*, not the agent.

- **Appends are exactly what it permits.** The agent this plugin observes runs at the same uid and
  can append forged records to the spool, and can compute their `record_integrity` links, because
  the fingerprint algorithm is unkeyed and published. `chattr +a` makes deletion and rewriting
  hard; it does nothing about addition. [Tamper-evidence](integrity.md) says the same about the
  chain, and for the same reason.
- **It is not a substitute for shipping.** Anything still on the host is still reachable by
  whoever holds `CAP_LINUX_IMMUTABLE` on the host. The attribute buys time and an audit trail of
  the clearing step; getting records off the machine is what removes them from the attacker's
  reach. Run a shipper.
- **It is Linux-only, and filesystem-dependent.** ext4, XFS and btrfs carry the attribute; NFS,
  tmpfs and overlayfs do not. `lsattr` on the spool is the check, and a spool on a filesystem that
  silently ignores the attribute looks exactly like one that has it if you only check that
  `chattr` exited zero — it does not, but check `lsattr` anyway.
