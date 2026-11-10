#!/usr/bin/env python3
"""Experimental BakaSU d5e9e025 adbroot query-response patch.

Applies three narrowly scoped changes to kernel/feature/selinux_hide.c.
No file is written unless all three unique source anchors match.
This alters visibility of an SELinux context to apps, not SELinux policy.
Not a verified security fix or a device-tested kernel patch.
"""
from pathlib import Path

TARGET = Path('kernel/feature/selinux_hide.c')
original = TARGET.read_text(encoding='utf-8')
if 'Experimental: return invalid only for a specific app context probe.' in original:
    raise SystemExit('ERROR patch already applied; no file changed')
source = original


def patch_range(label, start_marker, end_marker, anchor, insert):
    global source
    start = source.find(start_marker)
    end = source.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise SystemExit(f'ERROR {label}: function boundary not found; no file changed')
    section = source[start:end]
    n = section.count(anchor)
    if n != 1:
        raise SystemExit(f'ERROR {label}: expected 1 anchor in function, found {n}; no file changed')
    source = source[:start] + section.replace(anchor, insert + anchor, 1) + source[end:]
    print(f'OK {label}')


# Check context validity through /sys/fs/selinux/context. Insert immediately
# before the backup-policy resolution, after the normal access-control check.
patch_range(
    'context query',
    '__maybe_static ssize_t my_write_context(',
    '__maybe_static ssize_t my_write_access(',
    '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)\n',
    '''    /* Experimental: return invalid only for a specific app context probe. */
    if (ksu_get_uid_t(current_uid()) >= 10000 &&
        size == sizeof("u:r:adbroot:s0") - 1 &&
        !memcmp(buf, "u:r:adbroot:s0", sizeof("u:r:adbroot:s0") - 1)) {
        length = -EINVAL;
        goto out;
    }
''',
)

# /sys/fs/selinux/access: after the input has been parsed and lengths set.
patch_range(
    'access class-zero query',
    '__maybe_static ssize_t my_write_access(',
    'static inline u32 cred_sid(',
    '    tconlen = strlen(tcon);\n',
    '''    /* Experimental: only a class-zero context probe; preserve binder. */
    if (ksu_get_uid_t(current_uid()) >= 10000 && tclass == 0 &&
        (!strcmp(scon, "u:r:adbroot:s0") || !strcmp(tcon, "u:r:adbroot:s0"))) {
        length = -EINVAL;
        goto out;
    }
''',
)

# /proc/self/attr/current setprocattr test; keep the live policy unchanged.
comment = '    /* Obtain a SID for the context, if one was specified. */\n'
if source.count(comment) != 1 or source.find(comment) < source.find('int __nocfi ksu_handle_selinux_setprocattr('):
    raise SystemExit('ERROR setprocattr query: unique source anchor not found; no file changed')
source = source.replace(comment, '''    /* Experimental: app-only context probe, including trailing newline. */
    if (ksu_get_uid_t(current_uid()) >= 10000 && name && value &&
        !strcmp(name, "current") &&
        (size == sizeof("u:r:adbroot:s0") - 1 ||
         (size == sizeof("u:r:adbroot:s0") && ((char *)value)[size - 1] == '\\n')) &&
        !memcmp(value, "u:r:adbroot:s0", sizeof("u:r:adbroot:s0") - 1))
        return -EINVAL;
''' + comment, 1)
print('OK setprocattr query')

if source == original:
    raise SystemExit('ERROR no changes made; no file changed')
TARGET.write_text(source, encoding='utf-8')
print('SUCCESS: all three source edits applied; review diff and compile before use')
