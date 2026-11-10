#!/usr/bin/env python3
"""Experimental BakaSU d5e9e025 context-query test patch.

Edits SELinux Hide query responses for a single SELinux context and ordinary
Android app UIDs. Does not change live SELinux policy or remove the type.
Fails closed if the expected source anchors have changed.
"""
from pathlib import Path

path = Path('kernel/feature/selinux_hide.c')
src = path.read_text(encoding='utf-8')


def replace_once(label: str, anchor: str, replacement: str) -> None:
    global src
    count = src.count(anchor)
    if count != 1:
        raise SystemExit(f'ERROR {label}: expected 1 source anchor, found {count}. No file changed.')
    src = src.replace(anchor, replacement, 1)
    print(f'OK {label}')


context_anchor = '''    if (length)
        goto out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    length = security_context_to_sid_with_policy(backup_sepolicy, buf, size'''
context_change = '''    if (length)
        goto out;
    /* Experimental: app-facing adbroot context query only. */
    if (ksu_get_uid_t(current_uid()) >= 10000 &&
        size == sizeof("u:r:adbroot:s0") - 1 &&
        !memcmp(buf, "u:r:adbroot:s0", sizeof("u:r:adbroot:s0") - 1)) {
        length = -EINVAL;
        goto out;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    length = security_context_to_sid_with_policy(backup_sepolicy, buf, size'''
replace_once('context query', context_anchor, context_change)

access_anchor = '''    sconlen = strlen(scon);
    tconlen = strlen(tcon);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)'''
access_change = '''    sconlen = strlen(scon);
    tconlen = strlen(tcon);
    /* Experimental: class=0 probe only; preserve normal access decisions. */
    if (ksu_get_uid_t(current_uid()) >= 10000 && tclass == 0 &&
        (!strcmp(scon, "u:r:adbroot:s0") || !strcmp(tcon, "u:r:adbroot:s0"))) {
        length = -EINVAL;
        goto out;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)'''
replace_once('class-zero access query', access_anchor, access_change)

attr_anchor = '''    error = ksu_avc_has_perm_compat(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
    if (error)
        return error;
    /* Obtain a SID for the context, if one was specified. */'''
attr_change = '''    error = ksu_avc_has_perm_compat(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
    if (error)
        return error;
    /* Experimental: preserve original SELinux policy and other contexts. */
    if (ksu_get_uid_t(current_uid()) >= 10000 && name && value &&
        !strcmp(name, "current") &&
        (size == sizeof("u:r:adbroot:s0") - 1 ||
         (size == sizeof("u:r:adbroot:s0") && ((char *)value)[size - 1] == '\\n')) &&
        !memcmp(value, "u:r:adbroot:s0", sizeof("u:r:adbroot:s0") - 1))
        return -EINVAL;
    /* Obtain a SID for the context, if one was specified. */'''
replace_once('setprocattr query', attr_anchor, attr_change)

path.write_text(src, encoding='utf-8')
print('SUCCESS: source updated; run git diff --check and full compile before any device use')
