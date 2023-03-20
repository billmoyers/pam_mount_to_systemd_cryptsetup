# `pam_mount_to_systemd_cryptsetup`

## Description

This is used in `pam_mount.conf.xml` to mount volumes via `systemd`'s `cryptsetup`
with a stanza like:

```xml
<cryptmount>/usr/local/sbin/pam_mount_to_systemd_cryptsetup -- %(VOLUME)</cryptmount>
<cryptumount>/usr/local/sbin/pam_mount_to_systemd_cryptsetup -u -- %(VOLUME)</cryptumount>
```

This program will invoke the relevant `systemd` unit and send the password along from
`pam_mount` to the `systemd` responsible password agent.

The password agent behavior comes from [[1]](https://systemd.io/PASSWORD_AGENTS/).

## Installation

1. Setup the `apparmor` profile: `cp -i conf/etc/apparmor.d/usr.local.sbin.pam_mount_to_systemd_cryptsetup /etc/apparmor.d/`
2. Verify all tests pass: `mkdir target/test_inotify; cargo test`
3. Build: `cargo build --release`
4. Install: `cp -i target/release/pam_mount_to_systemd_cryptsetup /usr/local/sbin/`
