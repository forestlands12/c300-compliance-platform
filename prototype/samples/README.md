# Sample targets (fake data)

- `linux-web-01/` is a snapshot of config files from a deliberately weak Linux server.
  It has no `etc/shadow`, so FS-01 shows NOT_COLLECTED on purpose.
- `win-ws-01/secpol.inf` is a Windows security policy export in the same format as
  `secedit /export /cfg secpol.inf /areas SECURITYPOLICY`. Lockout is off
  (LockoutBadCount = 0), so there is no LockoutDuration line, as on a real export.

Nothing here comes from a real machine.
