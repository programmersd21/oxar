# security policy

## reporting

vulnerabilities must be reported privately, not in a public issue. open a draft
security advisory at https://github.com/programmersd21/oxar/security/advisories/new
or email geniussantu8385@gmail.com.

## supported versions

0.1.x receives security fixes while 0.2 is under development. earlier versions do
not receive fixes.

## response time

reports are acknowledged within three working days. a confirmed fix is released
within thirty days of the report, or a documented reason for delay is posted.

## scope

the archive is treated as hostile. the destination directory is trusted and the
process environment is trusted. concurrent modification of the destination by a
hostile process is out of scope: capability style directory handles remove
escapes but cannot stop a racing writer. windows process token requirements for
symbolic link creation are documented in docs/security_model.md.
