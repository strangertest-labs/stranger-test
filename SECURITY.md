# Security policy

## Reporting a problem in stranger-test

If you find a security problem in stranger-test itself (for example a way it
could send a credential somewhere it should not, write a secret to a report, or
contact a host it was not pointed at), please report it privately:

- Open the repository's **Security** tab and choose **Report a vulnerability**.

Please do not open a public issue for it. This is a one-maintainer project: the
maintainer aims to reply within a week, and fixes are best effort.

Only the newest release is supported.

## What the tool is and is not for

stranger-test tests systems for cross-user data leaks. Use it only on systems
you run or are authorized to test. It refuses non-local targets unless you pass
an explicit authorization, and it has no mode that scans many targets.

If stranger-test shows you a leak in someone else's software, report it to that
project's own security contact, privately. Do not post it publicly first.

## What stranger-test does not do

- It sends no telemetry.
- It never writes credentials to its output; reports show short fingerprints.
