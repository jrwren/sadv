# sadv
A saslauthd client - https://godoc.org/github.com/jrwren/sadv

I am already running (etv)[http://github.com/jrwren/etv] as root because it edits system files and changes iptables rules, so I decided to investigate what it would take to use system password auth. It turns out saslauthd is a very simple protocol.

I ported this from https://github.com/cyrusimap/cyrus-sasl/blob/master/saslauthd/testsaslauthd.c

