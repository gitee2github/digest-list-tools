bin_PROGRAMS=manage_digest_lists gen_digest_lists verify_digest_lists \
	     write_rpm_pgp_sig upload_digest_lists

manage_digest_lists_CFLAGS=-I$(top_srcdir)/include
manage_digest_lists_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la
manage_digest_lists_SOURCES=manage_digest_lists.c

gen_digest_lists_CFLAGS=-I$(top_srcdir)/include
gen_digest_lists_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la
gen_digest_lists_SOURCES=gen_digest_lists.c

verify_digest_lists_CFLAGS=-I$(top_srcdir)/include
verify_digest_lists_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la
verify_digest_lists_SOURCES=verify_digest_lists.c

write_rpm_pgp_sig_CFLAGS=-I$(top_srcdir)/include
write_rpm_pgp_sig_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la
write_rpm_pgp_sig_SOURCES=write_rpm_pgp_sig.c

upload_digest_lists_CFLAGS=-I$(top_srcdir)/include
upload_digest_lists_LDFLAGS=-all-static
upload_digest_lists_SOURCES=upload_digest_lists.c

libexecdir=$(prefix)/libexec
libexec_PROGRAMS=rpm_parser

rpm_parser_CFLAGS=-I$(top_srcdir)/include
rpm_parser_LDFLAGS=-all-static
rpm_parser_SOURCES=rpm_parser.c ../lib/kernel_lib.c
