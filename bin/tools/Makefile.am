include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LMDB_CFLAGS)

LDADD +=			\
	$(LIBDNS_LIBS)		\
	$(LIBISC_LIBS)		\
	$(LMDB_LIBS)

bin_PROGRAMS =			\
	arpaname		\
	mdig			\
	named-journalprint	\
	named-rrchecker		\
	nsec3hash		\
	named-nzd2nzf

arpaname_LDADD =		\
	$(LIBISC_LIBS)

if HAVE_DNSTAP
bin_PROGRAMS +=			\
	dnstap-read

dnstap_read_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(DNSTAP_CFLAGS)	\
	-I$(top_builddir)/lib/dns

dnstap_read_LDADD =		\
	$(LIBDNS_LIBS)		\
	$(LIBISC_LIBS)		\
	$(DNSTAP_LIBS)
endif
