# Makefile.am for ipsec/src

yncludedir = @yncludedir@/ipsec

client_DATA =			\
	ipsec.ycp		\
	ipsec_auto.ycp	\
	ipsec_proposal.ycp

ynclude_DATA =			\
	helps.ycp		\
	wizards.ycp		\
	dialogs.ycp		\
	complex.ycp

desktop_DATA =			\
	ipsec.desktop

module_DATA =			\
	IPsec.ycp               \
	IPsecPopups.ycp         \
	IPsecConfig.pm		\
	FreeSwanUtils.pm        \
	FreeSwanCerts.pm

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
