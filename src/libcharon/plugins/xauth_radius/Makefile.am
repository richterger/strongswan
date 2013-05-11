
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libradius

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-xauth-radius.la
else
libstrongswan_xauth_radius_la_LIBADD = $(top_builddir)/src/libradius/libradius.la
plugin_LTLIBRARIES = libstrongswan-xauth-radius.la
endif

libstrongswan_xauth_radius_la_SOURCES = \
	xauth_radius_plugin.h xauth_radius_plugin.c \
	xauth_radius.h xauth_radius.c

libstrongswan_xauth_radius_la_LDFLAGS = -module -avoid-version
