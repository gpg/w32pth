# Makefile.am -  Makefile for W32PTH
# Copyright (C) 2007, 2008 g10 Code GmbH
# 
# This file is part of W32PTH.
# 
# W32PTH is free software; you can redistribute it and/or modify it
# under the terms of the GNU LEsser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
# 
# W32PTH is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = 
AUTOMAKE_OPTIONS = no-dist-gzip dist-bzip2
DISTCHECK_CONFIGURE_FLAGS = --host=i586-mingw32msvc 

EXTRA_DIST = autogen.sh pth-config.in libw32pth.def

bin_SCRIPTS = pth-config
include_HEADERS = pth.h
lib_LTLIBRARIES = libw32pth.la

LTRCCOMPILE = $(LIBTOOL) --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) | \
     sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

.rc.lo:
	$(LTRCCOMPILE) -i $< -o $@

w32pth_res = versioninfo.lo
w32pth_res_ldflag = -Wl,.libs/versioninfo.o
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/libw32pth.def
w32pth_deps = $(w32pth_res) libw32pth.def

install-def-file:
	$(INSTALL) $(srcdir)/libw32pth.def $(DESTDIR)$(libdir)/libw32pth.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/libw32pth.def

libw32pth_la_LDFLAGS = $(w32pth_res_ldflag) $(no_undefined) $(export_symbols) \
      -version-info \
      @W32PTH_LT_CURRENT@:@W32PTH_LT_REVISION@:@W32PTH_LT_AGE@
libw32pth_la_DEPENDENCIES = $(w32pth_deps)
libw32pth_la_LIBADD = @LTLIBOBJS@ -lws2_32
libw32pth_la_SOURCES = pth.h debug.h w32-pth.c w32-io.h w32-io.c


install-data-local: install-def-file

uninstall-local: uninstall-def-file

dist-hook:
	@set -e; echo "$(VERSION)" > $(distdir)/VERSION
