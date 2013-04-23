# configure.ac - for w32pth
# Copyright (C) 2007, 2008 g10 Code GmbH
#
# This file is part of W32PTH
#
# W32PTH is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# W32PTH is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
min_automake_version="1.10"


# Remember to change the version number immediately *after* a release.
# Set my_issvn to "yes" for non-released code.  Remember to run an
# "svn up" and "autogen.sh" right before creating a distribution.
m4_define([my_version], [2.0.5])
m4_define([my_issvn], [no])

m4_define([svn_revision], m4_esyscmd([echo -n $( (svn info 2>/dev/null \
          || echo 'Revision: 0')|sed -n '/^Revision:/ s/[^0-9]//gp'|head -1)]))
m4_define([git_revision], m4_esyscmd([git branch -v 2>/dev/null \
          | awk '/^\* / {printf "%s",$3}']))
AC_INIT([w32pth],
        [my_version[]m4_if(my_issvn,[yes],
        [m4_if(git_revision,[],[-svn[]svn_revision],[-git[]git_revision])])],
        [gnupg-devel@gnupg.org])

# LT Version numbers: Remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
# Please remember to document interface changes in the NEWS file.
W32PTH_LT_CURRENT=2
W32PTH_LT_AGE=2
W32PTH_LT_REVISION=2
#-------------------
# If the API is changed in an incompatible way: increment the next counter.
W32PTH_CONFIG_API_VERSION=1

NEED_GPG_ERROR_VERSION=1.8

m4_define([git_brevis],m4_esyscmd(printf "%u" 0x[]m4_substr(git_revision,0,4)))
BUILD_REVISION=m4_if(git_revision,[],[svn_revision],[git_brevis])
PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR([w32-pth.c])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])
#AB_INIT

AC_GNU_SOURCE


AM_MAINTAINER_MODE


AC_SUBST(W32PTH_LT_CURRENT)
AC_SUBST(W32PTH_LT_AGE)
AC_SUBST(W32PTH_LT_REVISION)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])

#
# Initialize libtool
#
LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])



# Setup some stuff depending on host/target.
have_w32_system=no
have_w32ce_system=no
case "${host}" in
    *-mingw32ce*)
        have_w32_system=yes
        have_w32ce_system=yes
        ;;
    *-*-mingw32*)
      have_w32_system=yes
      ;;
    *)
      AC_MSG_ERROR([[This package may only be build for W32 systems]])
      ;;
esac
if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
   if test "$have_w32ce_system" = yes; then
      AC_DEFINE(HAVE_W32CE_SYSTEM,1,[Defined if we run on WindowsCE])
   fi
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)
AM_CONDITIONAL(HAVE_W32CE_SYSTEM, test "$have_w32ce_system" = yes)


# Checks for programs.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_C_INLINE


if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),_gcc_wopt=yes,_gcc_wopt=no)
    AC_MSG_RESULT($_gcc_wopt)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_wopt" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi

    AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wno-pointer-sign"
    AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi

fi

#
# On W32CE we need gpg-error because this provides our errno.h replacement.
#
if test "$have_w32ce_system" = yes; then
  AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION")
  if test "x$GPG_ERROR_LIBS" = "x"; then
    AC_MSG_ERROR([libgpg-error is needed for Windows CE.
                  See ftp://ftp.gnupg.org/gcrypt/libgpg-error/ .])
  fi
fi

AH_BOTTOM([
/* Under WindowsCE we need gpg-error's strerror macro.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1
])


#
# Set NETLIBS
#
if test "$have_w32ce_system" = yes; then
   NETLIBS="-lws2 $NETLIBS"
else
   NETLIBS="-lws2_32 $NETLIBS"
fi
AC_SUBST(NETLIBS)


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h signal.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

AC_C_BIGENDIAN

AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(long long)

# To be used in pth-config
W32PTH_CONFIG_LIBS="-lw32pth"
W32PTH_CONFIG_CFLAGS=""
AC_SUBST(W32PTH_CONFIG_LIBS)
AC_SUBST(W32PTH_CONFIG_CFLAGS)
AC_SUBST(W32PTH_CONFIG_API_VERSION)

# The Makefiles need to know about cross compiling
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

# Generate extended version information for W32.
if test "$have_w32_system" = yes; then
   BUILD_TIMESTAMP=`date --iso-8601=minutes`
   changequote(,)dnl
   BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
   changequote([,])dnl
   BUILD_FILEVERSION="${BUILD_FILEVERSION}${BUILD_REVISION}"
fi
AC_SUBST(BUILD_REVISION)
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION",
                   [Subversion revision used to build this package])


AC_CONFIG_FILES([
Makefile
versioninfo.rc
pth-config
])
AC_OUTPUT


echo "
        W32PTH v${VERSION} has been configured as follows:

        Platform:  $host

"

