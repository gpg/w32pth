/* debug.h - interface to debugging functions
   Copyright (C) 2002, 2004, 2005, 2007, 2008 g10 Code GmbH
 
   This file is part of PTH.

   PTH is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
   
   PTH is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef DEBUG_H
#define DEBUG_H

#include <string.h>


/* Keeps the current debug level. Define marcos to test them. */
extern int debug_level;
extern FILE *dbgfp;
#define DBG_ERROR  (debug_level >= 1)
#define DBG_INFO   (debug_level >= 2)
#define DBG_CALLS  (debug_level >= 3)


/* Indirect stringification, requires __STDC__ to work.  */
#define STRINGIFY(v) #v
#define XSTRINGIFY(v) STRINGIFY(v)

/* Log the formatted string FORMAT at debug level LEVEL or higher.  */
void _pth_debug (int level, const char *format, ...);


/* Trace support.  */

/* FIXME: For now.  */
#define _pth_debug_trace() 1

#define _TRACE(lvl, name, tag)					\
  int _pth_trace_level = lvl;					\
  const char *const _pth_trace_func = name;			\
  const char *const _pth_trace_tagname = STRINGIFY (tag);	\
  void *_pth_trace_tag = (void *) tag

#define TRACE_BEG(lvl, name, tag)			   \
  _TRACE (lvl, name, tag);				   \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): enter\n", \
		_pth_trace_func, _pth_trace_tagname,   \
		_pth_trace_tag), 0
#define TRACE_BEG0(lvl, name, tag, fmt)					\
  _TRACE (lvl, name, tag);						\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): enter: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag), 0
#define TRACE_BEG1(lvl, name, tag, fmt, arg1)				\
  _TRACE (lvl, name, tag);						\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): enter: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag, arg1), 0
#define TRACE_BEG2(lvl, name, tag, fmt, arg1, arg2)		    \
  _TRACE (lvl, name, tag);					    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): enter: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2), 0
#define TRACE_BEG3(lvl, name, tag, fmt, arg1, arg2, arg3)	    \
  _TRACE (lvl, name, tag);					    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): enter: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2, arg3), 0
#define TRACE_BEG4(lvl, name, tag, fmt, arg1, arg2, arg3, arg4)	    \
  _TRACE (lvl, name, tag);					    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): enter: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2, arg3, arg4), 0

#define TRACE(lvl, name, tag)						\
  _pth_debug (lvl, "%s (%s=0x%x): call\n",				\
		name, STRINGIFY (tag), (void *) tag), 0
#define TRACE0(lvl, name, tag, fmt)					\
  _pth_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",			\
		name, STRINGIFY (tag), (void *) tag), 0
#define TRACE1(lvl, name, tag, fmt, arg1)			       \
  _pth_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",		       \
		name, STRINGIFY (tag), (void *) tag, arg1), 0
#define TRACE2(lvl, name, tag, fmt, arg1, arg2)			       \
  _pth_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",		       \
		name, STRINGIFY (tag), (void *) tag, arg1, arg2), 0
#define TRACE3(lvl, name, tag, fmt, arg1, arg2, arg3)		       \
  _pth_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",		       \
		name, STRINGIFY (tag), (void *) tag, arg1, arg2,       \
		arg3), 0
#define TRACE6(lvl, name, tag, fmt, arg1, arg2, arg3, arg4, arg5, arg6)	\
  _pth_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",			\
		name, STRINGIFY (tag), (void *) tag, arg1, arg2, arg3,	\
		arg4, arg5, arg6), 0

#define TRACE_ERR(err)							\
  err == 0 ? (TRACE_SUC ()) :						\
    (_pth_debug (_pth_trace_level, "%s (%s=0x%x): error: %s <%s>\n",	\
		   _pth_trace_func, _pth_trace_tagname,		\
		   _pth_trace_tag, pth_strerror (err),		\
		   pth_strsource (err)), (err))
/* The cast to void suppresses GCC warnings.  */
#define TRACE_SYSRES(res)						\
  res >= 0 ? ((void) (TRACE_SUC1 ("result=%i", res)), (res)) :		\
    (_pth_debug (_pth_trace_level, "%s (%s=0x%x): error: %s\n",	\
		   _pth_trace_func, _pth_trace_tagname,		\
		   _pth_trace_tag, strerror (errno)), (res))
#define TRACE_SYSERR(res)						\
  res == 0 ? ((void) (TRACE_SUC1 ("result=%i", res)), (res)) :		\
    (_pth_debug (_pth_trace_level, "%s (%s=0x%x): error: %s\n",	\
		   _pth_trace_func, _pth_trace_tagname,		\
		   _pth_trace_tag, strerror (res)), (res))

#define TRACE_SUC()						 \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): leave\n",       \
		_pth_trace_func, _pth_trace_tagname,	 \
		_pth_trace_tag), 0
#define TRACE_SUC0(fmt)							\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag), 0
#define TRACE_SUC1(fmt, arg1)						\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag, arg1), 0
#define TRACE_SUC2(fmt, arg1, arg2)					\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag, arg1, arg2), 0
#define TRACE_SUC5(fmt, arg1, arg2, arg3, arg4, arg5)			\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag, arg1, arg2, arg3, arg4, arg5), 0

#define TRACE_LOG(fmt)							\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): check: " fmt "\n",	\
		_pth_trace_func, _pth_trace_tagname,		\
		_pth_trace_tag), 0
#define TRACE_LOG1(fmt, arg1)						\
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1), 0
#define TRACE_LOG2(fmt, arg1, arg2)				    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2), 0
#define TRACE_LOG3(fmt, arg1, arg2, arg3)			    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2, arg3), 0
#define TRACE_LOG4(fmt, arg1, arg2, arg3, arg4)			    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2, arg3, arg4), 0
#define TRACE_LOG6(fmt, arg1, arg2, arg3, arg4, arg5, arg6)	    \
  _pth_debug (_pth_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_pth_trace_func, _pth_trace_tagname,	    \
		_pth_trace_tag, arg1, arg2, arg3, arg4, arg5,	    \
		arg6), 0

#define TRACE_LOGBUF(buf, len)						\
  _pth_debug_buffer (_pth_trace_level, "%s (%s=0x%x): check: %s",	\
		       _pth_trace_func, _pth_trace_tagname,		\
		       _pth_trace_tag, buf, len)

#define TRACE_SEQ(hlp,fmt)						\
  _pth_debug_begin (&(hlp), _pth_trace_level,			\
		      "%s (%s=0x%x): check: " fmt,			\
		      _pth_trace_func, _pth_trace_tagname,		\
		      _pth_trace_tag)
#define TRACE_ADD0(hlp,fmt) \
  _pth_debug_add (&(hlp), fmt)
#define TRACE_ADD1(hlp,fmt,a) \
  _pth_debug_add (&(hlp), fmt, (a))
#define TRACE_ADD2(hlp,fmt,a,b) \
  _pth_debug_add (&(hlp), fmt, (a), (b))
#define TRACE_ADD3(hlp,fmt,a,b,c) \
  _pth_debug_add (&(hlp), fmt, (a), (b), (c))
#define TRACE_END(hlp,fmt) \
  _pth_debug_add (&(hlp), fmt); \
  _pth_debug_end (&(hlp))
#define TRACE_ENABLED(hlp) (!!(hlp))

#endif	/* DEBUG_H */
