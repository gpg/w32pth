/* w32-io.c - W32 API I/O functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <windows.h>

#include <assert.h>

#ifdef HAVE_W32CE_SYSTEM
# include <winioctl.h>
# include <devload.h>
# define GPGCEDEV_IOCTL_GET_RVID                                         \
  CTL_CODE (FILE_DEVICE_STREAMS, 2048, METHOD_BUFFERED, FILE_ANY_ACCESS)
# define GPGCEDEV_IOCTL_MAKE_PIPE                                        \
  CTL_CODE (FILE_DEVICE_STREAMS, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)

#warning fixme pth_pipe is not correct - only used in dirmngr - remove it?

#endif /*HAVE_W32CE_SYSTEM*/


#include "utils.h"
#include "debug.h"
#include "w32-io.h"




struct critsect_s
{
  const char *name;
  void *priv;
};

#define DEFINE_GLOBAL_LOCK(name) \
  struct critsect_s name = { #name, NULL }
#define DEFINE_STATIC_LOCK(name) \
  static struct critsect_s name  = { #name, NULL }

#define DECLARE_LOCK(name) \
  struct critsect_s name
#define INIT_LOCK(a)			\
  do					\
    {					\
      (a).name = #a;			\
      (a).priv = NULL;			\
    }					\
  while (0)
#define DESTROY_LOCK(name) _pth_sema_cs_destroy (&(name))
                       

#define LOCK(name)			\
  do					\
    {					\
      _pth_sema_cs_enter (&(name));	\
    }					\
  while (0)

#define UNLOCK(name)			\
  do					\
    {					\
      _pth_sema_cs_leave (&(name));	\
    }					\
  while (0)


static void
sema_fatal (const char *text)
{
    fprintf (stderr, "sema.c: %s\n", text);
    abort ();
}


static void
critsect_init (struct critsect_s *s)
{
    CRITICAL_SECTION *mp;
    static CRITICAL_SECTION init_lock;
    static int initialized;
    
    if (!initialized) {
        /* The very first time we call this function, we assume that
	   only one thread is running, so that we can bootstrap the
	   semaphore code.  */
        InitializeCriticalSection (&init_lock);
        initialized = 1;
    }
    if (!s)
        return; /* we just want to initialize ourself */

    /* first test whether it is really not initialized */
    EnterCriticalSection (&init_lock);
    if ( s->priv ) {
        LeaveCriticalSection (&init_lock);
        return;
    }
    /* now init it */
    mp = _pth_malloc ( sizeof *mp );
    if (!mp) {
        LeaveCriticalSection (&init_lock);
        sema_fatal ("out of core while creating critical section lock");
    }
    InitializeCriticalSection (mp);
    s->priv = mp;
    LeaveCriticalSection (&init_lock);
}


void
_pth_sema_subsystem_init (void)
{
    /* fixme: we should check that there is only one thread running */
    critsect_init (NULL);
}


void
_pth_sema_cs_enter ( struct critsect_s *s )
{
    if (!s->priv)
        critsect_init (s);
    EnterCriticalSection ( (CRITICAL_SECTION*)s->priv );
}

void
_pth_sema_cs_leave (struct critsect_s *s)
{
    if (!s->priv)
        critsect_init (s);
    LeaveCriticalSection ((CRITICAL_SECTION*)s->priv);
}

void
_pth_sema_cs_destroy ( struct critsect_s *s )
{
    if (s && s->priv) {
        DeleteCriticalSection ((CRITICAL_SECTION*)s->priv);
        _pth_free (s->priv);
        s->priv = NULL;
    }
}


DEFINE_STATIC_LOCK (debug_lock);

#define DEBUG_SYSIO 2

/* Log the formatted string FORMAT at debug level LEVEL or higher.  */
void
_pth_debug (int level, const char *format, ...)
{
  va_list arg_ptr;
  int saved_errno;

  saved_errno = errno;

  if (debug_level < level)
    return;

#ifdef HAVE_W32CE_SYSTEM
  if (dbghd)
    {
      LOCK (debug_lock);
      va_start (arg_ptr, format);
      {
        char buffer[256];
        DWORD n, nwritten;
        
        _snprintf (buffer, 30, "%lu/w32pth: ", 
                   (unsigned long)GetCurrentThreadId ());
        buffer[29] = 0;
        n = strlen (buffer);
        _vsnprintf (buffer + n, sizeof buffer - n, format, arg_ptr);
        buffer[sizeof buffer - 1] = 0;
        n = strlen (buffer);
        WriteFile (dbghd, buffer, n, &nwritten, NULL);
      }
      va_end (arg_ptr);
      UNLOCK (debug_lock);
    }
#else    
  va_start (arg_ptr, format);
  LOCK (debug_lock);
  fprintf (dbgfp, "%05lu/%lu.%lu/w32pth: ", 
           ((unsigned long)GetTickCount () % 100000),
           (unsigned long)GetCurrentProcessId (),
           (unsigned long)GetCurrentThreadId ());
  vfprintf (dbgfp, format, arg_ptr);
  va_end (arg_ptr);
  if(format && *format && format[strlen (format) - 1] != '\n')
    putc ('\n', dbgfp);
  UNLOCK (debug_lock);
  fflush (dbgfp);
#endif
  set_errno (saved_errno);
}


#define fd_to_handle(a)  ((HANDLE)(a))
#define handle_to_fd(a)  ((int)(a))
#define pid_to_handle(a) ((HANDLE)(a))
#define handle_to_pid(a) ((int)(a))

#define READBUF_SIZE 4096
#define WRITEBUF_SIZE 4096
#define PIPEBUF_SIZE  4096
#define MAX_READERS 40
#define MAX_WRITERS 40



struct reader_context_s
{
  HANDLE file_hd;
  HANDLE thread_hd;	
  int refcount;

  DECLARE_LOCK (mutex);

  int stop_me;
  int eof;
  int eof_shortcut;
  int error;
  int error_code;
  
  /* This is manually reset.  */
  HANDLE have_data_ev;
  /* This is automatically reset.  */
  HANDLE have_space_ev;
  HANDLE stopped;
  size_t readpos, writepos;
  char buffer[READBUF_SIZE];
};


static struct
{
  volatile int used;
  int fd;
  struct reader_context_s *context;
} reader_table[MAX_READERS];
static int reader_table_size= MAX_READERS;
DEFINE_STATIC_LOCK (reader_table_lock);


struct writer_context_s
{
  HANDLE file_hd;
  HANDLE thread_hd;	
  int refcount;

  DECLARE_LOCK (mutex);
  
  int stop_me;
  int error;
  int error_code;

  /* This is manually reset.  */
  HANDLE have_data;
  HANDLE is_empty;
  HANDLE stopped;
  size_t nbytes; 
  char buffer[WRITEBUF_SIZE];
};


static struct
{
  volatile int used;
  int fd;
  struct writer_context_s *context;
} writer_table[MAX_WRITERS];
static int writer_table_size= MAX_WRITERS;
DEFINE_STATIC_LOCK (writer_table_lock);


static int
get_desired_thread_priority (void)
{
  return THREAD_PRIORITY_HIGHEST;
}


static HANDLE
set_synchronize (HANDLE hd)
{
  HANDLE new_hd;

  /* For NT we have to set the sync flag.  It seems that the only way
     to do it is by duplicating the handle.  Tsss...  */
  if (!DuplicateHandle (GetCurrentProcess (), hd,
			GetCurrentProcess (), &new_hd,
			EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, 0))
    {
      TRACE1 (DEBUG_SYSIO, "pth:set_synchronize", hd,
	      "DuplicateHandle failed: ec=%d", (int) GetLastError ());
      /* FIXME: Should translate the error code.  */
      set_errno (EIO);
      return INVALID_HANDLE_VALUE;
    }

  CloseHandle (hd);
  return new_hd;
}


/* Return true if HD refers to a socket.  */
static int
is_socket (HANDLE hd)
{
#ifdef HAVE_W32CE_SYSTEM
  (void)hd;
  return 0;
#else
  /* We need to figure out whether we are working on a socket or on a
     handle.  A trivial way would be to check for the return code of
     recv and see if it is WSAENOTSOCK.  However the recv may block
     after the server process died and thus the destroy_reader will
     hang.  Another option is to use getsockopt to test whether it is
     a socket.  The bug here is that once a socket with a certain
     values has been opened, closed and later a CreatePipe returned
     the same value (i.e. handle), getsockopt still believes it is a
     socket.  What we do now is to use a combination of GetFileType
     and GetNamedPipeInfo.  The specs say that the latter may be used
     on anonymous pipes as well.  Note that there are claims that
     since winsocket version 2 ReadFile may be used on a socket but
     only if it is supported by the service provider.  Tests on a
     stock XP using a local TCP socket show that it does not work.  */
  DWORD dummyflags, dummyoutsize, dummyinsize, dummyinst;
  if (GetFileType (hd) == FILE_TYPE_PIPE
      && !GetNamedPipeInfo (hd, &dummyflags, &dummyoutsize,
                            &dummyinsize, &dummyinst))
    return 1; /* Function failed; thus we assume it is a socket.  */
  else
    return 0; /* Success; this is not a socket.  */
#endif
}


static DWORD CALLBACK 
reader (void *arg)
{
  struct reader_context_s *ctx = arg;
  int nbytes;
  DWORD nread;
  int sock;
  TRACE_BEG1 (DEBUG_SYSIO, "pth:reader", ctx->file_hd,
	      "thread=%p", ctx->thread_hd);

  sock = is_socket (ctx->file_hd);

  for (;;)
    {
      LOCK (ctx->mutex);
      /* Leave a 1 byte gap so that we can see whether it is empty or
	 full.  */
      if ((ctx->writepos + 1) % READBUF_SIZE == ctx->readpos)
	{ 
	  /* Wait for space.  */
	  if (!ResetEvent (ctx->have_space_ev))
	    TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  TRACE_LOG ("waiting for space");
	  WaitForSingleObject (ctx->have_space_ev, INFINITE);
	  TRACE_LOG ("got space");
	  LOCK (ctx->mutex);
       	}
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      nbytes = (ctx->readpos + READBUF_SIZE
		- ctx->writepos - 1) % READBUF_SIZE;
      if (nbytes > READBUF_SIZE - ctx->writepos)
	nbytes = READBUF_SIZE - ctx->writepos;
      UNLOCK (ctx->mutex);
      
      TRACE_LOG2 ("%s %d bytes", sock? "receiving":"reading", nbytes);

      if (sock)
        {
          int n;

          n = recv ((int)ctx->file_hd,
                    ctx->buffer + ctx->writepos, nbytes, 0);
          if (n < 0)
            {
              ctx->error_code = (int) WSAGetLastError ();
              if (ctx->error_code == ERROR_BROKEN_PIPE)
                {
                  ctx->eof = 1;
                  TRACE_LOG ("got EOF (broken connection)");
                }
              else
                {
                  ctx->error = 1;
                  TRACE_LOG1 ("recv error: ec=%d", ctx->error_code);
                }
              break;
            }
          nread = n;
        }
      else
        {
          if (!ReadFile (ctx->file_hd,
                         ctx->buffer + ctx->writepos, nbytes, &nread, NULL))
            {
              ctx->error_code = (int) GetLastError ();
              if (ctx->error_code == ERROR_BROKEN_PIPE)
                {
                  ctx->eof = 1;
                  TRACE_LOG ("got EOF (broken pipe)");
                }
#ifdef HAVE_W32CE_SYSTEM
              else if (ctx->error_code == ERROR_PIPE_NOT_CONNECTED
                       || ctx->error_code == ERROR_BUSY)
                {
                  /* This may happen while one pipe end is still dangling
                     because the child process has not yet completed the
                     pipe creation.  ERROR_BUSY has been seen as well, it
                     is propabaly returned by the device manager.  */
                  ctx->error_code = 0;
                  Sleep (100);
                  continue;
                }
#endif
              else
                {
                  ctx->error = 1;
                  TRACE_LOG1 ("read error: ec=%d", ctx->error_code);
                }
              break;
            }
        }
      if (!nread)
	{
	  ctx->eof = 1;
	  TRACE_LOG ("got eof");
	  break;
        }
      TRACE_LOG1 ("got %u bytes", nread);
      
      LOCK (ctx->mutex);
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      ctx->writepos = (ctx->writepos + nread) % READBUF_SIZE;
      if (!SetEvent (ctx->have_data_ev))
	TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error or EOF.  */
  if (!SetEvent (ctx->have_data_ev))
    TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
  SetEvent (ctx->stopped);
  
  return TRACE_SUC ();
}


static struct reader_context_s *
create_reader (HANDLE fd)
{
  struct reader_context_s *ctx;
  SECURITY_ATTRIBUTES sec_attr;
  DWORD tid;

  TRACE_BEG (DEBUG_SYSIO, "pth:create_reader", fd);

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;
  
  ctx = _pth_calloc (1, sizeof *ctx);
  if (!ctx)
    {
      TRACE_SYSERR (errno);
      return NULL;
    }

  ctx->file_hd = fd;
  ctx->refcount = 1;
  ctx->have_data_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data_ev)
    ctx->have_space_ev = CreateEvent (&sec_attr, FALSE, TRUE, NULL);
  if (ctx->have_space_ev)
    ctx->stopped = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data_ev || !ctx->have_space_ev || !ctx->stopped)
    {
      TRACE_LOG1 ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data_ev)
	CloseHandle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	CloseHandle (ctx->have_space_ev);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
      _pth_free (ctx);
      /* FIXME: Translate the error code.  */
      TRACE_SYSERR (EIO);
      return NULL;
    }

  ctx->have_data_ev = set_synchronize (ctx->have_data_ev);
  INIT_LOCK (ctx->mutex);

  ctx->thread_hd = CreateThread (&sec_attr, 0, reader, ctx, 0, &tid);
  if (!ctx->thread_hd)
    {
      TRACE_LOG1 ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data_ev)
	CloseHandle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	CloseHandle (ctx->have_space_ev);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
      _pth_free (ctx);
      TRACE_SYSERR (EIO);
      return NULL;
    }    
  else
    {
      /* We set the priority of the thread higher because we know that
         it only runs for a short time.  This greatly helps to
         increase the performance of the I/O.  */
      SetThreadPriority (ctx->thread_hd, get_desired_thread_priority ());
    }

  TRACE_SUC ();
  return ctx;
}


static void
destroy_reader (struct reader_context_s *ctx)
{
  LOCK (ctx->mutex);
  ctx->refcount--;
  if (ctx->refcount != 0)
    {
      UNLOCK (ctx->mutex);
      return;
    }
  ctx->stop_me = 1;
  if (ctx->have_space_ev) 
    SetEvent (ctx->have_space_ev);
  UNLOCK (ctx->mutex);

  TRACE1 (DEBUG_SYSIO, "pth:destroy_reader", ctx->file_hd,
	  "waiting for termination of thread %p", ctx->thread_hd);
  WaitForSingleObject (ctx->stopped, INFINITE);
  TRACE1 (DEBUG_SYSIO, "pth:destroy_reader", ctx->file_hd,
	  "thread %p has terminated", ctx->thread_hd);
    
  if (ctx->stopped)
    CloseHandle (ctx->stopped);
  if (ctx->have_data_ev)
    CloseHandle (ctx->have_data_ev);
  if (ctx->have_space_ev)
    CloseHandle (ctx->have_space_ev);
  CloseHandle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  _pth_free (ctx);
}


/* Find a reader context or create a new one.  Note that the reader
   context will last until a pth_close.  */
static struct reader_context_s *
find_reader (int fd, int start_it)
{
  struct reader_context_s *rd = NULL;
  int i;

  LOCK (reader_table_lock);
  for (i = 0; i < reader_table_size; i++)
    if (reader_table[i].used && reader_table[i].fd == fd)
      rd = reader_table[i].context;

  if (rd || !start_it)
    {
      UNLOCK (reader_table_lock);
      return rd;
    }

  for (i = 0; i < reader_table_size; i++)
    if (!reader_table[i].used)
      break;

  if (i != reader_table_size)
    {
      rd = create_reader (fd_to_handle (fd));
      reader_table[i].fd = fd;
      reader_table[i].context = rd;
      reader_table[i].used = 1;
    }

  UNLOCK (reader_table_lock);
  return rd;
}


static void
kill_reader (int fd)
{
  int i;

  LOCK (reader_table_lock);
  for (i = 0; i < reader_table_size; i++)
    {
      if (reader_table[i].used && reader_table[i].fd == fd)
	{
	  destroy_reader (reader_table[i].context);
	  reader_table[i].context = NULL;
	  reader_table[i].used = 0;
	  break;
	}
    }
  UNLOCK (reader_table_lock);
}


int
_pth_io_read (int fd, void *buffer, size_t count)
{
  int nread;
  struct reader_context_s *ctx;
  TRACE_BEG2 (DEBUG_SYSIO, "_pth_io_read", fd,
	      "buffer=%p, count=%u", buffer, count);
  
  ctx = find_reader (fd, 0);
  if (!ctx)
    {
      set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }
  if (ctx->eof_shortcut)
    return TRACE_SYSRES (0);

  LOCK (ctx->mutex);
  if (ctx->readpos == ctx->writepos && !ctx->error)
    {
      /* No data available.  */
      UNLOCK (ctx->mutex);
      TRACE_LOG1 ("waiting for data from thread %p", ctx->thread_hd);
      WaitForSingleObject (ctx->have_data_ev, INFINITE);
      TRACE_LOG1 ("data from thread %p available", ctx->thread_hd);
      LOCK (ctx->mutex);
    }
  
  if (ctx->readpos == ctx->writepos || ctx->error)
    {
      UNLOCK (ctx->mutex);
      ctx->eof_shortcut = 1;
      if (ctx->eof)
	return TRACE_SYSRES (0);
      if (!ctx->error)
	{
	  TRACE_LOG ("EOF but ctx->eof flag not set");
	  return 0;
	}
      set_errno (ctx->error_code);
      return TRACE_SYSRES (-1);
    }
  
  nread = ctx->readpos < ctx->writepos
    ? ctx->writepos - ctx->readpos
    : READBUF_SIZE - ctx->readpos;
  if (nread > count)
    nread = count;
  memcpy (buffer, ctx->buffer + ctx->readpos, nread);
  ctx->readpos = (ctx->readpos + nread) % READBUF_SIZE;
  if (ctx->readpos == ctx->writepos && !ctx->eof)
    {
      if (!ResetEvent (ctx->have_data_ev))
	{
	  TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  /* FIXME: Should translate the error code.  */
	  set_errno (EIO);
	  return TRACE_SYSRES (-1);
	}
    }
  if (!SetEvent (ctx->have_space_ev))
    {
      TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  UNLOCK (ctx->mutex);
  
#if 0
  TRACE_LOGBUF (buffer, nread);
#endif
  return TRACE_SYSRES (nread);
}


/* The writer does use a simple buffering strategy so that we are
   informed about write errors as soon as possible (i. e. with the the
   next call to the write function.  */
static DWORD CALLBACK 
writer (void *arg)
{
  struct writer_context_s *ctx = arg;
  DWORD nwritten;
  int sock;
  TRACE_BEG1 (DEBUG_SYSIO, "pth:writer", ctx->file_hd,
	      "thread=%p", ctx->thread_hd);

  sock = is_socket (ctx->file_hd);

  for (;;)
    {
      LOCK (ctx->mutex);
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      if (!ctx->nbytes)
	{ 
	  if (!SetEvent (ctx->is_empty))
	    TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
	  if (!ResetEvent (ctx->have_data))
	    TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  TRACE_LOG ("idle");
	  WaitForSingleObject (ctx->have_data, INFINITE);
	  TRACE_LOG ("got data to send");
	  LOCK (ctx->mutex);
       	}
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      UNLOCK (ctx->mutex);
      
      TRACE_LOG2 ("%s %d bytes", sock?"sending":"writing", ctx->nbytes);
 
      /* Note that CTX->nbytes is not zero at this point, because
	 _pth_io_write always writes at least 1 byte before waking
	 us up, unless CTX->stop_me is true, which we catch above.  */
      if (sock)
        {
          /* We need to try send first because a socket handle can't
             be used with WriteFile.  */
          int n;
          
          n = send ((int)ctx->file_hd,
                    ctx->buffer, ctx->nbytes, 0);
          if (n < 0)
            {
              ctx->error_code = (int) WSAGetLastError ();
              ctx->error = 1;
              TRACE_LOG1 ("send error: ec=%d", ctx->error_code);
              break;
            }
          nwritten = n;
        }
      else
        {
          if (!WriteFile (ctx->file_hd, ctx->buffer,
                          ctx->nbytes, &nwritten, NULL))
            {
              ctx->error_code = (int) GetLastError ();
#ifdef HAVE_W32CE_SYSTEM
              if (ctx->error_code == ERROR_PIPE_NOT_CONNECTED
                  || ctx->error_code == ERROR_BUSY)
                {
                  /* This may happen while one pipe end is still
                     dangling because the child process has not yet
                     completed the pipe creation.  ERROR_BUSY has been
                     seen as well, it is propabaly returned by the
                     device manager. */
                  ctx->error_code = 0;
                  Sleep (100);
                  continue;
                }
#endif
              ctx->error = 1;
              TRACE_LOG1 ("write error: ec=%d", ctx->error_code);
              break;
            }
	}
      TRACE_LOG1 ("wrote %d bytes", (int) nwritten);
      
      LOCK (ctx->mutex);
      ctx->nbytes -= nwritten;
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error.  */
  if (!SetEvent (ctx->is_empty))
    TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
  SetEvent (ctx->stopped);

  return TRACE_SUC ();
}


static struct writer_context_s *
create_writer (HANDLE fd)
{
  struct writer_context_s *ctx;
  SECURITY_ATTRIBUTES sec_attr;
  DWORD tid;

  TRACE_BEG (DEBUG_SYSIO, "pth:create_writer", fd);

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  ctx = _pth_calloc (1, sizeof *ctx);
  if (!ctx)
    {
      TRACE_SYSERR (errno);
      return NULL;
    }
  
  ctx->file_hd = fd;
  ctx->refcount = 1;
  ctx->have_data = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data)
    ctx->is_empty  = CreateEvent (&sec_attr, TRUE, TRUE, NULL);
  if (ctx->is_empty)
    ctx->stopped = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data || !ctx->is_empty || !ctx->stopped)
    {
      TRACE_LOG1 ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data)
	CloseHandle (ctx->have_data);
      if (ctx->is_empty)
	CloseHandle (ctx->is_empty);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
      _pth_free (ctx);
      /* FIXME: Translate the error code.  */
      TRACE_SYSERR (EIO);
      return NULL;
    }

  ctx->is_empty = set_synchronize (ctx->is_empty);
  INIT_LOCK (ctx->mutex);

  ctx->thread_hd = CreateThread (&sec_attr, 0, writer, ctx, 0, &tid );
  if (!ctx->thread_hd)
    {
      TRACE_LOG1 ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data)
	CloseHandle (ctx->have_data);
      if (ctx->is_empty)
	CloseHandle (ctx->is_empty);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
      _pth_free (ctx);
      TRACE_SYSERR (EIO);
      return NULL;
    }    
  else
    {
      /* We set the priority of the thread higher because we know
	 that it only runs for a short time.  This greatly helps to
	 increase the performance of the I/O.  */
      SetThreadPriority (ctx->thread_hd, get_desired_thread_priority ());
    }

  TRACE_SUC ();
  return ctx;
}

static void
destroy_writer (struct writer_context_s *ctx)
{
  LOCK (ctx->mutex);
  ctx->refcount--;
  if (ctx->refcount != 0)
    {
      UNLOCK (ctx->mutex);
      return;
    }
  ctx->stop_me = 1;
  if (ctx->have_data) 
    SetEvent (ctx->have_data);
  UNLOCK (ctx->mutex);
  
  TRACE1 (DEBUG_SYSIO, "pth:destroy_writer", ctx->file_hd,
	  "waiting for termination of thread %p", ctx->thread_hd);
  WaitForSingleObject (ctx->stopped, INFINITE);
  TRACE1 (DEBUG_SYSIO, "pth:destroy_writer", ctx->file_hd,
	  "thread %p has terminated", ctx->thread_hd);
  
  if (ctx->stopped)
    CloseHandle (ctx->stopped);
  if (ctx->have_data)
    CloseHandle (ctx->have_data);
  if (ctx->is_empty)
    CloseHandle (ctx->is_empty);
  CloseHandle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  _pth_free (ctx);
}


/* Find a writer context or create a new one.  Note that the writer
   context will last until a _pth_io_close.  */
static struct writer_context_s *
find_writer (int fd, int start_it)
{
  struct writer_context_s *wt = NULL;
  int i;

  LOCK (writer_table_lock);
  for (i = 0; i < writer_table_size; i++)
    if (writer_table[i].used && writer_table[i].fd == fd)
      wt = writer_table[i].context;

  if (wt || !start_it)
    {
      UNLOCK (writer_table_lock);
      return wt;
    }

  for (i = 0; i < writer_table_size; i++)
    if (!writer_table[i].used)
      break;

  if (i != writer_table_size)
    {
      wt = create_writer (fd_to_handle (fd));
      writer_table[i].fd = fd;
      writer_table[i].context = wt; 
      writer_table[i].used = 1;
    }

  UNLOCK (writer_table_lock);
  return wt;
}


static void
kill_writer (int fd)
{
  int i;

  LOCK (writer_table_lock);
  for (i = 0; i < writer_table_size; i++)
    {
      if (writer_table[i].used && writer_table[i].fd == fd)
	{
	  destroy_writer (writer_table[i].context);
	  writer_table[i].context = NULL;
	  writer_table[i].used = 0;
	  break;
	}
    }
  UNLOCK (writer_table_lock);
}


int
_pth_io_write (int fd, const void *buffer, size_t count)
{
  struct writer_context_s *ctx;
  TRACE_BEG2 (DEBUG_SYSIO, "_pth_io_write", fd,
	      "buffer=%p, count=%u", buffer, count);
#if 0
  TRACE_LOGBUF (buffer, count);
#endif

  if (count == 0)
    return TRACE_SYSRES (0);

  ctx = find_writer (fd, 0);
  if (!ctx)
    return TRACE_SYSRES (-1);

  LOCK (ctx->mutex);
  if (!ctx->error && ctx->nbytes)
    {
      /* Bytes are pending for send.  */

      /* Reset the is_empty event.  Better safe than sorry.  */
      if (!ResetEvent (ctx->is_empty))
	{
	  TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  /* FIXME: Should translate the error code.  */
	  set_errno (EIO);
	  return TRACE_SYSRES (-1);
	}
      UNLOCK (ctx->mutex);
      TRACE_LOG1 ("waiting for empty buffer in thread %p", ctx->thread_hd);
      WaitForSingleObject (ctx->is_empty, INFINITE);
      TRACE_LOG1 ("thread %p buffer is empty", ctx->thread_hd);
      LOCK (ctx->mutex);
    }

  if (ctx->error)
    {
      UNLOCK (ctx->mutex);
      if (ctx->error_code == ERROR_NO_DATA)
        set_errno (EPIPE);
      else
        set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  /* If no error occured, the number of bytes in the buffer must be
     zero.  */
  assert (!ctx->nbytes);

  if (count > WRITEBUF_SIZE)
    count = WRITEBUF_SIZE;
  memcpy (ctx->buffer, buffer, count);
  ctx->nbytes = count;

  /* We have to reset the is_empty event early, because it is also
     used by the select() implementation to probe the channel.  */
  if (!ResetEvent (ctx->is_empty))
    {
      TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  if (!SetEvent (ctx->have_data))
    {
      TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  UNLOCK (ctx->mutex);

  return TRACE_SYSRES ((int) count);
}


/* WindowsCE does not provide a pipe feature.  However we need
   something like a pipe to convey data between processes and in some
   cases within a process.  This replacement is not only used by
   libassuan but exported and thus usable by gnupg and gpgme as well.  */
static DWORD
create_pipe (HANDLE *read_hd, HANDLE *write_hd,
             LPSECURITY_ATTRIBUTES sec_attr, DWORD size)
{
#ifdef HAVE_W32CE_SYSTEM
  HANDLE hd[2];
  LONG rvid;
  TRACE_BEG (DEBUG_SYSIO, "pth:create_pipe", read_hd);

  *read_hd = *write_hd = INVALID_HANDLE_VALUE;

  ActivateDevice (L"Drivers\\GnuPG_Device", 0);

  hd[0] = CreateFile (L"GPG1:", GENERIC_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hd[0] == INVALID_HANDLE_VALUE)
    {
      DWORD lastrc = GetLastError ();
      TRACE_LOG1 ("CreateFile(\"GPG1:\", READ) failed: %d\n", lastrc);
      SetLastError (lastrc);
      return 0;
    }

  if (!DeviceIoControl (hd[0], GPGCEDEV_IOCTL_GET_RVID,
                        NULL, 0, &rvid, sizeof rvid, NULL, NULL))
    {
      DWORD lastrc = GetLastError ();
      TRACE_LOG1 ("GPGCEDEV_IOCTL_GET_RVID failed: %d\n", lastrc);
      CloseHandle (hd[0]);
      SetLastError (lastrc);
      return 0;
    }

  hd[1] = CreateFile (L"GPG1:", GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL);
  if (hd[1] == INVALID_HANDLE_VALUE)
    {
      DWORD lastrc = GetLastError ();
      TRACE_LOG1 ("CreateFile(\"GPG1:\", WRITE) failed: %d\n", lastrc);
      CloseHandle (hd[0]);
      SetLastError (lastrc);
      return 0;
    }
  
  if (!DeviceIoControl (hd, GPGCEDEV_IOCTL_MAKE_PIPE,
                        &rvid, sizeof rvid, NULL, 0, NULL, NULL))
    {
      DWORD lastrc = GetLastError ();
      TRACE_LOG1 ("GPGCEDEV_IOCTL_MAKE_PIPE failed: %d\n", lastrc);
      CloseHandle (hd[0]);
      CloseHandle (hd[1]);
      SetLastError (lastrc);
      return 0;
    }
  
  *read_hd = hd[0];
  *write_hd = hd[1];
  TRACE_SUC ();
  return 1;
#else /*!HAVE_W32CE_SYSTEM*/
  return CreatePipe (read_hd, write_hd, sec_attr, size);
#endif /*!HAVE_W32CE_SYSTEM*/
}

int
pth_pipe (int filedes[2], int inherit_idx)
{
  HANDLE rh;
  HANDLE wh;
  SECURITY_ATTRIBUTES sec_attr;
  TRACE_BEG2 (DEBUG_SYSIO, "_pth_pipe", filedes,
	      "inherit_idx=%i (used for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

  memset (&sec_attr, 0, sizeof (sec_attr));
  sec_attr.nLength = sizeof (sec_attr);
  sec_attr.bInheritHandle = FALSE;
  
  if (!create_pipe (&rh, &wh, &sec_attr, PIPEBUF_SIZE))
    {
      TRACE_LOG1 ("CreatePipe failed: ec=%d", (int) GetLastError ());
      /* FIXME: Should translate the error code.  */
      set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  /* Make one end inheritable.  */
  if (inherit_idx == 0)
    {
      /* Under Windows CE < 6 handles are global without a concept of
         inheritable handles.  */
#ifndef HAVE_W32CE_SYSTEM
      HANDLE hd;
      if (!DuplicateHandle (GetCurrentProcess(), rh,
			    GetCurrentProcess(), &hd, 0,
			    TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG1 ("DuplicateHandle failed: ec=%d",
		      (int) GetLastError ());
	  CloseHandle (rh);
	  CloseHandle (wh);
	  /* FIXME: Should translate the error code.  */
	  set_errno (EIO);
	  return TRACE_SYSRES (-1);
        }
      CloseHandle (rh);
      rh = hd;
#endif /*!HAVE_W32CE_SYSTEM*/
      /* Pre-create the writer thread.  */
      find_reader (handle_to_fd (wh), 1);
    }
  else if (inherit_idx == 1)
    {
#ifndef HAVE_W32CE_SYSTEM
      HANDLE hd;
      if (!DuplicateHandle( GetCurrentProcess(), wh,
			    GetCurrentProcess(), &hd, 0,
			    TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG1 ("DuplicateHandle failed: ec=%d",
		      (int) GetLastError ());
	  CloseHandle (rh);
	  CloseHandle (wh);
	  /* FIXME: Should translate the error code.  */
	  set_errno (EIO);
	  return TRACE_SYSRES (-1);
        }
      CloseHandle (wh);
      wh = hd;
#endif /*!HAVE_W32CE_SYSTEM*/
      /* Pre-create the reader thread.  */
      find_reader (handle_to_fd (rh), 1);
    }
  
  filedes[0] = handle_to_fd (rh);
  filedes[1] = handle_to_fd (wh);
  return TRACE_SUC2 ("read=%p, write=%p", rh, wh);
}


int
pth_close (int fd)
{
  TRACE_BEG (DEBUG_SYSIO, "pth_close", fd);

  if (fd == -1)
    {
      set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }

  kill_reader (fd);
  kill_writer (fd);

  if (!CloseHandle (fd_to_handle (fd)))
    { 
      TRACE_LOG1 ("CloseHandle failed: ec=%d", (int) GetLastError ());
      /* FIXME: Should translate the error code.  */
      set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  return TRACE_SYSRES (0);
}


HANDLE
_pth_get_reader_ev (int fd)
{
  struct reader_context_s *ctx = find_reader (fd, 0);
  
  if (! ctx)
    return INVALID_HANDLE_VALUE;

  return ctx->have_data_ev;
}


HANDLE
_pth_get_writer_ev (int fd)
{
  struct writer_context_s *ctx = find_writer (fd, 0);
  
  if (! ctx)
    return INVALID_HANDLE_VALUE;

  return ctx->is_empty;
}
