/* w32-pth.c - GNU Pth emulation for W32 (MS Windows).
 * Copyright (c) 1999-2003 Ralf S. Engelschall <rse@engelschall.com>
 * Copyright (C) 2004, 2006, 2007 g10 Code GmbH
 *
 * This file is part of W32PTH.
 *
 * W32PTH is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * W32PTH is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * ------------------------------------------------------------------
 * This code is based on Ralf Engelschall's GNU Pth, a non-preemptive
 * thread scheduling library which can be found at
 * http://www.gnu.org/software/pth/.  MS Windows (W32) specific code
 * written by Timo Schulz, g10 Code.
 */

#include <config.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <signal.h>

/* We don't want to have any Windows specific code in the header, thus
   we use a macro which defaults to a compatible type in w32-pth.h. */
#define W32_PTH_HANDLE_INTERNAL  HANDLE
#include "pth.h"


#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#if FALSE != 0 || TRUE != 1 
#error TRUE or FALSE defined to wrong values
#endif


/* States whether this module has been initialized.  */
static int pth_initialized;

/* Keeps the current debug level. Define marcos to test them. */
static int debug_level;
#define DBG_ERROR  (debug_level >= 1)
#define DBG_INFO   (debug_level >= 2)
#define DBG_CALLS  (debug_level >= 3)

/* Variables to support event handling. */
static int pth_signo;
static HANDLE pth_signo_ev;

/* Mutex to make sure only one thread is running. */
static CRITICAL_SECTION pth_shd;

/* Events are store in a double linked event ring.  */
struct pth_event_s
{
  struct pth_event_s * next;
  struct pth_event_s * prev;
  HANDLE hd;
  union
  {
    struct sigset_s * sig;
    int               fd;
    struct timeval    tv;
    pth_mutex_t     * mx;
  } u;
  int * val;
  int u_type;
  int flags;
};


struct pth_attr_s 
{
  unsigned int flags;
  unsigned int stack_size;
  char * name;
};


/* Object to keep information about a thread.  This may eventually be
   used to implement a scheduler queue.  */
struct thread_info_s
{
  void *(*thread)(void *); /* The actual thread fucntion.  */
  void * arg;              /* The argument passed to that fucntion.  */
  int joinable;            /* True if this Thread is joinable.  */
  HANDLE th;               /* Handle of this thread.  Used by non-joinable
                              threads to close the handle.  */
};


/* Convenience macro to startup the system.  */
#define implicit_init() do { if (!pth_initialized) pth_init(); } while (0)

/* Prototypes.  */
static pth_event_t do_pth_event (unsigned long spec, ...);
static unsigned int do_pth_waitpid (unsigned pid, int * status, int options);
static int do_pth_wait (pth_event_t ev);
static int do_pth_event_status (pth_event_t ev);
static void *launch_thread (void * ctx);




static const char *
log_get_prefix (const void *dummy)
{
  return "libw32pth";
}


int
pth_init (void)
{
  SECURITY_ATTRIBUTES sa;
  WSADATA wsadat;
  const char *s;
  
  if (pth_initialized)
    return TRUE;

  debug_level = (s=getenv ("DEBUG_PTH"))? atoi (s):0;
  if (debug_level)
    fprintf (stderr, "%s: pth_init: called.\n", log_get_prefix (NULL));

  if (WSAStartup (0x202, &wsadat))
    return FALSE;
  pth_signo = 0;
  InitializeCriticalSection (&pth_shd);
  if (pth_signo_ev)
    CloseHandle (pth_signo_ev);
  memset (&sa, 0, sizeof sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  sa.nLength = sizeof sa;
  pth_signo_ev = CreateEvent (&sa, TRUE, FALSE, NULL);
  if (!pth_signo_ev)
    return FALSE;

  pth_initialized = 1;
  EnterCriticalSection (&pth_shd);
  return TRUE;
}


int
pth_kill (void)
{
  pth_signo = 0;
  if (pth_signo_ev)
    {
      CloseHandle (pth_signo_ev);
      pth_signo_ev = NULL;
    }
  if (pth_initialized)
    DeleteCriticalSection (&pth_shd);
  WSACleanup ();
  pth_initialized = 0;
  return TRUE;
}


static char *
w32_strerror (char *strerr, size_t strerrsize)
{
  if (strerrsize > 1)
    FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, (int)GetLastError (),
                   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                   strerr, strerrsize, NULL);
  return strerr;
}


static void
enter_pth (const char *function)
{
  /* Fixme: I am not sure whether the same thread my enter a critical
     section twice.  */
  if (DBG_CALLS)
    fprintf (stderr, "%s: enter_pth (%s)\n",
             log_get_prefix (NULL), function? function:"");
  LeaveCriticalSection (&pth_shd);
}


static void
leave_pth (const char *function)
{
  EnterCriticalSection (&pth_shd);
  if (DBG_CALLS)
    fprintf (stderr, "%s: leave_pth (%s)\n",
             log_get_prefix (NULL), function? function:"");
}


long 
pth_ctrl (unsigned long query, ...)
{
  implicit_init ();

  switch (query)
    {
    case PTH_CTRL_GETAVLOAD:
    case PTH_CTRL_GETPRIO:
    case PTH_CTRL_GETNAME:
    case PTH_CTRL_GETTHREADS_NEW:
    case PTH_CTRL_GETTHREADS_READY:
    case PTH_CTRL_GETTHREADS_RUNNING:
    case PTH_CTRL_GETTHREADS_WAITING:
    case PTH_CTRL_GETTHREADS_SUSPENDED:
    case PTH_CTRL_GETTHREADS_DEAD:
    case PTH_CTRL_GETTHREADS:
    default:
      return -1;
    }
  return 0;
}



pth_time_t
pth_timeout (long sec, long usec)
{
  pth_time_t tvd;

  tvd.tv_sec  = sec;
  tvd.tv_usec = usec;    
  return tvd;
}


int
pth_read_ev (int fd, void *buffer, size_t size, pth_event_t ev)
{
  implicit_init ();
  return 0;
}


int
pth_read (int fd,  void * buffer, size_t size)
{
  int n;

  implicit_init ();
  enter_pth (__FUNCTION__);

  n = recv (fd, buffer, size, 0);
  if (n == -1 && WSAGetLastError () == WSAENOTSOCK)
    {
      DWORD nread = 0;
      n = ReadFile ((HANDLE)fd, buffer, size, &nread, NULL);
      if (!n)
        {
          char strerr[256];

          if (DBG_ERROR)
            fprintf (stderr, "%s: pth_read(%d) failed read from file: %s\n",
                     log_get_prefix (NULL), fd,
                     w32_strerror (strerr, sizeof strerr));
          n = -1;
        }
      else
        n = (int)nread;
    }
  leave_pth (__FUNCTION__);
  return n;
}


int
pth_write_ev (int fd, const void *buffer, size_t size, pth_event_t ev)
{
  implicit_init ();
  return 0;
}


int
pth_write (int fd, const void * buffer, size_t size)
{
  int n;

  implicit_init ();
  enter_pth (__FUNCTION__);
  n = send (fd, buffer, size, 0);
  if (n == -1 && WSAGetLastError () == WSAENOTSOCK)
    {
      DWORD nwrite;
      char strerr[256];

      /* This is no real error because we first need to figure out if
         we have a handle or a socket.  */

      n = WriteFile ((HANDLE)fd, buffer, size, &nwrite, NULL);
      if (!n)
        {
          if (DBG_ERROR)
            fprintf (stderr, "%s: pth_write(%d) failed in write: %s\n",
                     log_get_prefix (NULL), fd,
                     w32_strerror (strerr, sizeof strerr));
          n = -1;
        }
      else
        n = (int)nwrite;
    }
  leave_pth (__FUNCTION__);
  return n;
}


int
pth_select (int nfds, fd_set * rfds, fd_set * wfds, fd_set * efds,
	    const struct timeval * timeout)
{
  int n;

  implicit_init ();
  enter_pth (__FUNCTION__);
  n = select (nfds, rfds, wfds, efds, timeout);
  leave_pth (__FUNCTION__);
  return n;
}


int
pth_fdmode (int fd, int mode)
{
  unsigned long val;
  int ret = PTH_FDMODE_BLOCK;

  implicit_init ();
  /* Note: We don't do the enter/leave pth here because this is for one
     a fast function and secondly already called from inside such a
     block.  */
  /* XXX: figure out original fd mode */
  switch (mode)
    {
    case PTH_FDMODE_NONBLOCK:
      val = 1;
      if (ioctlsocket (fd, FIONBIO, &val) == SOCKET_ERROR)
        ret = PTH_FDMODE_ERROR;
      break;

    case PTH_FDMODE_BLOCK:
      val = 0;
      if (ioctlsocket (fd, FIONBIO, &val) == SOCKET_ERROR)
        ret = PTH_FDMODE_ERROR;
      break;
    }
  return ret;
}


int
pth_accept (int fd, struct sockaddr *addr, int *addrlen)
{
  int rc;

  implicit_init ();
  enter_pth (__FUNCTION__);
  rc = accept (fd, addr, addrlen);
  leave_pth (__FUNCTION__);
  return rc;
}


int
pth_accept_ev (int fd, struct sockaddr *addr, int *addrlen,
               pth_event_t ev_extra)
{
  pth_key_t ev_key;
  pth_event_t ev;
  int rv;
  int fdmode;

  implicit_init ();
  enter_pth (__FUNCTION__);

  fdmode = pth_fdmode (fd, PTH_FDMODE_NONBLOCK);
  if (fdmode == PTH_FDMODE_ERROR)
    {
      leave_pth (__FUNCTION__);
      return -1;
    }

  ev = NULL;
  while ((rv = accept (fd, addr, addrlen)) == -1 && 
         (WSAGetLastError () == WSAEINPROGRESS || 
          WSAGetLastError () == WSAEWOULDBLOCK))
    {
      if (!ev)
        {
          ev = do_pth_event (PTH_EVENT_FD|PTH_UNTIL_FD_READABLE|
                             PTH_MODE_STATIC, &ev_key, fd);
          if (!ev)
            {
              leave_pth (__FUNCTION__);
              return -1;
            }
          if (ev_extra)
            pth_event_concat (ev, ev_extra, NULL);
        }
      /* Wait until accept has a chance. */
      do_pth_wait (ev);
      if (ev_extra)
        {
          pth_event_isolate (ev);
          if (do_pth_event_status (ev) != PTH_STATUS_OCCURRED)
            {
              pth_fdmode (fd, fdmode);
              leave_pth (__FUNCTION__);
              return -1;
            }
        }
    }

  pth_fdmode (fd, fdmode);
  leave_pth (__FUNCTION__);
  return rv;   
}


int
pth_connect (int fd, struct sockaddr *name, int namelen)
{
  int rc;

  implicit_init ();
  enter_pth (__FUNCTION__);
  rc = connect (fd, name, namelen);
  leave_pth (__FUNCTION__);
  return rc;
}


int
pth_mutex_release (pth_mutex_t *mutex)
{
  int rc;

  implicit_init ();
  enter_pth (__FUNCTION__);

  if (!ReleaseMutex (*mutex))
    {
      char strerr[256];

      if (DBG_ERROR)
        fprintf (stderr, "%s: pth_release_mutex %p failed: %s\n",
                 log_get_prefix (NULL), *mutex,
                 w32_strerror (strerr, sizeof strerr));
      rc = FALSE;
    }
  else
    rc = TRUE;

  leave_pth (__FUNCTION__);
  return rc;
}


int
pth_mutex_acquire (pth_mutex_t *mutex, int tryonly, pth_event_t ev_extra)
{
  int code;
  int rc;

  implicit_init ();
  enter_pth (__FUNCTION__);

  /* FIXME: ev_extra is not yet supported.  */
  
  code = WaitForSingleObject (*mutex, INFINITE);
  switch (code) 
    {
      case WAIT_FAILED:
        {
          char strerr[256];
          
          if (DBG_ERROR)
            fprintf (stderr, "%s: pth_mutex_acquire for %p failed: %s\n",
                     log_get_prefix (NULL), *mutex,
                     w32_strerror (strerr, sizeof strerr));
        }
        rc = FALSE;
        break;
        
      case WAIT_OBJECT_0:
        rc = TRUE;
        break;

      default:
        if (DBG_ERROR)
          fprintf (stderr, "%s: WaitForSingleObject returned unexpected "
                   "code %d for mutex %p\n",
                   log_get_prefix (NULL), code, *mutex);
        rc = FALSE;
        break;
    }

  leave_pth (__FUNCTION__);
  return rc;
}



int
pth_mutex_init (pth_mutex_t *mutex)
{
  SECURITY_ATTRIBUTES sa;
  
  implicit_init ();
  enter_pth (__FUNCTION__);

  memset (&sa, 0, sizeof sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  sa.nLength = sizeof sa;
  *mutex = CreateMutex (&sa, FALSE, NULL);
  if (!*mutex)
   {
      free (*mutex);
      *mutex = NULL;
      leave_pth (__FUNCTION__);
      return FALSE;
    }
    
  leave_pth (__FUNCTION__);
  return TRUE;
}


pth_attr_t
pth_attr_new (void)
{
  pth_attr_t hd;

  implicit_init ();
  hd = calloc (1, sizeof *hd);
  return hd;
}


int
pth_attr_destroy (pth_attr_t hd)
{
  if (!hd)
    return -1;
  implicit_init ();
  if (hd->name)
    free (hd->name);
  free (hd);
  return TRUE;
}


int
pth_attr_set (pth_attr_t hd, int field, ...)
{    
  va_list args;
  char * str;
  int val;
  int rc = TRUE;

  implicit_init ();

  va_start (args, field);
  switch (field)
    {
    case PTH_ATTR_JOINABLE:
      val = va_arg (args, int);
      if (val)
        {
          hd->flags |= PTH_ATTR_JOINABLE;
          if (DBG_INFO)
            fprintf (stderr, "%s: pth_attr_set: PTH_ATTR_JOINABLE\n",
                     log_get_prefix (NULL));
        }
      break;

    case PTH_ATTR_STACK_SIZE:
      val = va_arg (args, int);
      if (val)
        {
          hd->flags |= PTH_ATTR_STACK_SIZE;
          hd->stack_size = val;
          if (DBG_INFO)
            fprintf (stderr, "%s: pth_attr_set: PTH_ATTR_STACK_SIZE %d\n",
                     log_get_prefix (NULL), val);
        }
      break;

    case PTH_ATTR_NAME:
      str = va_arg (args, char*);
      if (hd->name)
        free (hd->name);
      if (str)
        {
          hd->name = strdup (str);
          if (!hd->name)
            return FALSE;
          hd->flags |= PTH_ATTR_NAME;
          if (DBG_INFO)
            fprintf (stderr, "%s: pth_attr_set: PTH_ATTR_NAME %s\n",
                     log_get_prefix (NULL), hd->name);
        }
      break;

    default:
      rc = FALSE;
      break;
    }
  va_end (args);
  return rc;
}


static pth_t
do_pth_spawn (pth_attr_t hd, void *(*func)(void *), void *arg)
{
  SECURITY_ATTRIBUTES sa;
  DWORD tid;
  HANDLE th;
  struct thread_info_s *ctx;

  if (!hd)
    return NULL;

  memset (&sa, 0, sizeof sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  sa.nLength = sizeof sa;

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    return NULL;
  ctx->thread = func;
  ctx->arg = arg;
  ctx->joinable = (hd->flags & PTH_ATTR_JOINABLE);

  /* XXX: we don't use all thread attributes. */

  /* Note that we create the thread suspended so that we are able to
     store the thread's handle in the context structure.  We need to
     do this to be able to close the handle from the launch helper. 

     FIXME: We should no use th W32's Thread handle directly but keep
     our own thread control structure.  CTX may be used for that.  */
  if (DBG_INFO)
    fprintf (stderr, "%s: do_pth_spawn creating thread ...\n",
             log_get_prefix (NULL));
  th = CreateThread (&sa, hd->stack_size,
                     (LPTHREAD_START_ROUTINE)launch_thread,
                     ctx, CREATE_SUSPENDED, &tid);
  ctx->th = th;
  if (DBG_INFO)
    fprintf (stderr, "%s: do_pth_spawn created thread %p\n",
             log_get_prefix (NULL),th);
  if (!th)
    free (ctx);
  else
    ResumeThread (th);
  
  return th;
}

pth_t
pth_spawn (pth_attr_t hd, void *(*func)(void *), void *arg)
{
  HANDLE th;

  if (!hd)
    return NULL;

  implicit_init ();
  enter_pth (__FUNCTION__);
  th = do_pth_spawn (hd, func, arg);
  leave_pth (__FUNCTION__);
  return th;
}


pth_t 
pth_self (void)
{
  return GetCurrentThread ();
}

int
pth_join (pth_t hd, void **value)
{
  return TRUE;
}


/* friendly */
int
pth_cancel (pth_t hd)
{
  if (!hd)
    return -1;
  implicit_init ();
  enter_pth (__FUNCTION__);
  WaitForSingleObject (hd, 1000);
  TerminateThread (hd, 0);
  leave_pth (__FUNCTION__);
  return TRUE;
}


/* cruel */
int
pth_abort (pth_t hd)
{
  if (!hd)
    return -1;
  implicit_init ();
  enter_pth (__FUNCTION__);
  TerminateThread (hd, 0);
  leave_pth (__FUNCTION__);
  return TRUE;
}


void
pth_exit (void *value)
{
  implicit_init ();
  enter_pth (__FUNCTION__);
  pth_kill ();
  leave_pth (__FUNCTION__);
  exit ((int)(long)value);
}


static unsigned int
do_pth_waitpid (unsigned pid, int * status, int options)
{
#if 0
  pth_event_t ev;
  static pth_key_t ev_key = PTH_KEY_INIT;
  pid_t pid;

  pth_debug2("pth_waitpid: called from thread \"%s\"", pth_current->name);

  for (;;)
    {
      /* do a non-blocking poll for the pid */
      while (   (pid = pth_sc(waitpid)(wpid, status, options|WNOHANG)) < 0
                && errno == EINTR)
        ;

      /* if pid was found or caller requested a polling return immediately */
      if (pid == -1 || pid > 0 || (pid == 0 && (options & WNOHANG)))
        break;

      /* else wait a little bit */
      ev = pth_event(PTH_EVENT_TIME|PTH_MODE_STATIC, &ev_key,
                     pth_timeout (0,250000));
      pth_wait(ev);
    }

  pth_debug2("pth_waitpid: leave to thread \"%s\"", pth_current->name);
#endif
  return 0;
}


unsigned int
pth_waitpid (unsigned pid, int * status, int options)
{
  unsigned int n;

  implicit_init ();
  enter_pth (__FUNCTION__);
  n = do_pth_waitpid (pid, status, options);
  leave_pth (__FUNCTION__);
  return n;
}


static BOOL WINAPI
sig_handler (DWORD signo)
{
  switch (signo)
    {
    case CTRL_C_EVENT:     pth_signo = SIGINT; break;
    case CTRL_BREAK_EVENT: pth_signo = SIGTERM; break;
    }
  SetEvent (pth_signo_ev);
  if (DBG_INFO)
    fprintf (stderr, "%s: sig_handler=%d\n", log_get_prefix (NULL), pth_signo);
  return TRUE;
}


static pth_event_t
do_pth_event_body (unsigned long spec, va_list arg)
{
  SECURITY_ATTRIBUTES sa;
  pth_event_t ev;
  int rc;

  if (DBG_INFO)
    fprintf (stderr, "%s: pth_event spec=%lu\n", log_get_prefix (NULL), spec);
  ev = calloc (1, sizeof *ev);
  if (!ev)
    return NULL;
  if (spec == 0)
    ;
  else if (spec & PTH_EVENT_SIGS)
    {
      ev->u.sig = va_arg (arg, struct sigset_s *);
      ev->u_type = PTH_EVENT_SIGS;
      ev->val = va_arg (arg, int *);	
      rc = SetConsoleCtrlHandler (sig_handler, TRUE);
      if (DBG_INFO)
        fprintf (stderr, "%s: pth_event: sigs rc=%d\n",
                 log_get_prefix (NULL), rc);
    }
  else if (spec & PTH_EVENT_FD)
    {
      if (spec & PTH_UNTIL_FD_READABLE)
        ev->flags |= PTH_UNTIL_FD_READABLE;
      if (spec & PTH_MODE_STATIC)
        ev->flags |= PTH_MODE_STATIC;
      ev->u_type = PTH_EVENT_FD;
      va_arg (arg, pth_key_t);
      ev->u.fd = va_arg (arg, int);
      if (DBG_INFO)
        fprintf (stderr, "%s: pth_event: fd=%d\n",
                 log_get_prefix (NULL), ev->u.fd);
    }
  else if (spec & PTH_EVENT_TIME)
    {
      pth_time_t t;
      if (spec & PTH_MODE_STATIC)
        ev->flags |= PTH_MODE_STATIC;
      va_arg (arg, pth_key_t);
      t = va_arg (arg, pth_time_t);
      ev->u_type = PTH_EVENT_TIME;
      ev->u.tv.tv_sec =  t.tv_sec;
      ev->u.tv.tv_usec = t.tv_usec;
    }
  else if (spec & PTH_EVENT_MUTEX)
    {
      va_arg (arg, pth_key_t);
      ev->u_type = PTH_EVENT_MUTEX;
      ev->u.mx = va_arg (arg, pth_mutex_t*);
    }
    
  memset (&sa, 0, sizeof sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  sa.nLength = sizeof sa;
  ev->hd = CreateEvent (&sa, FALSE, FALSE, NULL);
  if (!ev->hd)
    {
      free (ev);
      return NULL;
    }
  ev->next = ev;
  ev->prev = ev;

  return ev;
}

static pth_event_t
do_pth_event (unsigned long spec, ...)
{
  va_list arg;
  pth_event_t ev;

  va_start (arg, spec);
  ev = do_pth_event_body (spec, arg);
  va_end (arg);
    
  return ev;
}

pth_event_t
pth_event (unsigned long spec, ...)
{
  va_list arg;
  pth_event_t ev;

  implicit_init ();
  enter_pth (__FUNCTION__);
  
  va_start (arg, spec);
  ev = do_pth_event_body (spec, arg);
  va_end (arg);
    
  leave_pth (__FUNCTION__);
  return ev;
}


static void
pth_event_add (pth_event_t root, pth_event_t node)
{
  pth_event_t n;

  for (n=root; n->next; n = n->next)
    ;
  n->next = node;
}


pth_event_t
pth_event_concat (pth_event_t evf, ...)
{
  pth_event_t evn;
  va_list ap;

  if (!evf)
    return NULL;

  implicit_init ();

  va_start (ap, evf);
  while ((evn = va_arg(ap, pth_event_t)) != NULL)
    pth_event_add (evf, evn);
  va_end (ap);

  return evf;
}


static int
wait_for_fd (int fd, int is_read, int nwait)
{
  struct timeval tv;
  fd_set r;
  fd_set w;
  int n;

  FD_ZERO (&r);
  FD_ZERO (&w);    
  FD_SET (fd, is_read ? &r : &w);

  tv.tv_sec = nwait;
  tv.tv_usec = 0;

  while (1)
    {
      n = select (fd+1, &r, &w, NULL, &tv);
      if (DBG_INFO)
        fprintf (stderr, "%s: wait_for_fd=%d fd %d (ec=%d)\n",
                 log_get_prefix (NULL), n, fd,(int)WSAGetLastError ());
      if (n == -1)
        break;
      if (!n)
        continue;
      if (n == 1)
        {
          if (is_read && FD_ISSET (fd, &r))
            break;
          else if (FD_ISSET (fd, &w))
            break;
        }
    }
  return 0;
}


static void *
launch_thread (void *arg)
{
  struct thread_info_s *c = arg;

  if (c)
    {
      leave_pth (__FUNCTION__);
      c->thread (c->arg);
      if (!c->joinable && c->th)
        {
          CloseHandle (c->th);
          c->th = NULL;
        }
      /* FIXME: We would badly fail if someone accesses the now
         deallocated handle. Don't use it directly but setup proper
         scheduling queues.  */
      enter_pth (__FUNCTION__);
      free (c);
    }
  ExitThread (0);
  return NULL;
}

/* void */
/* sigemptyset (struct sigset_s * ss) */
/* { */
/*     if (ss) { */
/* 	memset (ss->sigs, 0, sizeof ss->sigs); */
/* 	ss->idx = 0; */
/*     } */
/* } */


/* int */
/* sigaddset (struct sigset_s * ss, int signo) */
/* { */
/*     if (!ss) */
/* 	return -1; */
/*     if (ss->idx + 1 > 64) */
/* 	return -1; */
/*     ss->sigs[ss->idx] = signo; */
/*     ss->idx++; */
/*     return 0; */
/* }  */


static int
sigpresent (struct sigset_s * ss, int signo)
{
/*     int i; */
/*     for (i=0; i < ss->idx; i++) { */
/* 	if (ss->sigs[i] == signo) */
/* 	    return 1; */
/*     } */
/* FIXME: See how to implement it.  */
    return 0;
}


static int
do_pth_event_occurred (pth_event_t ev)
{
  int ret;

  if (!ev)
    return 0;

  ret = 0;
  switch (ev->u_type)
    {
    case 0:
      if (WaitForSingleObject (ev->hd, 0) == WAIT_OBJECT_0)
        ret = 1;
      break;

    case PTH_EVENT_SIGS:
      if (sigpresent (ev->u.sig, pth_signo) &&
          WaitForSingleObject (pth_signo_ev, 0) == WAIT_OBJECT_0)
        {
          if (DBG_INFO)
            fprintf (stderr, "%s: pth_event_occurred: sig signaled.\n",
                     log_get_prefix (NULL));
          (*ev->val) = pth_signo;
          ret = 1;
        }
      break;

    case PTH_EVENT_FD:
      if (WaitForSingleObject (ev->hd, 0) == WAIT_OBJECT_0)
        ret = 1;
      break;
    }

  return ret;
}


int
pth_event_occurred (pth_event_t ev)
{
  int ret;

  implicit_init ();
  enter_pth (__FUNCTION__);
  ret = do_pth_event_occurred (ev);
  leave_pth (__FUNCTION__);
  return ret;
}


static int
do_pth_event_status (pth_event_t ev)
{
  if (!ev)
    return 0;
  if (do_pth_event_occurred (ev))
    return PTH_STATUS_OCCURRED;
  return 0;
}

int
pth_event_status (pth_event_t ev)
{
  if (!ev)
    return 0;
  if (pth_event_occurred (ev))
    return PTH_STATUS_OCCURRED;
  return 0;
}


static int
do_pth_event_free (pth_event_t ev, int mode)
{
  if (!ev)
    return FALSE;

  if (mode == PTH_FREE_ALL)
    {
      pth_event_t cur = ev;
      do
        {
          pth_event_t next = cur->next;
          CloseHandle (cur->hd);
          cur->hd = NULL;
          free (cur);
          cur = next;
        }
      while (cur != ev);
    }
  else if (mode == PTH_FREE_THIS)
    {
      ev->prev->next = ev->next;
      ev->next->prev = ev->prev;
      CloseHandle (ev->hd);
      ev->hd = NULL;	    
      free (ev);
    }
  else
    return FALSE;

  return TRUE;
}

int
pth_event_free (pth_event_t ev, int mode)
{
  int rc;

  implicit_init ();
  enter_pth (__FUNCTION__);
  rc = do_pth_event_free (ev, mode);
  leave_pth (__FUNCTION__);
  return rc;
}


pth_event_t
pth_event_isolate (pth_event_t ev)
{
  pth_event_t ring;

  if (!ev)
    return NULL;
  if (ev->next == ev && ev->prev == ev)
    return NULL; /* Only one event.  */

  ring = ev->next;
  ev->prev->next = ev->next;
  ev->next->prev = ev->prev;
  ev->prev = ev;
  ev->next = ev;
  return ring;    
}


static int
event_count (pth_event_t ev)
{
  pth_event_t r;
  int cnt = 0;

  if (ev)
    {
      r = ev;
      do
        {
          cnt++;
          r = r->next;
        }
      while (r != ev);
    }

  return cnt;
}



static pth_t
spawn_helper_thread (void *(*func)(void *), void *arg)
{
  SECURITY_ATTRIBUTES sa;
  DWORD tid;
  HANDLE th;

  memset (&sa, 0, sizeof sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  sa.nLength = sizeof sa;

  if (DBG_INFO)
    fprintf (stderr, "%s: spawn_helper_thread creating thread ...\n",
             log_get_prefix (NULL));
  th = CreateThread (&sa, 32*1024,
                     (LPTHREAD_START_ROUTINE)func,
                     arg, 0, &tid);
  if (DBG_INFO)
    fprintf (stderr, "%s: spawn_helper_thread created thread %p\n",
             log_get_prefix (NULL), th);

  return th;
}


static void 
free_helper_threads (HANDLE *waitbuf, int *hdidx, int n)
{
  int i;

  for (i=0; i < n; i++)
    {
      CloseHandle (waitbuf[hdidx[i]]);
      waitbuf[hdidx[i]] = NULL;
    }
}


static void *
wait_fd_thread (void * ctx)
{
  pth_event_t ev = ctx;

  wait_for_fd (ev->u.fd, ev->flags & PTH_UNTIL_FD_READABLE, 3600);
  if (DBG_INFO)
    fprintf (stderr, "%s: wait_fd_thread: exit.\n", log_get_prefix (NULL));
  SetEvent (ev->hd);
  ExitThread (0);
  return NULL;
}


static void *
wait_timer_thread (void * ctx)
{
  pth_event_t ev = ctx;
  int n = ev->u.tv.tv_sec*1000;
  Sleep (n);
  SetEvent (ev->hd);
  if (DBG_INFO)
    fprintf (stderr, "%s: wait_timer_thread: exit.\n", log_get_prefix (NULL));
  ExitThread (0);
  return NULL;
}


static int
do_pth_wait (pth_event_t ev)
{
  HANDLE waitbuf[MAXIMUM_WAIT_OBJECTS/2];
  int    hdidx[MAXIMUM_WAIT_OBJECTS/2];
  DWORD n = 0;
  int pos=0, i=0;

  if (!ev)
    return 0;

  n = event_count (ev);
  if (n > MAXIMUM_WAIT_OBJECTS/2)
    return -1;

  if (DBG_INFO)
    fprintf (stderr, "%s: pth_wait: cnt %lu\n", log_get_prefix (NULL), n);
  if (ev)
    {
      pth_event_t r = ev;
      do
        {
          switch (r->u_type)
            {
            case 0:
              waitbuf[pos++] = r->hd;
              break;
              
            case PTH_EVENT_SIGS:
              waitbuf[pos++] = pth_signo_ev;
              if (DBG_INFO)
                fprintf (stderr, "pth_wait: add signal event.\n");
              break;
              
            case PTH_EVENT_FD:
              if (DBG_INFO)
                fprintf (stderr, "pth_wait: spawn event wait thread.\n");
              hdidx[i++] = pos;
              waitbuf[pos++] = spawn_helper_thread (wait_fd_thread, r);
              break;
              
            case PTH_EVENT_TIME:
              if (DBG_INFO)
                fprintf (stderr, "pth_wait: spawn event timer thread.\n");
              hdidx[i++] = pos;
              waitbuf[pos++] = spawn_helper_thread (wait_timer_thread, r);
              break;
          
            case PTH_EVENT_MUTEX:
              if (DBG_INFO)
                fprintf (stderr, "pth_wait: ignoring mutex event.\n");
              break;
            }
        }
      while ( r != ev );
    }
  if (DBG_INFO)
    fprintf (stderr, "%s: pth_wait: set %d\n", log_get_prefix (NULL), pos);
  n = WaitForMultipleObjects (pos, waitbuf, FALSE, INFINITE);
  free_helper_threads (waitbuf, hdidx, i);
  if (DBG_INFO)
    fprintf (stderr, "%s: pth_wait: n %ld\n", log_get_prefix (NULL), n);

  if (n != WAIT_TIMEOUT)
    return 1;
    
  return 0;
}

int
pth_wait (pth_event_t ev)
{
  int rc;

  implicit_init ();
  enter_pth (__FUNCTION__);
  rc = do_pth_wait (ev);
  leave_pth (__FUNCTION__);
  return rc;
}


int
pth_sleep (int sec)
{
  static pth_key_t ev_key = PTH_KEY_INIT;
  pth_event_t ev;

  implicit_init ();
  enter_pth (__FUNCTION__);

  if (sec == 0)
    {
      leave_pth (__FUNCTION__);
      return 0;
    }

  ev = do_pth_event (PTH_EVENT_TIME|PTH_MODE_STATIC, &ev_key,
                     pth_timeout (sec, 0));
  if (ev == NULL)
    {
      leave_pth (__FUNCTION__);
      return -1;
    }
  do_pth_wait (ev);
  do_pth_event_free (ev, PTH_FREE_ALL);

  leave_pth (__FUNCTION__);
  return 0;
}





/* 
   Some simple tests.  
 */
#ifdef TEST
#include <stdio.h>

void * thread (void * c)
{

  Sleep (2000);
  SetEvent (((pth_event_t)c)->hd);
  fprintf (stderr, "\n\nhallo!.\n");
  pth_exit (NULL);
  return NULL;
}


int main_1 (int argc, char ** argv)
{
  pth_attr_t t;
  pth_t hd;
  pth_event_t ev;

  pth_init ();
  ev = pth_event (0, NULL);
  t = pth_attr_new ();
  pth_attr_set (t, PTH_ATTR_JOINABLE, 1);
  pth_attr_set (t, PTH_ATTR_STACK_SIZE, 4096);
  pth_attr_set (t, PTH_ATTR_NAME, "hello");
  hd = pth_spawn (t, thread, ev);

  pth_wait (ev);
  pth_attr_destroy (t);
  pth_event_free (ev, 0);
  pth_kill ();

  return 0;
}


static pth_event_t 
setup_signals (struct sigset_s *sigs, int *signo)
{
  pth_event_t ev;

  sigemptyset (sigs);
  sigaddset (sigs, SIGINT);
  sigaddset (sigs, SIGTERM);

  ev = pth_event (PTH_EVENT_SIGS, sigs, signo);
  return ev;
}

int
main_2 (int argc, char ** argv)
{
  pth_event_t ev;
  struct sigset_s sigs;
  int signo = 0;

  pth_init ();
  ev = setup_signals (&sigs, &signo);
  pth_wait (ev);
  if (pth_event_occured (ev) && signo)
    fprintf (stderr, "signal caught! signo %d\n", signo);

  pth_event_free (ev, PTH_FREE_ALL);
  pth_kill ();
  return 0;
}

int
main_3 (int argc, char ** argv)
{
  struct sockaddr_in addr, rem;
  int fd, n = 0, infd;
  int signo = 0;
  struct sigset_s sigs;
  pth_event_t ev;

  pth_init ();
  fd = socket (AF_INET, SOCK_STREAM, 0);

  memset (&addr, 0, sizeof addr);
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons (5050);
  addr.sin_family = AF_INET;
  bind (fd, (struct sockaddr*)&addr, sizeof addr);
  listen (fd, 5);

  ev = setup_signals (&sigs, &signo);
  n = sizeof addr;
  infd = pth_accept_ev (fd, (struct sockaddr *)&rem, &n, ev);
  fprintf (stderr, "infd %d: %s:%d\n", infd, inet_ntoa (rem.sin_addr),
          htons (rem.sin_port));

  closesocket (infd);
  pth_event_free (ev, PTH_FREE_ALL);
  pth_kill ();
  return 0;
}

int
main (int argc, char ** argv)
{
  pth_event_t ev;
  pth_key_t ev_key;

  pth_init ();
  /*ev = pth_event (PTH_EVENT_TIME, &ev_key, pth_timeout (5, 0));
    pth_wait (ev);
    pth_event_free (ev, PTH_FREE_ALL);*/
  pth_sleep (5);
  pth_kill ();
  return 0;
}
#endif

