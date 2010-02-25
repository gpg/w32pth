/* utils.h - Internal definitions.
 * Copyright (C) 2010 g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UTILS_H
#define UTILS_H

#ifdef HAVE_W32CE_SYSTEM
# include <gpg-error.h>  /* Required for gpg_err_set_errno().  */
#endif


static inline void
set_errno (int value)
{
#ifdef HAVE_W32CE_SYSTEM
  gpg_err_set_errno (value);
#else
  errno = value;
#endif
}

#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)


/*-- w32-pth.c --*/
void *_pth_malloc (size_t n);
void *_pth_calloc (size_t n, size_t m);
void _pth_free (void *p);


#endif /*UTILS_H*/
