/*
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/*

Copyright 1993, 1994, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the copyright holders shall
not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization
from the copyright holders.

 * Copyright 1993, 1994 NCR Corporation - Dayton, Ohio, USA
 *
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name NCR not be used in advertising
 * or publicity pertaining to distribution of the software without specific,
 * written prior permission.  NCR makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * NCR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN
 * NO EVENT SHALL NCR BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ctype.h>
#ifdef XTHREADS
#include <X11/Xthreads.h>
#endif

#ifndef WIN32

#if defined(TCPCONN) || defined(UNIXCONN)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#if defined(TCPCONN) || defined(UNIXCONN)
#define X_INCLUDE_NETDB_H
#define XOS_USE_NO_LOCKING
#include <X11/Xos_r.h>
#endif

#ifdef UNIXCONN
#ifndef X_NO_SYS_UN
#include <sys/un.h>
#endif
#include <sys/stat.h>
#endif


#ifndef NO_TCP_H
#if defined(linux) || defined(__GLIBC__)
#include <sys/param.h>
#endif /* osf */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/param.h>
#include <machine/endian.h>
#endif /* __NetBSD__ || __OpenBSD__ || __FreeBSD__ || __DragonFly__ */
#include <netinet/tcp.h>
#endif /* !NO_TCP_H */

#include <sys/ioctl.h>
#if defined(SVR4) || defined(__SVR4)
#include <sys/filio.h>
#endif

#include <unistd.h>

#else /* !WIN32 */

#include <X11/Xwinsock.h>
#include <X11/Xwindows.h>
#include <X11/Xw32defs.h>
#undef close
#define close closesocket
#define ECONNREFUSED WSAECONNREFUSED
#define EADDRINUSE WSAEADDRINUSE
#define EPROTOTYPE WSAEPROTOTYPE
#undef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EINPROGRESS WSAEINPROGRESS
#undef EINTR
#define EINTR WSAEINTR
#define X_INCLUDE_NETDB_H
#define XOS_USE_MTSAFE_NETDBAPI
#include <X11/Xos_r.h>
#endif /* WIN32 */

#if defined(SO_DONTLINGER) && defined(SO_LINGER)
#undef SO_DONTLINGER
#endif

/* others don't need this */
#define SocketInitOnce() /**/

#ifdef linux
#define HAVE_ABSTRACT_SOCKETS
#endif

#define MIN_BACKLOG 128
#ifdef SOMAXCONN
#if SOMAXCONN > MIN_BACKLOG
#define BACKLOG SOMAXCONN
#endif
#endif
#ifndef BACKLOG
#define BACKLOG MIN_BACKLOG
#endif

/*
 * This is the Socket implementation of the X Transport service layer
 *
 * This file contains the implementation for both the UNIX and INET domains,
 * and can be built for either one, or both.
 *
 */

typedef struct _Sockettrans2dev {
    const char	*transname;
    int		family;
    int		devcotsname;
    int		devcltsname;
    int		protocol;
} Sockettrans2dev;

static Sockettrans2dev Sockettrans2devtab[] = {
#ifdef TCPCONN
    {"inet",AF_INET,SOCK_STREAM,SOCK_DGRAM,0},
#if !defined(IPv6) || !defined(AF_INET6)
    {"tcp",AF_INET,SOCK_STREAM,SOCK_DGRAM,0},
#else /* IPv6 */
    {"tcp",AF_INET6,SOCK_STREAM,SOCK_DGRAM,0},
    {"tcp",AF_INET,SOCK_STREAM,SOCK_DGRAM,0}, /* fallback */
    {"inet6",AF_INET6,SOCK_STREAM,SOCK_DGRAM,0},
#endif
#endif /* TCPCONN */
#ifdef UNIXCONN
    {"unix",AF_UNIX,SOCK_STREAM,SOCK_DGRAM,0},
#if !defined(LOCALCONN)
    {"local",AF_UNIX,SOCK_STREAM,SOCK_DGRAM,0},
#endif /* !LOCALCONN */
#endif /* UNIXCONN */
};

#define NUMSOCKETFAMILIES (sizeof(Sockettrans2devtab)/sizeof(Sockettrans2dev))

#ifdef TCPCONN
static int TRANS(SocketINETClose) (XtransConnInfo ciptr);
#endif

#ifdef UNIXCONN
#define UNIX_PATH "/tmp/.X11-unix/X"
#define UNIX_DIR "/tmp/.X11-unix"
#endif /* UNIXCONN */

#define PORTBUFSIZE	32

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#if defined HAVE_SOCKLEN_T || (defined(IPv6) && defined(AF_INET6))
# define SOCKLEN_T socklen_t
#elif defined(SVR4) || defined(__SVR4) || defined(__SCO__)
# define SOCKLEN_T size_t
#else
# define SOCKLEN_T int
#endif

/*
 * These are some utility function used by the real interface function below.
 */

static int
TRANS(SocketSelectFamily) (int first, const char *family)

{
    int     i;

    prmsg (3,"SocketSelectFamily(%s)\n", family);

    for (i = first + 1; i < NUMSOCKETFAMILIES;i++)
    {
        if (!strcmp (family, Sockettrans2devtab[i].transname))
	    return i;
    }

    return (first == -1 ? -2 : -1);
}


/*
 * This function gets the local address of the socket and stores it in the
 * XtransConnInfo structure for the connection.
 */

static int
TRANS(SocketINETGetAddr) (XtransConnInfo ciptr)

{
#if defined(IPv6) && defined(AF_INET6)
    struct sockaddr_storage socknamev6;
#else
    struct sockaddr_in socknamev4;
#endif
    void *socknamePtr;
    SOCKLEN_T namelen;

    prmsg (3,"SocketINETGetAddr(%p)\n", ciptr);

#if defined(IPv6) && defined(AF_INET6)
    namelen = sizeof(socknamev6);
    socknamePtr = &socknamev6;
#else
    namelen = sizeof(socknamev4);
    socknamePtr = &socknamev4;
#endif

    bzero(socknamePtr, namelen);

    if (getsockname (ciptr->fd,(struct sockaddr *) socknamePtr,
		     (void *)&namelen) < 0)
    {
#ifdef WIN32
	errno = WSAGetLastError();
#endif
	prmsg (1,"SocketINETGetAddr: getsockname() failed: %d\n",
	    EGET());
	return -1;
    }

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

    if ((ciptr->addr = malloc (namelen)) == NULL)
    {
        prmsg (1,
	    "SocketINETGetAddr: Can't allocate space for the addr\n");
        return -1;
    }

#if defined(IPv6) && defined(AF_INET6)
    ciptr->family = ((struct sockaddr *)socknamePtr)->sa_family;
#else
    ciptr->family = socknamev4.sin_family;
#endif
    ciptr->addrlen = namelen;
    memcpy (ciptr->addr, socknamePtr, ciptr->addrlen);

    return 0;
}


/*
 * This function gets the remote address of the socket and stores it in the
 * XtransConnInfo structure for the connection.
 */

static int
TRANS(SocketINETGetPeerAddr) (XtransConnInfo ciptr)

{
#if defined(IPv6) && defined(AF_INET6)
    struct sockaddr_storage socknamev6;
#endif
    struct sockaddr_in 	socknamev4;
    void *socknamePtr;
    SOCKLEN_T namelen;

#if defined(IPv6) && defined(AF_INET6)
    if (ciptr->family == AF_INET6)
    {
	namelen = sizeof(socknamev6);
	socknamePtr = &socknamev6;
    }
    else
#endif
    {
	namelen = sizeof(socknamev4);
	socknamePtr = &socknamev4;
    }

    bzero(socknamePtr, namelen);

    prmsg (3,"SocketINETGetPeerAddr(%p)\n", ciptr);

    if (getpeername (ciptr->fd, (struct sockaddr *) socknamePtr,
		     (void *)&namelen) < 0)
    {
#ifdef WIN32
	errno = WSAGetLastError();
#endif
	prmsg (1,"SocketINETGetPeerAddr: getpeername() failed: %d\n",
	    EGET());
	return -1;
    }

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

    if ((ciptr->peeraddr = malloc (namelen)) == NULL)
    {
        prmsg (1,
	   "SocketINETGetPeerAddr: Can't allocate space for the addr\n");
        return -1;
    }

    ciptr->peeraddrlen = namelen;
    memcpy (ciptr->peeraddr, socknamePtr, ciptr->peeraddrlen);

    return 0;
}

static XtransConnInfo
TRANS(SocketOpen) (int i, int type)

{
    XtransConnInfo	ciptr;

    prmsg (3,"SocketOpen(%d,%d)\n", i, type);

    if ((ciptr = calloc (1, sizeof(struct _XtransConnInfo))) == NULL)
    {
	prmsg (1, "SocketOpen: malloc failed\n");
	return NULL;
    }

    if ((ciptr->fd = socket(Sockettrans2devtab[i].family, type,
	Sockettrans2devtab[i].protocol)) < 0
#ifndef WIN32
#if !defined(USE_POLL) || defined(FS_t) || defined(FONT_t)
       || ciptr->fd >= sysconf(_SC_OPEN_MAX)
#endif
#endif
      ) {
#ifdef WIN32
	errno = WSAGetLastError();
#endif
	prmsg (2, "SocketOpen: socket() failed for %s\n",
	    Sockettrans2devtab[i].transname);

	free (ciptr);
	return NULL;
    }

#ifdef TCP_NODELAY
    if (Sockettrans2devtab[i].family == AF_INET
#if defined(IPv6) && defined(AF_INET6)
      || Sockettrans2devtab[i].family == AF_INET6
#endif
    )
    {
	/*
	 * turn off TCP coalescence for INET sockets
	 */

	int tmp = 1;
	setsockopt (ciptr->fd, IPPROTO_TCP, TCP_NODELAY,
	    (char *) &tmp, sizeof (int));
    }
#endif

    /*
     * Some systems provide a really small default buffer size for
     * UNIX sockets.  Bump it up a bit such that large transfers don't
     * proceed at glacial speed.
     */
#ifdef SO_SNDBUF
    if (Sockettrans2devtab[i].family == AF_UNIX)
    {
	SOCKLEN_T len = sizeof (int);
	int val;

	if (getsockopt (ciptr->fd, SOL_SOCKET, SO_SNDBUF,
	    (char *) &val, &len) == 0 && val < 64 * 1024)
	{
	    val = 64 * 1024;
	    setsockopt (ciptr->fd, SOL_SOCKET, SO_SNDBUF,
	        (char *) &val, sizeof (int));
	}
    }
#endif

    return ciptr;
}

static XtransConnInfo
TRANS(SocketReopen) (int i _X_UNUSED, int type, int fd, const char *port)

{
    XtransConnInfo	ciptr;
    int portlen;
    struct sockaddr *addr;
    size_t addrlen;

    prmsg (3,"SocketReopen(%d,%d,%s)\n", type, fd, port);

    if (port == NULL) {
      prmsg (1, "SocketReopen: port was null!\n");
      return NULL;
    }

    portlen = strlen(port) + 1; // include space for trailing null
#ifdef SOCK_MAXADDRLEN
    if (portlen < 0 || portlen > (SOCK_MAXADDRLEN + 2)) {
      prmsg (1, "SocketReopen: invalid portlen %d\n", portlen);
      return NULL;
    }
    if (portlen < 14) portlen = 14;
#else
    if (portlen < 0 || portlen > 14) {
      prmsg (1, "SocketReopen: invalid portlen %d\n", portlen);
      return NULL;
    }
#endif /*SOCK_MAXADDRLEN*/

    if ((ciptr = calloc (1, sizeof(struct _XtransConnInfo))) == NULL)
    {
	prmsg (1, "SocketReopen: malloc(ciptr) failed\n");
	return NULL;
    }

    ciptr->fd = fd;

    addrlen = portlen + offsetof(struct sockaddr, sa_data);
    if ((addr = calloc (1, addrlen)) == NULL) {
	prmsg (1, "SocketReopen: malloc(addr) failed\n");
	free (ciptr);
	return NULL;
    }
    ciptr->addr = (char *) addr;
    ciptr->addrlen = addrlen;

    if ((ciptr->peeraddr = calloc (1, addrlen)) == NULL) {
	prmsg (1, "SocketReopen: malloc(portaddr) failed\n");
	free (addr);
	free (ciptr);
	return NULL;
    }
    ciptr->peeraddrlen = addrlen;

    /* Initialize ciptr structure as if it were a normally-opened unix socket */
    ciptr->flags = TRANS_LOCAL | TRANS_NOUNLINK;
#ifdef BSD44SOCKETS
    addr->sa_len = addrlen;
#endif
    addr->sa_family = AF_UNIX;
#if defined(HAVE_STRLCPY) || defined(HAS_STRLCPY)
    strlcpy(addr->sa_data, port, portlen);
#else
    strncpy(addr->sa_data, port, portlen);
#endif
    ciptr->family = AF_UNIX;
    memcpy(ciptr->peeraddr, ciptr->addr, addrlen);
    ciptr->port = rindex(addr->sa_data, ':');
    if (ciptr->port == NULL) {
	if (is_numeric(addr->sa_data)) {
	    ciptr->port = addr->sa_data;
	}
    } else if (ciptr->port[0] == ':') {
	ciptr->port++;
    }
    /* port should now point to portnum or NULL */
    return ciptr;
}

/*
 * These functions are the interface supplied in the Xtransport structure
 */

static XtransConnInfo
TRANS(SocketOpenCOTSServer) (Xtransport *thistrans, const char *protocol,
			     const char *host, const char *port)

{
    XtransConnInfo	ciptr;
    int	i = -1;

    prmsg (2,"SocketOpenCOTSServer(%s,%s,%s)\n", protocol, host, port);

    SocketInitOnce();

    while ((i = TRANS(SocketSelectFamily) (i, thistrans->TransName)) >= 0) {
	if ((ciptr = TRANS(SocketOpen) (
		 i, Sockettrans2devtab[i].devcotsname)) != NULL)
	    break;
    }
    if (i < 0) {
	if (i == -1)
	    prmsg (1,"SocketOpenCOTSServer: Unable to open socket for %s\n",
		   thistrans->TransName);
	else
	    prmsg (1,"SocketOpenCOTSServer: Unable to determine socket type for %s\n",
		   thistrans->TransName);
	return NULL;
    }

    /*
     * Using this prevents the bind() check for an existing server listening
     * on the same port, but it is required for other reasons.
     */
#ifdef SO_REUSEADDR

    /*
     * SO_REUSEADDR only applied to AF_INET && AF_INET6
     */

    if (Sockettrans2devtab[i].family == AF_INET
#if defined(IPv6) && defined(AF_INET6)
      || Sockettrans2devtab[i].family == AF_INET6
#endif
    )
    {
	int one = 1;
	setsockopt (ciptr->fd, SOL_SOCKET, SO_REUSEADDR,
		    (char *) &one, sizeof (int));
    }
#endif
#ifdef IPV6_V6ONLY
    if (Sockettrans2devtab[i].family == AF_INET6)
    {
	int one = 1;
	setsockopt(ciptr->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(int));
    }
#endif
    /* Save the index for later use */

    ciptr->index = i;

    return ciptr;
}

static XtransConnInfo
TRANS(SocketReopenCOTSServer) (Xtransport *thistrans, int fd, const char *port)

{
    XtransConnInfo	ciptr;
    int			i = -1;

    prmsg (2,
	"SocketReopenCOTSServer(%d, %s)\n", fd, port);

    SocketInitOnce();

    while ((i = TRANS(SocketSelectFamily) (i, thistrans->TransName)) >= 0) {
	if ((ciptr = TRANS(SocketReopen) (
		 i, Sockettrans2devtab[i].devcotsname, fd, port)) != NULL)
	    break;
    }
    if (i < 0) {
	if (i == -1)
	    prmsg (1,"SocketReopenCOTSServer: Unable to open socket for %s\n",
		   thistrans->TransName);
	else
	    prmsg (1,"SocketReopenCOTSServer: Unable to determine socket type for %s\n",
		   thistrans->TransName);
	return NULL;
    }

    /* Save the index for later use */

    ciptr->index = i;

    return ciptr;
}

static int
TRANS(SocketSetOption) (XtransConnInfo ciptr, int option, int arg)

{
    prmsg (2,"SocketSetOption(%d,%d,%d)\n", ciptr->fd, option, arg);

    return -1;
}

#ifdef UNIXCONN
static int
set_sun_path(const char *port, const char *upath, char *path, int abstract)
{
    struct sockaddr_un s;
    int maxlen = sizeof(s.sun_path) - 1;
    const char *at = "";

    if (!port || !*port || !path)
	return -1;

#ifdef HAVE_ABSTRACT_SOCKETS
    if (port[0] == '@')
	upath = "";
    else if (abstract)
	at = "@";
#endif

    if (*port == '/') /* a full pathname */
	upath = "";

    if (strlen(port) + strlen(upath) > maxlen)
	return -1;
    snprintf(path, sizeof(s.sun_path), "%s%s%s", at, upath, port);
    return 0;
}
#endif

static int
TRANS(SocketCreateListener) (XtransConnInfo ciptr,
			     struct sockaddr *sockname,
			     int socknamelen, unsigned int flags)

{
    SOCKLEN_T namelen = socknamelen;
    int	fd = ciptr->fd;
    int	retry;

    prmsg (3, "SocketCreateListener(%p,%d)\n", ciptr, fd);

    if (Sockettrans2devtab[ciptr->index].family == AF_INET
#if defined(IPv6) && defined(AF_INET6)
      || Sockettrans2devtab[ciptr->index].family == AF_INET6
#endif
	)
	retry = 20;
    else
	retry = 0;

    while (bind (fd, (struct sockaddr *) sockname, namelen) < 0)
    {
	if (errno == EADDRINUSE) {
	    if (flags & ADDR_IN_USE_ALLOWED)
		break;
	    else
		return TRANS_ADDR_IN_USE;
	}

	if (retry-- == 0) {
	    prmsg (1, "SocketCreateListener: failed to bind listener\n");
	    close (fd);
	    return TRANS_CREATE_LISTENER_FAILED;
	}
#ifdef SO_REUSEADDR
	sleep (1);
#else
	sleep (10);
#endif /* SO_REUSEDADDR */
    }

    if (Sockettrans2devtab[ciptr->index].family == AF_INET
#if defined(IPv6) && defined(AF_INET6)
      || Sockettrans2devtab[ciptr->index].family == AF_INET6
#endif
	) {
#ifdef SO_DONTLINGER
	setsockopt (fd, SOL_SOCKET, SO_DONTLINGER, (char *) NULL, 0);
#else
#ifdef SO_LINGER
    {
	static int linger[2] = { 0, 0 };
	setsockopt (fd, SOL_SOCKET, SO_LINGER,
		(char *) linger, sizeof (linger));
    }
#endif
#endif
}

    if (listen (fd, BACKLOG) < 0)
    {
	prmsg (1, "SocketCreateListener: listen() failed\n");
	close (fd);
	return TRANS_CREATE_LISTENER_FAILED;
    }

    /* Set a flag to indicate that this connection is a listener */

    ciptr->flags = 1 | (ciptr->flags & TRANS_KEEPFLAGS);

    return 0;
}

#ifdef TCPCONN
static int
TRANS(SocketINETCreateListener) (XtransConnInfo ciptr, const char *port,
                                 unsigned int flags)

{
#if defined(IPv6) && defined(AF_INET6)
    struct sockaddr_storage sockname;
#else
    struct sockaddr_in	    sockname;
#endif
    unsigned short	    sport;
    SOCKLEN_T	namelen = sizeof(sockname);
    int		status;
    long	tmpport;
#ifdef XTHREADS_NEEDS_BYNAMEPARAMS
    _Xgetservbynameparams sparams;
#endif
    struct servent *servp;
    char	portbuf[PORTBUFSIZE];

    prmsg (2, "SocketINETCreateListener(%s)\n", port);

    /*
     * X has a well known port, that is transport dependent. It is easier
     * to handle it here, than try and come up with a transport independent
     * representation that can be passed in and resolved the usual way.
     *
     * The port that is passed here is really a string containing the idisplay
     * from ConnectDisplay().
     */

    if (is_numeric (port))
    {
	/* fixup the server port address */
	tmpport = X_TCP_PORT + strtol (port, (char**)NULL, 10);
	snprintf (portbuf, sizeof(portbuf), "%lu", tmpport);
	port = portbuf;
    }

    if (port && *port)
    {
	/* Check to see if the port string is just a number (handles X11) */

	if (!is_numeric (port))
	{
	    if ((servp = _XGetservbyname (port,"tcp",sparams)) == NULL)
	    {
		prmsg (1,
	     "SocketINETCreateListener: Unable to get service for %s\n",
		      port);
		return TRANS_CREATE_LISTENER_FAILED;
	    }
	    /* we trust getservbyname to return a valid number */
	    sport = servp->s_port;
	}
	else
	{
	    tmpport = strtol (port, (char**)NULL, 10);
	    /*
	     * check that somehow the port address isn't negative or in
	     * the range of reserved port addresses. This can happen and
	     * be very bad if the server is suid-root and the user does
	     * something (dumb) like `X :60049`.
	     */
	    if (tmpport < 1024 || tmpport > USHRT_MAX)
		return TRANS_CREATE_LISTENER_FAILED;

	    sport = (unsigned short) tmpport;
	}
    }
    else
	sport = 0;

    bzero(&sockname, sizeof(sockname));
#if defined(IPv6) && defined(AF_INET6)
    if (Sockettrans2devtab[ciptr->index].family == AF_INET) {
	namelen = sizeof (struct sockaddr_in);
#ifdef BSD44SOCKETS
	((struct sockaddr_in *)&sockname)->sin_len = namelen;
#endif
	((struct sockaddr_in *)&sockname)->sin_family = AF_INET;
	((struct sockaddr_in *)&sockname)->sin_port = htons(sport);
	((struct sockaddr_in *)&sockname)->sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
	namelen = sizeof (struct sockaddr_in6);
#ifdef SIN6_LEN
	((struct sockaddr_in6 *)&sockname)->sin6_len = sizeof(sockname);
#endif
	((struct sockaddr_in6 *)&sockname)->sin6_family = AF_INET6;
	((struct sockaddr_in6 *)&sockname)->sin6_port = htons(sport);
	((struct sockaddr_in6 *)&sockname)->sin6_addr = in6addr_any;
    }
#else
#ifdef BSD44SOCKETS
    sockname.sin_len = sizeof (sockname);
#endif
    sockname.sin_family = AF_INET;
    sockname.sin_port = htons (sport);
    sockname.sin_addr.s_addr = htonl (INADDR_ANY);
#endif

    if ((status = TRANS(SocketCreateListener) (ciptr,
	(struct sockaddr *) &sockname, namelen, flags)) < 0)
    {
	prmsg (1,
    "SocketINETCreateListener: ...SocketCreateListener() failed\n");
	return status;
    }

    if (TRANS(SocketINETGetAddr) (ciptr) < 0)
    {
	prmsg (1,
       "SocketINETCreateListener: ...SocketINETGetAddr() failed\n");
	return TRANS_CREATE_LISTENER_FAILED;
    }

    return 0;
}

#endif /* TCPCONN */


#ifdef UNIXCONN

static int
TRANS(SocketUNIXCreateListener) (XtransConnInfo ciptr, const char *port,
				 unsigned int flags)

{
    struct sockaddr_un	sockname;
    int			namelen;
    int			oldUmask;
    int			status;
    unsigned int	mode;
    char		tmpport[108];

    int			abstract = 0;
#ifdef HAVE_ABSTRACT_SOCKETS
    abstract = ciptr->transptr->flags & TRANS_ABSTRACT;
#endif

    prmsg (2, "SocketUNIXCreateListener(%s)\n",
	port ? port : "NULL");

    /* Make sure the directory is created */

    oldUmask = umask (0);

#ifdef UNIX_DIR
#ifdef HAS_STICKY_DIR_BIT
    mode = 01777;
#else
    mode = 0777;
#endif
    if (!abstract && trans_mkdir(UNIX_DIR, mode) == -1) {
	prmsg (1, "SocketUNIXCreateListener: mkdir(%s) failed, errno = %d\n",
	       UNIX_DIR, errno);
	(void) umask (oldUmask);
	return TRANS_CREATE_LISTENER_FAILED;
    }
#endif

    memset(&sockname, 0, sizeof(sockname));
    sockname.sun_family = AF_UNIX;

    if (!(port && *port)) {
	snprintf (tmpport, sizeof(tmpport), "%s%ld", UNIX_PATH, (long)getpid());
	port = tmpport;
    }
    if (set_sun_path(port, UNIX_PATH, sockname.sun_path, abstract) != 0) {
	prmsg (1, "SocketUNIXCreateListener: path too long\n");
	return TRANS_CREATE_LISTENER_FAILED;
    }

#if (defined(BSD44SOCKETS) || defined(__UNIXWARE__))
    sockname.sun_len = strlen(sockname.sun_path);
#endif

#if defined(BSD44SOCKETS) || defined(SUN_LEN)
    namelen = SUN_LEN(&sockname);
#else
    namelen = strlen(sockname.sun_path) + offsetof(struct sockaddr_un, sun_path);
#endif

    if (abstract) {
	sockname.sun_path[0] = '\0';
	namelen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(&sockname.sun_path[1]);
    }
    else
	unlink (sockname.sun_path);

    if ((status = TRANS(SocketCreateListener) (ciptr,
	(struct sockaddr *) &sockname, namelen, flags)) < 0)
    {
	prmsg (1,
    "SocketUNIXCreateListener: ...SocketCreateListener() failed\n");
	(void) umask (oldUmask);
	return status;
    }

    /*
     * Now that the listener is esablished, create the addr info for
     * this connection. getpeername() doesn't work for UNIX Domain Sockets
     * on some systems (hpux at least), so we will just do it manually, instead
     * of calling something like TRANS(SocketUNIXGetAddr).
     */

    namelen = sizeof (sockname); /* this will always make it the same size */

    if ((ciptr->addr = malloc (namelen)) == NULL)
    {
        prmsg (1,
        "SocketUNIXCreateListener: Can't allocate space for the addr\n");
	(void) umask (oldUmask);
        return TRANS_CREATE_LISTENER_FAILED;
    }

    if (abstract)
	sockname.sun_path[0] = '@';

    ciptr->family = sockname.sun_family;
    ciptr->addrlen = namelen;
    memcpy (ciptr->addr, &sockname, ciptr->addrlen);

    (void) umask (oldUmask);

    return 0;
}


static int
TRANS(SocketUNIXResetListener) (XtransConnInfo ciptr)

{
    /*
     * See if the unix domain socket has disappeared.  If it has, recreate it.
     */

    struct sockaddr_un 	*unsock = (struct sockaddr_un *) ciptr->addr;
    struct stat		statb;
    int 		status = TRANS_RESET_NOOP;
    unsigned int	mode;
    int abstract = 0;
#ifdef HAVE_ABSTRACT_SOCKETS
    abstract = ciptr->transptr->flags & TRANS_ABSTRACT;
#endif

    prmsg (3, "SocketUNIXResetListener(%p,%d)\n", ciptr, ciptr->fd);

    if (!abstract && (
	stat (unsock->sun_path, &statb) == -1 ||
        ((statb.st_mode & S_IFMT) !=
#if defined(NCR) || defined(SCO325) || !defined(S_IFSOCK)
	  		S_IFIFO
#else
			S_IFSOCK
#endif
				)))
    {
	int oldUmask = umask (0);

#ifdef UNIX_DIR
#ifdef HAS_STICKY_DIR_BIT
	mode = 01777;
#else
	mode = 0777;
#endif
        if (trans_mkdir(UNIX_DIR, mode) == -1) {
            prmsg (1, "SocketUNIXResetListener: mkdir(%s) failed, errno = %d\n",
	    UNIX_DIR, errno);
	    (void) umask (oldUmask);
	    return TRANS_RESET_FAILURE;
        }
#endif

	close (ciptr->fd);
	unlink (unsock->sun_path);

	if ((ciptr->fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	    TRANS(FreeConnInfo) (ciptr);
	    (void) umask (oldUmask);
	    return TRANS_RESET_FAILURE;
	}

	if (bind (ciptr->fd, (struct sockaddr *) unsock, ciptr->addrlen) < 0)
	{
	    close (ciptr->fd);
	    TRANS(FreeConnInfo) (ciptr);
	    return TRANS_RESET_FAILURE;
	}

	if (listen (ciptr->fd, BACKLOG) < 0)
	{
	    close (ciptr->fd);
	    TRANS(FreeConnInfo) (ciptr);
	    (void) umask (oldUmask);
	    return TRANS_RESET_FAILURE;
	}

	umask (oldUmask);

	status = TRANS_RESET_NEW_FD;
    }

    return status;
}

#endif /* UNIXCONN */


#ifdef TCPCONN

static XtransConnInfo
TRANS(SocketINETAccept) (XtransConnInfo ciptr, int *status)

{
    XtransConnInfo	newciptr;
    struct sockaddr_in	sockname;
    SOCKLEN_T		namelen = sizeof(sockname);

    prmsg (2, "SocketINETAccept(%p,%d)\n", ciptr, ciptr->fd);

    if ((newciptr = calloc (1, sizeof(struct _XtransConnInfo))) == NULL)
    {
	prmsg (1, "SocketINETAccept: malloc failed\n");
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return NULL;
    }

    if ((newciptr->fd = accept (ciptr->fd,
	(struct sockaddr *) &sockname, (void *)&namelen)) < 0)
    {
#ifdef WIN32
	errno = WSAGetLastError();
#endif
	prmsg (1, "SocketINETAccept: accept() failed\n");
	free (newciptr);
	*status = TRANS_ACCEPT_FAILED;
	return NULL;
    }

#ifdef TCP_NODELAY
    {
	/*
	 * turn off TCP coalescence for INET sockets
	 */

	int tmp = 1;
	setsockopt (newciptr->fd, IPPROTO_TCP, TCP_NODELAY,
	    (char *) &tmp, sizeof (int));
    }
#endif

    /*
     * Get this address again because the transport may give a more
     * specific address now that a connection is established.
     */

    if (TRANS(SocketINETGetAddr) (newciptr) < 0)
    {
	prmsg (1,
	    "SocketINETAccept: ...SocketINETGetAddr() failed:\n");
	close (newciptr->fd);
	free (newciptr);
	*status = TRANS_ACCEPT_MISC_ERROR;
        return NULL;
    }

    if (TRANS(SocketINETGetPeerAddr) (newciptr) < 0)
    {
	prmsg (1,
	  "SocketINETAccept: ...SocketINETGetPeerAddr() failed:\n");
	close (newciptr->fd);
	if (newciptr->addr) free (newciptr->addr);
	free (newciptr);
	*status = TRANS_ACCEPT_MISC_ERROR;
        return NULL;
    }

    *status = 0;

    return newciptr;
}

#endif /* TCPCONN */


#ifdef UNIXCONN
static XtransConnInfo
TRANS(SocketUNIXAccept) (XtransConnInfo ciptr, int *status)

{
    XtransConnInfo	newciptr;
    struct sockaddr_un	sockname;
    SOCKLEN_T 		namelen = sizeof sockname;

    prmsg (2, "SocketUNIXAccept(%p,%d)\n", ciptr, ciptr->fd);

    if ((newciptr = calloc (1, sizeof(struct _XtransConnInfo))) == NULL)
    {
	prmsg (1, "SocketUNIXAccept: malloc() failed\n");
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return NULL;
    }

    if ((newciptr->fd = accept (ciptr->fd,
	(struct sockaddr *) &sockname, (void *)&namelen)) < 0)
    {
	prmsg (1, "SocketUNIXAccept: accept() failed\n");
	free (newciptr);
	*status = TRANS_ACCEPT_FAILED;
	return NULL;
    }

	ciptr->addrlen = namelen;
    /*
     * Get the socket name and the peer name from the listener socket,
     * since this is unix domain.
     */

    if ((newciptr->addr = malloc (ciptr->addrlen)) == NULL)
    {
        prmsg (1,
        "SocketUNIXAccept: Can't allocate space for the addr\n");
	close (newciptr->fd);
	free (newciptr);
	*status = TRANS_ACCEPT_BAD_MALLOC;
        return NULL;
    }

    /*
     * if the socket is abstract, we already modified the address to have a
     * @ instead of the initial NUL, so no need to do that again here.
     */

    newciptr->addrlen = ciptr->addrlen;
    memcpy (newciptr->addr, ciptr->addr, newciptr->addrlen);

    if ((newciptr->peeraddr = malloc (ciptr->addrlen)) == NULL)
    {
        prmsg (1,
	      "SocketUNIXAccept: Can't allocate space for the addr\n");
	close (newciptr->fd);
	if (newciptr->addr) free (newciptr->addr);
	free (newciptr);
	*status = TRANS_ACCEPT_BAD_MALLOC;
        return NULL;
    }

    newciptr->peeraddrlen = ciptr->addrlen;
    memcpy (newciptr->peeraddr, ciptr->addr, newciptr->addrlen);

    newciptr->family = AF_UNIX;

    *status = 0;

    return newciptr;
}

#endif /* UNIXCONN */

static int
TRANS(SocketBytesReadable) (XtransConnInfo ciptr, BytesReadable_t *pend)

{
    prmsg (2,"SocketBytesReadable(%p,%d,%p)\n",
	ciptr, ciptr->fd, pend);
#ifdef WIN32
    {
	int ret = ioctlsocket ((SOCKET) ciptr->fd, FIONREAD, (u_long *) pend);
	if (ret == SOCKET_ERROR) errno = WSAGetLastError();
	return ret;
    }
#else
    return ioctl (ciptr->fd, FIONREAD, (char *) pend);
#endif /* WIN32 */
}

#if XTRANS_SEND_FDS

static void
appendFd(struct _XtransConnFd **prev, int fd, int do_close)
{
    struct _XtransConnFd *cf, *new;

    new = malloc (sizeof (struct _XtransConnFd));
    if (!new) {
        /* XXX mark connection as broken */
        close(fd);
        return;
    }
    new->next = 0;
    new->fd = fd;
    new->do_close = do_close;
    /* search to end of list */
    for (; (cf = *prev); prev = &(cf->next));
    *prev = new;
}

static int
removeFd(struct _XtransConnFd **prev)
{
    struct _XtransConnFd *cf;
    int fd;

    if ((cf = *prev)) {
        *prev = cf->next;
        fd = cf->fd;
        free(cf);
    } else
        fd = -1;
    return fd;
}

static void
discardFd(struct _XtransConnFd **prev, struct _XtransConnFd *upto, int do_close)
{
    struct _XtransConnFd *cf, *next;

    for (cf = *prev; cf != upto; cf = next) {
        next = cf->next;
        if (do_close || cf->do_close)
            close(cf->fd);
        free(cf);
    }
    *prev = upto;
}

static void
cleanupFds(XtransConnInfo ciptr)
{
    /* Clean up the send list but don't close the fds */
    discardFd(&ciptr->send_fds, NULL, 0);
    /* Clean up the recv list and *do* close the fds */
    discardFd(&ciptr->recv_fds, NULL, 1);
}

static int
nFd(struct _XtransConnFd **prev)
{
    struct _XtransConnFd *cf;
    int n = 0;

    for (cf = *prev; cf; cf = cf->next)
        n++;
    return n;
}

static int
TRANS(SocketRecvFd) (XtransConnInfo ciptr)
{
    prmsg (2, "SocketRecvFd(%d)\n", ciptr->fd);
    return removeFd(&ciptr->recv_fds);
}

static int
TRANS(SocketSendFd) (XtransConnInfo ciptr, int fd, int do_close)
{
    appendFd(&ciptr->send_fds, fd, do_close);
    return 0;
}

static int
TRANS(SocketRecvFdInvalid)(XtransConnInfo ciptr)
{
    errno = EINVAL;
    return -1;
}

static int
TRANS(SocketSendFdInvalid)(XtransConnInfo ciptr, int fd, int do_close)
{
    errno = EINVAL;
    return -1;
}

#define MAX_FDS		128

union fd_pass {
	struct cmsghdr	cmsghdr;
	char		buf[CMSG_SPACE(MAX_FDS * sizeof(int))];
};

#endif /* XTRANS_SEND_FDS */

static int
TRANS(SocketRead) (XtransConnInfo ciptr, char *buf, int size)

{
    prmsg (2,"SocketRead(%d,%p,%d)\n", ciptr->fd, buf, size);

#if defined(WIN32)
    {
	int ret = recv ((SOCKET)ciptr->fd, buf, size, 0);
#ifdef WIN32
	if (ret == SOCKET_ERROR) errno = WSAGetLastError();
#endif
	return ret;
    }
#else
#if XTRANS_SEND_FDS
    {
        struct iovec    iov = {
            .iov_base = buf,
            .iov_len = size
        };
        union fd_pass   cmsgbuf;
        struct msghdr   msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = cmsgbuf.buf,
            .msg_controllen = CMSG_LEN(MAX_FDS * sizeof(int))
        };

        size = recvmsg(ciptr->fd, &msg, 0);
        if (size >= 0) {
            struct cmsghdr *hdr;

            for (hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr)) {
                if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SCM_RIGHTS) {
                    int nfd = (hdr->cmsg_len - CMSG_LEN(0)) / sizeof (int);
                    int i;
                    int *fd = (int *) CMSG_DATA(hdr);

                    for (i = 0; i < nfd; i++)
                        appendFd(&ciptr->recv_fds, fd[i], 0);
                }
            }
        }
        return size;
    }
#else
    return read(ciptr->fd, buf, size);
#endif /* XTRANS_SEND_FDS */
#endif /* WIN32 */
}

static int
TRANS(SocketReadv) (XtransConnInfo ciptr, struct iovec *buf, int size)

{
    prmsg (2,"SocketReadv(%d,%p,%d)\n", ciptr->fd, buf, size);

#if XTRANS_SEND_FDS
    {
        union fd_pass   cmsgbuf;
        struct msghdr   msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = buf,
            .msg_iovlen = size,
            .msg_control = cmsgbuf.buf,
            .msg_controllen = CMSG_LEN(MAX_FDS * sizeof(int))
        };

        size = recvmsg(ciptr->fd, &msg, 0);
        if (size >= 0) {
            struct cmsghdr *hdr;

            for (hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr)) {
                if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SCM_RIGHTS) {
                    int nfd = (hdr->cmsg_len - CMSG_LEN(0)) / sizeof (int);
                    int i;
                    int *fd = (int *) CMSG_DATA(hdr);

                    for (i = 0; i < nfd; i++)
                        appendFd(&ciptr->recv_fds, fd[i], 0);
                }
            }
        }
        return size;
    }
#else
    return READV (ciptr, buf, size);
#endif
}


static int
TRANS(SocketWritev) (XtransConnInfo ciptr, struct iovec *buf, int size)

{
    prmsg (2,"SocketWritev(%d,%p,%d)\n", ciptr->fd, buf, size);

#if XTRANS_SEND_FDS
    if (ciptr->send_fds)
    {
        union fd_pass           cmsgbuf;
        int                     nfd = nFd(&ciptr->send_fds);
        struct _XtransConnFd    *cf = ciptr->send_fds;
        struct msghdr           msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = buf,
            .msg_iovlen = size,
            .msg_control = cmsgbuf.buf,
            .msg_controllen = CMSG_LEN(nfd * sizeof(int))
        };
        struct cmsghdr          *hdr = CMSG_FIRSTHDR(&msg);
        int                     i;
        int                     *fds;

        hdr->cmsg_len = msg.msg_controllen;
        hdr->cmsg_level = SOL_SOCKET;
        hdr->cmsg_type = SCM_RIGHTS;

        fds = (int *) CMSG_DATA(hdr);
        /* Set up fds */
        for (i = 0; i < nfd; i++) {
            fds[i] = cf->fd;
            cf = cf->next;
        }

        i = sendmsg(ciptr->fd, &msg, 0);
        if (i > 0)
            discardFd(&ciptr->send_fds, cf, 0);
        return i;
    }
#endif
    return WRITEV (ciptr, buf, size);
}


static int
TRANS(SocketWrite) (XtransConnInfo ciptr, char *buf, int size)

{
    prmsg (2,"SocketWrite(%d,%p,%d)\n", ciptr->fd, buf, size);

#if defined(WIN32)
    {
	int ret = send ((SOCKET)ciptr->fd, buf, size, 0);
#ifdef WIN32
	if (ret == SOCKET_ERROR) errno = WSAGetLastError();
#endif
	return ret;
    }
#else
#if XTRANS_SEND_FDS
    if (ciptr->send_fds)
    {
        struct iovec            iov;

        iov.iov_base = buf;
        iov.iov_len = size;
        return TRANS(SocketWritev)(ciptr, &iov, 1);
    }
#endif /* XTRANS_SEND_FDS */
    return write (ciptr->fd, buf, size);
#endif /* WIN32 */
}

static int
TRANS(SocketDisconnect) (XtransConnInfo ciptr)

{
    prmsg (2,"SocketDisconnect(%p,%d)\n", ciptr, ciptr->fd);

#ifdef WIN32
    {
	int ret = shutdown (ciptr->fd, 2);
	if (ret == SOCKET_ERROR) errno = WSAGetLastError();
	return ret;
    }
#else
    return shutdown (ciptr->fd, 2); /* disallow further sends and receives */
#endif
}


#ifdef TCPCONN
static int
TRANS(SocketINETClose) (XtransConnInfo ciptr)

{
    prmsg (2,"SocketINETClose(%p,%d)\n", ciptr, ciptr->fd);

#ifdef WIN32
    {
	int ret = close (ciptr->fd);
	if (ret == SOCKET_ERROR) errno = WSAGetLastError();
	return ret;
    }
#else
    return close (ciptr->fd);
#endif
}

#endif /* TCPCONN */


#ifdef UNIXCONN
static int
TRANS(SocketUNIXClose) (XtransConnInfo ciptr)
{
    /*
     * If this is the server side, then once the socket is closed,
     * it must be unlinked to completely close it
     */

    struct sockaddr_un	*sockname = (struct sockaddr_un *) ciptr->addr;
    int ret;

    prmsg (2,"SocketUNIXClose(%p,%d)\n", ciptr, ciptr->fd);

#if XTRANS_SEND_FDS
    cleanupFds(ciptr);
#endif
    ret = close(ciptr->fd);

    if (ciptr->flags
       && sockname
       && sockname->sun_family == AF_UNIX
       && sockname->sun_path[0])
    {
	if (!(ciptr->flags & TRANS_NOUNLINK
	    || ciptr->transptr->flags & TRANS_ABSTRACT))
		unlink (sockname->sun_path);
    }

    return ret;
}

static int
TRANS(SocketUNIXCloseForCloning) (XtransConnInfo ciptr)

{
    /*
     * Don't unlink path.
     */

    int ret;

    prmsg (2,"SocketUNIXCloseForCloning(%p,%d)\n",
	ciptr, ciptr->fd);

#if XTRANS_SEND_FDS
    cleanupFds(ciptr);
#endif
    ret = close(ciptr->fd);

    return ret;
}

#endif /* UNIXCONN */


#ifdef TCPCONN
static const char* tcp_nolisten[] = {
	"inet",
#if defined(IPv6) && defined(AF_INET6)
	"inet6",
#endif
	NULL
};

Xtransport	TRANS(SocketTCPFuncs) = {
	/* Socket Interface */
	"tcp",
        TRANS_ALIAS,
	tcp_nolisten,
	TRANS(SocketOpenCOTSServer),
	TRANS(SocketReopenCOTSServer),
	TRANS(SocketSetOption),
	TRANS(SocketINETCreateListener),
	NULL,		       			/* ResetListener */
	TRANS(SocketINETAccept),
	TRANS(SocketBytesReadable),
	TRANS(SocketRead),
	TRANS(SocketWrite),
	TRANS(SocketReadv),
	TRANS(SocketWritev),
#if XTRANS_SEND_FDS
        TRANS(SocketSendFdInvalid),
        TRANS(SocketRecvFdInvalid),
#endif
	TRANS(SocketDisconnect),
	TRANS(SocketINETClose),
	TRANS(SocketINETClose),
	};

Xtransport	TRANS(SocketINETFuncs) = {
	/* Socket Interface */
	"inet",
	0,
	NULL,
	TRANS(SocketOpenCOTSServer),
	TRANS(SocketReopenCOTSServer),
	TRANS(SocketSetOption),
	TRANS(SocketINETCreateListener),
	NULL,		       			/* ResetListener */
	TRANS(SocketINETAccept),
	TRANS(SocketBytesReadable),
	TRANS(SocketRead),
	TRANS(SocketWrite),
	TRANS(SocketReadv),
	TRANS(SocketWritev),
#if XTRANS_SEND_FDS
        TRANS(SocketSendFdInvalid),
        TRANS(SocketRecvFdInvalid),
#endif
	TRANS(SocketDisconnect),
	TRANS(SocketINETClose),
	TRANS(SocketINETClose),
	};

#if defined(IPv6) && defined(AF_INET6)
Xtransport     TRANS(SocketINET6Funcs) = {
	/* Socket Interface */
	"inet6",
	0,
	NULL,
	TRANS(SocketOpenCOTSServer),
	TRANS(SocketReopenCOTSServer),
	TRANS(SocketSetOption),
	TRANS(SocketINETCreateListener),
	NULL,					/* ResetListener */
	TRANS(SocketINETAccept),
	TRANS(SocketBytesReadable),
	TRANS(SocketRead),
	TRANS(SocketWrite),
	TRANS(SocketReadv),
	TRANS(SocketWritev),
#if XTRANS_SEND_FDS
        TRANS(SocketSendFdInvalid),
        TRANS(SocketRecvFdInvalid),
#endif
	TRANS(SocketDisconnect),
	TRANS(SocketINETClose),
	TRANS(SocketINETClose),
	};
#endif /* IPv6 */
#endif /* TCPCONN */

#ifdef UNIXCONN
#if !defined(LOCALCONN)
Xtransport	TRANS(SocketLocalFuncs) = {
	/* Socket Interface */
	"local",
#ifdef HAVE_ABSTRACT_SOCKETS
	TRANS_ABSTRACT,
#else
	0,
#endif
	NULL,
	TRANS(SocketOpenCOTSServer),
	TRANS(SocketReopenCOTSServer),
	TRANS(SocketSetOption),
	TRANS(SocketUNIXCreateListener),
	TRANS(SocketUNIXResetListener),
	TRANS(SocketUNIXAccept),
	TRANS(SocketBytesReadable),
	TRANS(SocketRead),
	TRANS(SocketWrite),
	TRANS(SocketReadv),
	TRANS(SocketWritev),
#if XTRANS_SEND_FDS
        TRANS(SocketSendFd),
        TRANS(SocketRecvFd),
#endif
	TRANS(SocketDisconnect),
	TRANS(SocketUNIXClose),
	TRANS(SocketUNIXCloseForCloning),
	};
#endif /* !LOCALCONN */
#  if !defined(LOCALCONN)
static const char* unix_nolisten[] = { "local" , NULL };
#  endif

Xtransport	TRANS(SocketUNIXFuncs) = {
	/* Socket Interface */
	"unix",
#if !defined(LOCALCONN) && !defined(HAVE_ABSTRACT_SOCKETS)
        TRANS_ALIAS,
#else
	0,
#endif
#if !defined(LOCALCONN)
	unix_nolisten,
#else
	NULL,
#endif
	TRANS(SocketOpenCOTSServer),
	TRANS(SocketReopenCOTSServer),
	TRANS(SocketSetOption),
	TRANS(SocketUNIXCreateListener),
	TRANS(SocketUNIXResetListener),
	TRANS(SocketUNIXAccept),
	TRANS(SocketBytesReadable),
	TRANS(SocketRead),
	TRANS(SocketWrite),
	TRANS(SocketReadv),
	TRANS(SocketWritev),
#if XTRANS_SEND_FDS
        TRANS(SocketSendFd),
        TRANS(SocketRecvFd),
#endif
	TRANS(SocketDisconnect),
	TRANS(SocketUNIXClose),
	TRANS(SocketUNIXCloseForCloning),
	};

#endif /* UNIXCONN */
