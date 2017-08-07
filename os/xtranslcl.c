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

Except as contained in this notice, the name of The Open Group shall
not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization
from The Open Group.

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

/*
 *
 * The connection code/ideas in lib/X and server/os for SVR4/Intel
 * environments was contributed by the following companies/groups:
 *
 *	MetroLink Inc
 *	NCR
 *	Pittsburgh Powercomputing Corporation (PPc)/Quarterdeck Office Systems
 *	SGCS
 *	Unix System Laboratories (USL) / Novell
 *	XFree86
 *
 * The goal is to have common connection code among all SVR4/Intel vendors.
 *
 * ALL THE ABOVE COMPANIES DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL THESE COMPANIES * BE LIABLE FOR ANY SPECIAL, INDIRECT
 * OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
 * OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <ctype.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#if defined(SVR4) || defined(__SVR4)
#include <sys/filio.h>
#endif
#ifdef __sun
# include <stropts.h>
#else
# include <sys/stropts.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>

/*
 * The local transports should be treated the same as a UNIX domain socket
 * wrt authentication, etc. Because of this, we will use struct sockaddr_un
 * for the address format. This will simplify the code in other places like
 * The X Server.
 */

#include <sys/socket.h>
#ifndef X_NO_SYS_UN
#include <sys/un.h>
#endif


/* Types of local connections supported:
 *  - PTS
 *  - named pipes
 *  - SCO
 */
#if !defined(__sun)
# define LOCAL_TRANS_PTS
#endif
#if defined(SVR4) || defined(__SVR4)
# define LOCAL_TRANS_NAMED
#endif
#if defined(__SCO__) || defined(__UNIXWARE__)
# define LOCAL_TRANS_SCO
#endif

static int TransLocalClose(XtransConnInfo ciptr);

/*
 * These functions actually implement the local connection mechanisms.
 */

/* Type Not Supported */

static int
TransOpenFail(XtransConnInfo ciptr _X_UNUSED, const char *port _X_UNUSED)
{
    return -1;
}

static int
TransReopenFail(XtransConnInfo ciptr _X_UNUSED, int fd _X_UNUSED,
                const char *port _X_UNUSED)
{
    return 0;
}

#if XTRANS_SEND_FDS
static int
TransLocalRecvFdInvalid(XtransConnInfo ciptr)
{
    errno = EINVAL;
    return -1;
}

static int
TransLocalSendFdInvalid(XtransConnInfo ciptr, int fd, int do_close)
{
    errno = EINVAL;
    return -1;
}
#endif

static int
TransFillAddrInfo(XtransConnInfo ciptr,
                  const char *sun_path, const char *peer_sun_path)
{
    struct sockaddr_un	*sunaddr;
    struct sockaddr_un	*p_sunaddr;

    ciptr->family = AF_UNIX;
    ciptr->addrlen = sizeof (struct sockaddr_un);

    if ((sunaddr = malloc (ciptr->addrlen)) == NULL)
    {
	prmsg(1,"FillAddrInfo: failed to allocate memory for addr\n");
	return 0;
    }

    sunaddr->sun_family = AF_UNIX;

    if (strlen(sun_path) > sizeof(sunaddr->sun_path) - 1) {
	prmsg(1, "FillAddrInfo: path too long\n");
	free((char *) sunaddr);
	return 0;
    }
    strcpy (sunaddr->sun_path, sun_path);
#if defined(BSD44SOCKETS)
    sunaddr->sun_len = strlen (sunaddr->sun_path);
#endif

    ciptr->addr = (char *) sunaddr;

    ciptr->peeraddrlen = sizeof (struct sockaddr_un);

    if ((p_sunaddr = malloc (ciptr->peeraddrlen)) == NULL)
    {
	prmsg(1,
	   "FillAddrInfo: failed to allocate memory for peer addr\n");
	free (sunaddr);
	ciptr->addr = NULL;

	return 0;
    }

    p_sunaddr->sun_family = AF_UNIX;

    if (strlen(peer_sun_path) > sizeof(p_sunaddr->sun_path) - 1) {
	prmsg(1, "FillAddrInfo: peer path too long\n");
	free((char *) p_sunaddr);
	return 0;
    }
    strcpy (p_sunaddr->sun_path, peer_sun_path);
#if defined(BSD44SOCKETS)
    p_sunaddr->sun_len = strlen (p_sunaddr->sun_path);
#endif

    ciptr->peeraddr = (char *) p_sunaddr;

    return 1;
}



#ifdef LOCAL_TRANS_PTS
/* PTS */

#if defined(SYSV) && !defined(__SCO__)
#define SIGNAL_T int
#else
#define SIGNAL_T void
#endif /* SYSV */

typedef SIGNAL_T (*PFV)();

extern PFV signal();

extern char *ptsname(
    int
);

static void _dummy(int sig _X_UNUSED)

{
}
#endif /* LOCAL_TRANS_PTS */

#ifndef __sun
#define X_STREAMS_DIR	"/dev/X"
#define DEV_SPX		"/dev/spx"
#else
#define X_STREAMS_DIR	"/tmp/.X11-pipe"
#endif

#define DEV_PTMX	"/dev/ptmx"

#define PTSNODENAME "/dev/X/server."
#ifdef __sun
#define NAMEDNODENAME "/tmp/.X11-pipe/X"
#else
#define NAMEDNODENAME "/dev/X/Nserver."

#define SCORNODENAME	"/dev/X%1sR"
#define SCOSNODENAME	"/dev/X%1sS"
#endif /* !__sun */

#ifdef LOCAL_TRANS_PTS

static int
TransPTSOpenServer(XtransConnInfo ciptr, const char *port)
{
#ifdef PTSNODENAME
    int fd, server;
    char server_path[64], *slave;
    int mode;
#endif

    prmsg(2,"PTSOpenServer(%s)\n", port);

#if !defined(PTSNODENAME)
    prmsg(1,"PTSOpenServer: Protocol is not supported by a pts connection\n");
    return -1;
#else
    if (port && *port ) {
	if( *port == '/' ) { /* A full pathname */
		(void) sprintf(server_path, "%s", port);
	    } else {
		(void) sprintf(server_path, "%s%s", PTSNODENAME, port);
	    }
    } else {
	(void) sprintf(server_path, "%s%d", PTSNODENAME, getpid());
    }

#ifdef HAS_STICKY_DIR_BIT
    mode = 01777;
#else
    mode = 0777;
#endif
    if (trans_mkdir(X_STREAMS_DIR, mode) == -1) {
	prmsg (1, "PTSOpenServer: mkdir(%s) failed, errno = %d\n",
	       X_STREAMS_DIR, errno);
	return(-1);
    }

#if 0
    if( (fd=open(server_path, O_RDWR)) >= 0 ) {
	/*
	 * This doesn't prevent the server from starting up, and doesn't
	 * prevent clients from trying to connect to the in-use PTS (which
	 * is often in use by something other than another server).
	 */
	prmsg(1, "PTSOpenServer: A server is already running on port %s\n", port);
	prmsg(1, "PTSOpenServer: Remove %s if this is incorrect.\n", server_path);
	close(fd);
	return(-1);
    }
#else
    /* Just remove the old path (which is what happens with UNIXCONN) */
#endif

    unlink(server_path);

    if( (fd=open(DEV_PTMX, O_RDWR)) < 0) {
	prmsg(1, "PTSOpenServer: Unable to open %s\n", DEV_PTMX);
	return(-1);
    }

    grantpt(fd);
    unlockpt(fd);

    if( (slave=ptsname(fd)) == NULL) {
	prmsg(1, "PTSOpenServer: Unable to get slave device name\n");
	close(fd);
	return(-1);
    }

    if( link(slave,server_path) < 0 ) {
	prmsg(1, "PTSOpenServer: Unable to link %s to %s\n", slave, server_path);
	close(fd);
	return(-1);
    }

    if( chmod(server_path, 0666) < 0 ) {
	prmsg(1, "PTSOpenServer: Unable to chmod %s to 0666\n", server_path);
	close(fd);
	return(-1);
    }

    if( (server=open(server_path, O_RDWR)) < 0 ) {
	prmsg(1, "PTSOpenServer: Unable to open server device %s\n", server_path);
	close(fd);
	return(-1);
    }

    close(server);

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

    if (TransFillAddrInfo(ciptr, server_path, server_path) == 0)
    {
	prmsg(1,"PTSOpenServer: failed to fill in addr info\n");
	close(fd);
	return -1;
    }

    return fd;

#endif /* !PTSNODENAME */
}

static int
TransPTSAccept(XtransConnInfo ciptr, XtransConnInfo newciptr, int *status)
{
    int			newfd;
    int			in;
    unsigned char	length;
    char		buf[256];
    struct sockaddr_un	*sunaddr;

    prmsg(2,"PTSAccept(%x->%d)\n",ciptr,ciptr->fd);

    if( (in=read(ciptr->fd,&length,1)) <= 0 ){
	if( !in ) {
		prmsg(2,
		"PTSAccept: Incoming connection closed\n");
		}
	else {
		prmsg(1,
	"PTSAccept: Error reading incoming connection. errno=%d \n",
								errno);
		}
	*status = TRANS_ACCEPT_MISC_ERROR;
	return -1;
    }

    if( (in=read(ciptr->fd,buf,length)) <= 0 ){
	if( !in ) {
		prmsg(2,
		"PTSAccept: Incoming connection closed\n");
		}
	else {
		prmsg(1,
"PTSAccept: Error reading device name for new connection. errno=%d \n",
								errno);
		}
	*status = TRANS_ACCEPT_MISC_ERROR;
	return -1;
    }

    buf[length] = '\0';

    if( (newfd=open(buf,O_RDWR)) < 0 ) {
	prmsg(1, "PTSAccept: Failed to open %s\n",buf);
	*status = TRANS_ACCEPT_MISC_ERROR;
	return -1;
    }

    write(newfd,"1",1);

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

    newciptr->addrlen=ciptr->addrlen;
    if( (newciptr->addr = malloc(newciptr->addrlen)) == NULL ) {
	prmsg(1,"PTSAccept: failed to allocate memory for peer addr\n");
	close(newfd);
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return -1;
    }

    memcpy(newciptr->addr,ciptr->addr,newciptr->addrlen);

    newciptr->peeraddrlen=sizeof(struct sockaddr_un);
    if( (sunaddr = malloc(newciptr->peeraddrlen)) == NULL ) {
	prmsg(1,"PTSAccept: failed to allocate memory for peer addr\n");
	free(newciptr->addr);
	close(newfd);
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return -1;
    }

    sunaddr->sun_family=AF_UNIX;
    strcpy(sunaddr->sun_path,buf);
#if defined(BSD44SOCKETS)
    sunaddr->sun_len=strlen(sunaddr->sun_path);
#endif

    newciptr->peeraddr=(char *)sunaddr;

    *status = 0;

    return newfd;
}

#endif /* LOCAL_TRANS_PTS */


#ifdef LOCAL_TRANS_NAMED

/* NAMED */
#ifdef NAMEDNODENAME
static int
TransNAMEDOpenPipe(const char *server_path)
{
    int			fd, pipefd[2];
    struct stat		sbuf;
    int			mode;

    prmsg(2,"NAMEDOpenPipe(%s)\n", server_path);

#ifdef HAS_STICKY_DIR_BIT
    mode = 01777;
#else
    mode = 0777;
#endif
    if (trans_mkdir(X_STREAMS_DIR, mode) == -1) {
	prmsg (1, "NAMEDOpenPipe: mkdir(%s) failed, errno = %d\n",
	       X_STREAMS_DIR, errno);
	return(-1);
    }

    if(stat(server_path, &sbuf) != 0) {
	if (errno == ENOENT) {
	    if ((fd = creat(server_path, (mode_t)0666)) == -1) {
		prmsg(1, "NAMEDOpenPipe: Can't open %s\n", server_path);
		return(-1);
	    }
	    close(fd);
	    if (chmod(server_path, (mode_t)0666) < 0) {
		prmsg(1, "NAMEDOpenPipe: Can't open %s\n", server_path);
		return(-1);
	    }
	} else {
	    prmsg(1, "NAMEDOpenPipe: stat on %s failed\n", server_path);
	    return(-1);
	}
    }

    if( pipe(pipefd) != 0) {
	prmsg(1, "NAMEDOpenPipe: pipe() failed, errno=%d\n",errno);
	return(-1);
    }

    if( ioctl(pipefd[0], I_PUSH, "connld") != 0) {
	prmsg(1, "NAMEDOpenPipe: ioctl(I_PUSH,\"connld\") failed, errno=%d\n",errno);
	close(pipefd[0]);
	close(pipefd[1]);
	return(-1);
    }

    if( fattach(pipefd[0], server_path) != 0) {
	prmsg(1, "NAMEDOpenPipe: fattach(%s) failed, errno=%d\n", server_path,errno);
	close(pipefd[0]);
	close(pipefd[1]);
	return(-1);
    }

    return(pipefd[1]);
}
#endif

static int
TransNAMEDOpenServer(XtransConnInfo ciptr, const char *port)
{
#ifdef NAMEDNODENAME
    int			fd;
    char		server_path[64];
#endif

    prmsg(2,"NAMEDOpenServer(%s)\n", port);

#if !defined(NAMEDNODENAME)
    prmsg(1,"NAMEDOpenServer: Protocol is not supported by a NAMED connection\n");
    return -1;
#else
    if ( port && *port ) {
	if( *port == '/' ) { /* A full pathname */
	    (void) snprintf(server_path, sizeof(server_path), "%s", port);
	} else {
	    (void) snprintf(server_path, sizeof(server_path), "%s%s",
			    NAMEDNODENAME, port);
	}
    } else {
	(void) snprintf(server_path, sizeof(server_path), "%s%ld",
		       NAMEDNODENAME, (long)getpid());
    }

    fd = TransNAMEDOpenPipe(server_path);
    if (fd < 0) {
	return -1;
    }

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

    if (TransFillAddrInfo(ciptr, server_path, server_path) == 0)
    {
	prmsg(1,"NAMEDOpenServer: failed to fill in addr info\n");
	TransLocalClose(ciptr);
	return -1;
    }

    return fd;

#endif /* !NAMEDNODENAME */
}

static int
TransNAMEDResetListener(XtransConnInfo ciptr)
{
  struct sockaddr_un      *sockname=(struct sockaddr_un *) ciptr->addr;
  struct stat     statb;

  prmsg(2,"NAMEDResetListener(%p, %d)\n", ciptr, ciptr->fd);

  if (ciptr->fd != -1) {
    /*
     * see if the pipe has disappeared
     */

    if (stat (sockname->sun_path, &statb) == -1 ||
	(statb.st_mode & S_IFMT) != S_IFIFO) {
      prmsg(3, "Pipe %s trashed, recreating\n", sockname->sun_path);
      TransLocalClose(ciptr);
      ciptr->fd = TransNAMEDOpenPipe(sockname->sun_path);
      if (ciptr->fd >= 0)
	  return TRANS_RESET_NEW_FD;
      else
	  return TRANS_CREATE_LISTENER_FAILED;
    }
  }
  return TRANS_RESET_NOOP;
}

static int
TransNAMEDAccept(XtransConnInfo ciptr, XtransConnInfo newciptr, int *status)
{
    struct strrecvfd str;

    prmsg(2,"NAMEDAccept(%p->%d)\n", ciptr, ciptr->fd);

    if( ioctl(ciptr->fd, I_RECVFD, &str ) < 0 ) {
	prmsg(1, "NAMEDAccept: ioctl(I_RECVFD) failed, errno=%d\n", errno);
	*status = TRANS_ACCEPT_MISC_ERROR;
	return(-1);
    }

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */
    newciptr->family=ciptr->family;
    newciptr->addrlen=ciptr->addrlen;
    if( (newciptr->addr = malloc(newciptr->addrlen)) == NULL ) {
	prmsg(1,
	      "NAMEDAccept: failed to allocate memory for pipe addr\n");
	close(str.fd);
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return -1;
    }

    memcpy(newciptr->addr,ciptr->addr,newciptr->addrlen);

    newciptr->peeraddrlen=newciptr->addrlen;
    if( (newciptr->peeraddr = malloc(newciptr->peeraddrlen)) == NULL ) {
	prmsg(1,
	"NAMEDAccept: failed to allocate memory for peer addr\n");
	free(newciptr->addr);
	close(str.fd);
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return -1;
    }

    memcpy(newciptr->peeraddr,newciptr->addr,newciptr->peeraddrlen);

    *status = 0;

    return str.fd;
}

#endif /* LOCAL_TRANS_NAMED */

#if defined(LOCAL_TRANS_SCO)

/*
 * connect_spipe is used by the SCO connection type.
 */
static int
connect_spipe(int fd1, int fd2)
{
    long temp;
    struct strfdinsert sbuf;

    sbuf.databuf.maxlen = -1;
    sbuf.databuf.len = -1;
    sbuf.databuf.buf = NULL;
    sbuf.ctlbuf.maxlen = sizeof(long);
    sbuf.ctlbuf.len = sizeof(long);
    sbuf.ctlbuf.buf = (caddr_t)&temp;
    sbuf.offset = 0;
    sbuf.fildes = fd2;
    sbuf.flags = 0;

    if( ioctl(fd1, I_FDINSERT, &sbuf) < 0 )
	return(-1);

    return(0);
}

/*
 * named_spipe is used by the SCO connection type.
 */

static int
named_spipe(int fd, char *path)

{
    int oldUmask, ret;
    struct stat sbuf;

    oldUmask = umask(0);

    (void) fstat(fd, &sbuf);
    ret = mknod(path, 0020666, sbuf.st_rdev);

    umask(oldUmask);

    if (ret < 0) {
	ret = -1;
    } else {
	ret = fd;
    }

    return(ret);
}

/* SCO */

/*
 * 2002-11-09 (jkj@sco.com)
 *
 * This code has been modified to match what is in the actual SCO X server.
 * This greatly helps inter-operability between X11R6 and X11R5 (the native
 * SCO server). Mainly, it relies on streams nodes existing in /dev, not
 * creating them or unlinking them, which breaks the native X server.
 *
 * However, this is only for the X protocol. For all other protocols, we
 * do in fact create the nodes, as only X11R6 will use them, and this makes
 * it possible to have both types of clients running, otherwise we get all
 * kinds of nasty errors on startup for anything that doesnt use the X
 * protocol (like SM, when KDE starts up).
 */

static int
TransSCOOpenServer(XtransConnInfo ciptr, const char *port)
{
#ifdef SCORNODENAME
    char		serverR_path[64];
    char		serverS_path[64];
    struct flock	mylock;
    int			fdr = -1;
    int			fds = -1;
#endif

    prmsg(2,"SCOOpenServer(%s)\n", port);
    if (!port || !port[0])
	port = "0";

#if !defined(SCORNODENAME)
    prmsg(1,"SCOOpenServer: Protocol is not supported by a SCO connection\n");
    return -1;
#else
    (void) sprintf(serverR_path, SCORNODENAME, port);
    (void) sprintf(serverS_path, SCOSNODENAME, port);

#if !defined(__SCO__)
    unlink(serverR_path);
    unlink(serverS_path);

    if ((fds = open(DEV_SPX, O_RDWR)) < 0 ||
	(fdr = open(DEV_SPX, O_RDWR)) < 0 ) {
	prmsg(1,"SCOOpenServer: failed to open %s\n", DEV_SPX);
	if (fds >= 0)
		close(fds);
	if (fdr >= 0)
		close(fdr);
	return -1;
    }

    if (named_spipe (fds, serverS_path) == -1) {
	prmsg(1,"SCOOpenServer: failed to create %s\n", serverS_path);
	close (fdr);
	close (fds);
	return -1;
    }

    if (named_spipe (fdr, serverR_path) == -1) {
	prmsg(1,"SCOOpenServer: failed to create %s\n", serverR_path);
	close (fdr);
	close (fds);
	return -1;
    }
#else /* __SCO__ */

    fds = open (serverS_path, O_RDWR | O_NDELAY);
    if (fds < 0) {
	prmsg(1,"SCOOpenServer: failed to open %s\n", serverS_path);
	return -1;
    }

    /*
     * Lock the connection device for the duration of the server.
     * This resolves multiple server starts especially on SMP machines.
     */
    mylock.l_type	= F_WRLCK;
    mylock.l_whence	= 0;
    mylock.l_start	= 0;
    mylock.l_len	= 0;
    if (fcntl (fds, F_SETLK, &mylock) < 0) {
	prmsg(1,"SCOOpenServer: failed to lock %s\n", serverS_path);
	close (fds);
	return -1;
    }

    fdr = open (serverR_path, O_RDWR | O_NDELAY);
    if (fdr < 0) {
	prmsg(1,"SCOOpenServer: failed to open %s\n", serverR_path);
	close (fds);
	return -1;
    }
#endif /* __SCO__ */

    if (connect_spipe(fds, fdr)) {
	prmsg(1,"SCOOpenServer: ioctl(I_FDINSERT) failed on %s\n",
	      serverS_path);
	close (fdr);
	close (fds);
	return -1;
    }

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

#if defined(__SCO__)
    ciptr->flags |= TRANS_NOUNLINK;
#endif
    if (TransFillAddrInfo(ciptr, serverS_path, serverR_path) == 0) {
	prmsg(1,"SCOOpenServer: failed to fill in addr info\n");
	close(fds);
	close(fdr);
	return -1;
    }

    return(fds);

#endif /* !SCORNODENAME */
}

static int
TransSCOAccept(XtransConnInfo ciptr, XtransConnInfo newciptr, int *status)
{
    char		c;
    int			fd;

    prmsg(2,"SCOAccept(%d)\n", ciptr->fd);

    if (read(ciptr->fd, &c, 1) < 0) {
	prmsg(1,"SCOAccept: can't read from client\n");
	*status = TRANS_ACCEPT_MISC_ERROR;
	return(-1);
    }

    if( (fd = open(DEV_SPX, O_RDWR)) < 0 ) {
	prmsg(1,"SCOAccept: can't open \"%s\"\n",DEV_SPX);
	*status = TRANS_ACCEPT_MISC_ERROR;
	return(-1);
    }

    if (connect_spipe (ciptr->fd, fd) < 0) {
	prmsg(1,"SCOAccept: ioctl(I_FDINSERT) failed\n");
	close (fd);
	*status = TRANS_ACCEPT_MISC_ERROR;
	return -1;
    }

    /*
     * Everything looks good: fill in the XtransConnInfo structure.
     */

    newciptr->addrlen=ciptr->addrlen;
    if( (newciptr->addr = malloc(newciptr->addrlen)) == NULL ) {
	prmsg(1,
	      "SCOAccept: failed to allocate memory for peer addr\n");
	close(fd);
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return -1;
    }

    memcpy(newciptr->addr,ciptr->addr,newciptr->addrlen);
#if defined(__SCO__)
    newciptr->flags |= TRANS_NOUNLINK;
#endif

    newciptr->peeraddrlen=newciptr->addrlen;
    if( (newciptr->peeraddr = malloc(newciptr->peeraddrlen)) == NULL ) {
	prmsg(1,
	      "SCOAccept: failed to allocate memory for peer addr\n");
	free(newciptr->addr);
	close(fd);
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return -1;
    }

    memcpy(newciptr->peeraddr,newciptr->addr,newciptr->peeraddrlen);

    *status = 0;

    return(fd);
}

#endif /* LOCAL_TRANS_SCO */

#ifdef LOCAL_TRANS_PTS

static int
TransPTSReopenServer(XtransConnInfo ciptr, int fd, const char *port)
{
#ifdef PTSNODENAME
    char server_path[64];
#endif

    prmsg(2,"PTSReopenServer(%d,%s)\n", fd, port);

#if !defined(PTSNODENAME)
    prmsg(1,"PTSReopenServer: Protocol is not supported by a pts connection\n");
    return 0;
#else
    if (port && *port ) {
	if( *port == '/' ) { /* A full pathname */
	    snprintf(server_path, sizeof(server_path), "%s", port);
	} else {
	    snprintf(server_path, sizeof(server_path), "%s%s",
		     PTSNODENAME, port);
	}
    } else {
	snprintf(server_path, sizeof(server_path), "%s%ld",
		PTSNODENAME, (long)getpid());
    }

    if (TransFillAddrInfo(ciptr, server_path, server_path) == 0)
    {
	prmsg(1,"PTSReopenServer: failed to fill in addr info\n");
	return 0;
    }

    return 1;

#endif /* !PTSNODENAME */
}

#endif /* LOCAL_TRANS_PTS */

#ifdef LOCAL_TRANS_NAMED

static int
TransNAMEDReopenServer(XtransConnInfo ciptr, int fd _X_UNUSED, const char *port)
{
#ifdef NAMEDNODENAME
    char server_path[64];
#endif

    prmsg(2,"NAMEDReopenServer(%s)\n", port);

#if !defined(NAMEDNODENAME)
    prmsg(1,"NAMEDReopenServer: Protocol is not supported by a NAMED connection\n");
    return 0;
#else
    if ( port && *port ) {
	if( *port == '/' ) { /* A full pathname */
	    snprintf(server_path, sizeof(server_path),"%s", port);
	} else {
	    snprintf(server_path, sizeof(server_path), "%s%s",
		     NAMEDNODENAME, port);
	}
    } else {
	snprintf(server_path, sizeof(server_path), "%s%ld",
		NAMEDNODENAME, (long)getpid());
    }

    if (TransFillAddrInfo(ciptr, server_path, server_path) == 0)
    {
	prmsg(1,"NAMEDReopenServer: failed to fill in addr info\n");
	return 0;
    }

    return 1;

#endif /* !NAMEDNODENAME */
}

#endif /* LOCAL_TRANS_NAMED */


#ifdef LOCAL_TRANS_SCO
static int
TransSCOReopenServer(XtransConnInfo ciptr, int fd, const char *port)
{
#ifdef SCORNODENAME
    char serverR_path[64], serverS_path[64];
#endif

    prmsg(2,"SCOReopenServer(%s)\n", port);
    if (!port || !port[0])
      port = "0";

#if !defined(SCORNODENAME)
    prmsg(2,"SCOReopenServer: Protocol is not supported by a SCO connection\n");
    return 0;
#else
    (void) sprintf(serverR_path, SCORNODENAME, port);
    (void) sprintf(serverS_path, SCOSNODENAME, port);

#if defined(__SCO__)
    ciptr->flags |= TRANS_NOUNLINK;
#endif
    if (TransFillAddrInfo(ciptr, serverS_path, serverR_path) == 0)
    {
	prmsg(1, "SCOReopenServer: failed to fill in addr info\n");
	return 0;
    }

    return 1;

#endif /* SCORNODENAME */
}

#endif /* LOCAL_TRANS_SCO */

/*
 * This table contains all of the entry points for the different local
 * connection mechanisms.
 */

typedef struct _LOCALtrans2dev {
    const char	*transname;

    int	(*devcotsopenserver)(
	XtransConnInfo, const char * /*port*/
);

    int	(*devcltsopenserver)(
	XtransConnInfo, const char * /*port*/
);

    int	(*devcotsreopenserver)(
	XtransConnInfo,
	int, 	/* fd */
	const char * 	/* port */
);

    int	(*devcltsreopenserver)(
	XtransConnInfo,
	int, 	/* fd */
	const char *	/* port */
);

    int (*devreset)(
	XtransConnInfo /* ciptr */
);

    int	(*devaccept)(
	XtransConnInfo, XtransConnInfo, int *
);


} LOCALtrans2dev;

static LOCALtrans2dev LOCALtrans2devtab[] = {
#ifdef LOCAL_TRANS_PTS
{"",
     TransPTSOpenServer,
     TransOpenFail,
     TransPTSReopenServer,
     TransReopenFail,
     NULL,		/* ResetListener */
     TransPTSAccept
},

{"local",
     TransPTSOpenServer,
     TransOpenFail,
     TransPTSReopenServer,
     TransReopenFail,
     NULL,		/* ResetListener */
     TransPTSAccept
},

{"pts",
     TransPTSOpenServer,
     TransOpenFail,
     TransPTSReopenServer,
     TransReopenFail,
     NULL,		/* ResetListener */
     TransPTSAccept
},
#else /* !LOCAL_TRANS_PTS */
{"",
     TransNAMEDOpenServer,
     TransOpenFail,
     TransNAMEDReopenServer,
     TransReopenFail,
     TransNAMEDResetListener,
     TransNAMEDAccept
},

{"local",
     TransNAMEDOpenServer,
     TransOpenFail,
     TransNAMEDReopenServer,
     TransReopenFail,
     TransNAMEDResetListener,
     TransNAMEDAccept
},
#endif /* !LOCAL_TRANS_PTS */

#ifdef LOCAL_TRANS_NAMED
{"named",
     TransNAMEDOpenServer,
     TransOpenFail,
     TransNAMEDReopenServer,
     TransReopenFail,
     TransNAMEDResetListener,
     TransNAMEDAccept
},

#ifdef __sun /* Alias "pipe" to named, since that's what Solaris called it */
{"pipe",
     TransNAMEDOpenServer,
     TransOpenFail,
     TransNAMEDReopenServer,
     TransReopenFail,
     TransNAMEDResetListener,
     TransNAMEDAccept
},
#endif /* __sun */
#endif /* LOCAL_TRANS_NAMED */


#ifdef LOCAL_TRANS_SCO
{"sco",
     TransSCOOpenServer,
     TransOpenFail,
     TransSCOReopenServer,
     TransReopenFail,
     NULL,		/* ResetListener */
     TransSCOAccept
},
#endif /* LOCAL_TRANS_SCO */
};

#define NUMTRANSPORTS	(sizeof(LOCALtrans2devtab)/sizeof(LOCALtrans2dev))

static const char	*XLOCAL=NULL;
static	char	*workingXLOCAL=NULL;
static	char	*freeXLOCAL=NULL;

#if defined(__SCO__)
#define DEF_XLOCAL "SCO:UNIX:PTS"
#elif defined(__UNIXWARE__)
#define DEF_XLOCAL "UNIX:PTS:NAMED:SCO"
#elif defined(__sun)
#define DEF_XLOCAL "UNIX:NAMED"
#else
#define DEF_XLOCAL "UNIX:PTS:NAMED:SCO"
#endif

static void
TransLocalInitTransports(const char *protocol)
{
    prmsg(3,"LocalInitTransports(%s)\n", protocol);

    if( strcmp(protocol,"local") && strcmp(protocol,"LOCAL") )
    {
	workingXLOCAL = freeXLOCAL = strdup (protocol);
    }
    else {
	XLOCAL=(char *)getenv("XLOCAL");
	if(XLOCAL==NULL)
	    XLOCAL=DEF_XLOCAL;
	workingXLOCAL = freeXLOCAL = strdup (XLOCAL);
    }
}

static void
TransLocalEndTransports(void)
{
    prmsg(3,"LocalEndTransports()\n");
    free(freeXLOCAL);
}

#define TYPEBUFSIZE	32

static XtransConnInfo
TransLocalOpenServer(int type, const char *protocol,
                       const char *host _X_UNUSED, const char *port)
{
    int	i;
    XtransConnInfo ciptr;

    prmsg(2,"LocalOpenServer(%d,%s,%s)\n", type, protocol, port);

    /*
     * For X11, the port will be in the format xserverN where N is the
     * display number. All of the local connections just need to know
     * the display number because they don't do any name resolution on
     * the port. This just truncates port to the display portion.
     */

    if( (ciptr = calloc(1,sizeof(struct _XtransConnInfo))) == NULL )
    {
	prmsg(1,"LocalOpenServer: calloc(1,%lu) failed\n",
	      sizeof(struct _XtransConnInfo));
	return NULL;
    }

    for(i=1;i<NUMTRANSPORTS;i++)
    {
	if( strcmp(protocol,LOCALtrans2devtab[i].transname) != 0 )
	    continue;
	switch( type )
	{
	case XTRANS_OPEN_COTS_CLIENT:
	    prmsg(1,
		  "LocalOpenServer: Should not be opening a client with this function\n");
	    break;
	case XTRANS_OPEN_COTS_SERVER:
	    ciptr->fd=LOCALtrans2devtab[i].devcotsopenserver(ciptr,port);
	    break;
	default:
	    prmsg(1,"LocalOpenServer: Unknown Open type %d\n",
		  type );
	}
	if( ciptr->fd >= 0 ) {
	    ciptr->priv=(char *)&LOCALtrans2devtab[i];
	    ciptr->index=i;
	    ciptr->flags = 1 | (ciptr->flags & TRANS_KEEPFLAGS);
	    return ciptr;
	}
    }

    free(ciptr);
    return NULL;
}

static XtransConnInfo
TransLocalReopenServer(int type, int index, int fd, const char *port)
{
    XtransConnInfo ciptr;
    int stat = 0;

    prmsg(2,"LocalReopenServer(%d,%d,%d)\n", type, index, fd);

    if( (ciptr = calloc(1,sizeof(struct _XtransConnInfo))) == NULL )
    {
	prmsg(1,"LocalReopenServer: calloc(1,%lu) failed\n",
	      sizeof(struct _XtransConnInfo));
	return NULL;
    }

    ciptr->fd = fd;

    switch( type )
    {
    case XTRANS_OPEN_COTS_SERVER:
	stat = LOCALtrans2devtab[index].devcotsreopenserver(ciptr,fd,port);
	break;
    default:
	prmsg(1,"LocalReopenServer: Unknown Open type %d\n",
	  type );
    }

    if( stat > 0 ) {
	ciptr->priv=(char *)&LOCALtrans2devtab[index];
	ciptr->index=index;
	ciptr->flags = 1 | (ciptr->flags & TRANS_KEEPFLAGS);
	return ciptr;
    }

    free(ciptr);
    return NULL;
}

/*
 * This is the Local implementation of the X Transport service layer
 */

static XtransConnInfo
TransLocalOpenCOTSServer(Xtransport *thistrans, const char *protocol,
                         const char *host, const char *port)
{
    char *typetocheck = NULL;
    int found = 0;
    char typebuf[TYPEBUFSIZE];

    prmsg(2,"LocalOpenCOTSServer(%s,%s,%s)\n",protocol,host,port);

    /* Check if this local type is in the XLOCAL list */
    TransLocalInitTransports("local");
    typetocheck = workingXLOCAL;
    while (typetocheck && !found) {
	int j;

	workingXLOCAL = strchr(workingXLOCAL, ':');
	if (workingXLOCAL && *workingXLOCAL)
	    *workingXLOCAL++ = '\0';
	strncpy(typebuf, typetocheck, TYPEBUFSIZE);
	for (j = 0; j < TYPEBUFSIZE; j++)
	    if (isupper(typebuf[j]))
		typebuf[j] = tolower(typebuf[j]);
	if (!strcmp(thistrans->TransName, typebuf))
	    found = 1;
	typetocheck = workingXLOCAL;
    }
    TransLocalEndTransports();

    if (!found) {
	prmsg(3,"LocalOpenCOTSServer: disabling %s\n",thistrans->TransName);
	thistrans->flags |= TRANS_DISABLED;
	return NULL;
    }

    return TransLocalOpenServer(XTRANS_OPEN_COTS_SERVER, protocol, host, port);
}

static XtransConnInfo
TransLocalReopenCOTSServer(Xtransport *thistrans, int fd, const char *port)
{
    int index;

    prmsg(2,"LocalReopenCOTSServer(%d,%s)\n", fd, port);

    for(index=1;index<NUMTRANSPORTS;index++)
    {
	if( strcmp(thistrans->TransName,
	    LOCALtrans2devtab[index].transname) == 0 )
	    break;
    }

    if (index >= NUMTRANSPORTS)
    {
	return (NULL);
    }

    return TransLocalReopenServer(XTRANS_OPEN_COTS_SERVER,
	index, fd, port);
}

static int
TransLocalSetOption(XtransConnInfo ciptr, int option, int arg)
{
    prmsg(2,"LocalSetOption(%d,%d,%d)\n",ciptr->fd,option,arg);

    return -1;
}

static int
TransLocalCreateListener(XtransConnInfo ciptr, const char *port,
                         unsigned int flags _X_UNUSED)
{
    prmsg(2,"LocalCreateListener(%p->%d,%s)\n",ciptr,ciptr->fd,port);

    return 0;
}

static int
TransLocalResetListener(XtransConnInfo ciptr)
{
    LOCALtrans2dev	*transptr;

    prmsg(2,"LocalResetListener(%p)\n",ciptr);

    transptr=(LOCALtrans2dev *)ciptr->priv;
    if (transptr->devreset != NULL) {
	return transptr->devreset(ciptr);
    }
    return TRANS_RESET_NOOP;
}


static XtransConnInfo
TransLocalAccept(XtransConnInfo ciptr, int *status)
{
    XtransConnInfo	newciptr;
    LOCALtrans2dev	*transptr;

    prmsg(2,"LocalAccept(%p->%d)\n", ciptr, ciptr->fd);

    transptr=(LOCALtrans2dev *)ciptr->priv;

    if( (newciptr = calloc(1,sizeof(struct _XtransConnInfo)))==NULL )
    {
	prmsg(1,"LocalAccept: calloc(1,%lu) failed\n",
	      sizeof(struct _XtransConnInfo));
	*status = TRANS_ACCEPT_BAD_MALLOC;
	return NULL;
    }

    newciptr->fd=transptr->devaccept(ciptr,newciptr,status);

    if( newciptr->fd < 0 )
    {
	free(newciptr);
	return NULL;
    }

    newciptr->priv=(char *)transptr;
    newciptr->index = ciptr->index;

    *status = 0;

    return newciptr;
}

static int
TransLocalBytesReadable(XtransConnInfo ciptr, BytesReadable_t *pend )
{
    prmsg(2,"LocalBytesReadable(%p->%d,%p)\n", ciptr, ciptr->fd, pend);

#if defined(SCO325)
    return ioctl(ciptr->fd, I_NREAD, (char *)pend);
#else
    return ioctl(ciptr->fd, FIONREAD, (char *)pend);
#endif
}

static int
TransLocalRead(XtransConnInfo ciptr, char *buf, int size)

{
    prmsg(2,"LocalRead(%d,%p,%d)\n", ciptr->fd, buf, size );

    return read(ciptr->fd,buf,size);
}

static int
TransLocalWrite(XtransConnInfo ciptr, char *buf, int size)
{
    prmsg(2,"LocalWrite(%d,%p,%d)\n", ciptr->fd, buf, size );

    return write(ciptr->fd,buf,size);
}

static int
TransLocalReadv(XtransConnInfo ciptr, struct iovec *buf, int size)
{
    prmsg(2,"LocalReadv(%d,%p,%d)\n", ciptr->fd, buf, size );

    return READV(ciptr,buf,size);
}

static int
TransLocalWritev(XtransConnInfo ciptr, struct iovec *buf, int size)
{
    prmsg(2,"LocalWritev(%d,%p,%d)\n", ciptr->fd, buf, size );

    return WRITEV(ciptr,buf,size);
}

static int
TransLocalDisconnect(XtransConnInfo ciptr)
{
    prmsg(2,"LocalDisconnect(%p->%d)\n", ciptr, ciptr->fd);

    return 0;
}

static int
TransLocalClose(XtransConnInfo ciptr)
{
    struct sockaddr_un      *sockname=(struct sockaddr_un *) ciptr->addr;
    int	ret;

    prmsg(2,"LocalClose(%p->%d)\n", ciptr, ciptr->fd );

    ret=close(ciptr->fd);

    if(ciptr->flags
       && sockname
       && sockname->sun_family == AF_UNIX
       && sockname->sun_path[0] )
    {
	if (!(ciptr->flags & TRANS_NOUNLINK))
	    unlink(sockname->sun_path);
    }

    return ret;
}

static int
TransLocalCloseForCloning(XtransConnInfo ciptr)
{
    int ret;

    prmsg(2,"LocalCloseForCloning(%p->%d)\n", ciptr, ciptr->fd );

    /* Don't unlink path */

    ret=close(ciptr->fd);

    return ret;
}


/*
 * MakeAllCOTSServerListeners() will go through the entire Xtransports[]
 * array defined in Xtrans.c and try to OpenCOTSServer() for each entry.
 * We will add duplicate entries to that table so that the OpenCOTSServer()
 * function will get called once for each type of local transport.
 *
 * The TransName is in lowercase, so it will never match during a normal
 * call to SelectTransport() in Xtrans.c.
 */

static const char * local_aliases[] = {
# ifdef LOCAL_TRANS_PTS
                                  "pts",
# endif
				  "named",
# ifdef __sun
				  "pipe", /* compatibility with Solaris Xlib */
# endif
# ifdef LOCAL_TRANS_SCO
				  "sco",
# endif
				  NULL };

Xtransport	TransLocalFuncs = {
	/* Local Interface */
	"local",
	TRANS_ALIAS | TRANS_LOCAL,
	local_aliases,
	TransLocalOpenCOTSServer,
	TransLocalReopenCOTSServer,
	TransLocalSetOption,
	TransLocalCreateListener,
	TransLocalResetListener,
	TransLocalAccept,
	TransLocalBytesReadable,
	TransLocalRead,
	TransLocalWrite,
	TransLocalReadv,
	TransLocalWritev,
#if XTRANS_SEND_FDS
	TransLocalSendFdInvalid,
	TransLocalRecvFdInvalid,
#endif
	TransLocalDisconnect,
	TransLocalClose,
	TransLocalCloseForCloning,
};

#ifdef LOCAL_TRANS_PTS

Xtransport	TransPTSFuncs = {
	/* Local Interface */
	"pts",
	TRANS_LOCAL,
	NULL,
	TransLocalOpenCOTSServer,
	TransLocalReopenCOTSServer,
	TransLocalSetOption,
	TransLocalCreateListener,
	TransLocalResetListener,
	TransLocalAccept,
	TransLocalBytesReadable,
	TransLocalRead,
	TransLocalWrite,
	TransLocalReadv,
	TransLocalWritev,
#if XTRANS_SEND_FDS
	TransLocalSendFdInvalid,
	TransLocalRecvFdInvalid,
#endif
	TransLocalDisconnect,
	TransLocalClose,
	TransLocalCloseForCloning,
};

#endif /* LOCAL_TRANS_PTS */

#ifdef LOCAL_TRANS_NAMED

Xtransport	TransNAMEDFuncs = {
	/* Local Interface */
	"named",
	TRANS_LOCAL,
	NULL,
	TransLocalOpenCOTSServer,
	TransLocalReopenCOTSServer,
	TransLocalSetOption,
	TransLocalCreateListener,
	TransLocalResetListener,
	TransLocalAccept,
	TransLocalBytesReadable,
	TransLocalRead,
	TransLocalWrite,
	TransLocalReadv,
	TransLocalWritev,
#if XTRANS_SEND_FDS
	TransLocalSendFdInvalid,
	TransLocalRecvFdInvalid,
#endif
	TransLocalDisconnect,
	TransLocalClose,
	TransLocalCloseForCloning,
};

#ifdef __sun
Xtransport	TransPIPEFuncs = {
	/* Local Interface */
	"pipe",
	TRANS_ALIAS | TRANS_LOCAL,
	NULL,
	TransLocalOpenCOTSServer,
	TransLocalReopenCOTSServer,
	TransLocalSetOption,
	TransLocalCreateListener,
	TransLocalResetListener,
	TransLocalAccept,
	TransLocalBytesReadable,
	TransLocalRead,
	TransLocalWrite,
	TransLocalReadv,
	TransLocalWritev,
#if XTRANS_SEND_FDS
	TransLocalSendFdInvalid,
	TransLocalRecvFdInvalid,
#endif
	TransLocalDisconnect,
	TransLocalClose,
	TransLocalCloseForCloning,
};
#endif /* __sun */
#endif /* LOCAL_TRANS_NAMED */


#ifdef LOCAL_TRANS_SCO
Xtransport	TransSCOFuncs = {
	/* Local Interface */
	"sco",
	TRANS_LOCAL,
	NULL,
	TransLocalOpenCOTSServer,
	TransLocalReopenCOTSServer,
	TransLocalSetOption,
	TransLocalCreateListener,
	TransLocalResetListener,
	TransLocalAccept,
	TransLocalBytesReadable,
	TransLocalRead,
	TransLocalWrite,
	TransLocalReadv,
	TransLocalWritev,
#if XTRANS_SEND_FDS
	TransLocalSendFdInvalid,
	TransLocalRecvFdInvalid,
#endif
	TransLocalDisconnect,
	TransLocalClose,
	TransLocalCloseForCloning,
};
#endif /* LOCAL_TRANS_SCO */
