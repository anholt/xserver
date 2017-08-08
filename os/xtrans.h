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

#ifndef _XTRANS_H_
#define _XTRANS_H_

#include <X11/Xfuncproto.h>
#include <X11/Xos.h>
#include <X11/Xmd.h>

#ifndef WIN32
#include <sys/socket.h>
#endif

/*
 * Create a single address structure that can be used wherever
 * an address structure is needed. struct sockaddr is not big enough
 * to hold a sockadd_un, so we create this definition to have a single
 * structure that is big enough for all the structures we might need.
 *
 * This structure needs to be independent of the socket/TLI interface used.
 */

#if defined(IPv6) && defined(AF_INET6)
typedef struct sockaddr_storage Xtransaddr;
#else
#define XTRANS_MAX_ADDR_LEN	128	/* large enough to hold sun_path */

typedef	struct {
    unsigned char	addr[XTRANS_MAX_ADDR_LEN];
} Xtransaddr;
#endif

#ifdef LONG64
typedef int BytesReadable_t;
#else
typedef long BytesReadable_t;
#endif


#if defined(WIN32) || defined(USG)

/*
 *      TransReadv and TransWritev use struct iovec, normally found
 *      in Berkeley systems in <sys/uio.h>.  See the readv(2) and writev(2)
 *      manual pages for details.
 */

struct iovec {
    caddr_t iov_base;
    int iov_len;
};

#else
#include <sys/uio.h>
#endif

typedef struct _XtransConnInfo *XtransConnInfo;


/*
 * Transport Option definitions
 */

#define TRANS_NONBLOCKING	1
#define	TRANS_CLOSEONEXEC	2


/*
 * Return values of Connect (0 is success)
 */

#define TRANS_CONNECT_FAILED 	-1
#define TRANS_TRY_CONNECT_AGAIN -2
#define TRANS_IN_PROGRESS	-3


/*
 * Return values of CreateListener (0 is success)
 */

#define TRANS_CREATE_LISTENER_FAILED 	-1
#define TRANS_ADDR_IN_USE		-2


/*
 * Return values of Accept (0 is success)
 */

#define TRANS_ACCEPT_BAD_MALLOC			-1
#define TRANS_ACCEPT_FAILED 			-2
#define TRANS_ACCEPT_MISC_ERROR			-3


/*
 * ResetListener return values
 */

#define TRANS_RESET_NOOP	1
#define TRANS_RESET_NEW_FD	2
#define TRANS_RESET_FAILURE	3


/*
 * Function prototypes for the exposed interface
 */

void TransFreeConnInfo (
    XtransConnInfo 	/* ciptr */
);



XtransConnInfo TransOpenCOTSServer(
    const char *	/* address */
);



XtransConnInfo TransReopenCOTSServer(
    int,		/* trans_id */
    int,		/* fd */
    const char *	/* port */
);

int TransGetReopenInfo(
    XtransConnInfo,	/* ciptr */
    int *,		/* trans_id */
    int *,		/* fd */
    char **		/* port */
);



int TransSetOption(
    XtransConnInfo,	/* ciptr */
    int,		/* option */
    int			/* arg */
);


int TransCreateListener(
    XtransConnInfo,	/* ciptr */
    const char *,	/* port */
    unsigned int	/* flags */
);

int TransReceived (
    const char*         /* protocol*/
);

int TransNoListen (
    const char*         /* protocol*/
);

int TransListen (
    const char*         /* protocol*/
);

int TransIsListening (
    const char*         /* protocol*/
);

int TransResetListener(
    XtransConnInfo	/* ciptr */
);

XtransConnInfo TransAccept(
    XtransConnInfo,	/* ciptr */
    int *		/* status */
);



int TransBytesReadable(
    XtransConnInfo,	/* ciptr */
    BytesReadable_t *	/* pend */
);

int TransRead(
    XtransConnInfo,	/* ciptr */
    char *,		/* buf */
    int			/* size */
);

int TransWrite(
    XtransConnInfo,	/* ciptr */
    char *,		/* buf */
    int			/* size */
);

int TransReadv(
    XtransConnInfo,	/* ciptr */
    struct iovec *,	/* buf */
    int			/* size */
);

int TransWritev(
    XtransConnInfo,	/* ciptr */
    struct iovec *,	/* buf */
    int			/* size */
);

int TransSendFd (XtransConnInfo ciptr, int fd, int do_close);

int TransRecvFd (XtransConnInfo ciptr);

int TransDisconnect(
    XtransConnInfo	/* ciptr */
);

int TransClose(
    XtransConnInfo	/* ciptr */
);

int TransCloseForCloning(
    XtransConnInfo	/* ciptr */
);

int TransIsLocal(
    XtransConnInfo	/* ciptr */
);

int TransGetPeerAddr(
    XtransConnInfo,	/* ciptr */
    int *,		/* familyp */
    int *,		/* addrlenp */
    Xtransaddr **	/* addrp */
);

int TransGetConnectionNumber(
    XtransConnInfo	/* ciptr */
);


int TransMakeAllCOTSServerListeners(
    const char *,	/* port */
    int *,		/* partial */
    int *,		/* count_ret */
    XtransConnInfo **	/* ciptrs_ret */
);

/*
 * Function Prototypes for Utility Functions.
 */

int TransConvertAddress(
    int *,		/* familyp */
    int *,		/* addrlenp */
    Xtransaddr **	/* addrp */
);

int
TransGetHostname (
    char *	/* buf */,
    int 	/* maxlen */
);

#if defined(WIN32) && defined(TCPCONN)
int TransWSAStartup();
#endif

#endif /* _XTRANS_H_ */
