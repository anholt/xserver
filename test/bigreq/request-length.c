/*
 * Copyright © 2017 Broadcom
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <xcb/xcb.h>
#include <xcb/bigreq.h>

int main(int argc, char **argv)
{
    xcb_connection_t *c = xcb_connect(NULL, NULL);
    xcb_screen_t *screen = xcb_setup_roots_iterator(xcb_get_setup(c)).data;
    xcb_gcontext_t gc = xcb_generate_id(c);
    int fd = xcb_get_file_descriptor(c);
    struct {
        uint8_t reqtype;
        uint8_t coordmode;
        uint16_t length;
        uint32_t length_bigreq;
        uint32_t drawable;
        uint32_t gc;
    } polyline_req = {
        .reqtype = XCB_POLY_LINE,
        .drawable = screen->root,
        .gc = gc,

        /* This is the value that triggers the bug. */
        .length_bigreq = 0,
    };

    xcb_create_gc(c, gc, screen->root, 0, NULL);

    free(xcb_big_requests_enable_reply(c, xcb_big_requests_enable(c), NULL));

    /* Manually write out the bad request.  XCB can't help us here.*/
    write(fd, &polyline_req, sizeof(polyline_req));

    /* Block until the server has processed our mess.  If the server
     * crashes, the simple-xinit will return failure.
     */
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    poll(&pfd, 1, -1);

    return 0;
}
