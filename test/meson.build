test_srcs = [
    'tests-common.c',
    'list.c',
    'string.c',
    'tests.c',
    'misc.c',
]

test_xserver_link = [
    libxserver,
    libxserver_config,
    libxserver_xext_vidmode,
]

test_c_args = []
test_xserver_c_args = []
test_xserver_inc = [inc]
if build_xorg
    test_srcs += [
        'fixes.c',
        'input.c',
        'signal-logging.c',
        'test_xkb.c',
        'touch.c',
        'xfree86.c',
        'xtest.c',
    ]
    test_xserver_link = xorg_link
    test_xserver_c_args = xorg_c_args
    test_xserver_inc += xorg_inc
    test_c_args += '-DXORG_TESTS'
endif

if build_res
    test_srcs += 'hashtabletest.c'
    test_c_args += '-DRES_TESTS'
endif

# Aggregate together a lib of all the xserver components, so we don't
# have to worry about linker ordering.
test_xserver_lib = static_library('test_xserver',
    '../mi/miinitext.c',
    link_whole: test_xserver_link,
    include_directories: test_xserver_inc,
    c_args: test_xserver_c_args,
    dependencies: common_dep,
)

monolithic_tests = executable(
    'monolithic tests',
    test_srcs,
    dependencies: common_dep,
    c_args: test_c_args,
    include_directories: [inc, xorg_inc],
    link_with: test_xserver_lib,
)

# Disable the test for now.  It fails linking on Travis CI.
# test('monolithic', monolithic_tests)

simple_xinit = executable(
    'simple-xinit',
    'simple-xinit.c',
    include_directories: inc,
)

# Array of pairs of [server name, server command array] to
# have rendering testing done on them
test_servers = []

piglit_env = environment()
piglit_env.set('XSERVER_DIR', meson.source_root())
piglit_env.set('XSERVER_BUILDDIR', meson.build_root())
piglit_env.append('PIGLIT_ARGS', '-x rendercheck', separator: ' ')

if get_option('xvfb')
    xvfb_invocation = [
        xvfb_server,
        '-noreset',
        '-screen',
        'scrn',
        '1280x1024x24'
    ]

    test('xvfb-piglit', find_program('scripts/xvfb-piglit.sh'),
        env: piglit_env,
        timeout: 1200,
    )
    test_servers += [['Xvfb', xvfb_invocation + ['--']]]

    if get_option('xephyr') and build_glamor
        xephyr_glamor_invocation = [
            xephyr_server,
                '-noreset',
                '-schedMax',
                '2000',
                '-glamor',
                '-glamor-skip-present',
                '-screen',
                '1280x1024',
            ]

        test('xephyr-glamor',
            find_program('scripts/xephyr-glamor-piglit.sh'),
            env: piglit_env,
            timeout: 1200,
        )

        test_servers += [['Xephyr-glamor', xvfb_invocation + ['--', simple_xinit] + xephyr_glamor_invocation + ['--']]]
    endif
endif


rendercheck_tests = [
    ['blend/All/a8r8g8b8', ['-t', 'blend', '-f', 'a8r8g8b8']],
    ['blend/All/x8r8g8b8', ['-t', 'blend', '-f', 'a8r8g8b8,x8r8g8b8']],
    ['blend/All/a2r10g10b10', ['-t', 'blend', '-f', 'a8r8g8b8,a2r10g10b10']],
    ['blend/Clear', ['-t', 'blend', '-o', 'clear']],
    ['blend/Src', ['-t', 'blend', '-o', 'src']],
    ['blend/Over', ['-t', 'blend', '-o', 'over']],
    ['composite/All/a8r8g8b8', ['-t', 'composite', '-f', 'a8r8g8b8']],
    ['composite/All/x8r8g8b8', ['-t', 'composite', '-f', 'a8r8g8b8,x8r8g8b8']],
    ['composite/All/a2r10g10b10', ['-t', 'composite', '-f', 'a8r8g8b8,a2r10g10b10']],
    ['ca composite/All/a8r8g8b8', ['-t', 'cacomposite', '-f', 'a8r8g8b8']],
    ['ca composite/All/a8', ['-t', 'cacomposite', '-f', 'a8r8g8b8,a8']],
    ['ca composite/All/x8r8g8b8', ['-t', 'cacomposite', '-f', 'a8r8g8b8,x8r8g8b8']],
    ['ca composite/All/a2r10g10b10', ['-t', 'cacomposite', '-f', 'a8r8g8b8,a2r10g10b10']],
    ['fill', ['-t', 'fill']],
    ['bug7366', ['-t', 'bug7366']],
    ['destination coordinates', ['-t', 'dcoords']],
    ['source coordinates', ['-t', 'scoords']],
    ['mask coordinates', ['-t', 'mcoords']],
    ['translated source coordinates', ['-t', 'tscoords']],
    ['translated mask coordinates', ['-t', 'tmcoords']],
    ['triangles', ['-t', 'triangles']],
    ['LibreOffice xRGB', ['-t', 'libreoffice_xrgb']],
    ['GTK ARGB vs xBGR', ['-t', 'gtk_argb_xbgr']],
]
rendercheck = find_program('rendercheck')

foreach s: test_servers
    servername = s[0]
    serverargs = s[1]

    foreach r: rendercheck_tests
        testname = 'rendercheck/' + r[0]
        testargs = r[1]

        # It looks like Meson doesn't flatten arrays in arguments, so
        # do so by hand using +=
        xinit_args = serverargs
        xinit_args += rendercheck.path()
        xinit_args += testargs

        test(
            servername + '/' + testname,
            simple_xinit,
            args: xinit_args,
            timeout: 300,
        )
    endforeach
endforeach

