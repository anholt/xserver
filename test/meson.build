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

test('monolithic', monolithic_tests)

simple_xinit = executable(
    'simple-xinit',
    'simple-xinit.c',
    include_directories: inc,
)

piglit_env = environment()
piglit_env.set('XSERVER_DIR', meson.source_root())
piglit_env.set('XSERVER_BUILDDIR', meson.build_root())

if get_option('xvfb')
    test('xvfb-piglit', find_program('scripts/xvfb-piglit.sh'),
        env: piglit_env,
        timeout: 1200,
    )
endif

if get_option('xephyr') and build_glamor
    test('xephyr-glamor',
        find_program('scripts/xephyr-glamor-piglit.sh'),
        env: piglit_env,
        timeout: 1200,
    )
endif
