srcs_xorg_dixmods = [
    'xkbVT.c',
    'xkbPrivate.c',
    'xkbKillSrv.c',
]

xorg_dixmods = static_library('xorg_dixmods',
    srcs_xorg_dixmods,
    include_directories: [inc, xorg_inc],
    dependencies: common_dep,
    c_args: xorg_c_args,
)

shared_module(
    'fb',
    'fbmodule.c',

    include_directories: [inc, xorg_inc],
    c_args: xorg_c_args,
    dependencies: common_dep,
    link_whole: libxserver_fb,

    install: true,
    install_dir: module_dir,
)

shared_module(
    'wfb',
    'fbmodule.c',

    include_directories: [inc, xorg_inc],
    c_args: [ xorg_c_args, wfb_args ],
    dependencies: common_dep,
    link_whole: libxserver_wfb,

    install: true,
    install_dir: module_dir,
)
shared_module(
    'shadow',
    'shmodule.c',

    include_directories: [inc, xorg_inc],
    c_args: xorg_c_args,
    dependencies: common_dep,
    link_whole: libxserver_miext_shadow,

    install: true,
    install_dir: module_dir,
)

if build_glx
    shared_module(
        'glx',
        [ 'glxmodule.c', srcs_glxdri2 ],

        include_directories: [ inc, xorg_inc, glx_inc ],
        c_args: [ xorg_c_args, glx_align64 ],
        dependencies: [ common_dep, dl_dep ],
        link_whole: libxserver_glx,

        install: true,
        install_dir: join_paths(module_dir, 'extensions')
    )
endif
