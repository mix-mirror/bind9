custom_target(
    'epub',
    build_always_stale: true,
    build_by_default: false,
    output: 'epub',
    env: {
        'BIND_MESON_PROJECT_VERSION': meson.project_version(),
        'MESON_SOURCE_ROOT': meson.project_source_root(),
    },
    command: [
        sphinx_build,
        sphinx_common_options,
        '-a',
        '-b', 'epub',
        '-d', '@PRIVATE_DIR@',
        '-c', '@CURRENT_SOURCE_DIR@',
        '@CURRENT_SOURCE_DIR@',
        '@OUTPUT@',
    ],
)

custom_target(
    'html',
    build_always_stale: true,
    build_by_default: false,
    output: 'html',
    env: {
        'BIND_MESON_PROJECT_VERSION': meson.project_version(),
        'MESON_SOURCE_ROOT': meson.project_source_root(),
    },
    command: [
        sphinx_build,
        sphinx_common_options,
        '-a',
        '-b', 'html',
        '-d', '@PRIVATE_DIR@',
        '-c', '@CURRENT_SOURCE_DIR@',
        '@CURRENT_SOURCE_DIR@',
        '@OUTPUT@',
    ],
)

custom_target(
    'singlehtml',
    build_always_stale: true,
    build_by_default: false,
    output: 'singlehtml',
    env: {
        'BIND_MESON_PROJECT_VERSION': meson.project_version(),
        'MESON_SOURCE_ROOT': meson.project_source_root(),
    },
    command: [
        sphinx_build,
        sphinx_common_options,
        '-a',
        '-b', 'singlehtml',
        '-d', '@PRIVATE_DIR@',
        '-c', '@CURRENT_SOURCE_DIR@',
        '@CURRENT_SOURCE_DIR@',
        '@OUTPUT@',
    ],
)
