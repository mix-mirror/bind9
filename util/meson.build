configure_file(
    input: 'check-make-install.in',
    output: 'check-make-install',
    configuration: {
        'abs_builddir': meson.project_build_root(),
        'abs_top_srcdir': meson.project_source_root(),
        'prefix': prefix,
        'includedir': includedir,
    },
)
