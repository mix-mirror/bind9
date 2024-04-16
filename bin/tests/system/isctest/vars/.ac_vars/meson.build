configure_file(
    configuration: {'abs_top_srcdir': meson.project_source_root()},
    input: 'TOP_SRCDIR.in',
    output: 'TOP_SRCDIR',
)

configure_file(
    configuration: {'abs_top_builddir': meson.project_build_root()},
    input: 'TOP_BUILDDIR.in',
    output: 'TOP_BUILDDIR',
)

foreach name, prog : {
    'CURL': curl,
    'FSTRM_CAPTURE': fstrm_capture,
    'NC': nc,
    'PERL': perl,
    'PYTEST': pytest,
    'PYTHON': python,
    'SHELL': sh,
    'XSLTPROC': xsltproc,
}
    if prog.found()
        configure_file(
            configuration: {name: prog.full_path()},
            input: fs.replace_suffix(name, '.in'),
            output: name,
        )
    endif
endforeach
