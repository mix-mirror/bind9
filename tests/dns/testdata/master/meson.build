master_data += custom_target(
    'master-data-12',
    feed: true,
    capture: true,
    input: files('master12.data.in'),
    output: 'master12.data',
    command: [perl, '-e', master_data_script],
)

master_data += custom_target(
    'master-data-13',
    feed: true,
    capture: true,
    input: files('master13.data.in'),
    output: 'master13.data',
    command: [
        perl,
        '-e', 'use strict;',
        '-e', 'chomp(my $line = <STDIN>);',
        '-e', 'print pack("H*", $line);',
    ],
)

master_data += custom_target(
    'master-data-14',
    feed: true,
    capture: true,
    input: files('master14.data.in'),
    output: 'master14.data',
    command: [
        perl,
        '-e', 'use strict;',
        '-e', 'chomp(my $line = <STDIN>);',
        '-e', 'print pack("H*", $line);',
    ],
)

configure_file(
    input: 'master18.data.in',
    output: 'master18.data',
    configuration: {
        'TOP_SRCDIR': meson.project_source_root() / '..' ,
    },
)
