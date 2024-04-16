if not sphinx_build.found()
    subdir_done()
endif

rst_epilog = f'''.. |rndc_conf| replace:: ``@sysconfdir@/rndc.conf``
.. |rndc_key| replace:: ``@sysconfdir@/rndc.key``
.. |named_conf| replace:: ``@sysconfdir@/named.key``
.. |named_pid| replace:: ``@runstatedir@/named.key``
.. |session_key| replace:: ``@runstatedir@/session.key``'''

sphinx_common_options = ['-W', '-n', '-D', f'rst_epilog=@rst_epilog@']

subdir('arm')
subdir('man')
