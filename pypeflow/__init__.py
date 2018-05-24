try:
    import sys, pkg_resources
    version = pkg_resources.get_distribution('pypeflow')
    sys.stderr.write('{}\n'.format(pkg_resources.get_distribution('pypeflow')))
except Exception:
    version = '2.0.3' # should match setup.py
