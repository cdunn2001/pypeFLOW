import pypeflow
from .. import io
import argparse
import sys

def foo():
    """
    >>> foo()
    """

def parse_args(argv):
    """
    -j -T --reason --printshellcmds --stats=stats.json  -s
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', '-n', action='store_true',
            help='n/a')
    parser.add_argument('--profile',
            help='n/a')
    parser.add_argument('--snakefile', '-s',
            help='n/a')
    parser.add_argument('--cores', '--jobs', '-j', type=int,
            metavar='N',
            help='n/a')
    parser.add_argument('--local-cores', type=int,
            metavar='N',
            help='n/a')
    parser.add_argument('--resources', nargs='+',
            help='n/a')
    parser.add_argument('--config', nargs='+',
            help='n/a')
    parser.add_argument('--configfile',
            help='n/a')
    parser.add_argument('--directory', '-d',
            help='n/a')
    parser.add_argument('--touch', '-t', action='store_true',
            help='n/a')
    parser.add_argument('--keep-going', '-k', action='store_true',
            help='n/a')
    parser.add_argument('--force', '-f', action='store_true',
            help='n/a')
    parser.add_argument('--forceall', '-F', action='store_true',
            help='n/a')
    parser.add_argument('--forcerun', nargs='+',
            help='n/a')
    parser.add_argument('--rerun-incomplete', '--ri', action='store_true',
            help='n/a')
    parser.add_argument('--list', '-l', action='store_true',
            help='n/a')
    parser.add_argument('--list-target-rules', '--lt', action='store_true',
            help='n/a')
    parser.add_argument('--dag', action='store_true',
            help='n/a')
    parser.add_argument('--rulegraph', action='store_true',
            help='n/a')
    parser.add_argument('--summary', '-S', action='store_true',
            help='n/a')
    parser.add_argument('--detailed-summary', '-D', action='store_true',
            help='n/a')
    parser.add_argument('--cleanup-shadow', action='store_true',
            help='n/a')
    parser.add_argument('--reason', '-r', action='store_true',
            help='n/a')
    parser.add_argument('--printshellcmds', '-p', action='store_true',
            help='n/a')
    parser.add_argument('--quiet', '-q', action='store_true',
            help='n/a')
    parser.add_argument('--timestamp', '-T', action='store_true',
            help='n/a')
    parser.add_argument('--verbose', action='store_true',
            help='n/a')
    parser.add_argument('--force-use-threads', action='store_true',
            help='n/a')
    parser.add_argument('--allow-ambiguity', '-a', action='store_true',
            help='n/a')
    parser.add_argument('--latency-wait', '--output-wait', '-w', type=int,
            metavar='SECONDS',
            help='n/a')
    parser.add_argument('--notemp', '--nt', action='store_true',
            help='n/a')
    parser.add_argument('--max-jobs-per-second', type=int,
            default=10,
            help='n/a')
    parser.add_argument('--max-status-checks-per-second', type=int,
            default=10,
            help='n/a')
    parser.add_argument('--restart-times', type=int,
            default=0,
            help='n/a')
    parser.add_argument('--debug', action='store_true',
            help='n/a')
    parser.add_argument('--cluster-sync',
            help='n/a')
    parser.add_argument('--cluster-config', '-u',
            help='n/a')
    parser.add_argument('--jobscript', '--js',
            help='n/a')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(pypeflow.version))
    return parser.parse_args(argv[1:])

def main(argv=sys.argv):
    print('hi', argv)
    args = parse_args(argv)
    print('args:', args)
