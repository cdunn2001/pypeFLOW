from .. import io
import pypeflow
import argparse, logging, re, sys

LOG = logging.getLogger(__name__)

def foo():
    """
    >>> foo()
    """
re_rule = re.compile(r'^rule\s+([^:]+)\s*:')
def isrule(line):
    """
    >>> isrule('rule a:')
    True
    >>> isrule(' rule indented:')
    False
    """
    return bool(re_rule.search(line))

def iscomment(line):
    """
    >>> iscomment('# comment')
    True
    >>> iscomment('not comment #')
    False
    """
    # We want only column-0 comments.
    return line.startswith('#')

def isindented(line):
    """
    >>> isindented('\tfoo')
    True
    >>> isindented(' foo')
    True
    >>> isindented('foo\tfoo')
    False
    """
    return line != line.lstrip()

def split_snakefile(stream):
    header = []
    rules = []
    footer = []
    section = header
    for line in stream:
        if isrule(line):
            section = rules
        elif section is rules and not iscomment(line) and not isindented(line):
            section = footer
        section.append(line)
    return header, rules, footer

def parse_rules(lines):
    """
    Drop all comments.
    Return list of lists of lists ..., based on indentation.
    """
    rule = []
    inrule = False
    for line in lines:
        if inrule:
            if not isrule(line) and not iscomment(line):
                if not iscomment(line.lstrip()) and not not line.strip():
                    rule.append(line)
                continue
            yield rule
            rule = []
            inrule = False
        if iscomment(line) or not line.rstrip():
            continue
        mo = re_rule.search(line)
        if not mo:
            msg = 'Pattern {!r} did not match line {!r}'.format(
                    re_rule.pattern, line)
            raise Exception(msg)
        inrule = True
        rule.append(line)
    if rule:
        yield rule

def snakemake(args):
    LOG.debug('Reading from {!r}'.format(args.snakefile))
    with open(args.snakefile) as stream:
        header, middle, footer = split_snakefile(stream)
    print('middle:', middle)
    rules = list(parse_rules(middle))
    print('hello')
    for rule in rules:
        print("rule:", rule)

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
    parser.add_argument('--cores', '--jobs', type=int,
            metavar='N', default=1,
            help='Use at most N cores in parallel. (See also -j)')
    parser.add_argument('-j', action='store_true',
            help='Set cores/jobs to number of cores on machine. (Unlike snakemake, we cannot accept "-j N", as flag options cannot take args.)')
    parser.add_argument('--local-cores', type=int,
            metavar='N',
            help='n/a')
    parser.add_argument('--stats',
            metavar='FILE',
            help='Write stats about Snakefile execution in JSON format to the given file.')
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
    args = parser.parse_args(argv[1:])
    if args.j:
        import multiprocessing
        ncores = multiprocessing.cpu_count()
        if args.cores != 1 and args.cores != ncores:
            msg = 'Cannot set both -j and --cores={} (ncores={})'.format(args.cores, ncores)
            raise Exception(msg)
        args.cores = ncores
    return args

def main(argv=sys.argv):
    print('hi', argv)
    args = parse_args(argv)
    print('args:', args)
    level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARN
    logging.basicConfig(level=level)
    snakemake(args)
