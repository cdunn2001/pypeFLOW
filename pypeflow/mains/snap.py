from .. import io
import pypeflow.tasks
from pypeflow.simple_pwatcher_bridge import (PypeProcWatcherWorkflow, PypeTask, Dist)
import argparse, collections, logging, pprint, re, sys

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

def parse_indented_text(lines):
    """
    Drop all comments.
    Return list of (text, list of (text, list of ...)), based on indentation.
    """
    # We keep 2 matching queues.
    # (It could be a single queue of pairs, but this is easier
    #  to read.)
    # Ones is a stack of indentations.
    # The other is a stack of tree-lists for appending.
    # A tree-list is the recursive return type, list(text, treelist).
    # The top tree-list is actually the sub-tree-list of the last tuple
    # of the next-to-list stack element, so when we pop it we do not
    # need to record it anyway.
    textq = collections.deque()
    indentq = collections.deque()
    textq.append(list())
    indentq.append('')
    re_indent = re.compile(r'^(\s*)(.*)$')
    try:
        nlines = 0
        for line in lines:
            nlines += 1
            mo = re_indent.search(line)
            if not mo:
                # This regex should match any line.
                msg = 'Pattern {!r} did not match line {!r}'.format(
                        re_indent.pattern, line)
                raise Exception(msg)
            indent, text = mo.groups()
            text = text.rstrip()
            if text.startswith('#') or text == '':
                # Skip comments and blank lines.
                continue
            while len(indent) < len(indentq[-1]):
                indentq.pop()
                textq.pop()
            if len(indent) > len(indentq[-1]):
                #print('top:', textq[-1])
                indentq.append(indent)
                textq.append(textq[-1][-1][1]) # not a copy
            if indent != indentq[-1]:
                msg = 'Detected indentation error. {!r} != {!r} at text #{}:\n{}'.format(
                        indent, indentq[-1], nlines, text)
                raise Exception(msg)
            textq[-1].append((text, list()))
        return textq[0]
    except:
        msg = '\nCurrent textq==\n{}\nCurrent indentq==\n{}'.format(
                pprint.pformat(textq), pprint.pformat(indentq))
        LOG.error(msg)
        raise

def get_stuff(text, sub_list):
    # For now, we do not support anything on the line with the colon,
    # so we ignore 'text'.
    foreval = 'dict({})'.format(' '.join(item[0] for item in sub_list))
    return eval(foreval)

re_input = re.compile(r'input\s*:')
re_output = re.compile(r'output\s*:')
re_shell = re.compile(r'shell\s*:')
re_run = re.compile(r'run\s*:')
def gen_pypeflow_task(rule_text, tree_list):
    dist = Dist(local=True)
    parameters = None
    script = 'echo HELLO'
    inputs = dict()
    outputs = dict()
    mo = re_rule.search(rule_text)
    assert mo, (mo, re_rule.pattern, rule_text)
    for (sub_text, sub_list) in tree_list:
        if re_input.search(sub_text):
            inputs = get_stuff(sub_text, sub_list)
        if re_output.search(sub_text):
            outputs = get_stuff(sub_text, sub_list)
        if re_shell.search(sub_text):
            script = '\n'.join(eval(item[0]) for item in sub_list)
        if re_run.search(sub_text):
            raise Exception('We support "shell", not "run" in "{}"\n{}'.format(
                rule_text, pprint.pformat(tree_list)))
    return pypeflow.tasks.gen_task(script, inputs, outputs, parameters, dist)
def snakemake(args):
    LOG.debug('Reading from {!r}'.format(args.snakefile))
    with open(args.snakefile) as stream:
        header, middle, footer = split_snakefile(stream)
    rule_tree = parse_indented_text(middle)
    wf = PypeProcWatcherWorkflow(
            #job_defaults=config['job.defaults'],
            squash=False,
    )
    for rule in rule_tree:
        #print(pprint.pformat(rule))
        assert isinstance(rule, tuple), rule
        assert 2 == len(rule), rule
        task = gen_pypeflow_task(*rule)
        wf.addTask(task)
    wf.refreshTargets()

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
    LOG.debug('argv={!r}'.format(argv))
    args = parse_args(argv)
    LOG.debug('args={!r}'.format(args))
    level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARN
    logging.basicConfig(
            format='[%(levelname)s] %(msg)s',
        level=level)
    snakemake(args)
