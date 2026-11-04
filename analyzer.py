"""Offline, deliberately restricted C sequence candidate analyzer. Python 3.10+."""
import argparse
import json
import re
from pathlib import Path

ID = r"[A-Za-z_][A-Za-z_0-9]*"
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'+ID+r'|\d+|==|!=|<=|>=|&&|\|\||[^\s]')


class Unsupported(ValueError):
    pass


def tokens(text):
    # Keep string/comment delimiters inside strings from being treated as comments.
    clean = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*',
                   lambda m: ' ' if m[0].startswith(('/',)) else m[0], text)
    if re.search(r'^\s*#', clean, re.M):
        raise Unsupported('Preprocessor directives require a reviewed, normalized input copy')
    return TOKEN.findall(clean)


class Parser:
    def __init__(self, ts):
        self.ts, self.i = ts, 0

    def take(self, expected=None):
        if self.i >= len(self.ts):
            raise Unsupported('Unexpected end of C input')
        t = self.ts[self.i]
        self.i += 1
        if expected is not None and t != expected:
            raise Unsupported('Expected ' + expected + ', got ' + t)
        return t

    def group(self):
        self.take('(')
        out, depth = [], 1
        while depth:
            t = self.take()
            depth += (t == '(') - (t == ')')
            if depth:
                out.append(t)
        return out

    def statement(self):
        t = self.ts[self.i]
        if t == '{':
            self.take()
            out = []
            while self.i < len(self.ts) and self.ts[self.i] != '}':
                out.append(self.statement())
            self.take('}')
            return ('block', out)
        if t == 'if':
            self.take()
            condition_tokens = self.group()
            if '(' in condition_tokens or '=' in condition_tokens:
                raise Unsupported('Condition calls/grouping/assignment need review')
            cond, yes = ' '.join(condition_tokens), self.statement()
            no = ('block', [])
            if self.i < len(self.ts) and self.ts[self.i] == 'else':
                self.take()
                no = self.statement()
            return ('if', cond, yes, no)
        if t in {'for', 'while', 'do', 'switch', 'goto', 'break', 'continue', 'case'}:
            raise Unsupported('Unsupported control flow: ' + t)
        out = []
        while True:
            t = self.take()
            if t == ';':
                break
            if t in {'{', '}'}:
                raise Unsupported('Unsupported statement structure')
            out.append(t)
        return ('stmt', out)


def parse(text):
    p, functions = Parser(tokens(text)), {}
    while p.i < len(p.ts):
        header = []
        while p.i < len(p.ts) and p.ts[p.i] not in {'{', ';'}:
            header.append(p.take())
        if p.i == len(p.ts):
            raise Unsupported('Incomplete top-level declaration')
        if p.ts[p.i] == ';':
            p.take()
            continue
        if '(' not in header:
            raise Unsupported('Only function bodies and simple declarations are supported')
        at = header.index('(')
        name = header[at-1]
        if name in functions:
            raise Unsupported('Ambiguous duplicate function: ' + name)
        functions[name] = p.statement()
    return functions


def calls(ts):
    out = []
    for i in range(len(ts)-1):
        if re.fullmatch(ID, ts[i]) and ts[i+1] == '(':
            if i and ts[i-1] in {'*', '.', '->'}:
                raise Unsupported('Indirect/member call')
            p = Parser(ts)
            p.i = i+1
            args = p.group()
            if '(' in args:
                raise Unsupported('Nested calls/parenthesized arguments need review')
            out.append((ts[i], ' '.join(args)))
    return out


def traces(node, functions, stack=(), limit=256):
    kind = node[0]
    if kind == 'block':
        paths = [([], [], False)]
        for child in node[1]:
            new = []
            for events, guards, stopped in paths:
                if stopped:
                    new.append((events, guards, True))
                else:
                    for ev, gd, stop in traces(child, functions, stack, limit):
                        new.append((events+ev, guards+gd, stop))
                        if len(new) > limit:
                            raise Unsupported('Path limit exceeded')
            paths = new
        return paths
    if kind == 'if':
        # Explore the final else before its preceding true alternatives.
        out = []
        for branch, guard in [(node[3], 'NOT ('+node[1]+')'), (node[2], node[1])]:
            for ev, gd, stop in traces(branch, functions, stack, limit):
                out.append((ev, [guard]+gd, stop))
        if len(out) > limit:
            raise Unsupported('Path limit exceeded')
        return out
    ts = node[1]
    if any(t in ts for t in ['?', 'sizeof', '&&', '||']):
        raise Unsupported('Conditional/unevaluated expression needs review')
    if any(ts[i:i+2] == [')', '('] for i in range(len(ts)-1)):
        raise Unsupported('Indirect call needs review')
    found = calls(ts)
    if len(found) > 1:
        raise Unsupported('Multiple calls in one statement have uncertain evaluation order')
    result = [([], [], bool(ts and ts[0] == 'return'))]
    for name, args in found:
        event = {'function': name, 'arguments': args, 'caller': stack[-1] if stack else None}
        if name in functions:
            if name in stack or len(stack) >= 32:
                raise Unsupported('Recursion/depth limit at ' + name)
            result = [([event]+ev, gd, bool(ts and ts[0] == 'return'))
                      for ev, gd, _ in traces(functions[name], functions, stack+(name,), limit)]
        else:
            result = [([event], [], bool(ts and ts[0] == 'return'))]
    return result


def analyze(functions, sequence, entries):
    if not sequence or not entries or any(not re.fullmatch(ID, n) for n in sequence+entries):
        raise ValueError('Sequence and entries must contain C identifiers')
    candidates, unknown = [], []
    for entry in entries:
        if entry not in functions:
            unknown.append(entry + ': entry definition missing')
            continue
        try:
            paths = traces(functions[entry], functions, (entry,))
            for number, (events, guards, _) in enumerate(paths, 1):
                events = [{'function': entry, 'arguments': '', 'caller': None}]+events
                pos = 0
                for event in events:
                    if pos < len(sequence) and event['function'] == sequence[pos]:
                        pos += 1
                candidates.append({'entry': entry, 'priority': number, 'conditions': guards,
                                   'events': events, 'matched_prefix': pos,
                                   'status': 'order_candidate' if pos == len(sequence) else 'partial'})
        except Unsupported as exc:
            unknown.append(entry+': '+str(exc))
    writes = [e for c in candidates for e in c['events'] if e['function'].startswith('Rte_Write_')]
    links = []
    for c in candidates:
        for e in c['events']:
            if e['function'].startswith('Rte_Read_'):
                suffix = e['function'][9:]
                matches = [w for w in writes if w['function'][10:] == suffix]
                links.append({'read': e, 'write_candidates': matches,
                              'basis': 'name suffix only; ARXML mapping and schedule unverified'})
    return {'schema_version': 1, 'sequence': sequence, 'candidates': candidates,
            'unknown': unknown, 'rte_links': links, 'execution_verified': False,
            'ct_2025_review': [
                'Select entry/runnable and preserve manual invocation order.',
                'Review each symbolic guard; assign inputs/globals and RTE stub outputs manually.',
                'Conditions use source names, not SSA: mutations, aliases and side effects are unresolved.',
                'Name-matched RTE writers are data candidates, never runnable call edges.',
                'Review RTE return status, output-pointer values and buffering/scheduler behavior.',
                'Stub external dependencies only; do not stub target functions being measured.',
                'Verify calls, order, values and coverage in CT 2025; no vendor API/export is assumed.'
            ]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', nargs='+', required=True, type=Path)
    ap.add_argument('--plan', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    a = ap.parse_args()
    try:
        functions = {}
        for source in a.source:
            if source.stat().st_size > 2_000_000:
                raise ValueError('Source file exceeds 2 MB limit')
            for name, body in parse(source.read_text(encoding='utf-8')).items():
                if name in functions:
                    raise Unsupported('Ambiguous duplicate function: '+name)
                functions[name] = body
        plan = json.loads(a.plan.read_text(encoding='utf-8'))
        report = analyze(functions, plan['sequence'], plan['entries'])
    except (ValueError, KeyError, OSError, RecursionError) as exc:
        ap.exit(2, 'Analysis stopped: '+str(exc)+'\n')
    if a.output.resolve() in [p.resolve() for p in a.source+[a.plan]]:
        ap.exit(2, 'Output must not overwrite an input\n')
    with a.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    print('Review report:', a.output)


if __name__ == '__main__':
    main()
