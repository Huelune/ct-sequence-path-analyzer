import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from analyzer import Unsupported, analyze, parse


class AnalysisTests(unittest.TestCase):
    def report(self, code, seq, entry='Root'):
        return analyze(parse(code), seq, [entry])

    def test_else_if_final_else_first(self):
        r = self.report('void Root(){if(x==1){A();}else if(x==2){B();}else{C();}}', ['C'])
        self.assertEqual(r['candidates'][0]['status'], 'order_candidate')
        self.assertEqual(r['candidates'][0]['conditions'], ['NOT (x == 1)', 'NOT (x == 2)'])

    def test_mutually_exclusive_calls_do_not_form_sequence(self):
        r = self.report('void Root(){if(x){A();}else{B();}}', ['A', 'B'])
        self.assertTrue(all(c['status'] == 'partial' for c in r['candidates']))

    def test_duplicate_target_order(self):
        r = self.report('void Root(){A();A();}', ['A', 'A'])
        self.assertEqual(r['candidates'][0]['matched_prefix'], 2)

    def test_early_return(self):
        r = self.report('void Root(){if(x){return;} A();}', ['A'])
        self.assertEqual([c['matched_prefix'] for c in r['candidates']], [1, 0])

    def test_callee_return_does_not_stop_caller(self):
        r = self.report('void Child(){return;} void Root(){Child();A();}', ['Child', 'A'])
        self.assertEqual(r['candidates'][0]['matched_prefix'], 2)

    def test_rte_is_not_call_edge(self):
        r = self.report('void W(){Rte_Write_X(3);} void Root(){Rte_Read_X(&x);}', ['W'])
        self.assertEqual(r['rte_links'][0]['write_candidates'], [])
        self.assertEqual(r['candidates'][0]['matched_prefix'], 0)

    def test_rte_candidate_from_separate_entry(self):
        r = analyze(parse('void W(){Rte_Write_X(3);} void R(){Rte_Read_X(&x);}'), ['R'], ['W', 'R'])
        self.assertEqual(r['rte_links'][0]['write_candidates'][0]['function'], 'Rte_Write_X')

    def test_recursion_unknown(self):
        r = self.report('void Root(){Root();}', ['Root'])
        self.assertTrue(r['unknown'])
        self.assertEqual(r['candidates'], [])

    def test_unsupported_control_flow(self):
        for code in ['void Root(){while(x){A();}}', '#define A B\nvoid Root(){}',
                     'void Root(){if(Check()){A();}}', 'void Root(){A();']:
            with self.subTest(code=code), self.assertRaises(Unsupported):
                parse(code)

    def test_duplicate_definitions(self):
        with self.assertRaises(Unsupported):
            parse('void A(){} void A(){}')

    def test_nested_and_indirect_calls_unknown(self):
        for body in ['A(B());', '(*fp)();', 'x ? A() : B();']:
            r = self.report('void Root(){'+body+'}', ['A'])
            self.assertTrue(r['unknown'])

    def test_comments_and_strings_not_calls(self):
        r = self.report('void Root(){/* Fake(); */ Log("// Fake()");}', ['Fake'])
        self.assertEqual(r['candidates'][0]['matched_prefix'], 0)

    def test_missing_entry(self):
        self.assertTrue(analyze({}, ['A'], ['Root'])['unknown'])

    def test_path_explosion_bounded(self):
        r = self.report('void Root(){'+ 'if(x){A();}else{B();}'*9+'}', ['A'])
        self.assertIn('Path limit', r['unknown'][0])

    def test_cli_synthetic_and_no_overwrite(self):
        base = Path(__file__).parent
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'report.json'
            command = [sys.executable, str(base/'analyzer.py'), '--source', str(base/'examples/synthetic.c'),
                       '--plan', str(base/'examples/plan.json'), '--output', str(out)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            report = json.loads(out.read_text())
            self.assertEqual(report['candidates'][0]['status'], 'order_candidate')
            self.assertFalse(report['execution_verified'])
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
