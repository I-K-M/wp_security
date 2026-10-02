import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_scan', ROOT / 'local_scan.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class LocalTests(unittest.TestCase):
    def test_no_follow_no_excerpt_no_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'wp-content/uploads').mkdir(parents=True)
            php = root / 'wp-content/uploads/test.php'
            php.write_text('<?php eval(base64_decode("SECRET_VALUE"));')
            (root / 'link.php').symlink_to(php)
            rows = module.scan_files(root, 10000, [])
            self.assertEqual(len([r for r in rows if r['id'] == 'LOCAL-OBFUSCATION']), 1)
            self.assertNotIn('SECRET_VALUE', str(rows))
            self.assertTrue(any(r['id'] == 'LOCAL-UPLOAD-PHP' for r in rows))
    def test_large_file_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'big.php').write_text('x' * 100)
            self.assertEqual(module.scan_files(root, 10, [])[0]['status'], 'unknown')
    def test_normal_function_is_not_confirmed_malware(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'normal.php').write_text('<?php fopen("cache", "r");')
            self.assertEqual(module.scan_files(root, 1000, []), [])
    def test_checksum_mismatch_and_extra(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'index.php').write_text('modified')
            (root / 'wp-includes').mkdir()
            (root / 'wp-includes/extra.php').write_text('extra')
            rows = module.verify_inventory(root, {'index.php': '0' * 32})
            self.assertEqual({r['id'] for r in rows}, {'INTEGRITY-MISMATCH', 'INTEGRITY-EXTRA'})

if __name__ == '__main__': unittest.main()
