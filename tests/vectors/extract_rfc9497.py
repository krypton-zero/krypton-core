"""Extract the RFC 9497 Appendix A.1.2 (ristretto255-SHA512, VOPRF) test vectors mechanically from the RFC text,
so that no value is mistyped by copying it by hand.

    curl -so rfc9497.txt https://www.rfc-editor.org/rfc/rfc9497.txt   # sha256 95160517…0432
    python3 extract_rfc9497.py rfc9497.txt rfc9497-ristretto255-voprf.json
"""
import re, json, sys
src, dst = sys.argv[1], sys.argv[2]
t = open(src).read()
start = t.index('\nA.1.2.  VOPRF Mode\n')
end = t.index('\nA.1.3.  POPRF Mode\n')
sec = t[start:end]
lines = [l for l in sec.split('\n') if not re.match(r'^(RFC 9497|Davidson, et al\.)', l) and '\x0c' not in l]
fields = []
cur = None
for l in lines:
    m = re.match(r'^   (\w+) = (\S+)$', l)
    if m:
        cur = [m.group(1), m.group(2)]
        fields.append(cur)
        continue
    m2 = re.match(r'^   ([0-9a-f,]+)$', l)
    if m2 and cur:
        cur[1] += m2.group(1)
        continue
    if l.strip() == '' or l.startswith('A.1.2'):
        cur = None
        continue
    raise SystemExit('unknown line: %r' % l)
head = {k: v for k, v in fields[:4]}
assert list(head) == ['Seed', 'KeyInfo', 'skSm', 'pkSm'], head
vecs = []
v = None
for k, val in fields[4:]:
    if k == 'Input':
        v = {}
        vecs.append(v)
    v[k] = val.split(',')
out = {
    "source": "RFC 9497 Appendix A.1.2 (ristretto255-SHA512, VOPRF mode). Extracted by script from https://www.rfc-editor.org/rfc/rfc9497.txt (sha256 95160517617374655fe23af2c6cec311eae326deb7689239f97641fd5a560432)",
    "suite": "ristretto255-SHA512",
    "mode": "VOPRF",
    "seed": head['Seed'],
    "key_info": head['KeyInfo'],
    "sk_sm": head['skSm'],
    "pk_sm": head['pkSm'],
    "vectors": [
        {
            "input": v['Input'],
            "blind": v['Blind'],
            "blinded_element": v['BlindedElement'],
            "evaluation_element": v['EvaluationElement'],
            "proof": v['Proof'][0],
            "proof_random_scalar": v['ProofRandomScalar'][0],
            "output": v['Output'],
        }
        for v in vecs
    ],
}
for v in out['vectors']:
    n = len(v['input'])
    assert all(len(v[k]) == n for k in ['blind', 'blinded_element', 'evaluation_element', 'output'])
    assert len(v['proof']) == 128 and len(v['proof_random_scalar']) == 64
    assert all(len(x) == 64 for x in v['blind'] + v['blinded_element'] + v['evaluation_element'])
    assert all(len(x) == 128 for x in v['output'])
assert len(out['vectors']) == 3
with open(dst, 'w') as f:
    json.dump(out, f, indent=2)
    f.write('\n')
print('ok', [len(v['input']) for v in out['vectors']])
