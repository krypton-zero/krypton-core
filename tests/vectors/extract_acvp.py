"""Extract from the NIST ACVP (FIPS 203, FIPS 204) test vectors only the parameter sets we use (ML-KEM-768, ML-DSA-65),
so that no value is mistyped by copying it by hand.

Source: usnistgov/ACVP-Server, gen-val/json-files/<directory>/internalProjection.json (master branch):

    ML-KEM-keyGen-FIPS203      sha256 d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b
    ML-KEM-encapDecap-FIPS203  sha256 a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f
    ML-DSA-keyGen-FIPS204      sha256 e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf
    ML-DSA-sigVer-FIPS204      sha256 47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437

    python3 extract_acvp.py kem-keygen.json kem-encdec.json dsa-keygen.json dsa-sigver.json

Output: acvp-ml-kem-768.json and acvp-ml-dsa-65.json (in this directory). To keep the files small, only one parameter set
is kept, and some test categories keep only their first few cases.
"""
import json, os, sys

kem_keygen, kem_encdec, dsa_keygen, dsa_sigver = (json.load(open(p)) for p in sys.argv[1:5])
here = os.path.dirname(os.path.abspath(__file__))


def group(doc, **want):
    for g in doc['testGroups']:
        if all(g.get(k) == v for k, v in want.items()):
            return g['tests']
    raise SystemExit(f'no such test group: {want}')


kem = {
    'source': 'NIST ACVP-Server gen-val/json-files ML-KEM-keyGen-FIPS203, ML-KEM-encapDecap-FIPS203 internalProjection (ML-KEM-768)',
    # Deterministic key generation ML-KEM.KeyGen_internal(d, z) → ek
    'keyGen': [{'tcId': t['tcId'], 'd': t['d'], 'z': t['z'], 'ek': t['ek']}
               for t in group(kem_keygen, parameterSet='ML-KEM-768')],
    # Deterministic encapsulation ML-KEM.Encaps_internal(ek, m) → (k, c)
    'encapsulation': [{'tcId': t['tcId'], 'ek': t['ek'], 'm': t['m'], 'c': t['c'], 'k': t['k']}
                      for t in group(kem_encdec, parameterSet='ML-KEM-768', function='encapsulation')[:10]],
    # Encapsulation key check (FIPS 203 §7.2 modulus check): a key whose testPassed is false must be rejected
    'encapsulationKeyCheck': [{'tcId': t['tcId'], 'ek': t['ek'], 'testPassed': t['testPassed']}
                              for t in group(kem_encdec, parameterSet='ML-KEM-768', function='encapsulationKeyCheck')],
}

dsa = {
    'source': 'NIST ACVP-Server gen-val/json-files ML-DSA-keyGen-FIPS204, ML-DSA-sigVer-FIPS204 internalProjection (ML-DSA-65)',
    # Deterministic key generation ML-DSA.KeyGen_internal(ξ) → pk
    'keyGen': [{'tcId': t['tcId'], 'seed': t['seed'], 'pk': t['pk']}
               for t in group(dsa_keygen, parameterSet='ML-DSA-65')[:10]],
    # Pure ML-DSA (not HashML-DSA), external interface with a context string: ML-DSA.Verify(pk, M, sig, ctx)
    'sigVer': [{'tcId': t['tcId'], 'pk': t['pk'], 'message': t['message'], 'context': t['context'],
                'signature': t['signature'], 'testPassed': t['testPassed']}
               for t in group(dsa_sigver, parameterSet='ML-DSA-65', signatureInterface='external', preHash='pure')],
}

for name, doc in (('acvp-ml-kem-768.json', kem), ('acvp-ml-dsa-65.json', dsa)):
    with open(os.path.join(here, name), 'w') as f:
        json.dump(doc, f, indent=1)
        f.write('\n')
    print(name, os.path.getsize(os.path.join(here, name)))
