import sys, glob, warnings, os
warnings.filterwarnings("ignore")
import pgpy
d = sys.argv[1]
data = open(os.path.join(d, "SHA256SUMS"), "rb").read()
raw = open(os.path.join(d, "SHA256SUMS.asc")).read()
# split concatenated detached signatures
parts = raw.split("-----BEGIN PGP SIGNATURE-----")[1:]
sigs = [pgpy.PGPSignature.from_blob("-----BEGIN PGP SIGNATURE-----" + p.split("-----END PGP SIGNATURE-----")[0] + "-----END PGP SIGNATURE-----") for p in parts]
keys = {}
for f in glob.glob(os.path.join(d, "keys", "*.gpg")):
    try:
        k, _ = pgpy.PGPKey.from_file(f)
        keys[os.path.basename(f)] = k
    except Exception as e:
        pass
good = []
for s in sigs:
    for name, k in keys.items():
        cands = [k] + list(k.subkeys.values())
        for c in cands:
            if c.fingerprint.keyid == s.signer or str(c.fingerprint).endswith(s.signer):
                try:
                    if k.verify(data, s):
                        good.append(name)
                except Exception as e:
                    print("err", name, e)
print(f"signatures: {len(sigs)}, keys loaded: {len(keys)}, good: {len(set(good))}")
print(sorted(set(good)))
