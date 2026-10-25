# Initial analysis

## 1. Experiment information

- Run: 20260922T084234Z_e864a464e30f
- WAF: naxsi
- Source: `Week_07/results/final/naxsi-week6-reviewed.csv`
- Source SHA-256: 85be649913e2741940382d5d0e058f382a9ba5137b9db86db814ab000ad06902
- Test-set SHA-256: 78123abfcb920965749a0877a3d1f6e28126e339b6ae66acf589eec5dc1a10d7
- Collection timestamps: 2026-09-22T08:42:35.125661+00:00 to 2026-09-22T08:45:58.207847+00:00
- Report generated: 2026-09-22T10:55:57.932062+00:00

## 2. Number of tests

Rows: 1684; HTTP responses: 1684; errors: 0; skipped: 0.
Unclassified rows: 0. Skipped rows are not executed trials.

## 3. Normal traffic

Rows: 120; TN: 108; FP: 12.
False-positive rate: 0.1.
Normal allow rate: 0.9.

## 4. Malicious traffic

Rows: 1564; TP: 1310; FN: 254.
Detection rate: 0.8375959079283888.
False-negative rate: 0.16240409207161124.

## 5. Overall confusion matrix

| Expected | BLOCKED | ALLOWED |
|---|---:|---:|
| MALICIOUS | 1310 | 254 |
| NORMAL | 12 | 108 |

UNKNOWN (0) is excluded from matrix rates, not converted to FN/TN.

## 6. Per-category detection

| Category | HTTP responses | Blocked | Allowed | Unknown responses | Errors | Skipped | Detection rate |
|---|---:|---:|---:|---:|---:|---:|---|
| command_injection | 120 | 120 | 0 | 0 | 0 | 0 | 1.0 |
| path_traversal | 120 | 78 | 42 | 0 | 0 | 0 | 0.65 |
| sqli | 724 | 632 | 92 | 0 | 0 | 0 | 0.8729281767955801 |
| xss | 600 | 480 | 120 | 0 | 0 | 0 | 0.8 |

## 7. Missed detections

| Test ID | Parent | Category | Transformation | Evidence |
|---|---|---|---|---|
| XSS_0022_DOUBLEENC | XSS_0022 | xss | doubleenc | naxsi-access.log:rid=27f860911db5416280600f7e7aa1b19f;apache-backend.log:rid=27f860911db5416280600f7e7aa1b19f;response=XSS_0022_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0015 |  | path_traversal |  | naxsi-access.log:rid=af1dbd87dfcc46f48c34ac8ff63936dc;apache-backend.log:rid=af1dbd87dfcc46f48c34ac8ff63936dc;response=PATH_TRAVERSAL_0015.response.bin |
| SQLI_0090_DOUBLEENC | SQLI_0090 | sqli | doubleenc | naxsi-access.log:rid=4d6bc28b1e314b4d83c4fcd29a468855;apache-backend.log:rid=4d6bc28b1e314b4d83c4fcd29a468855;response=SQLI_0090_DOUBLEENC.response.bin |
| XSS_0040_DOUBLEENC | XSS_0040 | xss | doubleenc | naxsi-access.log:rid=f325385a57994918abd83c6e1a7628a7;apache-backend.log:rid=f325385a57994918abd83c6e1a7628a7;response=XSS_0040_DOUBLEENC.response.bin |
| XSS_0034_DOUBLEENC | XSS_0034 | xss | doubleenc | naxsi-access.log:rid=aebb2d6f0e8d4167867b814228870f5b;apache-backend.log:rid=aebb2d6f0e8d4167867b814228870f5b;response=XSS_0034_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0039 |  | path_traversal |  | naxsi-access.log:rid=ae982f9759ea4d17bddc43e14020b688;apache-backend.log:rid=ae982f9759ea4d17bddc43e14020b688;response=PATH_TRAVERSAL_0039.response.bin |
| XSS_0119_DOUBLEENC | XSS_0119 | xss | doubleenc | naxsi-access.log:rid=baf9ce63d3f0433ebdb2c54f9f1a9db3;apache-backend.log:rid=baf9ce63d3f0433ebdb2c54f9f1a9db3;response=XSS_0119_DOUBLEENC.response.bin |
| XSS_0007_DOUBLEENC | XSS_0007 | xss | doubleenc | naxsi-access.log:rid=e89f0427d5764dfcbdeaeca2bdf42060;apache-backend.log:rid=e89f0427d5764dfcbdeaeca2bdf42060;response=XSS_0007_DOUBLEENC.response.bin |
| XSS_0067_DOUBLEENC | XSS_0067 | xss | doubleenc | naxsi-access.log:rid=1cb8857b38dc489bb9b18a7e4c738ccf;apache-backend.log:rid=1cb8857b38dc489bb9b18a7e4c738ccf;response=XSS_0067_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0111 |  | path_traversal |  | naxsi-access.log:rid=7dd517cda987440581e8ca32a87ed9f4;apache-backend.log:rid=7dd517cda987440581e8ca32a87ed9f4;response=PATH_TRAVERSAL_0111.response.bin |
| SQLI_0021_DOUBLEENC | SQLI_0021 | sqli | doubleenc | naxsi-access.log:rid=1c577958e7f44e18891c014934fe0561;apache-backend.log:rid=1c577958e7f44e18891c014934fe0561;response=SQLI_0021_DOUBLEENC.response.bin |
| XSS_0103_DOUBLEENC | XSS_0103 | xss | doubleenc | naxsi-access.log:rid=21b563977e7b437f87af4c826579b0dc;apache-backend.log:rid=21b563977e7b437f87af4c826579b0dc;response=XSS_0103_DOUBLEENC.response.bin |
| XSS_0032_DOUBLEENC | XSS_0032 | xss | doubleenc | naxsi-access.log:rid=e8ee78230526453997ef7589d4614039;apache-backend.log:rid=e8ee78230526453997ef7589d4614039;response=XSS_0032_DOUBLEENC.response.bin |
| XSS_0043_DOUBLEENC | XSS_0043 | xss | doubleenc | naxsi-access.log:rid=c1f8d3c95c2d49f28072ae5936e3c05a;apache-backend.log:rid=c1f8d3c95c2d49f28072ae5936e3c05a;response=XSS_0043_DOUBLEENC.response.bin |
| XSS_0011_DOUBLEENC | XSS_0011 | xss | doubleenc | naxsi-access.log:rid=9e48939008364a7f8552268af611421f;apache-backend.log:rid=9e48939008364a7f8552268af611421f;response=XSS_0011_DOUBLEENC.response.bin |
| SQLI_0039_DOUBLEENC | SQLI_0039 | sqli | doubleenc | naxsi-access.log:rid=984e4d6070334599857fdbdd41248602;apache-backend.log:rid=984e4d6070334599857fdbdd41248602;response=SQLI_0039_DOUBLEENC.response.bin |
| XSS_0052_DOUBLEENC | XSS_0052 | xss | doubleenc | naxsi-access.log:rid=2ba1ff9a64fb4ea289a224abbf060b13;apache-backend.log:rid=2ba1ff9a64fb4ea289a224abbf060b13;response=XSS_0052_DOUBLEENC.response.bin |
| SQLI_0046_DOUBLEENC | SQLI_0046 | sqli | doubleenc | naxsi-access.log:rid=edbb3718c877411a9d153d1f9d0676a5;apache-backend.log:rid=edbb3718c877411a9d153d1f9d0676a5;response=SQLI_0046_DOUBLEENC.response.bin |
| XSS_0108_DOUBLEENC | XSS_0108 | xss | doubleenc | naxsi-access.log:rid=e87d5ed788f347b6936abc27897d790d;apache-backend.log:rid=e87d5ed788f347b6936abc27897d790d;response=XSS_0108_DOUBLEENC.response.bin |
| SQLI_0072_DOUBLEENC | SQLI_0072 | sqli | doubleenc | naxsi-access.log:rid=54c6ebd40a0246a9a7af15d55baeb4bd;apache-backend.log:rid=54c6ebd40a0246a9a7af15d55baeb4bd;response=SQLI_0072_DOUBLEENC.response.bin |
| XSS_0091_DOUBLEENC | XSS_0091 | xss | doubleenc | naxsi-access.log:rid=e2892aaa04ba4a54bd4f6c2b7a2f6a33;apache-backend.log:rid=e2892aaa04ba4a54bd4f6c2b7a2f6a33;response=XSS_0091_DOUBLEENC.response.bin |
| SQLI_0017_DOUBLEENC | SQLI_0017 | sqli | doubleenc | naxsi-access.log:rid=723a739da1b44114bdd706793cf76564;apache-backend.log:rid=723a739da1b44114bdd706793cf76564;response=SQLI_0017_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0106 |  | path_traversal |  | naxsi-access.log:rid=5361b1ec117c424b9c1469a1c3db3b0e;apache-backend.log:rid=5361b1ec117c424b9c1469a1c3db3b0e;response=PATH_TRAVERSAL_0106.response.bin |
| XSS_0047_DOUBLEENC | XSS_0047 | xss | doubleenc | naxsi-access.log:rid=b0f11fc8cefb4d05b5729035815645c9;apache-backend.log:rid=b0f11fc8cefb4d05b5729035815645c9;response=XSS_0047_DOUBLEENC.response.bin |
| XSS_0001_DOUBLEENC | XSS_0001 | xss | doubleenc | naxsi-access.log:rid=31cc168b320240cf9c21750b6bedd830;apache-backend.log:rid=31cc168b320240cf9c21750b6bedd830;response=XSS_0001_DOUBLEENC.response.bin |
| SQLI_0031_DOUBLEENC | SQLI_0031 | sqli | doubleenc | naxsi-access.log:rid=807692845a4a4f568d96e4d57c768e60;apache-backend.log:rid=807692845a4a4f568d96e4d57c768e60;response=SQLI_0031_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0089 |  | path_traversal |  | naxsi-access.log:rid=32a8e8f569ab412b9124c5406fadd609;apache-backend.log:rid=32a8e8f569ab412b9124c5406fadd609;response=PATH_TRAVERSAL_0089.response.bin |
| PATH_TRAVERSAL_0043 |  | path_traversal |  | naxsi-access.log:rid=28853b4e59494423b29d608a3b66f871;apache-backend.log:rid=28853b4e59494423b29d608a3b66f871;response=PATH_TRAVERSAL_0043.response.bin |
| XSS_0015_DOUBLEENC | XSS_0015 | xss | doubleenc | naxsi-access.log:rid=badb21c3edf5444ba737cabb78f9feaf;apache-backend.log:rid=badb21c3edf5444ba737cabb78f9feaf;response=XSS_0015_DOUBLEENC.response.bin |
| XSS_0021_DOUBLEENC | XSS_0021 | xss | doubleenc | naxsi-access.log:rid=f1cd42232c9148cda08c47a4b192282b;apache-backend.log:rid=f1cd42232c9148cda08c47a4b192282b;response=XSS_0021_DOUBLEENC.response.bin |
| SQLI_0010_DOUBLEENC | SQLI_0010 | sqli | doubleenc | naxsi-access.log:rid=9a3bb85b3d3840558308847d6f9b2127;apache-backend.log:rid=9a3bb85b3d3840558308847d6f9b2127;response=SQLI_0010_DOUBLEENC.response.bin |
| SQLI_0003_DOUBLEENC | SQLI_0003 | sqli | doubleenc | naxsi-access.log:rid=ad665110984d4b0eb04fdc1fb52bd389;apache-backend.log:rid=ad665110984d4b0eb04fdc1fb52bd389;response=SQLI_0003_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0037 |  | path_traversal |  | naxsi-access.log:rid=91da9db0e7da4f7bb71eea1d26055526;apache-backend.log:rid=91da9db0e7da4f7bb71eea1d26055526;response=PATH_TRAVERSAL_0037.response.bin |
| XSS_0086_DOUBLEENC | XSS_0086 | xss | doubleenc | naxsi-access.log:rid=5d883bfc062e46a3927f5e7663a21995;apache-backend.log:rid=5d883bfc062e46a3927f5e7663a21995;response=XSS_0086_DOUBLEENC.response.bin |
| XSS_0058_DOUBLEENC | XSS_0058 | xss | doubleenc | naxsi-access.log:rid=7362debb105b47608cf8c17b125e7a99;apache-backend.log:rid=7362debb105b47608cf8c17b125e7a99;response=XSS_0058_DOUBLEENC.response.bin |
| XSS_0077_DOUBLEENC | XSS_0077 | xss | doubleenc | naxsi-access.log:rid=db36e066c6d446f79ed8ac78e8f03cd2;apache-backend.log:rid=db36e066c6d446f79ed8ac78e8f03cd2;response=XSS_0077_DOUBLEENC.response.bin |
| XSS_0076_DOUBLEENC | XSS_0076 | xss | doubleenc | naxsi-access.log:rid=95d4267768d1402d97563f1da48db082;apache-backend.log:rid=95d4267768d1402d97563f1da48db082;response=XSS_0076_DOUBLEENC.response.bin |
| XSS_0113_DOUBLEENC | XSS_0113 | xss | doubleenc | naxsi-access.log:rid=2815499d23164ad9a34cb04d51b3bc49;apache-backend.log:rid=2815499d23164ad9a34cb04d51b3bc49;response=XSS_0113_DOUBLEENC.response.bin |
| SQLI_0043_DOUBLEENC | SQLI_0043 | sqli | doubleenc | naxsi-access.log:rid=161c430d768645afb7d83d2f473adf72;apache-backend.log:rid=161c430d768645afb7d83d2f473adf72;response=SQLI_0043_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0047 |  | path_traversal |  | naxsi-access.log:rid=90b51aa5c224453d8a1cc1d70c69202e;apache-backend.log:rid=90b51aa5c224453d8a1cc1d70c69202e;response=PATH_TRAVERSAL_0047.response.bin |
| PATH_TRAVERSAL_0009 |  | path_traversal |  | naxsi-access.log:rid=40bfecc02bd04ebfbf688eaabb366b7c;apache-backend.log:rid=40bfecc02bd04ebfbf688eaabb366b7c;response=PATH_TRAVERSAL_0009.response.bin |
| XSS_0018_DOUBLEENC | XSS_0018 | xss | doubleenc | naxsi-access.log:rid=364c79f4c6e648c7b4389d8eac5d213a;apache-backend.log:rid=364c79f4c6e648c7b4389d8eac5d213a;response=XSS_0018_DOUBLEENC.response.bin |
| XSS_0053_DOUBLEENC | XSS_0053 | xss | doubleenc | naxsi-access.log:rid=7ad2094f882d4a6a98c06ee4aed684d3;apache-backend.log:rid=7ad2094f882d4a6a98c06ee4aed684d3;response=XSS_0053_DOUBLEENC.response.bin |
| SQLI_0053_DOUBLEENC | SQLI_0053 | sqli | doubleenc | naxsi-access.log:rid=ed6196759a804abbaddc5a26ff10a3cd;apache-backend.log:rid=ed6196759a804abbaddc5a26ff10a3cd;response=SQLI_0053_DOUBLEENC.response.bin |
| XSS_0031_DOUBLEENC | XSS_0031 | xss | doubleenc | naxsi-access.log:rid=ee0526fcbcd449c287da2ca5865baf8f;apache-backend.log:rid=ee0526fcbcd449c287da2ca5865baf8f;response=XSS_0031_DOUBLEENC.response.bin |
| SQLI_0016_DOUBLEENC | SQLI_0016 | sqli | doubleenc | naxsi-access.log:rid=5f90e08905dc45fea82dbdc723d13df4;apache-backend.log:rid=5f90e08905dc45fea82dbdc723d13df4;response=SQLI_0016_DOUBLEENC.response.bin |
| SQLI_0093_DOUBLEENC | SQLI_0093 | sqli | doubleenc | naxsi-access.log:rid=65cd66b746ab4541a14ed1b022111459;apache-backend.log:rid=65cd66b746ab4541a14ed1b022111459;response=SQLI_0093_DOUBLEENC.response.bin |
| SQLI_0015_DOUBLEENC | SQLI_0015 | sqli | doubleenc | naxsi-access.log:rid=c5c9cbd0b3d94f638cc90a3e526dfdd9;apache-backend.log:rid=c5c9cbd0b3d94f638cc90a3e526dfdd9;response=SQLI_0015_DOUBLEENC.response.bin |
| XSS_0056_DOUBLEENC | XSS_0056 | xss | doubleenc | naxsi-access.log:rid=d5418dcca7bb4f29a2b22631c3f7e94d;apache-backend.log:rid=d5418dcca7bb4f29a2b22631c3f7e94d;response=XSS_0056_DOUBLEENC.response.bin |
| SQLI_0077_DOUBLEENC | SQLI_0077 | sqli | doubleenc | naxsi-access.log:rid=35f31768b20847c39ee25014a0bc4529;apache-backend.log:rid=35f31768b20847c39ee25014a0bc4529;response=SQLI_0077_DOUBLEENC.response.bin |
| XSS_0012_DOUBLEENC | XSS_0012 | xss | doubleenc | naxsi-access.log:rid=66337d6ab85c40e89c330dd2c98b65ff;apache-backend.log:rid=66337d6ab85c40e89c330dd2c98b65ff;response=XSS_0012_DOUBLEENC.response.bin |
| SQLI_0069_DOUBLEENC | SQLI_0069 | sqli | doubleenc | naxsi-access.log:rid=cc67b4f67dfa408492f72667cd128876;apache-backend.log:rid=cc67b4f67dfa408492f72667cd128876;response=SQLI_0069_DOUBLEENC.response.bin |
| XSS_0070_DOUBLEENC | XSS_0070 | xss | doubleenc | naxsi-access.log:rid=4209231e036940e2962d1d8b56245d21;apache-backend.log:rid=4209231e036940e2962d1d8b56245d21;response=XSS_0070_DOUBLEENC.response.bin |
| XSS_0010_DOUBLEENC | XSS_0010 | xss | doubleenc | naxsi-access.log:rid=afbbf287dfca41d08eeaa4aa143fc24b;apache-backend.log:rid=afbbf287dfca41d08eeaa4aa143fc24b;response=XSS_0010_DOUBLEENC.response.bin |
| SQLI_0065_DOUBLEENC | SQLI_0065 | sqli | doubleenc | naxsi-access.log:rid=df1354479e034eeda304fb5462e9010e;apache-backend.log:rid=df1354479e034eeda304fb5462e9010e;response=SQLI_0065_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0065 |  | path_traversal |  | naxsi-access.log:rid=460294d86f7f4d159bff185c7b5826c9;apache-backend.log:rid=460294d86f7f4d159bff185c7b5826c9;response=PATH_TRAVERSAL_0065.response.bin |
| XSS_0085_DOUBLEENC | XSS_0085 | xss | doubleenc | naxsi-access.log:rid=71693f1846784baf9545bf515a72874a;apache-backend.log:rid=71693f1846784baf9545bf515a72874a;response=XSS_0085_DOUBLEENC.response.bin |
| XSS_0049_DOUBLEENC | XSS_0049 | xss | doubleenc | naxsi-access.log:rid=eb96c7e664d04658a79f70e4d9de9459;apache-backend.log:rid=eb96c7e664d04658a79f70e4d9de9459;response=XSS_0049_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0114 |  | path_traversal |  | naxsi-access.log:rid=c5439d90a6fd4131a954bb5f3d2f94d4;apache-backend.log:rid=c5439d90a6fd4131a954bb5f3d2f94d4;response=PATH_TRAVERSAL_0114.response.bin |
| PATH_TRAVERSAL_0025 |  | path_traversal |  | naxsi-access.log:rid=78d05bcfc88b48bf961e6fe3b0fe84eb;apache-backend.log:rid=78d05bcfc88b48bf961e6fe3b0fe84eb;response=PATH_TRAVERSAL_0025.response.bin |
| SQLI_0006_DOUBLEENC | SQLI_0006 | sqli | doubleenc | naxsi-access.log:rid=63cc89f28f53475f80699ee34ff4d2c8;apache-backend.log:rid=63cc89f28f53475f80699ee34ff4d2c8;response=SQLI_0006_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0078 |  | path_traversal |  | naxsi-access.log:rid=6b5b4c9295494c1d9b6941070b0f6a2f;apache-backend.log:rid=6b5b4c9295494c1d9b6941070b0f6a2f;response=PATH_TRAVERSAL_0078.response.bin |
| PATH_TRAVERSAL_0059 |  | path_traversal |  | naxsi-access.log:rid=efe66040f2834d458ffcfb30d393cb18;apache-backend.log:rid=efe66040f2834d458ffcfb30d393cb18;response=PATH_TRAVERSAL_0059.response.bin |
| SQLI_0011_DOUBLEENC | SQLI_0011 | sqli | doubleenc | naxsi-access.log:rid=2a1d0c3eb31942a7848dfdbf9b1430e1;apache-backend.log:rid=2a1d0c3eb31942a7848dfdbf9b1430e1;response=SQLI_0011_DOUBLEENC.response.bin |
| XSS_0092_DOUBLEENC | XSS_0092 | xss | doubleenc | naxsi-access.log:rid=3f6e13f0f73a4429a2554ad1f3aa2bba;apache-backend.log:rid=3f6e13f0f73a4429a2554ad1f3aa2bba;response=XSS_0092_DOUBLEENC.response.bin |
| XSS_0112_DOUBLEENC | XSS_0112 | xss | doubleenc | naxsi-access.log:rid=3e50eb251e3841a6b8b6ab9aa49ff99c;apache-backend.log:rid=3e50eb251e3841a6b8b6ab9aa49ff99c;response=XSS_0112_DOUBLEENC.response.bin |
| XSS_0105_DOUBLEENC | XSS_0105 | xss | doubleenc | naxsi-access.log:rid=403bb6f7e8a44a4581cbfa113305be19;apache-backend.log:rid=403bb6f7e8a44a4581cbfa113305be19;response=XSS_0105_DOUBLEENC.response.bin |
| XSS_0097_DOUBLEENC | XSS_0097 | xss | doubleenc | naxsi-access.log:rid=fc6dab9739184e3aaef6730f448fb704;apache-backend.log:rid=fc6dab9739184e3aaef6730f448fb704;response=XSS_0097_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0107 |  | path_traversal |  | naxsi-access.log:rid=a69ee9bde2d94ab09f2ca55a32c03ba4;apache-backend.log:rid=a69ee9bde2d94ab09f2ca55a32c03ba4;response=PATH_TRAVERSAL_0107.response.bin |
| XSS_0028_DOUBLEENC | XSS_0028 | xss | doubleenc | naxsi-access.log:rid=b8ab6036bd1d4bb4ad414294d0dee7e0;apache-backend.log:rid=b8ab6036bd1d4bb4ad414294d0dee7e0;response=XSS_0028_DOUBLEENC.response.bin |
| XSS_0089_DOUBLEENC | XSS_0089 | xss | doubleenc | naxsi-access.log:rid=ba021994c80a4e57adc5097702a8c18f;apache-backend.log:rid=ba021994c80a4e57adc5097702a8c18f;response=XSS_0089_DOUBLEENC.response.bin |
| SQLI_0114_DOUBLEENC | SQLI_0114 | sqli | doubleenc | naxsi-access.log:rid=d7dbe9b61bac43fe9711c01891922b8f;apache-backend.log:rid=d7dbe9b61bac43fe9711c01891922b8f;response=SQLI_0114_DOUBLEENC.response.bin |
| SQLI_0060_DOUBLEENC | SQLI_0060 | sqli | doubleenc | naxsi-access.log:rid=a97a1bec59184963a78cac8232831a53;apache-backend.log:rid=a97a1bec59184963a78cac8232831a53;response=SQLI_0060_DOUBLEENC.response.bin |
| SQLI_0089_DOUBLEENC | SQLI_0089 | sqli | doubleenc | naxsi-access.log:rid=2f66e99f281b4868951834f9ca416d44;apache-backend.log:rid=2f66e99f281b4868951834f9ca416d44;response=SQLI_0089_DOUBLEENC.response.bin |
| XSS_0078_DOUBLEENC | XSS_0078 | xss | doubleenc | naxsi-access.log:rid=68e06ce4289c4284a5023b6056ade215;apache-backend.log:rid=68e06ce4289c4284a5023b6056ade215;response=XSS_0078_DOUBLEENC.response.bin |
| SQLI_0107_DOUBLEENC | SQLI_0107 | sqli | doubleenc | naxsi-access.log:rid=b3cbc77c54b94fa6ac7fbd4a435b335a;apache-backend.log:rid=b3cbc77c54b94fa6ac7fbd4a435b335a;response=SQLI_0107_DOUBLEENC.response.bin |
| SQLI_0004_DOUBLEENC | SQLI_0004 | sqli | doubleenc | naxsi-access.log:rid=2aaefd6595f14c6397613a9caaad04f5;apache-backend.log:rid=2aaefd6595f14c6397613a9caaad04f5;response=SQLI_0004_DOUBLEENC.response.bin |
| XSS_0006_DOUBLEENC | XSS_0006 | xss | doubleenc | naxsi-access.log:rid=9a3b9e966d4444c3b20587e445492afc;apache-backend.log:rid=9a3b9e966d4444c3b20587e445492afc;response=XSS_0006_DOUBLEENC.response.bin |
| XSS_0020_DOUBLEENC | XSS_0020 | xss | doubleenc | naxsi-access.log:rid=75e630cb7cc54f20b27951b1ed1f0a84;apache-backend.log:rid=75e630cb7cc54f20b27951b1ed1f0a84;response=XSS_0020_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0077 |  | path_traversal |  | naxsi-access.log:rid=19fddb9688e94449b6780d25b18351d7;apache-backend.log:rid=19fddb9688e94449b6780d25b18351d7;response=PATH_TRAVERSAL_0077.response.bin |
| PATH_TRAVERSAL_0019 |  | path_traversal |  | naxsi-access.log:rid=1b14d4eebfdd4c6b8d1a5ab3a6a1cc27;apache-backend.log:rid=1b14d4eebfdd4c6b8d1a5ab3a6a1cc27;response=PATH_TRAVERSAL_0019.response.bin |
| XSS_0064_DOUBLEENC | XSS_0064 | xss | doubleenc | naxsi-access.log:rid=adc997f367e24287a1febac9104a42a4;apache-backend.log:rid=adc997f367e24287a1febac9104a42a4;response=XSS_0064_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0016 |  | path_traversal |  | naxsi-access.log:rid=2a0713793b58445ab645d1aa8069013f;apache-backend.log:rid=2a0713793b58445ab645d1aa8069013f;response=PATH_TRAVERSAL_0016.response.bin |
| XSS_0060_DOUBLEENC | XSS_0060 | xss | doubleenc | naxsi-access.log:rid=5508361a5e9d4c2cb526b0d9249adcfb;apache-backend.log:rid=5508361a5e9d4c2cb526b0d9249adcfb;response=XSS_0060_DOUBLEENC.response.bin |
| XSS_0014_DOUBLEENC | XSS_0014 | xss | doubleenc | naxsi-access.log:rid=d0e4bb12a5d54cad8b97c7262c6e3c5a;apache-backend.log:rid=d0e4bb12a5d54cad8b97c7262c6e3c5a;response=XSS_0014_DOUBLEENC.response.bin |
| XSS_0026_DOUBLEENC | XSS_0026 | xss | doubleenc | naxsi-access.log:rid=a279dde3128a45a8979448a0c616dab0;apache-backend.log:rid=a279dde3128a45a8979448a0c616dab0;response=XSS_0026_DOUBLEENC.response.bin |
| SQLI_0007_DOUBLEENC | SQLI_0007 | sqli | doubleenc | naxsi-access.log:rid=7a17953eb2b646b68141133608d41ec0;apache-backend.log:rid=7a17953eb2b646b68141133608d41ec0;response=SQLI_0007_DOUBLEENC.response.bin |
| SQLI_0085_DOUBLEENC | SQLI_0085 | sqli | doubleenc | naxsi-access.log:rid=9de3a42431ad44d894fbf4f2b9d71f98;apache-backend.log:rid=9de3a42431ad44d894fbf4f2b9d71f98;response=SQLI_0085_DOUBLEENC.response.bin |
| XSS_0055_DOUBLEENC | XSS_0055 | xss | doubleenc | naxsi-access.log:rid=3fe5eeee920343b0aaf34cc0906a8929;apache-backend.log:rid=3fe5eeee920343b0aaf34cc0906a8929;response=XSS_0055_DOUBLEENC.response.bin |
| SQLI_0108_DOUBLEENC | SQLI_0108 | sqli | doubleenc | naxsi-access.log:rid=f362e4a04d644d2a896a752d25ff96aa;apache-backend.log:rid=f362e4a04d644d2a896a752d25ff96aa;response=SQLI_0108_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0120 |  | path_traversal |  | naxsi-access.log:rid=df35d136479c4723aaf13e6f079d0231;apache-backend.log:rid=df35d136479c4723aaf13e6f079d0231;response=PATH_TRAVERSAL_0120.response.bin |
| XSS_0048_DOUBLEENC | XSS_0048 | xss | doubleenc | naxsi-access.log:rid=f7caf31fa5574647bcb21e0b106c181f;apache-backend.log:rid=f7caf31fa5574647bcb21e0b106c181f;response=XSS_0048_DOUBLEENC.response.bin |
| SQLI_0104_DOUBLEENC | SQLI_0104 | sqli | doubleenc | naxsi-access.log:rid=a82216d6293b4d20b43f872f7b163172;apache-backend.log:rid=a82216d6293b4d20b43f872f7b163172;response=SQLI_0104_DOUBLEENC.response.bin |
| SQLI_0092_DOUBLEENC | SQLI_0092 | sqli | doubleenc | naxsi-access.log:rid=90f4917b1a164222960598b1db642682;apache-backend.log:rid=90f4917b1a164222960598b1db642682;response=SQLI_0092_DOUBLEENC.response.bin |
| SQLI_0068_DOUBLEENC | SQLI_0068 | sqli | doubleenc | naxsi-access.log:rid=0266a31f906c43ec9bd987d4051df75e;apache-backend.log:rid=0266a31f906c43ec9bd987d4051df75e;response=SQLI_0068_DOUBLEENC.response.bin |
| SQLI_0044_DOUBLEENC | SQLI_0044 | sqli | doubleenc | naxsi-access.log:rid=e5a35b1fb8ec409c928aaaac2e71c32e;apache-backend.log:rid=e5a35b1fb8ec409c928aaaac2e71c32e;response=SQLI_0044_DOUBLEENC.response.bin |
| SQLI_0008_DOUBLEENC | SQLI_0008 | sqli | doubleenc | naxsi-access.log:rid=38d60f68556a4cb78b9b49acf18c972c;apache-backend.log:rid=38d60f68556a4cb78b9b49acf18c972c;response=SQLI_0008_DOUBLEENC.response.bin |
| SQLI_0061_DOUBLEENC | SQLI_0061 | sqli | doubleenc | naxsi-access.log:rid=870c6b85b1cb47e4a5bf3bf7ef2c2349;apache-backend.log:rid=870c6b85b1cb47e4a5bf3bf7ef2c2349;response=SQLI_0061_DOUBLEENC.response.bin |
| XSS_0068_DOUBLEENC | XSS_0068 | xss | doubleenc | naxsi-access.log:rid=e22991c9e1bb4321a2b047fdfbf5243d;apache-backend.log:rid=e22991c9e1bb4321a2b047fdfbf5243d;response=XSS_0068_DOUBLEENC.response.bin |
| XSS_0071_DOUBLEENC | XSS_0071 | xss | doubleenc | naxsi-access.log:rid=3518d65202154206a89dac5193777f39;apache-backend.log:rid=3518d65202154206a89dac5193777f39;response=XSS_0071_DOUBLEENC.response.bin |
| XSS_0080_DOUBLEENC | XSS_0080 | xss | doubleenc | naxsi-access.log:rid=38462e03e1bb4cc3bff8f67399c4b9ed;apache-backend.log:rid=38462e03e1bb4cc3bff8f67399c4b9ed;response=XSS_0080_DOUBLEENC.response.bin |
| XSS_0072_DOUBLEENC | XSS_0072 | xss | doubleenc | naxsi-access.log:rid=1858a8f05d6e44e19ab058084f41e792;apache-backend.log:rid=1858a8f05d6e44e19ab058084f41e792;response=XSS_0072_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0046 |  | path_traversal |  | naxsi-access.log:rid=2c6c69ba5a86473c834df099c9afa488;apache-backend.log:rid=2c6c69ba5a86473c834df099c9afa488;response=PATH_TRAVERSAL_0046.response.bin |
| SQLI_0014_DOUBLEENC | SQLI_0014 | sqli | doubleenc | naxsi-access.log:rid=e7d3a7998f334da682d8ea192ac9dffd;apache-backend.log:rid=e7d3a7998f334da682d8ea192ac9dffd;response=SQLI_0014_DOUBLEENC.response.bin |
| XSS_0088_DOUBLEENC | XSS_0088 | xss | doubleenc | naxsi-access.log:rid=23881844073f4e0cabe92d09c5c70557;apache-backend.log:rid=23881844073f4e0cabe92d09c5c70557;response=XSS_0088_DOUBLEENC.response.bin |
| SQLI_0115_DOUBLEENC | SQLI_0115 | sqli | doubleenc | naxsi-access.log:rid=197c645f79674ebabbc45cddf4c5b1ef;apache-backend.log:rid=197c645f79674ebabbc45cddf4c5b1ef;response=SQLI_0115_DOUBLEENC.response.bin |
| XSS_0003_DOUBLEENC | XSS_0003 | xss | doubleenc | naxsi-access.log:rid=745707d912514b058a1080d4d0aa5e16;apache-backend.log:rid=745707d912514b058a1080d4d0aa5e16;response=XSS_0003_DOUBLEENC.response.bin |
| XSS_0063_DOUBLEENC | XSS_0063 | xss | doubleenc | naxsi-access.log:rid=afeaffb38ddd46078b50381e92dbfaa1;apache-backend.log:rid=afeaffb38ddd46078b50381e92dbfaa1;response=XSS_0063_DOUBLEENC.response.bin |
| SQLI_0096_DOUBLEENC | SQLI_0096 | sqli | doubleenc | naxsi-access.log:rid=2332e94759374934b4fab802752f0991;apache-backend.log:rid=2332e94759374934b4fab802752f0991;response=SQLI_0096_DOUBLEENC.response.bin |
| XSS_0087_DOUBLEENC | XSS_0087 | xss | doubleenc | naxsi-access.log:rid=8e99bc0de13d41c6b68647e1feb3ca10;apache-backend.log:rid=8e99bc0de13d41c6b68647e1feb3ca10;response=XSS_0087_DOUBLEENC.response.bin |
| XSS_0017_DOUBLEENC | XSS_0017 | xss | doubleenc | naxsi-access.log:rid=0bea376546144cff961586fb6f494c80;apache-backend.log:rid=0bea376546144cff961586fb6f494c80;response=XSS_0017_DOUBLEENC.response.bin |
| SQLI_0047_DOUBLEENC | SQLI_0047 | sqli | doubleenc | naxsi-access.log:rid=9afc02c43caa4a2f8d9ef4b4a0681d25;apache-backend.log:rid=9afc02c43caa4a2f8d9ef4b4a0681d25;response=SQLI_0047_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0036 |  | path_traversal |  | naxsi-access.log:rid=0c46277e4b584edda4d1ce65a41d350e;apache-backend.log:rid=0c46277e4b584edda4d1ce65a41d350e;response=PATH_TRAVERSAL_0036.response.bin |
| XSS_0027_DOUBLEENC | XSS_0027 | xss | doubleenc | naxsi-access.log:rid=ba15cea1b5764353b0be4444020388ae;apache-backend.log:rid=ba15cea1b5764353b0be4444020388ae;response=XSS_0027_DOUBLEENC.response.bin |
| SQLI_0091_DOUBLEENC | SQLI_0091 | sqli | doubleenc | naxsi-access.log:rid=754027a7997a4228a7e3a1493fef963e;apache-backend.log:rid=754027a7997a4228a7e3a1493fef963e;response=SQLI_0091_DOUBLEENC.response.bin |
| XSS_0111_DOUBLEENC | XSS_0111 | xss | doubleenc | naxsi-access.log:rid=92b9ad48e9854659a3f9aeb5880f95d7;apache-backend.log:rid=92b9ad48e9854659a3f9aeb5880f95d7;response=XSS_0111_DOUBLEENC.response.bin |
| XSS_0073_DOUBLEENC | XSS_0073 | xss | doubleenc | naxsi-access.log:rid=fa799027ea854dea81a722988b416324;apache-backend.log:rid=fa799027ea854dea81a722988b416324;response=XSS_0073_DOUBLEENC.response.bin |
| XSS_0005_DOUBLEENC | XSS_0005 | xss | doubleenc | naxsi-access.log:rid=ae839934ac46487aaa3cd0470b3822ac;apache-backend.log:rid=ae839934ac46487aaa3cd0470b3822ac;response=XSS_0005_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0082 |  | path_traversal |  | naxsi-access.log:rid=ce25e9555af74b8cbfef18da761750d3;apache-backend.log:rid=ce25e9555af74b8cbfef18da761750d3;response=PATH_TRAVERSAL_0082.response.bin |
| SQLI_0022_DOUBLEENC | SQLI_0022 | sqli | doubleenc | naxsi-access.log:rid=56341ce28a9e407d893e2843ef24abd8;apache-backend.log:rid=56341ce28a9e407d893e2843ef24abd8;response=SQLI_0022_DOUBLEENC.response.bin |
| SQLI_0119_DOUBLEENC | SQLI_0119 | sqli | doubleenc | naxsi-access.log:rid=07e00fc81fa34838a4b9db8176e44531;apache-backend.log:rid=07e00fc81fa34838a4b9db8176e44531;response=SQLI_0119_DOUBLEENC.response.bin |
| XSS_0120_DOUBLEENC | XSS_0120 | xss | doubleenc | naxsi-access.log:rid=2b35a2e1ba5a40d1929eb343bd752d85;apache-backend.log:rid=2b35a2e1ba5a40d1929eb343bd752d85;response=XSS_0120_DOUBLEENC.response.bin |
| XSS_0025_DOUBLEENC | XSS_0025 | xss | doubleenc | naxsi-access.log:rid=7ff79be470114915b6998d97018bd4d1;apache-backend.log:rid=7ff79be470114915b6998d97018bd4d1;response=XSS_0025_DOUBLEENC.response.bin |
| XSS_0045_DOUBLEENC | XSS_0045 | xss | doubleenc | naxsi-access.log:rid=9790028d4a8240e99fdf156bd440e4e8;apache-backend.log:rid=9790028d4a8240e99fdf156bd440e4e8;response=XSS_0045_DOUBLEENC.response.bin |
| XSS_0100_DOUBLEENC | XSS_0100 | xss | doubleenc | naxsi-access.log:rid=834a811f49c145289ecf260fd0534a84;apache-backend.log:rid=834a811f49c145289ecf260fd0534a84;response=XSS_0100_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0100 |  | path_traversal |  | naxsi-access.log:rid=3e429f85373243eab4eae30137f9a481;apache-backend.log:rid=3e429f85373243eab4eae30137f9a481;response=PATH_TRAVERSAL_0100.response.bin |
| SQLI_0098_DOUBLEENC | SQLI_0098 | sqli | doubleenc | naxsi-access.log:rid=0c365a0fe0a043c786f83464d0d89d4e;apache-backend.log:rid=0c365a0fe0a043c786f83464d0d89d4e;response=SQLI_0098_DOUBLEENC.response.bin |
| SQLI_0049_DOUBLEENC | SQLI_0049 | sqli | doubleenc | naxsi-access.log:rid=044ceb3f4e4048619e70aab93913cefb;apache-backend.log:rid=044ceb3f4e4048619e70aab93913cefb;response=SQLI_0049_DOUBLEENC.response.bin |
| XSS_0104_DOUBLEENC | XSS_0104 | xss | doubleenc | naxsi-access.log:rid=0a0404c9129746fa9fbdcddd55aee321;apache-backend.log:rid=0a0404c9129746fa9fbdcddd55aee321;response=XSS_0104_DOUBLEENC.response.bin |
| XSS_0009_DOUBLEENC | XSS_0009 | xss | doubleenc | naxsi-access.log:rid=a1238236bc334ed88e3314581c0e2b9a;apache-backend.log:rid=a1238236bc334ed88e3314581c0e2b9a;response=XSS_0009_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0094 |  | path_traversal |  | naxsi-access.log:rid=e62a96bbf34a446f920387023e3dedd2;apache-backend.log:rid=e62a96bbf34a446f920387023e3dedd2;response=PATH_TRAVERSAL_0094.response.bin |
| SQLI_0055_DOUBLEENC | SQLI_0055 | sqli | doubleenc | naxsi-access.log:rid=c00cb8cb592b4b2fb7fdd71e938dba7f;apache-backend.log:rid=c00cb8cb592b4b2fb7fdd71e938dba7f;response=SQLI_0055_DOUBLEENC.response.bin |
| XSS_0081_DOUBLEENC | XSS_0081 | xss | doubleenc | naxsi-access.log:rid=dd79ae4bd2e044aa98d3801825b532ee;apache-backend.log:rid=dd79ae4bd2e044aa98d3801825b532ee;response=XSS_0081_DOUBLEENC.response.bin |
| SQLI_0013_DOUBLEENC | SQLI_0013 | sqli | doubleenc | naxsi-access.log:rid=798aae778cea454fbefa118f75d63823;apache-backend.log:rid=798aae778cea454fbefa118f75d63823;response=SQLI_0013_DOUBLEENC.response.bin |
| XSS_0061_DOUBLEENC | XSS_0061 | xss | doubleenc | naxsi-access.log:rid=4377a81dacca4e4f8661911c09645640;apache-backend.log:rid=4377a81dacca4e4f8661911c09645640;response=XSS_0061_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0054 |  | path_traversal |  | naxsi-access.log:rid=b4327edd0d5840f588a3f9446b5fb159;apache-backend.log:rid=b4327edd0d5840f588a3f9446b5fb159;response=PATH_TRAVERSAL_0054.response.bin |
| SQLI_0036_DOUBLEENC | SQLI_0036 | sqli | doubleenc | naxsi-access.log:rid=991ea93a95994588a6cbba7fa802f3d8;apache-backend.log:rid=991ea93a95994588a6cbba7fa802f3d8;response=SQLI_0036_DOUBLEENC.response.bin |
| SQLI_0076_DOUBLEENC | SQLI_0076 | sqli | doubleenc | naxsi-access.log:rid=cb21b74c738e49a5a49221746e071a49;apache-backend.log:rid=cb21b74c738e49a5a49221746e071a49;response=SQLI_0076_DOUBLEENC.response.bin |
| XSS_0096_DOUBLEENC | XSS_0096 | xss | doubleenc | naxsi-access.log:rid=13e1242bf5074f4b86049084a1dcb71b;apache-backend.log:rid=13e1242bf5074f4b86049084a1dcb71b;response=XSS_0096_DOUBLEENC.response.bin |
| XSS_0004_DOUBLEENC | XSS_0004 | xss | doubleenc | naxsi-access.log:rid=b45fed6776df4c338ad6b796d261fc19;apache-backend.log:rid=b45fed6776df4c338ad6b796d261fc19;response=XSS_0004_DOUBLEENC.response.bin |
| XSS_0065_DOUBLEENC | XSS_0065 | xss | doubleenc | naxsi-access.log:rid=13a5e4b6b3314aba9f937c642048d8d5;apache-backend.log:rid=13a5e4b6b3314aba9f937c642048d8d5;response=XSS_0065_DOUBLEENC.response.bin |
| XSS_0116_DOUBLEENC | XSS_0116 | xss | doubleenc | naxsi-access.log:rid=5b615f1540c24076b83cc013d5a27cb3;apache-backend.log:rid=5b615f1540c24076b83cc013d5a27cb3;response=XSS_0116_DOUBLEENC.response.bin |
| SQLI_0052_DOUBLEENC | SQLI_0052 | sqli | doubleenc | naxsi-access.log:rid=350bccdda2ff42a9b526fc2ba1a4e0e8;apache-backend.log:rid=350bccdda2ff42a9b526fc2ba1a4e0e8;response=SQLI_0052_DOUBLEENC.response.bin |
| SQLI_0032_DOUBLEENC | SQLI_0032 | sqli | doubleenc | naxsi-access.log:rid=1746f943f6544831857dd63942023575;apache-backend.log:rid=1746f943f6544831857dd63942023575;response=SQLI_0032_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0052 |  | path_traversal |  | naxsi-access.log:rid=67a3395de232443ea16022599701d0e0;apache-backend.log:rid=67a3395de232443ea16022599701d0e0;response=PATH_TRAVERSAL_0052.response.bin |
| SQLI_0112_DOUBLEENC | SQLI_0112 | sqli | doubleenc | naxsi-access.log:rid=525966e8711d4d94acf662cc09b5817b;apache-backend.log:rid=525966e8711d4d94acf662cc09b5817b;response=SQLI_0112_DOUBLEENC.response.bin |
| XSS_0002_DOUBLEENC | XSS_0002 | xss | doubleenc | naxsi-access.log:rid=95f92b9d4938451083c45923887f4ae3;apache-backend.log:rid=95f92b9d4938451083c45923887f4ae3;response=XSS_0002_DOUBLEENC.response.bin |
| SQLI_0026_DOUBLEENC | SQLI_0026 | sqli | doubleenc | naxsi-access.log:rid=556e0a0587bf4ff39948ef313d064b5d;apache-backend.log:rid=556e0a0587bf4ff39948ef313d064b5d;response=SQLI_0026_DOUBLEENC.response.bin |
| XSS_0118_DOUBLEENC | XSS_0118 | xss | doubleenc | naxsi-access.log:rid=fcd6c34242f24bbb93ab201bc1efb49e;apache-backend.log:rid=fcd6c34242f24bbb93ab201bc1efb49e;response=XSS_0118_DOUBLEENC.response.bin |
| SQLI_0030_DOUBLEENC | SQLI_0030 | sqli | doubleenc | naxsi-access.log:rid=b56d7d25d4014ebf87ce65130494cd1a;apache-backend.log:rid=b56d7d25d4014ebf87ce65130494cd1a;response=SQLI_0030_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0083 |  | path_traversal |  | naxsi-access.log:rid=fa290e3e944e493aa3979bb7ca3535cd;apache-backend.log:rid=fa290e3e944e493aa3979bb7ca3535cd;response=PATH_TRAVERSAL_0083.response.bin |
| SQLI_0038_DOUBLEENC | SQLI_0038 | sqli | doubleenc | naxsi-access.log:rid=8565de787db94969a1460ed31168cdd8;apache-backend.log:rid=8565de787db94969a1460ed31168cdd8;response=SQLI_0038_DOUBLEENC.response.bin |
| XSS_0039_DOUBLEENC | XSS_0039 | xss | doubleenc | naxsi-access.log:rid=e0efa2db380a49c0bb68844147d0d6e3;apache-backend.log:rid=e0efa2db380a49c0bb68844147d0d6e3;response=XSS_0039_DOUBLEENC.response.bin |
| SQLI_0035_DOUBLEENC | SQLI_0035 | sqli | doubleenc | naxsi-access.log:rid=4286ad9ca23d4cd4abd7443f29c1269b;apache-backend.log:rid=4286ad9ca23d4cd4abd7443f29c1269b;response=SQLI_0035_DOUBLEENC.response.bin |
| XSS_0023_DOUBLEENC | XSS_0023 | xss | doubleenc | naxsi-access.log:rid=9315892600314f3494bb04302c44a111;apache-backend.log:rid=9315892600314f3494bb04302c44a111;response=XSS_0023_DOUBLEENC.response.bin |
| SQLI_0083_DOUBLEENC | SQLI_0083 | sqli | doubleenc | naxsi-access.log:rid=c94e7f46e9af4ff99bb78fabf39f4f21;apache-backend.log:rid=c94e7f46e9af4ff99bb78fabf39f4f21;response=SQLI_0083_DOUBLEENC.response.bin |
| XSS_0016_DOUBLEENC | XSS_0016 | xss | doubleenc | naxsi-access.log:rid=87822c2235a9440c81e0c39263968f9a;apache-backend.log:rid=87822c2235a9440c81e0c39263968f9a;response=XSS_0016_DOUBLEENC.response.bin |
| XSS_0106_DOUBLEENC | XSS_0106 | xss | doubleenc | naxsi-access.log:rid=ede2968244334006b70a2f244b05007b;apache-backend.log:rid=ede2968244334006b70a2f244b05007b;response=XSS_0106_DOUBLEENC.response.bin |
| SQLI_0051_DOUBLEENC | SQLI_0051 | sqli | doubleenc | naxsi-access.log:rid=46140f28766549b699225b876515666c;apache-backend.log:rid=46140f28766549b699225b876515666c;response=SQLI_0051_DOUBLEENC.response.bin |
| SQLI_0120_DOUBLEENC | SQLI_0120 | sqli | doubleenc | naxsi-access.log:rid=e936316db9884f3cbe3f780fb407d2c4;apache-backend.log:rid=e936316db9884f3cbe3f780fb407d2c4;response=SQLI_0120_DOUBLEENC.response.bin |
| SQLI_0081_DOUBLEENC | SQLI_0081 | sqli | doubleenc | naxsi-access.log:rid=07bd55b09f21451290c5168ec50fd120;apache-backend.log:rid=07bd55b09f21451290c5168ec50fd120;response=SQLI_0081_DOUBLEENC.response.bin |
| SQLI_0054_DOUBLEENC | SQLI_0054 | sqli | doubleenc | naxsi-access.log:rid=27b2d9232fea4557aa9648b2436daa58;apache-backend.log:rid=27b2d9232fea4557aa9648b2436daa58;response=SQLI_0054_DOUBLEENC.response.bin |
| SQLI_0009_DOUBLEENC | SQLI_0009 | sqli | doubleenc | naxsi-access.log:rid=32a8ade2e72f4948892087e98308e9ed;apache-backend.log:rid=32a8ade2e72f4948892087e98308e9ed;response=SQLI_0009_DOUBLEENC.response.bin |
| XSS_0046_DOUBLEENC | XSS_0046 | xss | doubleenc | naxsi-access.log:rid=9d04da565ba241a5ad1f111ef087728d;apache-backend.log:rid=9d04da565ba241a5ad1f111ef087728d;response=XSS_0046_DOUBLEENC.response.bin |
| XSS_0029_DOUBLEENC | XSS_0029 | xss | doubleenc | naxsi-access.log:rid=2160df585d91433bbb01907aeedfc267;apache-backend.log:rid=2160df585d91433bbb01907aeedfc267;response=XSS_0029_DOUBLEENC.response.bin |
| SQLI_0078_DOUBLEENC | SQLI_0078 | sqli | doubleenc | naxsi-access.log:rid=ded0dee693e64c4ca7df13d9d8c6e12d;apache-backend.log:rid=ded0dee693e64c4ca7df13d9d8c6e12d;response=SQLI_0078_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0024 |  | path_traversal |  | naxsi-access.log:rid=6f10eda4de2746a6ae7aad3e70fabe72;apache-backend.log:rid=6f10eda4de2746a6ae7aad3e70fabe72;response=PATH_TRAVERSAL_0024.response.bin |
| XSS_0069_DOUBLEENC | XSS_0069 | xss | doubleenc | naxsi-access.log:rid=657dec74396640bdaa121cce507892e2;apache-backend.log:rid=657dec74396640bdaa121cce507892e2;response=XSS_0069_DOUBLEENC.response.bin |
| XSS_0101_DOUBLEENC | XSS_0101 | xss | doubleenc | naxsi-access.log:rid=f7db8738073c42e8ada524695083e4b3;apache-backend.log:rid=f7db8738073c42e8ada524695083e4b3;response=XSS_0101_DOUBLEENC.response.bin |
| XSS_0066_DOUBLEENC | XSS_0066 | xss | doubleenc | naxsi-access.log:rid=1f6f8d94b3e64a05a74d0484692cb5d7;apache-backend.log:rid=1f6f8d94b3e64a05a74d0484692cb5d7;response=XSS_0066_DOUBLEENC.response.bin |
| XSS_0115_DOUBLEENC | XSS_0115 | xss | doubleenc | naxsi-access.log:rid=6a7a3ac3b5724af98dfab26c6ee16898;apache-backend.log:rid=6a7a3ac3b5724af98dfab26c6ee16898;response=XSS_0115_DOUBLEENC.response.bin |
| SQLI_0042_DOUBLEENC | SQLI_0042 | sqli | doubleenc | naxsi-access.log:rid=cb9f005d98e84350ae7c71a7f5355532;apache-backend.log:rid=cb9f005d98e84350ae7c71a7f5355532;response=SQLI_0042_DOUBLEENC.response.bin |
| XSS_0107_DOUBLEENC | XSS_0107 | xss | doubleenc | naxsi-access.log:rid=1a69e16f97d24895ab56e4b513bd70a1;apache-backend.log:rid=1a69e16f97d24895ab56e4b513bd70a1;response=XSS_0107_DOUBLEENC.response.bin |
| XSS_0037_DOUBLEENC | XSS_0037 | xss | doubleenc | naxsi-access.log:rid=4f9e85e906364b44a867dc3850a93a0f;apache-backend.log:rid=4f9e85e906364b44a867dc3850a93a0f;response=XSS_0037_DOUBLEENC.response.bin |
| XSS_0062_DOUBLEENC | XSS_0062 | xss | doubleenc | naxsi-access.log:rid=bc7ff2b7cdec43e88fa7fa2c229e15c9;apache-backend.log:rid=bc7ff2b7cdec43e88fa7fa2c229e15c9;response=XSS_0062_DOUBLEENC.response.bin |
| XSS_0109_DOUBLEENC | XSS_0109 | xss | doubleenc | naxsi-access.log:rid=e3c088b3a0834045a530535da438b0b3;apache-backend.log:rid=e3c088b3a0834045a530535da438b0b3;response=XSS_0109_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0113 |  | path_traversal |  | naxsi-access.log:rid=e0ed6a45abc8401cb5d222837d79023e;apache-backend.log:rid=e0ed6a45abc8401cb5d222837d79023e;response=PATH_TRAVERSAL_0113.response.bin |
| PATH_TRAVERSAL_0034 |  | path_traversal |  | naxsi-access.log:rid=e19837fdc04f4c42876e5e7dbc947e3a;apache-backend.log:rid=e19837fdc04f4c42876e5e7dbc947e3a;response=PATH_TRAVERSAL_0034.response.bin |
| SQLI_0070_DOUBLEENC | SQLI_0070 | sqli | doubleenc | naxsi-access.log:rid=9b8f93bf859e4ff2ac25f6de19b47244;apache-backend.log:rid=9b8f93bf859e4ff2ac25f6de19b47244;response=SQLI_0070_DOUBLEENC.response.bin |
| SQLI_0033_DOUBLEENC | SQLI_0033 | sqli | doubleenc | naxsi-access.log:rid=ae90c877008b4434ae05ac0d7022f1e4;apache-backend.log:rid=ae90c877008b4434ae05ac0d7022f1e4;response=SQLI_0033_DOUBLEENC.response.bin |
| SQLI_0067_DOUBLEENC | SQLI_0067 | sqli | doubleenc | naxsi-access.log:rid=904f00cbf1044343963143295def6240;apache-backend.log:rid=904f00cbf1044343963143295def6240;response=SQLI_0067_DOUBLEENC.response.bin |
| SQLI_0028_DOUBLEENC | SQLI_0028 | sqli | doubleenc | naxsi-access.log:rid=36ee81184f654b54814ad3f017a22e48;apache-backend.log:rid=36ee81184f654b54814ad3f017a22e48;response=SQLI_0028_DOUBLEENC.response.bin |
| XSS_0117_DOUBLEENC | XSS_0117 | xss | doubleenc | naxsi-access.log:rid=3fe536a92dff4da69393f4684df3aacf;apache-backend.log:rid=3fe536a92dff4da69393f4684df3aacf;response=XSS_0117_DOUBLEENC.response.bin |
| XSS_0102_DOUBLEENC | XSS_0102 | xss | doubleenc | naxsi-access.log:rid=5cabf756d2234ffbbce5d766127fe1cf;apache-backend.log:rid=5cabf756d2234ffbbce5d766127fe1cf;response=XSS_0102_DOUBLEENC.response.bin |
| SQLI_0080_DOUBLEENC | SQLI_0080 | sqli | doubleenc | naxsi-access.log:rid=0e07bac3dad84f6e9860d430d5df2e8e;apache-backend.log:rid=0e07bac3dad84f6e9860d430d5df2e8e;response=SQLI_0080_DOUBLEENC.response.bin |
| SQLI_0012_DOUBLEENC | SQLI_0012 | sqli | doubleenc | naxsi-access.log:rid=02e587c011b84dbc891b795cf5dd1978;apache-backend.log:rid=02e587c011b84dbc891b795cf5dd1978;response=SQLI_0012_DOUBLEENC.response.bin |
| XSS_0019_DOUBLEENC | XSS_0019 | xss | doubleenc | naxsi-access.log:rid=96181d7c67a04cf8b75545173855e9f7;apache-backend.log:rid=96181d7c67a04cf8b75545173855e9f7;response=XSS_0019_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0002 |  | path_traversal |  | naxsi-access.log:rid=5e506b2a888e42ceac32d1f401212ec0;apache-backend.log:rid=5e506b2a888e42ceac32d1f401212ec0;response=PATH_TRAVERSAL_0002.response.bin |
| PATH_TRAVERSAL_0033 |  | path_traversal |  | naxsi-access.log:rid=35db228258634a2eb25055725de5cdea;apache-backend.log:rid=35db228258634a2eb25055725de5cdea;response=PATH_TRAVERSAL_0033.response.bin |
| XSS_0084_DOUBLEENC | XSS_0084 | xss | doubleenc | naxsi-access.log:rid=4f6363be22e8423b920a7471f60480bd;apache-backend.log:rid=4f6363be22e8423b920a7471f60480bd;response=XSS_0084_DOUBLEENC.response.bin |
| XSS_0059_DOUBLEENC | XSS_0059 | xss | doubleenc | naxsi-access.log:rid=af2a18075c1847039245a359fb0ec06c;apache-backend.log:rid=af2a18075c1847039245a359fb0ec06c;response=XSS_0059_DOUBLEENC.response.bin |
| XSS_0038_DOUBLEENC | XSS_0038 | xss | doubleenc | naxsi-access.log:rid=5e4006a1e8a44930b339e13d9c02bf14;apache-backend.log:rid=5e4006a1e8a44930b339e13d9c02bf14;response=XSS_0038_DOUBLEENC.response.bin |
| SQLI_0073_DOUBLEENC | SQLI_0073 | sqli | doubleenc | naxsi-access.log:rid=e07275f4379745acb8f3c3c43f5ef9c9;apache-backend.log:rid=e07275f4379745acb8f3c3c43f5ef9c9;response=SQLI_0073_DOUBLEENC.response.bin |
| SQLI_0087_DOUBLEENC | SQLI_0087 | sqli | doubleenc | naxsi-access.log:rid=b7ede58e6d2245878cac0f453cf140ed;apache-backend.log:rid=b7ede58e6d2245878cac0f453cf140ed;response=SQLI_0087_DOUBLEENC.response.bin |
| SQLI_0094_DOUBLEENC | SQLI_0094 | sqli | doubleenc | naxsi-access.log:rid=63cbc6d32425486ea7941b5080d5a769;apache-backend.log:rid=63cbc6d32425486ea7941b5080d5a769;response=SQLI_0094_DOUBLEENC.response.bin |
| XSS_0008_DOUBLEENC | XSS_0008 | xss | doubleenc | naxsi-access.log:rid=41bcd7b2d5354cafb1bc5b4df1232803;apache-backend.log:rid=41bcd7b2d5354cafb1bc5b4df1232803;response=XSS_0008_DOUBLEENC.response.bin |
| XSS_0051_DOUBLEENC | XSS_0051 | xss | doubleenc | naxsi-access.log:rid=31b599a816b442e1b86f809a13931c54;apache-backend.log:rid=31b599a816b442e1b86f809a13931c54;response=XSS_0051_DOUBLEENC.response.bin |
| SQLI_0025_DOUBLEENC | SQLI_0025 | sqli | doubleenc | naxsi-access.log:rid=e0da21648c9c4ca791bb875e5fd89e8b;apache-backend.log:rid=e0da21648c9c4ca791bb875e5fd89e8b;response=SQLI_0025_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0041 |  | path_traversal |  | naxsi-access.log:rid=679d9f2b267d4577871d73a81177fb72;apache-backend.log:rid=679d9f2b267d4577871d73a81177fb72;response=PATH_TRAVERSAL_0041.response.bin |
| SQLI_0057_DOUBLEENC | SQLI_0057 | sqli | doubleenc | naxsi-access.log:rid=5f08a2003c3743d7ae9dccb71e073ece;apache-backend.log:rid=5f08a2003c3743d7ae9dccb71e073ece;response=SQLI_0057_DOUBLEENC.response.bin |
| SQLI_0037_DOUBLEENC | SQLI_0037 | sqli | doubleenc | naxsi-access.log:rid=0e447fdb3b1c4e9dbc36d7d1d627e7f7;apache-backend.log:rid=0e447fdb3b1c4e9dbc36d7d1d627e7f7;response=SQLI_0037_DOUBLEENC.response.bin |
| XSS_0082_DOUBLEENC | XSS_0082 | xss | doubleenc | naxsi-access.log:rid=e9bee7be1a0847e0b1279b3fb958add5;apache-backend.log:rid=e9bee7be1a0847e0b1279b3fb958add5;response=XSS_0082_DOUBLEENC.response.bin |
| SQLI_0024_DOUBLEENC | SQLI_0024 | sqli | doubleenc | naxsi-access.log:rid=db408de81ceb4bf78181d175b45681e1;apache-backend.log:rid=db408de81ceb4bf78181d175b45681e1;response=SQLI_0024_DOUBLEENC.response.bin |
| XSS_0094_DOUBLEENC | XSS_0094 | xss | doubleenc | naxsi-access.log:rid=4b232a91dcc0403997a6b933a8fa6d00;apache-backend.log:rid=4b232a91dcc0403997a6b933a8fa6d00;response=XSS_0094_DOUBLEENC.response.bin |
| XSS_0035_DOUBLEENC | XSS_0035 | xss | doubleenc | naxsi-access.log:rid=39151609a4f444c98da52dbfc450fcf5;apache-backend.log:rid=39151609a4f444c98da52dbfc450fcf5;response=XSS_0035_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0072 |  | path_traversal |  | naxsi-access.log:rid=c8019bc59fe84112a9eaaf5adafb19df;apache-backend.log:rid=c8019bc59fe84112a9eaaf5adafb19df;response=PATH_TRAVERSAL_0072.response.bin |
| SQLI_0082_DOUBLEENC | SQLI_0082 | sqli | doubleenc | naxsi-access.log:rid=eff53a85d1984b0ba5abefc1a9abedab;apache-backend.log:rid=eff53a85d1984b0ba5abefc1a9abedab;response=SQLI_0082_DOUBLEENC.response.bin |
| XSS_0044_DOUBLEENC | XSS_0044 | xss | doubleenc | naxsi-access.log:rid=0448b730df4644338269f8af5ad4a1c4;apache-backend.log:rid=0448b730df4644338269f8af5ad4a1c4;response=XSS_0044_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0066 |  | path_traversal |  | naxsi-access.log:rid=7703d904ed894b33bd7e425af4eca05b;apache-backend.log:rid=7703d904ed894b33bd7e425af4eca05b;response=PATH_TRAVERSAL_0066.response.bin |
| SQLI_0075_DOUBLEENC | SQLI_0075 | sqli | doubleenc | naxsi-access.log:rid=ee748ad1262b4fd1b9d2612bf1d3741c;apache-backend.log:rid=ee748ad1262b4fd1b9d2612bf1d3741c;response=SQLI_0075_DOUBLEENC.response.bin |
| XSS_0057_DOUBLEENC | XSS_0057 | xss | doubleenc | naxsi-access.log:rid=7a4690dde6af42f3991428120193e33e;apache-backend.log:rid=7a4690dde6af42f3991428120193e33e;response=XSS_0057_DOUBLEENC.response.bin |
| SQLI_0106_DOUBLEENC | SQLI_0106 | sqli | doubleenc | naxsi-access.log:rid=5095fa5cb1094f4eaf82eddfeef7049a;apache-backend.log:rid=5095fa5cb1094f4eaf82eddfeef7049a;response=SQLI_0106_DOUBLEENC.response.bin |
| XSS_0013_DOUBLEENC | XSS_0013 | xss | doubleenc | naxsi-access.log:rid=577f7dbb4d3047589e74974700652c11;apache-backend.log:rid=577f7dbb4d3047589e74974700652c11;response=XSS_0013_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0108 |  | path_traversal |  | naxsi-access.log:rid=67b0162b3e3e43468851a2b14a9b4497;apache-backend.log:rid=67b0162b3e3e43468851a2b14a9b4497;response=PATH_TRAVERSAL_0108.response.bin |
| SQLI_0064_DOUBLEENC | SQLI_0064 | sqli | doubleenc | naxsi-access.log:rid=f027bad2f2f041ea90cc3e928bf0ef6f;apache-backend.log:rid=f027bad2f2f041ea90cc3e928bf0ef6f;response=SQLI_0064_DOUBLEENC.response.bin |
| SQLI_0116_DOUBLEENC | SQLI_0116 | sqli | doubleenc | naxsi-access.log:rid=94c85f0dc9c6417e937f5a821d2a5696;apache-backend.log:rid=94c85f0dc9c6417e937f5a821d2a5696;response=SQLI_0116_DOUBLEENC.response.bin |
| XSS_0054_DOUBLEENC | XSS_0054 | xss | doubleenc | naxsi-access.log:rid=4d05702c43c44b3190f61670b889c2d9;apache-backend.log:rid=4d05702c43c44b3190f61670b889c2d9;response=XSS_0054_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0060 |  | path_traversal |  | naxsi-access.log:rid=9a620e0b09884b749c419b2722d1e41c;apache-backend.log:rid=9a620e0b09884b749c419b2722d1e41c;response=PATH_TRAVERSAL_0060.response.bin |
| XSS_0050_DOUBLEENC | XSS_0050 | xss | doubleenc | naxsi-access.log:rid=8f57f4ef88fb4b1db97a0a0be554a3f8;apache-backend.log:rid=8f57f4ef88fb4b1db97a0a0be554a3f8;response=XSS_0050_DOUBLEENC.response.bin |
| XSS_0110_DOUBLEENC | XSS_0110 | xss | doubleenc | naxsi-access.log:rid=6404333e5b294bdbaf174f6acfeadc26;apache-backend.log:rid=6404333e5b294bdbaf174f6acfeadc26;response=XSS_0110_DOUBLEENC.response.bin |
| SQLI_0019_DOUBLEENC | SQLI_0019 | sqli | doubleenc | naxsi-access.log:rid=f4775368fe834cf68f70ca345def9282;apache-backend.log:rid=f4775368fe834cf68f70ca345def9282;response=SQLI_0019_DOUBLEENC.response.bin |
| XSS_0036_DOUBLEENC | XSS_0036 | xss | doubleenc | naxsi-access.log:rid=76a9aef0e711458b9431e093dab97ec9;apache-backend.log:rid=76a9aef0e711458b9431e093dab97ec9;response=XSS_0036_DOUBLEENC.response.bin |
| SQLI_0029_DOUBLEENC | SQLI_0029 | sqli | doubleenc | naxsi-access.log:rid=be8c342bcf7f41a497fe4e2dae4456d5;apache-backend.log:rid=be8c342bcf7f41a497fe4e2dae4456d5;response=SQLI_0029_DOUBLEENC.response.bin |
| SQLI_0002_DOUBLEENC | SQLI_0002 | sqli | doubleenc | naxsi-access.log:rid=e0a356f509954008b8510aa90264d7f2;apache-backend.log:rid=e0a356f509954008b8510aa90264d7f2;response=SQLI_0002_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0068 |  | path_traversal |  | naxsi-access.log:rid=cfe8fe2714dc4443870834bb32f8c9a4;apache-backend.log:rid=cfe8fe2714dc4443870834bb32f8c9a4;response=PATH_TRAVERSAL_0068.response.bin |
| PATH_TRAVERSAL_0010 |  | path_traversal |  | naxsi-access.log:rid=cadbb5dc0c2e477f95fea8003f5563c8;apache-backend.log:rid=cadbb5dc0c2e477f95fea8003f5563c8;response=PATH_TRAVERSAL_0010.response.bin |
| SQLI_0058_DOUBLEENC | SQLI_0058 | sqli | doubleenc | naxsi-access.log:rid=4864defb7a174949a0eded985985df65;apache-backend.log:rid=4864defb7a174949a0eded985985df65;response=SQLI_0058_DOUBLEENC.response.bin |
| SQLI_0050_DOUBLEENC | SQLI_0050 | sqli | doubleenc | naxsi-access.log:rid=5360b1f662a14dc482df667ecc8e0129;apache-backend.log:rid=5360b1f662a14dc482df667ecc8e0129;response=SQLI_0050_DOUBLEENC.response.bin |
| XSS_0075_DOUBLEENC | XSS_0075 | xss | doubleenc | naxsi-access.log:rid=bcc483f0d54e4ec8adeb29935818f40b;apache-backend.log:rid=bcc483f0d54e4ec8adeb29935818f40b;response=XSS_0075_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0004 |  | path_traversal |  | naxsi-access.log:rid=ad2e44aa370f4ec1a82e7aea57d5c591;apache-backend.log:rid=ad2e44aa370f4ec1a82e7aea57d5c591;response=PATH_TRAVERSAL_0004.response.bin |
| SQLI_0066_DOUBLEENC | SQLI_0066 | sqli | doubleenc | naxsi-access.log:rid=31a71dd3f3324747b3d53e8bb95ae93a;apache-backend.log:rid=31a71dd3f3324747b3d53e8bb95ae93a;response=SQLI_0066_DOUBLEENC.response.bin |
| XSS_0024_DOUBLEENC | XSS_0024 | xss | doubleenc | naxsi-access.log:rid=2af711e720d3486395379a14034ece03;apache-backend.log:rid=2af711e720d3486395379a14034ece03;response=XSS_0024_DOUBLEENC.response.bin |
| XSS_0099_DOUBLEENC | XSS_0099 | xss | doubleenc | naxsi-access.log:rid=f30693577c5d4910a597789d61570860;apache-backend.log:rid=f30693577c5d4910a597789d61570860;response=XSS_0099_DOUBLEENC.response.bin |
| XSS_0083_DOUBLEENC | XSS_0083 | xss | doubleenc | naxsi-access.log:rid=d8d0ed55a82544e48e8d81015c980e49;apache-backend.log:rid=d8d0ed55a82544e48e8d81015c980e49;response=XSS_0083_DOUBLEENC.response.bin |
| XSS_0114_DOUBLEENC | XSS_0114 | xss | doubleenc | naxsi-access.log:rid=48abf8527ccb484b827ebdec14ef9d81;apache-backend.log:rid=48abf8527ccb484b827ebdec14ef9d81;response=XSS_0114_DOUBLEENC.response.bin |
| SQLI_0018_DOUBLEENC | SQLI_0018 | sqli | doubleenc | naxsi-access.log:rid=e18594b4edb64a278e41689c91165522;apache-backend.log:rid=e18594b4edb64a278e41689c91165522;response=SQLI_0018_DOUBLEENC.response.bin |
| XSS_0095_DOUBLEENC | XSS_0095 | xss | doubleenc | naxsi-access.log:rid=6dda09677ea8438d8a2aeae662383d59;apache-backend.log:rid=6dda09677ea8438d8a2aeae662383d59;response=XSS_0095_DOUBLEENC.response.bin |
| SQLI_0102_DOUBLEENC | SQLI_0102 | sqli | doubleenc | naxsi-access.log:rid=e5c1135acb134467a0d89e4a4c3499ff;apache-backend.log:rid=e5c1135acb134467a0d89e4a4c3499ff;response=SQLI_0102_DOUBLEENC.response.bin |
| SQLI_0105_DOUBLEENC | SQLI_0105 | sqli | doubleenc | naxsi-access.log:rid=f908fdc3151f4cfe8c8f7852a8a8e914;apache-backend.log:rid=f908fdc3151f4cfe8c8f7852a8a8e914;response=SQLI_0105_DOUBLEENC.response.bin |
| XSS_0033_DOUBLEENC | XSS_0033 | xss | doubleenc | naxsi-access.log:rid=21bac144a08a4809826690410710a94f;apache-backend.log:rid=21bac144a08a4809826690410710a94f;response=XSS_0033_DOUBLEENC.response.bin |
| XSS_0042_DOUBLEENC | XSS_0042 | xss | doubleenc | naxsi-access.log:rid=c4ad0275cc7d43f88a7a73b8738250d1;apache-backend.log:rid=c4ad0275cc7d43f88a7a73b8738250d1;response=XSS_0042_DOUBLEENC.response.bin |
| XSS_0090_DOUBLEENC | XSS_0090 | xss | doubleenc | naxsi-access.log:rid=d0e17eb8184e4184bbc0e05dca768b94;apache-backend.log:rid=d0e17eb8184e4184bbc0e05dca768b94;response=XSS_0090_DOUBLEENC.response.bin |
| XSS_0041_DOUBLEENC | XSS_0041 | xss | doubleenc | naxsi-access.log:rid=fc1dcec3ac4c47e9bce37129d26ddd93;apache-backend.log:rid=fc1dcec3ac4c47e9bce37129d26ddd93;response=XSS_0041_DOUBLEENC.response.bin |
| SQLI_0100_DOUBLEENC | SQLI_0100 | sqli | doubleenc | naxsi-access.log:rid=b2f5e4c1bee54157bc9a5b0f6e6bb90b;apache-backend.log:rid=b2f5e4c1bee54157bc9a5b0f6e6bb90b;response=SQLI_0100_DOUBLEENC.response.bin |
| SQLI_0020_DOUBLEENC | SQLI_0020 | sqli | doubleenc | naxsi-access.log:rid=87f0f658176c4ea99f72285f7aeb2f6c;apache-backend.log:rid=87f0f658176c4ea99f72285f7aeb2f6c;response=SQLI_0020_DOUBLEENC.response.bin |
| XSS_0093_DOUBLEENC | XSS_0093 | xss | doubleenc | naxsi-access.log:rid=dab67f33e3b3433fa757da72c091401b;apache-backend.log:rid=dab67f33e3b3433fa757da72c091401b;response=XSS_0093_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0013 |  | path_traversal |  | naxsi-access.log:rid=fee5bc5de734486fb05d101788c5b8fd;apache-backend.log:rid=fee5bc5de734486fb05d101788c5b8fd;response=PATH_TRAVERSAL_0013.response.bin |
| XSS_0074_DOUBLEENC | XSS_0074 | xss | doubleenc | naxsi-access.log:rid=c0bcf3a22f3b462ea052fd0d7b572099;apache-backend.log:rid=c0bcf3a22f3b462ea052fd0d7b572099;response=XSS_0074_DOUBLEENC.response.bin |
| SQLI_0084_DOUBLEENC | SQLI_0084 | sqli | doubleenc | naxsi-access.log:rid=d9b991f640b948c08ce51e4f26c5b21b;apache-backend.log:rid=d9b991f640b948c08ce51e4f26c5b21b;response=SQLI_0084_DOUBLEENC.response.bin |
| XSS_0030_DOUBLEENC | XSS_0030 | xss | doubleenc | naxsi-access.log:rid=e999995596e54307ac978a1f014144c3;apache-backend.log:rid=e999995596e54307ac978a1f014144c3;response=XSS_0030_DOUBLEENC.response.bin |
| XSS_0079_DOUBLEENC | XSS_0079 | xss | doubleenc | naxsi-access.log:rid=e91bb56fed0a44c098880a6ec9769f0e;apache-backend.log:rid=e91bb56fed0a44c098880a6ec9769f0e;response=XSS_0079_DOUBLEENC.response.bin |
| SQLI_0095_DOUBLEENC | SQLI_0095 | sqli | doubleenc | naxsi-access.log:rid=6f62a1eeeae340d2809588548eedfd37;apache-backend.log:rid=6f62a1eeeae340d2809588548eedfd37;response=SQLI_0095_DOUBLEENC.response.bin |
| XSS_0098_DOUBLEENC | XSS_0098 | xss | doubleenc | naxsi-access.log:rid=d1ea7f388c904442af82b54753068586;apache-backend.log:rid=d1ea7f388c904442af82b54753068586;response=XSS_0098_DOUBLEENC.response.bin |
| PATH_TRAVERSAL_0109 |  | path_traversal |  | naxsi-access.log:rid=b29fcb02ffb5465f8f2eb0afe2b68208;apache-backend.log:rid=b29fcb02ffb5465f8f2eb0afe2b68208;response=PATH_TRAVERSAL_0109.response.bin |

## 8. Baseline vs obfuscated comparison

- candidate_rows: 1084
- classified_pairs: 1084
- blocked_to_allowed: 212
- allowed_to_blocked: 0
- unchanged: 872
- unpaired_or_unknown: 0

These are within-run paired dispositions, not proof that every variation preserved attack semantics.

## 9. Limitations

Rates are fractions from 0 to 1 and use classified denominators only. Unknowns can bias the observed rates.
Human evidence references must be audited against retained logs. CSV validation cannot establish authenticity.
A WAF allowance is not proof of successful exploitation. Review application/session state and payload validity.
Lab engine versions, thresholds, repetitions, ordering and corpus representativeness limit generalisation.
Unreviewed cases/variants and unsupported XML scenarios provide no detection evidence.
No confidence intervals, population estimates, rule-cause claims or graphs are inferred automatically.
Baseline/variant rows are related observations; do not assume statistical independence.
