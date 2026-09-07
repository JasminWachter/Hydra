# MITRE ATT&CK Data Provenance

Hydra includes CSV and rule artifacts derived from the MITRE ATT&CK STIX 2.1
dataset.

## Pinned source

- Dataset: MITRE ATT&CK STIX Data
- ATT&CK release: v17.1
- Upstream release date: May 6, 2025
- Upstream repository: https://github.com/mitre-attack/attack-stix-data
- Upstream commit: `d4a34a19eb60dcd0a9d15a456da842a42e1003fc`
- Hydra snapshot date: October 19, 2025

October 19, 2025 is the first auditable appearance of all three derived CSVs in
Hydra's private development history. Their repository blobs remained unchanged
through preparation of the public release. The earlier local download time was
not retained.

The notebook uses these immutable sources:

- Enterprise: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/d4a34a19eb60dcd0a9d15a456da842a42e1003fc/enterprise-attack/enterprise-attack-17.1.json
- Mobile: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/d4a34a19eb60dcd0a9d15a456da842a42e1003fc/mobile-attack/mobile-attack-17.1.json
- ICS: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/d4a34a19eb60dcd0a9d15a456da842a42e1003fc/ics-attack/ics-attack-17.1.json

## Source bundle hashes

| Bundle | SHA-256 |
| --- | --- |
| Enterprise ATT&CK v17.1 JSON | `0D1C347A4D584CF7E11EF46556C33B7689341443BF86299188D46C307274323B` |
| Mobile ATT&CK v17.1 JSON | `33968697B94A5FF5568016A28BBCC93F7869DC2F2B2653EAD833758867AB5BC9` |
| ICS ATT&CK v17.1 JSON | `CB207F963CA270994D9DABEFE52237D46CF25056F154057F4B961F1C0803A8F3` |

## Derived CSV hashes

| Artifact | Rows | SHA-256 |
| --- | ---: | --- |
| `enterprise-techniques.csv` | 823 | `A0E6965BFDDC13140D215137BCDF8C514CF3BADDD0E42C18765C8984DE2BE3F8` |
| `mobile-techniques.csv` | 188 | `9BC436EECD9F5B1CBFCC33F19815F8F52CB81358B1ADB25045774197A7A03341` |
| `ics-techniques.csv` | 95 | `A947BF1320A6FA4C84CB59CCCC305F7951034B6E68FF005CB5F1185CDB118C41` |

The notebook's extraction and normalization logic was replayed against official
ATT&CK v17.1, v18.0, and v18.1 bundles. All fields in all three checked-in CSVs
matched v17.1 exactly. The v18.0 and v18.1 comparisons did not match. Every
generated rule retained in `mulval_rules/` and `nlp_outputs/` has a technique ID
and STIX ID present in the v17.1-derived CSVs.

## Copyright and terms

Copyright 2020-2025 The MITRE Corporation. Approved for public release. Case
number 19-3504.

This project makes use of MITRE ATT&CK®. Use and redistribution of ATT&CK data
are subject to MITRE's terms and the upstream notice preserved at:

https://github.com/mitre-attack/attack-stix-data/blob/d4a34a19eb60dcd0a9d15a456da842a42e1003fc/LICENSE.txt

Hydra is not affiliated with or endorsed by The MITRE Corporation.
