# Full Interaction Rules Generation Pipeline

## Runtime Positioning

This document describes how the full MITRE-aligned ruleset is generated.
At runtime, the active benchmark and MulVAL pipeline defaults to
`MulVAL/kb/web_security_rules.P` for web/CTF-focused attack-path quality.

The generated full ruleset (`full_interaction_rules.P`) remains available for
explicit override scenarios that require broader MITRE technique coverage.

The `full_interaction_rules.P` knowledge base is produced by a hybrid NLP-to-symbolic compilation workflow in which LLMs are constrained by a fixed predicate schema and then normalized into MulVAL/XSB-compatible logic. The process begins with ATT&CK technique extraction (Enterprise/ICS/Mobile) and per-technique stub generation (`nlp_outputs/*.rule`), while the semantic contract for rule synthesis is anchored in three registry files: `nlp_inputs/predicates_core.jsonl`, `nlp_inputs/predicates_meta.jsonl`, and `nlp_inputs/var_canonical.jsonl`. These registries are needed because the LLM is not allowed to invent the symbolic world from scratch: it must know which predicates already exist, which ones describe operational attack logic versus metadata, and which variable names should be reused consistently across rules. `predicates_core.jsonl` contains the executable domain vocabulary used in rule bodies and heads, for example records describing signatures such as `attacker_at/1`, `connects/3`, `service/5`, `vuln/3`, `cred/3`, `exec/2`, and `compromise/2`; each JSONL record stores the predicate signature, arity, normalized argument schema, origin, description, and status, so the model can generate Prolog clauses using the same argument order and meaning as the existing fact base. `predicates_meta.jsonl` contains non-operational descriptive predicates such as `technique/7`, `rule_map/2`, `severity/2`, `confidence/2`, `source_file/2`, and `data_source/2`; these are needed so the model can see how a rule is situated in the ATT&CK and provenance layer without confusing metadata with attack preconditions or effects. `var_canonical.jsonl` contains the shared variable concept dictionary, mapping semantic roles to preferred symbolic names such as `Host`, `User`, `Network`, `Port`, `Service`, `Id`, `Uri`, and `Privilege`; this file is needed to keep generated rules readable and structurally consistent, so that the same concept is not alternately written as `H`, `Target`, `Machine`, or `Node` across different techniques. During the NLP stage, each technique file is interpreted with `nlp_inputs/systemprompt.md`, and only clauses inside `% ---- RULE LLM START` and `% ---- RULE LLM END` are accepted as candidate logic; optional schema extensions are emitted to `nlp_outputs/additional_predicates_from_llm.P`. The compiler (`generate_full_kb.py`) then performs deterministic assembly: it imports declared primitives from JSONL and additional predicates, parses each generated clause to infer head/call arities, separates primitives from inferred derived predicates, auto-detects recursive symbols for tabling, and emits a consolidated `kb/full_interaction_rules.P` containing primitive declarations, `derived(...)` declarations, table directives, utility shims, raw technique clauses, and `interaction_rule((...), rule_desc(Label, Metric))` wrappers for graph-relevant heads. The base predicate substrate used to guide LLM rule induction is not generic; it is domain-structured and explicitly includes network/access predicates (`attacker_at/1`, `connects/3`, `reachable/3`, `service/5`, `exposed/2`), vulnerability predicates (`vuln/3`, `exploit_possible/1`, `service_matches/2`, `local_vuln/2`, `misconfig/2`, `remote_service_vulnerable/4`), identity/auth predicates (`user_on_host/2`, `cred/3`, `auth_possible/3`, `accepts_hash/2`, `valid_account/2`, `pth_feasible/2`), attack-state predicates (`exec/2`, `compromise/2`, `priv_escalation/3`, `persistence/2`, `loot/3`, `c2_channel/2`, `exfiltrated/3`), plus cloud/mobile/ICS extensions (`cloud_account/2`, `iam_policy/4`, `app_installed/3`, `mobile_perm/2`, `plc/1`, `protocol/3`, `safety_instrumented/1`); this constrained vocabulary ensures LLM-generated rules remain semantically grounded, compositional across ATT&CK techniques, and directly executable by MulVAL for attack-graph construction.

## MITRE ATT&CK Technique Extraction

Technique extraction is implemented in the notebook as a deterministic Python
utility that downloads STIX data from the public MITRE ATT&CK repository. The
checked-in CSV and rule artifacts use **MITRE ATT&CK v17.1**, released May 6,
2025, at immutable upstream commit
`d4a34a19eb60dcd0a9d15a456da842a42e1003fc`. The three CSVs first appear in
Hydra's private repository history on October 19, 2025, and their Git blobs are
unchanged through the release snapshot.

The notebook pins the versioned Enterprise, Mobile, and ICS bundles at that
commit. A field-by-field replay of the notebook extractor matched all checked-in
CSV records exactly: 823 Enterprise techniques, 188 Mobile techniques, and 95
ICS techniques. The same replay did not match ATT&CK v18.0 or v18.1. The
checked-in CSV SHA-256 values are:

- `enterprise-techniques.csv`: `A0E6965BFDDC13140D215137BCDF8C514CF3BADDD0E42C18765C8984DE2BE3F8`
- `mobile-techniques.csv`: `9BC436EECD9F5B1CBFCC33F19815F8F52CB81358B1ADB25045774197A7A03341`
- `ics-techniques.csv`: `A947BF1320A6FA4C84CB59CCCC305F7951034B6E68FF005CB5F1185CDB118C41`

The extractor issues an HTTP `GET` with `timeout=30`, parses the returned JSON,
and keeps objects whose STIX `type` is `attack-pattern`. It records the ATT&CK
identifier, name, description, platforms, tactics, detection guidance, data
sources, reference URL, and STIX identifier. Text normalization collapses
newlines, unescapes HTML entities, and trims the result. Rows are sorted by a
stable natural key so parent techniques and sub-techniques remain adjacent.

© 2025 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation and is subject to the MITRE ATT&CK Terms of
Use.

	
## Stub Generation

The next stage is also deterministic and currently uses a single universal template rather than technique-specific symbolic logic. The notebook cell labeled as `generate_mulval_rules.py` functionality reads one or more CSVs (`CSV_PATHS = ["enterprise-techniques.csv", "mobile-techniques.csv", "ics-techniques.csv"]`) and emits one `.rule` file per technique into `mulval_rules/`. Domain membership is inferred from the CSV filename when the CSV row does not already carry a `domain` field, and this inferred domain is then used both for metadata and for file placement. Filenames are sanitized with `_safe_filename`, which lowercases names, replaces non-safe characters with underscores, collapses repeated underscores, and preserves dotted sub-technique IDs by converting `.` to `_` inside the template slug. If `sep_subtech=True`, sub-techniques are emitted beneath `mulval_rules/subtechniques/`; if `domain_prefix=True`, the domain name is prepended to the filename. Rows are again sorted deterministically by `(domain, main technique number, sub-technique number, TID, technique name)` before emission.

Each generated file contains a metadata header followed by a minimal rule stub. The metadata header records `technique_id`, `technique_name`, `domain`, `tactic(s)`, `platforms`, `url`, `is_subtechnique`, `stix_id`, `description`, and `generated_by: notebook_generate_rules`. Descriptions longer than 5000 characters are truncated to 4997 characters plus ellipsis. The body template is intentionally generic:

```prolog
% ---- RULE STUB START (minimal) ----
potential_<technique_slug>(Host) :-
	attacker_at(net),
	connects(net, Host, _Port).

compromise(Host, user) :-
	potential_<technique_slug>(Host).
% ---- RULE STUB END ----
```

This means stub generation does not yet encode ATT&CK-specific preconditions; it only guarantees that every technique is represented as a syntactically valid placeholder that the later LLM stage can rewrite. The generator can skip existing files unless `force=True`, and it optionally writes a machine-readable manifest to `rules.manifest.json`. The pipeline log indicates that the later LLM phase attempted to process 1108 `.rule` files, which is consistent with the union of main techniques and sub-techniques across the selected ATT&CK domains.

## Predicate Bootstrapping for the NLP Stage

Before any LLM call is made, the notebook materializes a predicate registry from `initial_predicates.P`. This step is important for reproducibility because it constrains the model vocabulary. A parser reads `initial_predicates.P`, ignores Prolog directives such as `:- table ...`, captures contiguous `%` comments as predicate descriptions, and emits two append-only JSONL registries: `nlp_inputs/predicates_core.jsonl` and `nlp_inputs/predicates_meta.jsonl`. Wrapper declarations such as `primitive(host(_H)).`, `derived(exposed(H,Port)).`, and `meta(technique(...)).` are recognized explicitly, while plain heads in rules or facts are also harvested. Argument names are normalized into snake_case from Prolog variables and atoms, and each predicate is stored with a stable schema containing `signature`, `name`, `arity`, `args_schema`, description, origin, and status.

The variable vocabulary is then derived deterministically from these registries into `nlp_inputs/var_canonical.jsonl`. The notebook maps argument names heuristically into coarse semantic roles such as `network`, `host`, `port`, `user`, `service`, `id`, `uri`, and `privilege`, then seeds canonical variables like `Network`, `Host`, `Port`, `User`, `Service`, `Id`, and `Privilege`. This canonicalization step is what allows the LLM prompt to require consistent variable names instead of unconstrained free-form Prolog variables. In other words, the model is not prompted only with natural language technique descriptions; it is also conditioned on a typed symbolic vocabulary extracted from the local predicate base.

## LLM Rule Completion

The LLM stage is implemented in the notebook as a recursive directory walk over `mulval_rules/**/*.rule`. For each file, the driver loads `nlp_inputs/systemprompt.md`, `predicates_core.jsonl`, `predicates_meta.jsonl`, and `var_canonical.jsonl`, parses the technique metadata from comment headers, and packages the full rule file plus all three JSONL registries into a single user payload. The actual model call uses the OpenAI Chat Completions API via `client.chat.completions.create(...)` with `model="gpt-4o"` and `temperature=0.2`. The notebook sets `DRY_RUN = False`, so the stored implementation is configured to call the live API rather than the placeholder branch. No explicit values are recorded for `seed`, `top_p`, `max_tokens`, `presence_penalty`, `frequency_penalty`, or retry/backoff policy; therefore, those settings default to the client or API defaults and are not fully reproducible from the notebook alone.

The system prompt imposes several constraints that materially affect output reproducibility: reuse existing predicates whenever possible, prefer canonical variable names from `var_canonical.jsonl`, keep rules simple, and emit output in three sections: `rule:`, `new_predicates:`, and `new_vars:`. Only the text located between `% ---- RULE LLM START` and `% ---- RULE LLM END` is later accepted as authoritative logic. Newly proposed predicates and canonical variables are appended to `predicates_core.jsonl` and `var_canonical.jsonl` respectively, making the pipeline incremental and path-dependent: later rule generations may see a larger predicate inventory than earlier ones. This append-only behavior improves coverage but reduces strict replayability unless the exact JSONL inputs are snapshotted before each batch run.

## Reproducibility Notes

The deterministic extraction stage is reproducible from the pinned ATT&CK
v17.1 commit, the checked-in CSVs, and the hashes above. Other reproducible
components include the CSV sort order, stub generator, registry builders, and
the `generate_full_kb.py` compiler. The remaining threats to exact replay are
the lack of an API seed for LLM calls, append-only mutation of the predicate and
variable registries during batch processing, and historical rate-limit or quota
interruptions. A stricter experimental replay should freeze the JSONL registries
before each batch, record all model parameters, and export a per-technique
success/failure manifest.

## Static Scanner and Nmap Integration

Scanner integration is implemented in `MulVAL/` as a five-component pipeline built on the Strategy design pattern. The entry point is `generate_predicates.py`, which instantiates the `UnifiedPipeline` class; that class owns a `ScannerExecutor` for subprocess management, a `PredicateAggregator` that holds registered `ScannerStrategy` objects, a `MulvalExecutor` for graph generation, and a `ReportGenerator` for human-readable summaries. The active scanner strategies are nmap, trivy, and semgrep, and the pipeline can be narrowed to any subset with `--scanners trivy,semgrep,nmap`. The CLI also accepts `--skip-scanning` with `--trivy-json`, `--semgrep-json`, and `--nmap-xml` flags to inject pre-existing scan results without re-running the tools, and `--force-rescan` to bypass the size-based cache guard (`output_file.stat().st_size > 100` bytes) that prevents redundant scans.

### Nmap Execution and XML Parsing

Nmap is invoked by `ScannerExecutor._run_nmap` as a blocking subprocess with a 300-second timeout. The exact command issued is:

```
nmap -Pn -sV -sC -p 22,80,443,8000,8080,8443,3000,3306,5432,6379,27017 -oX <output.xml> <host>
```

`-Pn` treats the target as up regardless of ICMP response; `-sV` activates service and version detection; `-sC` runs the default NSE script set; `-p` restricts the scan to 11 fixed ports that cover SSH, HTTP variants, HTTPS variants, common development servers, MySQL, PostgreSQL, Redis, and MongoDB. Output is written as XML to `scan_results/nmap_results.xml`. If the initial subprocess returns a non-zero code and the process is running as a non-root user, the executor retries with `sudo -n nmap` using the same arguments; success is determined by return code zero or by the presence of a non-empty XML file on disk.

XML parsing is performed by `NmapParserStrategy.parse` using `xml.etree.ElementTree`. The parser iterates over `//host` elements, extracts the IPv4 address from `<address addrtype="ipv4">`, and uses the caller-supplied `host` identifier string as the Prolog atom rather than the raw IP when one is provided. Only `<port>` elements whose `<state state="open"/>` child is present are processed further. For each open port the parser reads `portid`, `protocol`, and the `<service>` child's `name`, `product`, and `version` attributes. String atoms are sanitized by wrapping in single quotes with interior quotes stripped (`ScannerStrategy.sanitize`); package names used as atoms are lower-cased with hyphens, dots, and spaces converted to underscores (`ScannerStrategy.atom`). An OS match is extracted from the first `<osmatch>` element if present and simplified to `linux` or `windows` using substring checks.

The predicate emissions from nmap are:

| Source                                       | Predicate emitted                                 | Category           |
| -------------------------------------------- | ------------------------------------------------- | ------------------ |
| Host IP                                      | `host('host_id').`                                | `network_topology` |
| OS match                                     | `os('host', 'linux'/'windows').`                  | `os_info`          |
| Open port + service                          | `service('host', port, proto, 'svc', 'version').` | `services`         |
| Any open port                                | `connects('internet', 'host', port).`             | `network_topology` |
| Any open port                                | `exposed('host', port).`                          | `network_topology` |
| Service in WEB_SERVICES or port in WEB_PORTS | `role('host', 'webserver').`                      | `roles`            |
| Service in DATABASE_SERVICES                 | `role('host', 'database').`                       | `roles`            |
| Service in AUTH_SERVICES                     | `role('host', 'ssh_server'/'auth_service').`      | `roles`            |
| Database role present                        | `has_data('host', 'customer_records').`           | `data_context`     |
| Database role present                        | `has_data('host', 'sensitive').`                  | `data_context`     |

`WEB_SERVICES` covers `http`, `https`, `nginx`, `apache`, `node`, `express`, `flask`, `django`, `tomcat`, `php`, `iis`, and related names. `DATABASE_SERVICES` covers `mysql`, `postgresql`, `mongodb`, `redis`, `mssql`, `mariadb`, `elasticsearch`, and others. `AUTH_SERVICES` covers `ssh`, `openssh`, `ftp`, `rdp`, `vnc`, `smb`, `ldap`, `kerberos`, and related. `WEB_PORTS` is the fixed set `{80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 4443}`.

In addition to per-port predicates, the parser processes each `<script>` element found under the port and dispatches on `script_id` to emit secondary predicates. The active script dispatch table is:

| Script id                                     | Condition                                                             | Additional predicate                              |
| --------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------- |
| `http-methods`                                | output contains `PUT` or `DELETE`                                     | `dangerous_http_methods('host', port).`           |
| `http-title` or `http-server-header`          | output contains a framework keyword                                   | `web_framework('host', port, 'framework').`       |
| `http-title` or `http-server-header`          | output contains `api`, `webhook`, `gunicorn`, `uvicorn`, or `fastapi` | `has_api_endpoint('host', port, 'POST', '/api').` |
| `http-default-accounts` or `ssh-auth-methods` | output contains `password`                                            | `auth_possible('host', 'default', 'password').`   |
| `mongodb-info`                                | output does not contain `authentication` or contains `disabled`       | `no_auth_required('host', port).`                 |

Frameworks recognized in title/header scripts are `express`, `nginx`, `apache`, `django`, `flask`, `fastapi`, `uvicorn`, `gunicorn`, `tomcat`, `iis`, and `php`.

### Trivy and Semgrep Execution and JSON Parsing

Trivy is invoked by `ScannerExecutor._run_trivy` as:

```
trivy fs --scanners vuln,secret,misconfig --format json --output <output.json> <target_dir>
```

This performs a filesystem scan of the target directory covering vulnerability, secret, and misconfiguration checks and writes the complete Trivy JSON schema to `scan_results/trivy_results.json`. The timeout is 300 seconds.

Semgrep is invoked by `ScannerExecutor._run_semgrep` and writes JSON output to `scan_results/semgrep_results.json`.

Trivy and Semgrep are parsed by dedicated strategy classes (`TrivyParserStrategy` and `SemgrepParserStrategy`) that implement the same `ScannerStrategy` abstract interface. The Trivy parser iterates `data['Results'][*]['Vulnerabilities']` and emits CVE-centered predicates filtered to `CRITICAL`/`HIGH`, while the Semgrep parser iterates `data['results']` and emits vulnerability-class predicates (for example `detected_vuln/3`) from rule findings.

The predicate emissions from both vulnerability scanners are:

| Source                          | Predicate emitted                              | Category        |
| ------------------------------- | ---------------------------------------------- | --------------- |
| Any kept CVE (CRITICAL or HIGH) | `vuln('host', 'CVE-XXXX-YYYY', package_atom).` | `critical_cves` |
| CRITICAL CVE only               | `exploit_possible('CVE-XXXX-YYYY').`           | `exploits`      |

Both parsers also populate a `self.cves` list (a list of dicts with keys `cve_id`, `package`, `version`, `severity`, `description`) that is read by the aggregator's cross-scanner correlation step described below.

### Base Parser and Strategy Pattern

All three strategies inherit from `ScannerStrategy`, an abstract base class in `parsers/base_parser.py`. The abstract interface requires implementing `parse(input_file: str) -> List[Predicate]` and `get_scanner_name() -> str`. The base class provides: predicate deduplication via a `seen_predicates: Set[str]` (deduplication is by exact string equality of the Prolog term); per-category statistics in `self._stats`; the shared `sanitize(s)` static method that wraps any string in single quotes and strips interior quotes; the `atom(s)` static method that converts hyphens, dots, and spaces to underscores and lower-cases the result; and a `clear()` method for reset between runs. The `Predicate` class is a thin wrapper holding the Prolog string, a category label for output grouping, and an optional metadata dict. Its `__hash__` and `__eq__` are defined over the Prolog string alone so that `Predicate` objects can be stored in sets for deduplication at the aggregator level.

### Cross-Scanner CVE-to-Service Correlation

After all scanner parsers have run, `PredicateAggregator._correlate_cves_to_services()` performs a join between the nmap service list and the Trivy CVE list. The nmap strategy populates `strategy.services` as a list of dicts with keys `host`, `port` (int), `service`, `product`, and `version`; the Trivy strategy populates `strategy.cves` as described above. The aggregator collects these lists from whichever strategies ran.

The correlation logic iterates every `(service, cve)` pair. For each pair it checks whether the CVE severity is `CRITICAL` or `HIGH` (lower-severity CVEs are skipped even here), then looks up the CVE's package name against the `PKG_TO_SERVICE` dictionary to find a canonical service token. If that token appears as a substring of either the nmap service name or the nmap product name, the match is considered confirmed. The `PKG_TO_SERVICE` map covers 14 entries: `openssh → openssh`, `openssl → openssl`, `nginx → nginx`, `apache → apache`, `httpd → httpd`, `node/nodejs/express → node_js_express_framework`, `mongodb → mongodb`, `mysql → mysql`, `postgresql → postgresql`, `redis → redis`, `sqlite/libsqlite → sqlite`, `curl → curl`, `git → git`, `python → python`, `php → php`. For each confirmed match the aggregator emits:

```prolog
remote_service_vulnerable('host', port, 'CVE-XXXX-YYYY', 'svc_name').
```

into the `service_cve_correlation` category. Duplicates are suppressed by a `seen: Set[tuple]` keyed on `(host, port, cve_id, svc_name)`. The count of matched pairs is logged. This predicate is directly consumed by the `remote_service_vulnerable/4` head in the interaction rules to activate exploit-chain sequences in the attack graph.

### Web Context Inference

After parsing and correlation, `PredicateAggregator.detect_web_context()` performs a second semantic enrichment pass over the accumulated nmap service list. For every service identified as a web service (by name in `WEB_SERVICES` or port in `WEB_PORTS`), it emits `web_service('host', port, 'product').` and `has_user_input('host', port, 'http_params').`; the latter is the entry predicate for injection-chain rules. If the combined service name and product string contains any of `express`, `node`, `flask`, `django`, or `rails`, the inferencer additionally emits `has_api_endpoint('host', port, 'POST', '/api')`, `has_login_form('host', port)`, `has_file_upload('host', port)`, and `has_cookie_auth('host', port)` — each of which activates a distinct rule chain (injection, credential brute-force, file upload exploitation, and session fixation respectively). For database services it emits `uses_database('host', port, 'svc')` and `has_data('host', 'database_records')`. For auth services it emits `auth_service('host', port, 'svc')`. These predicates are placed in the `web_context`, `data_context`, and `auth_context` categories.

### Attack Goal Generation

`PredicateAggregator.generate_attack_goals()` generates `attackGoal(...)` predicates that tell MulVAL which goal states to search for in the attack graph. The generation is conditional on the discovered context: `attackGoal(compromise(Host, _))` is always emitted; `attackGoal(initial_access(Host, _, _))` and `attackGoal(exec_achieved(Host, _))` are added if any web ports were found; `attackGoal(data_exfiltrated(Host, _, _))` is added if any database service was discovered; `attackGoal(cred_obtained(Host, _, _))` is added if any auth service (SSH, FTP, RDP, etc.) was discovered. This means the set of goals is data-driven from scanner output rather than hardcoded, so a target with only a database service and no web interface will produce a graph optimized for exfiltration rather than web exploitation.

### Predicate File Output Format

`PredicateAggregator.write_predicates(output_file)` writes the final `input_predicates.P` with a header comment block and predicates organized in a fixed category order: `network_topology`, `services`, `os_info`, `roles`, `web_context`, `auth_context`, `data_context`, `critical_cves`, `exploits`, `service_cve_correlation`, followed by any remaining categories and then the `Attack Goals` block. Each category is preceded by a `% === Category Name ===` comment. The `attacker_at('internet')` and `host('target')` network context predicates are added by `add_network_context()` just before writing, ensuring every input file satisfies the minimum topology requirements for MulVAL's graph traversal. The total predicate count (including goals) is logged on completion.

### MulVAL Execution and Rules File Selection

After `input_predicates.P` is written, `MulvalExecutor.run()` resolves the rules file. If no custom `--rules` path is provided, it uses `kb/web_security_rules.P`; the web security rules define a focused 10-stage kill chain (reconnaissance → surface detection → vulnerability confirmation → initial access → code execution → privilege escalation → credential access → data exfiltration → lateral movement → full compromise) that is matched to the CTF and web-target predicate vocabulary emitted by the scanner pipeline.

The executor first invokes the locally installed `graph_gen.sh`, `attack_graph`, and `render.sh` tools. If local execution is unavailable or fails, it checks Docker availability and falls back to:

```
docker run --rm -v <base_dir>:/data -w /data/<output_dir> wilbercui/mulval \
  bash -lc "graph_gen.sh /data/input_predicates.P -r /data/kb/web_security_rules.P -v"
```

Both execution paths use a 120-second timeout. After execution, `TraceProcessor.normalize_trace_output` normalizes the raw `trace_output.P` for parser compatibility, `TraceProcessor.parse_trace_to_json` extracts structured attack paths into `paths.json`, and the attack graph PDF is generated via `attack_graph` and `render.sh`. The `paths.json` schema stores `total_paths`, `attack_goals`, `target_host`, and a `paths` array where each entry carries a `path_id`, `goal`, `length`, `technique_count`, `min_confidence`, and a `steps` array distinguishing `precondition` and `technique` step types with `rule_description`, `confidence`, and `derived_fact` fields.

## Source Files (Implementation)

- `interaction_rule_generation/nlp_pipeline/initial_predicates.P`
- `interaction_rule_generation/nlp_pipeline/enterprise-techniques.csv`
- `interaction_rule_generation/nlp_pipeline/mobile-techniques.csv`
- `interaction_rule_generation/nlp_pipeline/ics-techniques.csv`
- `interaction_rule_generation/nlp_pipeline/rules.manifest.json`
- `interaction_rule_generation/nlp_pipeline/rule-gen_logs.txt`
- `interaction_rule_generation/nlp_pipeline/nlp_inputs/predicates_core.jsonl`
- `interaction_rule_generation/nlp_pipeline/nlp_inputs/predicates_meta.jsonl`
- `interaction_rule_generation/nlp_pipeline/nlp_inputs/var_canonical.jsonl`
- `interaction_rule_generation/nlp_pipeline/nlp_inputs/systemprompt.md`
- `interaction_rule_generation/nlp_pipeline/mulval_rules/`
- `interaction_rule_generation/nlp_pipeline/nlp_outputs/`
- `interaction_rule_generation/nlp_pipeline/generate_full_kb.py`
- `interaction_rule_generation/nlp_pipeline/kb/full_interaction_rules.P`
- `MulVAL/generate_predicates.py`
- `MulVAL/scanner_executor.py`
- `MulVAL/mulval_executor.py`
- `MulVAL/trace_processor.py`
- `MulVAL/report_generator.py`
- `MulVAL/parsers/base_parser.py`
- `MulVAL/parsers/nmap_parser_strategy.py`
- `MulVAL/parsers/trivy_parser_strategy.py`
- `MulVAL/parsers/scanner_strategy_factory.py`
- `MulVAL/kb/web_security_rules.P`
- `MulVAL/kb/full_interaction_rules.P`
