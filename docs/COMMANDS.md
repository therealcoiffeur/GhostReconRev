# Commands Used

## `amass`

```bash
amass enum -silent -timeout ${AMASS_TIMEOUT:-60} -d <DOMAIN>
amass subs -names -d <DOMAIN> -o artifacts/collectors/<TASK_ID>_amass.txt
```

## `subfinder`

```bash
subfinder -silent -d <DOMAIN> -all -o artifacts/collectors/<TASK_ID>_subfinder.txt
```

## `assetfinder`

```bash
assetfinder -subs-only <DOMAIN> > artifacts/collectors/<TASK_ID>_assetfinder.txt
```

## `crt.sh`

```text
GET https://crt.sh/json?q=<DOMAIN>
```

This response is saved as the following file.

```text
artifacts/collectors/<TASK_ID>_crtsh.json
```

The `crt.sh` task retries up to 3 times before it is marked failed, and the raw
JSON response is stored without truncation.

## `gau`

```bash
echo "<DOMAIN_OR_SUBDOMAIN>" | gau --threads ${GAU_THREADS:-10} --o artifacts/collectors/<TASK_ID>_gau_<HASH>.txt
```

This runs in the dedicated `run_gau_enumeration` task after passive collection
and executes in parallel with `run_dnsx_resolution`.

## `dnsx`

```bash
echo "<DOMAIN_OR_SUBDOMAIN>" | dnsx -no-color -recon -o artifacts/collectors/<TASK_ID>_dnsx_<HASH>.txt
```

Parsed records determine status shown in Targets tree (`RESOLVED` / `UNRESOLVED`).
Before running `dnsx`, the pipeline runs `host <DOMAIN_OR_SUBDOMAIN>`. `dnsx` is
executed only when that pre-check command succeeds.

Resolution classification is strict.
- `RESOLVED` only when `dnsx` reports at least one `A`, `AAAA`, or `CNAME`
record for the hostname.
- `NEEDCHECK` when `dnsx` succeeds but has no `A` / `AAAA` / `CNAME` proof
(including outputs with only `SOA` / `TXT` / `NS` / `MX` / `SRV`).
- `UNRESOLVED` when pre-check or collector fails and no usable `dnsx` proof is
available.

## `naabu`

```bash
naabu -host <DOMAIN_OR_SUBDOMAIN> -o artifacts/collectors/<TASK_ID>_naabu_<HASH>.txt
```

This runs in the dedicated `run_naabu_resolved` task (`ENRICH_POST`) and only
targets entities marked `RESOLVED` by `dnsx` classification.

## `nerva`

```bash
nerva --json -t <DOMAIN_OR_SUBDOMAIN>:<PORT> -o artifacts/collectors/<TASK_ID>_nerva_<HASH>_<PORT>.json
```

This task is disabled by default. It is only added to the pipeline when
`ACTIVE_ENRICHMENT_ENABLED=true` is set in `.env` and the operator keeps active
enrichment enabled for that run on the start page. When active enrichment
support is available, that checkbox is preselected by default. Once the run is
started with that option enabled, supported active enrichment tasks are
scheduled automatically when their prerequisites are met.

- `httpx` enrichment for detected `host:port` endpoints.

```bash
httpx -no-color -random-agent -status-code -location -title -server -tech-detect -wordpress -ip -extract-fqdn -cdn -follow-redirects -max-redirects <HTTPX_MAX_REDIRECTS> -u <DOMAIN_OR_SUBDOMAIN>:<PORT> -o artifacts/collectors/<TASK_ID>_httpx_<HASH>_<PORT>.txt
```

This runs in the dedicated `run_httpx_on_open_ports` task (`ENRICH_POST`) after
`naabu` results are available. Inside this task, endpoints are probed in
parallel (bounded by `HTTPX_MAX_WORKERS`) and the redirect cap is controlled by
`HTTPX_MAX_REDIRECTS`.