# soachecker

fetches SOA for last seen object in passivedns stream

SOA serves as an additional intel source for suspect domains

## Installation
config: edit the `soachecker.conf` file, especially the `local_nets`, `stop_list` and `passivedns_log_file` parameters.

The associated `Pipfile` contains all dependencies, install by:
```
pipenv install
```

run:
```
pipenv run python soachecker.py
```

## Operation
workers: a bunch of worker-threads is created, all listening on a single task-queue
- a SOA-request is issued for every key (host/domain-name) encountered
   - before a request is made, the internal cache (maintained by collector, below) is checked to avoid excessive identical queries
   - dns.resolver.zone_for_name() to determine zone-top
- resolved SOA are fed into the result-queue

feeder: one (main) thread reads (by pygtail) the passivedns/bro/zeek log file
- log file configurable in soachecker.conf
- filters internal requests of certain types and feeds the task-queue (also in config)

collector: one thread reads the result-queue and manages the internal cache
- at given intervals the cache is cleaned based on the TTL from the response (still it might get really big in corporate environments)

The request/response pair is logged via passivedns like any other request (eg. captured in SIEM)
