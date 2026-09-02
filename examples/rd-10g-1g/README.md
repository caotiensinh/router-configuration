# 10G + 1G reference example

This example is synthetic and contains no live credentials or production router configuration.

After installing the package locally:

```bash
routerctl multiwan --wan wan10g=10000 --wan wan1g=1000
```

Expected normalized weight:

```json
{
  "wan10g": 10,
  "wan1g": 1
}
```

Generate a read-only change plan:

```bash
routerctl plan \
  --desired examples/rd-10g-1g/desired.json \
  --actual examples/rd-10g-1g/actual.json
```

`routerctl plan` does not connect to a router and does not apply changes. Secret-like paths are redacted in plan output.