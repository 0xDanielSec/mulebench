# Security policy

## Reporting a vulnerability in Mulebench

Please report vulnerabilities **privately**, through a GitHub security
advisory: on the repository page, open **Security**, then **Report a
vulnerability**. Do not open a public issue, pull request or discussion for
a vulnerability.

A useful report includes:

- the affected version or commit;
- what an attacker can do, and under which conditions;
- steps to reproduce, ideally with a minimal scenario, report or trace file;
- any suggested fix.

What to expect: an acknowledgement within 7 days, and an assessment within 30
days. Fixes are released and credited (unless you prefer otherwise) once a fix
is available. This is a volunteer project; the timelines are best effort.

## Scope

In scope: the Mulebench tool itself, meaning the code in this repository and
the packages built from it. For example:

- the harness, ledger or invariants misjudging an attack in a way that hides
  a violation (a false "resisted"), or that can be triggered by scenario,
  report or trace input;
- code execution, path traversal or file writes outside the requested
  output when loading scenarios, workloads, reports, traces or
  `--agent-module` specs, or when building the HTML viewer;
- secrets (API keys, model output text the reports promise not to store)
  leaking into reports, checkpoints, cassettes, logs or the viewer;
- the monitor's KQL/Sigma exports producing queries that are unsafe to run.

Out of scope:

- the behaviour of third-party models or agents under test (see below);
- vulnerabilities in dependencies, which belong upstream (tell us too if
  Mulebench is affected in a way that needs a change here);
- the synthetic attack scenarios themselves: they are intentionally
  malicious inputs for testing agents, and finding that an agent fails them
  is the tool working as designed;
- reports that require a modified Mulebench or a malicious `--agent-module`
  you chose to run (agent modules are trusted code, see
  [docs/bring-your-own-agent.md](docs/bring-your-own-agent.md)).

## Findings about models and agent vendors

Mulebench is meant to find weaknesses in AI agents. If you use it and find
that a third-party model, agent product or vendor service can be manipulated
into violating a financial invariant, that is a finding about the vendor, not
about Mulebench. Report it to the vendor through its own disclosure channel
and follow coordinated disclosure: give the vendor reasonable time to fix
before publishing, and do not publish working exploit details against a
live, deployed system. Scenarios contributed to this repository must stay
synthetic and target the bundled reference agents and your own agents only
(see [CONTRIBUTING.md](CONTRIBUTING.md)).
