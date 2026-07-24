# Documentation changes for branch `ha-optimizations`

These instructions are for the Claude that maintains the docs repo
**`/home/sergio/Escritorio/openvidu/openvidu.io`** (branch **`next`**, already up to date).

They describe the user-facing documentation updates required by the OpenVidu **PRO High
Availability on DigitalOcean** optimizations implemented in `openvidu-digitalocean`
(directory `pro/ha/`). Apply them step by step.

> Context of the code change that motivates this:
> - `initialNumberOfMediaNodes` was declared but **unused** in the DO HA Terraform. It now
>   has effect: on the autoscaler's **first run** (when the cluster has 0 media nodes) the
>   cluster is brought straight to `max(minNumberOfMediaNodes, initialNumberOfMediaNodes)`
>   media nodes. After bootstrap the floor is just `minNumberOfMediaNodes`.
> - The autoscaler is now **invoked once immediately** at deploy time (bootstrap), so the
>   first media node(s) come up without waiting for the first `*/4` cron tick (saves up to
>   ~4 minutes of idle time).
> - The new source-of-truth wording lives in `pro/ha/variables.tf`:
>   *"Number of media nodes to create at bootstrap. On its first run (when no media nodes
>   exist yet) the autoscaler brings the cluster straight to
>   max(minNumberOfMediaNodes, initialNumberOfMediaNodes); afterwards autoscaling keeps it
>   between min and max based on CPU. Ignored when fixedNumberOfMediaNodes > 0."*

---

## Change A — `initialNumberOfMediaNodes` description in the HA DigitalOcean install page

**File:** `docs/docs/self-hosting/ha/digitalocean/install.md`

Inside the parameters table (wrapped in a `<details>` element), locate the
`initialNumberOfMediaNodes` row (around **lines 115–117**). Only the third cell (the
description) changes.

**Find (exact line, 4-space indentation):**

```html
    <td>Number of initial media nodes to deploy.</td>
```

immediately below these two lines (use them to disambiguate — this description string
does not appear anywhere else in this file):

```html
    <td style="white-space: nowrap;"><code>initialNumberOfMediaNodes</code></td>
    <td style="white-space: nowrap;"><code>1</code></td>
```

**Replace that description cell with:**

```html
    <td>Number of Media Nodes to create at initial deployment. On its first run the autoscaler brings the cluster straight to <code>max(minNumberOfMediaNodes, initialNumberOfMediaNodes)</code> Media Nodes; afterwards the number stays between <code>minNumberOfMediaNodes</code> and <code>maxNumberOfMediaNodes</code> based on CPU load. Ignored when <code>fixedNumberOfMediaNodes</code> &gt; 0.</td>
```

(Note: `>` is written `&gt;` because it is inside an HTML table cell.)

---

## Change B — `initialNumberOfMediaNodes` description in the Scalability page (DigitalOcean tab)

**File:** `docs/docs/self-hosting/production-ready/scalability.md`

This page repeats the autoscaling parameter table per cloud provider inside content tabs.
The string `<td>Number of initial media nodes to deploy.</td>` appears **three times**
(AWS tab, DigitalOcean tab, OCI tab). **Only change the DigitalOcean one.**

1. Find the DigitalOcean tab, which starts with this line (around **line 284**):

   ```
   === ":fontawesome-brands-digital-ocean:{.icon .lg-icon .tab-icon} DigitalOcean"
   ```

2. Within that tab (before the next tab
   `=== ":custom-oracle-cloud-infrastructure:{.icon .lg-icon .tab-icon} OCI"`),
   locate the `initialNumberOfMediaNodes` row (around **lines 300–302**):

   ```html
                   <td>initialNumberOfMediaNodes</td>
                   <td>1</td>
                   <td>Number of initial media nodes to deploy.</td>
   ```

3. Replace **only** the description cell (16-space indentation) with:

   ```html
                   <td>Number of Media Nodes to create at initial deployment. On its first run the autoscaler brings the cluster straight to max(minNumberOfMediaNodes, initialNumberOfMediaNodes) Media Nodes; afterwards the number stays between min and max based on CPU load. Ignored when fixedNumberOfMediaNodes &gt; 0.</td>
   ```

> ⚠️ **IMPORTANT CAVEAT — shared with OpenVidu Elastic on DigitalOcean.**
> The DigitalOcean tab in `scalability.md` documents autoscaling for **both** Elastic and HA
> on DigitalOcean (it links both at the top of the tab). The `initialNumberOfMediaNodes`
> fix in this branch was applied **only to `pro/ha/`**; `pro/elastic/` on DigitalOcean was
> intentionally left unchanged and still ignores `initialNumberOfMediaNodes` (its autoscaler
> still uses `if n < MIN_NODES`).
>
> Therefore, decide with the orchestrator before applying Change B:
> - **Option 1 (recommended):** apply the equivalent code fix to `pro/elastic/` on
>   DigitalOcean first, then this shared description is accurate for both.
> - **Option 2:** hold Change B until Elastic is fixed, and apply **only Change A** now
>   (the HA-specific page), which is unambiguously correct.
>
> Do **not** apply Change B blindly while Elastic DO still has the old behavior, or the
> shared table will misdescribe Elastic.

---

## Change C — (Optional) Add a startup-time note on the HA DigitalOcean install page

**File:** `docs/docs/self-hosting/ha/digitalocean/install.md`

The HA DigitalOcean page currently publishes **no figure** for how long a deployment takes
to have media capacity ready. The bootstrap-invocation optimization shortens the initial
wait for the first Media Node(s). If the team wants to publish a figure, add a note next to
the autoscaling bullet (around **line 43**):

**Find:**

```markdown
    - An automated process using DigitalOcean Functions handles the scale-in and scale-out of Media Nodes based on system load.
```

**Append a sub-note (fill the numbers from an `ov-cloud-tester` measurement):**

```markdown
    - An automated process using DigitalOcean Functions handles the scale-in and scale-out of Media Nodes based on system load. The initial Media Node(s) are provisioned right after the Master Nodes are ready (a bootstrap invocation avoids waiting for the first scheduled tick). A full deployment is typically ready in **X to Y minutes** _(rellenar con medición de ov-cloud-tester)_.
```

This is optional; if no measurement is available yet, skip it rather than publishing a
placeholder.

---

## Confirmation — what does NOT change for users

- **No variable renames, no new user-facing variables, no removed variables, no output
  changes.** Default values are unchanged (`initialNumberOfMediaNodes = 1`,
  `minNumberOfMediaNodes = 1`, `maxNumberOfMediaNodes = 5`, `scaleTargetCPU = 50`,
  `fixedNumberOfMediaNodes = 0`).
- The credential-verification flow is unchanged: `secrets.env` still appears in the
  cluster-data Space and still contains all credentials
  (`docs/.../ha/digitalocean/install.md` sections around lines 249–265 remain valid).
- The internal coordination redesign (each Master publishes its private IP to a separate
  `coordination/master-ip-N` object in the cluster-data bucket instead of a serial
  read-modify-write of a single `secrets.env`) is **not surfaced in the docs** and needs no
  documentation change.

## Obsolete-claims audit (point d)

- Searched both pages and the shared include
  `shared/self-hosting/digitalocean/custom-scale-in.md`. **No claim states that the
  autoscaler "creates 1 node per cycle"**, so there is nothing to correct there. The shared
  include only describes the four-minute scale-in schedule and the draining/graceful
  shutdown, which are **unchanged** — do not edit it.
- **Minor, optional:** the screenshot `assets/images/platform/self-hosting/ha/digitalocean/secrets-env.png`
  (referenced around line 254 of the HA install page) may now be slightly stale if it shows
  `MASTER_NODE_PRIVATE_IP_1..4` lines, because `secrets.env` no longer stores Master IPs.
  This does not affect the documented purpose (viewing credentials). Re-capture only if the
  screenshot explicitly shows those removed lines.
