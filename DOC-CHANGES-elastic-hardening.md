# Documentation changes — OpenVidu DigitalOcean elastic hardening

Target repository: **openvidu.io**, branch **`next`**.

These documentation edits accompany the `elastic-hardening` changes in `openvidu-digitalocean`.
After that work, the DigitalOcean **elastic** autoscaler now enforces `min`/`max` and honors
`initialNumberOfMediaNodes` on first boot — exactly like the **HA** deployment already did.
The docs below still describe the old (pre-hardening) behavior and need updating.

All line numbers are indicative; match on the surrounding text.

---

## (a) Elastic install.md — `initialNumberOfMediaNodes` row

File: `docs/docs/self-hosting/elastic/digitalocean/install.md` (≈ lines 113–116)

The elastic autoscaler now brings the cluster to `max(min, initial)` on its first run, so the
row should describe the real behavior. The HA install.md (≈ line 117) already uses this wording;
align elastic with it.

**Current**

```html
<tr>
<td style="white-space: nowrap;"><code>initialNumberOfMediaNodes</code></td>
<td style="white-space: nowrap;"><code>1</code></td>
<td>Number of initial media nodes to deploy.</td>
</tr>
```

**Proposed**

```html
<tr>
<td style="white-space: nowrap;"><code>initialNumberOfMediaNodes</code></td>
<td style="white-space: nowrap;"><code>1</code></td>
<td>Number of Media Nodes to create at initial deployment. On its first run the autoscaler brings the cluster straight to <code>max(minNumberOfMediaNodes, initialNumberOfMediaNodes)</code> Media Nodes; afterwards the number stays between <code>minNumberOfMediaNodes</code> and <code>maxNumberOfMediaNodes</code> based on CPU load. Ignored when <code>fixedNumberOfMediaNodes</code> &gt; 0.</td>
</tr>
```

---

## (b) production-ready/scalability.md — DigitalOcean tab, `initialNumberOfMediaNodes` row

File: `docs/docs/self-hosting/production-ready/scalability.md` (≈ lines 292–325, DigitalOcean tab)

This table is shared by the DO elastic and HA deployments. Updating the `initialNumberOfMediaNodes`
description here was previously deferred because elastic and HA behaved differently. They now behave
identically, so the shared row can be updated.

**Current** (≈ lines 300–302)

```html
<tr>
    <td>initialNumberOfMediaNodes</td>
    <td>1</td>
    <td>Number of initial media nodes to deploy.</td>
</tr>
```

**Proposed**

```html
<tr>
    <td>initialNumberOfMediaNodes</td>
    <td>1</td>
    <td>Number of Media Nodes to create at initial deployment. On its first run the autoscaler scales the cluster straight to max(minNumberOfMediaNodes, initialNumberOfMediaNodes); afterwards it stays between min and max based on CPU load. Ignored when fixedNumberOfMediaNodes &gt; 0.</td>
</tr>
```

The `minNumberOfMediaNodes` / `maxNumberOfMediaNodes` rows in this same table (≈ lines 305–312)
are already accurate ("Minimum/Maximum number of media nodes to deploy") — no change needed.

---

## (c) Remove the misleading "(for reference, manual scaling required)" from min/max rows

The autoscaler (a DigitalOcean Function on a 4-minute schedule) actively enforces both
`minNumberOfMediaNodes` and `maxNumberOfMediaNodes`. The "manual scaling required" caveat is
no longer true for either deployment and should be removed.

### (c.1) Elastic install.md

File: `docs/docs/self-hosting/elastic/digitalocean/install.md` (≈ lines 118–126)

**Current**

```html
<td>Minimum number of media nodes to deploy (for reference, manual scaling required).</td>
...
<td>Maximum number of media nodes to deploy (for reference, manual scaling required).</td>
```

**Proposed**

```html
<td>Minimum number of media nodes. The autoscaler never scales below this value.</td>
...
<td>Maximum number of media nodes. The autoscaler never scales above this value.</td>
```

### (c.2) HA install.md

File: `docs/docs/self-hosting/ha/digitalocean/install.md` (≈ lines 122 and 127)

Same replacement as (c.1) — the two rows carry the identical "(for reference, manual scaling
required)" text and should get the identical "never scales below/above this value" wording.

---

## (d) custom-scale-in.md — "Lambda function" → "DigitalOcean Function"

File: `shared/self-hosting/digitalocean/custom-scale-in.md` (line 7)

This is the DigitalOcean-specific shared snippet, yet it calls the scaler a "Lambda function"
(AWS terminology). On DigitalOcean the scaler is a **DigitalOcean Function** (OpenWhisk).

**Current** (line 7)

```markdown
    - A Lambda function is deployed on a four-minute schedule to manage the scaling of Media Nodes. It does this by checking the **`minNumberOfMediaNodes`** and **`maxNumberOfMediaNodes`** variables, polling the average CPU usage, and comparing it against **`scaleTargetCPU`**. Once a scale-in decision is made, the main tag is removed from the target Media Node and a "draining" tag is applied to mark it as ready for shutdown.
```

**Proposed**

```markdown
    - A DigitalOcean Function is deployed on a four-minute schedule to manage the scaling of Media Nodes. It does this by checking the **`minNumberOfMediaNodes`** and **`maxNumberOfMediaNodes`** variables, polling the average CPU usage, and comparing it against **`scaleTargetCPU`**. Once a scale-in decision is made, a "draining" tag is applied to the target Media Node and the main tag is then removed, marking it as ready for shutdown.
```

Two edits in this sentence:

1. "A Lambda function" → "A DigitalOcean Function".
2. Tag order: the hardening reversed the scale-in tagging so the **draining** tag is applied
   **before** the main tag is removed (previously the main tag was removed first, which left an
   untagged droplet invisible to the autoscaler/destroy/watcher if the Function crashed between the
   two API calls). The sentence has been reworded to match the new, safe order.

---

## (e) Optional — deployment-time figures for DO elastic (none exist today)

There are currently no time estimates documented for the DigitalOcean elastic deployment.
This is optional and should only be added after measuring, but note one relevant improvement:

- The master node now publishes `secrets.env` to the Space (with `ALL_SECRETS_GENERATED=true`)
  and the shared URLs **early** — right after the secrets are generated and **before** the OpenVidu
  installer runs. Media nodes wait for that object, so they can begin their own installation roughly
  **4–6 minutes earlier** than before (the master no longer has to finish installing first).

If the docs team decides to publish a "typical time to ready" for DO elastic, this is the moment to
measure it, since the startup critical path changed.
