# dionysus

Read-only AWS **network segmentation + application communication** mapper.

It takes the one thing your old tool got right — reading route tables, security
groups and the resources attached to them — and stops trying to draw the whole
account as a single picture. Instead it emits **many small Mermaid (`.mmd`)
diagrams**, each small enough that [mermaid.live](https://mermaid.live) loads it
instantly, and each answering one of the two questions a segmentation audit
asks.

```bash
git clone https://github.com/PAla46/dionysus.git
cd dionysus
python3 dionysus.py --all-regions --out ./seg-comm-map
```

Then paste any `*.mmd` file from `seg-comm-map/` into
<https://mermaid.live>. Start with `START-HERE.md`.

It only calls `Describe*` / `List*` APIs. It never creates, modifies or deletes
anything. It is a single file (`dionysus.py`) with no dependency beyond
`boto3` (preinstalled on AWS CloudShell).

---

## Why two families, not one big diagram

The two halves of the audit live in two different layers of the AWS config, and
they have to be drawn from two different axes:

| Question | The data that answers it | This tool emits |
| --- | --- | --- |
| "Is segmentation in place?" | Subnets + route tables + NACLs | one `10-seg-*.mmd` per VPC |
| "Which applications can talk to which?" | Security group references | one `20-comms-*.mmd` per VPC (SG-level) |

**Route tables describe routing, not conversation.** A route table says
"traffic for `10.x` goes via the transit gateway"; it never says
"app-server-01 may reach db-03 on :5432". That second fact is a *security group
reference* (`sg-app` allows ingress from `sg-alb` on `:8080`). So splitting a
too-big diagram by route table can never produce the application graph — only
splitting by security group can.

A single `00-network-topology.mmd` for a real production account (a couple of
VPCs, one of them large) runs to tens of KB and hundreds of edges, which
mermaid.live refuses to render. Every file this tool writes is intentionally
small.

---

## What it produces

```
<out>/
  00-overview.mmd                 account overview: VPCs, TGWs, peerings, VPN
  10-seg-<vpc>.mmd                HIGH: one per VPC, route-table level, aggregated arrows
  10-seg-<vpc>-detail.mmd         LOW:  one per VPC, subnet level, every route/CIDR
  20-comms-<vpc>.mmd              HIGH: one per VPC, SG -> SG references only
  20-comms-<vpc>-detail.mmd       LOW:  one per VPC, SG -> SG plus CIDR rules
  20-focus-<sg>-<id>.mmd          (only with --focus-sg) that SG highlighted
  21-internet-exposure.mmd        every SG reachable from 0.0.0.0/0 or ::/0
  START-HERE.md                   index + how to read each family
  comms/<sg>-<id>.mmd             (only with --sg-drilldowns) one per security group
  reports/
    subnets.csv                   every subnet and its derived classification
    route-tables.csv              every route, normalised
    security-group-rules.csv      every SG rule, flattened (the full evidence)
    security-group-members.csv    which EC2/ALB/RDS/ENI uses each SG
```

By default `--granularity both` emits the high and low variants of each family;
`--granularity high` or `--granularity low` emits just one.

### `10-seg-*` — segmentation (two granularities)

- **High** (`10-seg-<vpc>.mmd`): one box per **route table** (listing its
  subnets), one aggregated arrow per gateway target. This is what keeps a
  16-subnet VPC from turning into a 40,000-px hairball.
- **Low** (`10-seg-<vpc>-detail.mmd`): one node per **subnet**, one arrow per
  route/CIDR. The full detail.

Either way, each subnet/route table is coloured by its **derived** tier, and the
colour is backed by evidence in the label:

- `PUBLIC` (orange) — default route `0.0.0.0/0 → Internet Gateway`
- `PRIVATE` (grey) — default route to NAT / TGW / VPN
- `ISOLATED` (amber) — no default route at all

Classification comes from the route table, never from the subnet name.

### `20-comms-*` — application communication (two granularities)

One diagram per VPC, drawn at **security-group level** (not resource level).
Each node is a security group; an arrow `A --> B :5432/tcp` means B's rules let A
reach B on 5432 (or A's rules let A send to B). Red nodes are reachable from the
internet. Node labels list the EC2/ALB/RDS resources using the group, so
`sg-0abc…` reads as "the database tier".

- **High** (`20-comms-<vpc>.mmd`): security-group → security-group references only.
- **Low** (`20-comms-<vpc>-detail.mmd`): the same graph **plus the CIDR/prefix
  rules**, so "allows the whole VPC / a peer network" becomes a visible arrow.

For a single-application zoom, `--sg-drilldowns` writes one `comms/<sg>-<id>.mmd`
per security group, and `--focus-sg <id>` produces one diagram with that SG's
arrows highlighted and everything else dimmed.

### Arrow colours

Edges are coloured semantically (a 58-SG graph cannot carry 58 colours):
red = management/internet ingress, blue = web, green = data stores,
purple/pink/teal = TGW/peering/endpoint, grey = `all`/other. With `--focus-sg`,
the focus SG's arrows are orange and the rest dim grey.

### `21-internet-exposure`

Every security group with an ingress rule from `0.0.0.0/0` or `::/0`, with the
open ports. This is usually the first thing an auditor looks at.

---

## Usage

```bash
# every enabled region
python3 dionysus.py --all-regions --out ./seg-comm-map

# specific regions
python3 dionysus.py --regions eu-west-1,ap-south-1 --out ./map

# a specific profile (CloudShell uses the session by default)
python3 dionysus.py --all-regions --profile audit

# only one granularity (default is 'both')
python3 dionysus.py --all-regions --granularity high --out ./map
python3 dionysus.py --all-regions --granularity low  --out ./map

# trace one security group's arrows (highlighted, rest dimmed)
python3 dionysus.py --all-regions --focus-sg sg-0123456789abcdef0 --out ./map

# per-security-group drill-downs, too (a comms/<sg>-<id>.mmd per SG)
python3 dionysus.py --all-regions --out ./map --sg-drilldowns

# no AWS? verify the tool works first:
python3 dionysus.py --demo --out ./demo
```

### Permissions (read-only)

```
ec2:DescribeVpcs                 ec2:DescribeSubnets
ec2:DescribeRouteTables          ec2:DescribeInternetGateways
ec2:DescribeNatGateways          ec2:DescribeTransitGateways
ec2:DescribeTransitGatewayAttachments
ec2:DescribeVpcPeeringConnections
ec2:DescribeVpnGateways          ec2:DescribeVpcEndpoints
ec2:DescribeSecurityGroups       ec2:DescribeNetworkAcls
ec2:DescribeNetworkInterfaces    ec2:DescribeInstances
ec2:DescribeFlowLogs             ec2:DescribeRegions
elasticloadbalancing:DescribeLoadBalancers    # names the ALBs (optional)
rds:DescribeDBInstances                       # names the databases (optional)
sts:GetCallerIdentity
```

A denied call is recorded as a collection warning and printed in
`START-HERE.md`; the affected part of the output degrades instead of failing the
run. If the ELB or RDS calls are denied you still get the full map, just with
fewer human-readable "used by" names.

---

## Limitations

- **Configured, never observed.** These diagrams show what routing + security
  groups *allow*, not what actually flows. Only VPC Flow Logs (or TGW flow logs,
  Network Firewall) contain observed traffic. The overview annotates each VPC
  with its flow-log status so this gap stays visible.
- **Security group references are the app graph's unit.** An app-to-app path
  that is expressed as a CIDR rule rather than an `sg-id` reference appears only
  in `security-group-rules.csv` and the per-SG exposure, not as an `sg → sg`
  arrow.
- **One SG reference = one arrow.** Ports are collapsed per rule, not per
  source IP.

---

## Demo

`--demo` builds a small synthetic estate (two VPCs, public/private/isolated
subnets, an ALB → app → DB tier) with no AWS calls, so you can verify the tool
end-to-end before pointing it at a real account.

## License

MIT. See [LICENSE](LICENSE).
