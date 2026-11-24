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
| "Which applications can talk to which?" | Security group references | one `20-comms-*.mmd` per SG |

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
  00-overview.mmd            account overview: VPCs, TGWs, peerings, VPN
  10-seg-<vpc>.mmd           one per VPC: subnet tiers + gateways + routes
  20-comms-<sg>-<id>.mmd     one per security group with an app-to-app rule
  21-internet-exposure.mmd   every SG reachable from 0.0.0.0/0 or ::/0
  START-HERE.md              index + how to read each family
  reports/
    subnets.csv              every subnet and its derived classification
    route-tables.csv         every route, normalised
    security-group-rules.csv every SG rule, flattened (the full evidence)
    security-group-members.csv  which EC2/ALB/RDS/ENI uses each SG
```

### `10-seg-*` — segmentation

Each subnet is a node, coloured by its **derived** tier, and the colour is
backed by evidence in the label:

- `PUBLIC` (orange) — default route `0.0.0.0/0 → Internet Gateway`
- `PRIVATE` (grey) — default route to NAT / TGW / VPN
- `ISOLATED` (amber) — no default route at all

The node also carries its route table and NACL, and arrows show
`subnet → IGW/NAT/VGW/TGW/peering/endpoint` with the route that justifies each
hop. Classification comes from the route table, never from the subnet name.

### `20-comms-*` — application communication

The blue hub node is the security group you are inspecting. An arrow **into**
the hub is a rule that lets the source reach it; an arrow **out** is a rule that
lets it reach the destination. Labels are port/protocol (`:5432/tcp`, `:443/tcp`,
`all`). The node lists who uses it (`used by: EC2 app-01, RDS prod-postgres`),
which is what turns "sg-0abc…" into "the database tier".

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
