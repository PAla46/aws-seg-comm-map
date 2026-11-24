#!/usr/bin/env python3
"""Dionysus \u2014 AWS network segmentation + application communication mapper.

Read-only. Runs straight from a clone on AWS CloudShell (boto3 is preinstalled):

    git clone https://github.com/PAla46/dionysus.git
    cd dionysus
    python3 dionysus.py --all-regions --out ./seg-comm-map

It answers the two questions a network segmentation audit asks, and it answers
them with *separate* diagrams because the single "whole account" topology is
what mermaid.live refuses to load:

  1. "Is segmentation in place?"         -> one .mmd per VPC, subnet-tier only.
  2. "Which applications can talk to     -> one .mmd per security group that
     which applications?"                    participates in a rule.

The key insight: route tables describe *routing* (subnet tiers, gateway paths),
but configured app-to-app reachability lives in *security group references*
(sg-a allows ingress from sg-b on :5432). Splitting by route table cannot show
the app graph; splitting by security group can.

It only calls Describe* / List* APIs. It never creates, modifies or deletes.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Mermaid text helpers (no third-party deps beyond boto3)
# --------------------------------------------------------------------------- #

ESCAPES = {
    '"': "#quot;",
    "#": "#35;",
    "&": "#amp;",
    "<": "#lt;",
    ">": "#gt;",
    "|": "#124;",
    "`": "#96;",
    "\\": "#92;",
    "{": "#123;",
    "}": "#125;",
    ";": "#59;",
}
_ESCAPE_RE = re.compile("[" + re.escape("".join(ESCAPES)) + "]")


def esc(text: object) -> str:
    raw = str(text if text is not None else "").replace("\r", "")
    lines = [
        _ESCAPE_RE.sub(lambda m: ESCAPES[m.group()], part).strip()
        for part in raw.split("\n")
    ]
    return "<br/>".join(l for l in lines if l) or " "


def trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


# Edge labels are unquoted (`-->|label|`), and Mermaid v11 rejects raw
# brackets/parentheses there. Node labels are already inside `["..."]`, so they
# do not need this and stay readable in the raw file.
_EDGE_ESCAPES = {"(": "#40;", ")": "#41;", "[": "#91;", "]": "#93;"}
_EDGE_RE = re.compile("[" + re.escape("".join(_EDGE_ESCAPES)) + "]")


def esc_edge(text: object) -> str:
    return _EDGE_RE.sub(lambda m: _EDGE_ESCAPES[m.group()], esc(text))


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(text: str, limit: int = 40) -> str:
    out = _SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return (out or "x")[:limit].strip("-")


# classDef bodies (a class is only emitted if at least one node uses it)
STYLES = {
    "internet": "fill:#dbeafe,stroke:#1d4ed8,color:#0f172a",
    "onprem": "fill:#e7e5e4,stroke:#57534e,color:#1c1917",
    "tgw": "fill:#ede9fe,stroke:#6d28d9,color:#1e1b4b",
    "peering": "fill:#f5d0fe,stroke:#a21caf,color:#3b0764",
    "vgw": "fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b",
    "endpoint": "fill:#ccfbf1,stroke:#0f766e,color:#042f2e",
    "public": "fill:#fed7aa,stroke:#c2410c,color:#431407",
    "private": "fill:#e2e8f0,stroke:#475569,color:#0f172a",
    "isolated": "fill:#fef3c7,stroke:#b45309,color:#451a03",
    "rtb": "fill:#f1f5f9,stroke:#64748b,color:#0f172a,stroke-dasharray:4 3",
    "sg": "fill:#e0f2fe,stroke:#0369a1,color:#082f49",
    "sghub": "fill:#bae6fd,stroke:#0284c7,color:#082f49",
    "cidr": "fill:#f8fafc,stroke:#94a3b8,color:#0f172a",
    "exposed": "fill:#fee2e2,stroke:#b91c1c,color:#450a0a",
    "vpc": "fill:#eef2ff,stroke:#4f46e5,color:#1e1b4b",
}

_SHAPES = {
    "box": '["{text}"]',
    "round": '("{text}")',
    "stadium": '(["{text}"])',
    "diamond": '{{"{text}"}}',
    "subroutine": '[["{text}"]]',
    "hex": '{{{{"{text}"}}}}',
}


class Mermaid:
    """Deterministic mermaid flowchart builder (ids come from a counter)."""

    def __init__(self, title: str = "", direction: str = "TB"):
        self.title = title
        self.direction = direction
        self._lines: List[str] = []
        self._ids: Dict[str, str] = {}
        self._counter = 0
        self._defined: set = set()
        self._edges: set = set()
        self._class_of: Dict[str, str] = {}
        self._classes: set = set()
        self._sg_counter = 0

    def nid(self, key: str) -> str:
        if key not in self._ids:
            self._counter += 1
            self._ids[key] = f"n{self._counter}"
        return self._ids[key]

    def node(self, key: str, label: str, shape: str = "box", cls: str = "", limit: int = 80) -> str:
        nid = self.nid(key)
        if nid not in self._defined:
            text = esc(trunc(label, limit))
            rendered = f"{nid}" + _SHAPES.get(shape, _SHAPES["box"]).format(text=text)
            self._lines.append(rendered)
            self._defined.add(nid)
        if cls and self._class_of.get(nid) != cls:
            self._lines.append(f"  class {nid} {cls};")
            self._classes.add(cls)
            self._class_of[nid] = cls
        return nid

    def edge(self, src: str, dst: str, label: str = "", style: str = "-->") -> None:
        a, b = self.nid(src), self.nid(dst)
        body = f"  {a} {style}|{esc_edge(trunc(label, 60))}| {b}" if label else f"  {a} {style} {b}"
        if body in self._edges:
            return
        self._edges.add(body)
        self._lines.append(body)

    def group(self, key: str, label: str) -> "_Group":
        return _Group(self, key, label)

    def render(self) -> str:
        out = [f"flowchart {self.direction}"]
        if self.title:
            out.append(f"%% {self.title}")
        out.extend(self._lines)
        for name in sorted(self._classes):
            out.append(f"  classDef {name} {STYLES[name]};")
        return "\n".join(out) + "\n"


class _Group:
    def __init__(self, b: Mermaid, key: str, label: str):
        self.b = b
        self.label = label
        self.id = ""

    def __enter__(self) -> str:
        self.b._sg_counter += 1
        self.id = f"sg{self.b._sg_counter}"
        self.b._lines.append(f'subgraph {self.id}["{esc(self.label)}"]')
        self.b._lines.append("  direction " + self.b.direction)
        return self.id

    def __exit__(self, *exc) -> bool:
        self.b._lines.append("end")
        return False


# --------------------------------------------------------------------------- #
# Route target classification
# --------------------------------------------------------------------------- #

# (response field, kind) in the order AWS fills them in a route object.
_ROUTE_FIELDS = (
    ("GatewayId", None),  # kind decided from the id prefix
    ("NatGatewayId", "nat"),
    ("NetworkInterfaceId", "eni"),
    ("TransitGatewayId", "tgw"),
    ("VpcPeeringConnectionId", "pcx"),
    ("EgressOnlyInternetGatewayId", "eigw"),
    ("VpcEndpointId", "vpce"),
    ("TransitGatewayAttachmentId", "tgw-attach"),
    ("LocalGatewayId", "lgw"),
    ("CoreNetworkArn", "core"),
    ("InstanceId", "instance"),
)


def _gateway_kind(gateway_id: str) -> str:
    if gateway_id == "local":
        return "local"
    for prefix, kind in (("igw-", "igw"), ("vgw-", "vgw"), ("eigw-", "eigw"), ("lgw-", "lgw")):
        if gateway_id.startswith(prefix):
            return kind
    return "other"


def route_target(raw: dict) -> Tuple[str, str]:
    for field, kind in _ROUTE_FIELDS:
        value = raw.get(field)
        if value:
            if field == "GatewayId":
                kind = _gateway_kind(value)
            return kind or "other", value
    return "other", ""


def route_dest(raw: dict) -> str:
    return (
        raw.get("DestinationCidrBlock")
        or raw.get("DestinationIpv6CidrBlock")
        or raw.get("DestinationPrefixListId")
        or ""
    )


TARGET_PHRASE = {
    "igw": "Internet Gateway",
    "nat": "NAT Gateway",
    "tgw": "Transit Gateway",
    "pcx": "VPC Peering",
    "vgw": "Virtual Private Gateway",
    "eigw": "Egress-only Internet Gateway",
    "vpce": "VPC Endpoint",
    "eni": "Network Interface",
    "local": "local",
}

DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")


def classify(rtb: Optional[dict]) -> Tuple[str, Optional[dict]]:
    """PUBLIC (default -> IGW), PRIVATE (default -> anything else), ISOLATED (no default)."""
    if not rtb:
        return "isolated", None
    default = None
    for route in rtb["routes"]:
        if route["state"] != "active":
            continue
        if route["destination"] in DEFAULT_ROUTES:
            default = route
            break
    if default is None:
        return "isolated", None
    return ("public" if default["kind"] == "igw" else "private"), default


def classification_reason(cls: str, default: Optional[dict]) -> str:
    if default is None:
        return "ISOLATED \u2014 no 0.0.0.0/0 route"
    phrase = TARGET_PHRASE.get(default["kind"], default["kind"])
    return f"{cls.upper()} \u2014 {default['destination']} \u2192 {phrase}"


# --------------------------------------------------------------------------- #
# Inventory (plain dicts; produced identically by live collection or --demo)
# --------------------------------------------------------------------------- #


def new_inventory(account_id: str = "", regions: Sequence[str] = ()) -> dict:
    return {
        "account_id": account_id,
        "regions": sorted(set(regions)),
        "vpcs": {},
        "subnets": {},
        "rtbs": {},
        "igws": {},
        "nats": {},
        "tgws": {},
        "peerings": {},
        "vgws": {},
        "endpoints": {},
        "nacls": {},
        "sgs": {},
        "enis": {},
        "flow_logs": {},  # vpc_id -> count
        "members": {},   # sg_id -> sorted list of owner labels
        "errors": [],
    }


def add_member(inv: dict, sg_id: str, label: str) -> None:
    if not sg_id or not label:
        return
    inv["members"].setdefault(sg_id, set()).add(label)


# --------------------------------------------------------------------------- #
# Collection (read-only boto3)
# --------------------------------------------------------------------------- #


def _try(fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - a missing permission degrades, never aborts
        return exc


class Collector:
    def __init__(self, regions: Sequence[str], profile: str = ""):
        self.regions = regions
        self.profile = profile
        self.errors: List[str] = []

    def client(self, region: str, service: str):
        import boto3

        kwargs = {"region_name": region}
        if self.profile:
            kwargs["profile_name"] = self.profile
        return boto3.client(service, **kwargs)

    def _list(self, client, method: str, key: str, **kwargs) -> List[dict]:
        paginator = client.get_paginator(method)
        out: List[dict] = []
        for page in paginator.paginate(**kwargs):
            out.extend(page.get(key, []) or [])
        return out

    def account_id(self) -> str:
        import boto3

        try:
            kwargs = {"profile_name": self.profile} if self.profile else {}
            sts = boto3.client("sts", **kwargs)
            return sts.get_caller_identity()["Account"]
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"sts.get_caller_identity: {exc}")
            return ""

    def collect(self) -> dict:
        inv = new_inventory(self.account_id(), self.regions)
        for region in self.regions:
            self._collect_region(inv, region)
        inv["errors"] = self.errors
        return inv

    def _collect_region(self, inv: dict, region: str) -> None:
        try:
            ec2 = self.client(region, "ec2")
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"{region}: ec2 client: {exc}")
            return

        def call(method: str, key: str, **kwargs):
            try:
                return self._list(ec2, method, key, **kwargs)
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"{region} {method}: {exc}")
                return []

        vpcs = call("describe_vpcs", "Vpcs")
        for v in vpcs:
            name = ""
            for t in v.get("Tags") or []:
                if t.get("Key") == "Name":
                    name = t.get("Value", "")
            inv["vpcs"][v["VpcId"]] = {
                "id": v["VpcId"],
                "region": region,
                "name": name,
                "cidr": v.get("CidrBlock", ""),
                "is_default": bool(v.get("IsDefault")),
            }

        for s in call("describe_subnets", "Subnets"):
            name = ""
            for t in s.get("Tags") or []:
                if t.get("Key") == "Name":
                    name = t.get("Value", "")
            inv["subnets"][s["SubnetId"]] = {
                "id": s["SubnetId"],
                "vpc_id": s.get("VpcId", ""),
                "region": region,
                "cidr": s.get("CidrBlock", "") or s.get("Ipv6CidrBlock", ""),
                "az": s.get("AvailabilityZone", ""),
                "name": name,
                "rtb_id": "",  # resolved in _link
            }

        for rt in call("describe_route_tables", "RouteTables"):
            name = ""
            for t in rt.get("Tags") or []:
                if t.get("Key") == "Name":
                    name = t.get("Value", "")
            subnet_ids, is_main = [], False
            for a in rt.get("Associations", []) or []:
                if a.get("Main"):
                    is_main = True
                if a.get("SubnetId"):
                    subnet_ids.append(a["SubnetId"])
            inv["rtbs"][rt["RouteTableId"]] = {
                "id": rt["RouteTableId"],
                "vpc_id": rt.get("VpcId", ""),
                "region": region,
                "name": name,
                "is_main": is_main,
                "subnet_ids": subnet_ids,
                "routes": [_norm_route(r) for r in rt.get("Routes", []) or []],
            }

        for i in call("describe_internet_gateways", "InternetGateways"):
            attached = any(a.get("State") == "available" for a in i.get("Attachments", []) or [])
            vpc_id = next((a["VpcId"] for a in i.get("Attachments", []) or [] if a.get("VpcId")), "")
            inv["igws"][i["InternetGatewayId"]] = {
                "id": i["InternetGatewayId"],
                "vpc_id": vpc_id,
                "attached": attached,
            }

        for n in call("describe_nat_gateways", "NatGateways"):
            inv["nats"][n["NatGatewayId"]] = {
                "id": n["NatGatewayId"],
                "vpc_id": n.get("VpcId", ""),
                "subnet_id": n.get("SubnetId", ""),
                "state": n.get("State", ""),
                "connect_type": n.get("ConnectivityType", "public"),
            }

        for t in call("describe_transit_gateways", "TransitGateways"):
            name = ""
            for tag in t.get("Tags") or []:
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
            inv["tgws"][t["TransitGatewayId"]] = {
                "id": t["TransitGatewayId"],
                "name": name,
                "state": t.get("State", ""),
                "attachments": [],
            }

        for a in call("describe_transit_gateway_attachments", "TransitGatewayAttachments"):
            tgw = inv["tgws"].get(a.get("TransitGatewayId", ""))
            if tgw is not None:
                tgw["attachments"].append(
                    {
                        "vpc_id": a.get("ResourceId", ""),
                        "type": a.get("ResourceType", ""),
                        "state": a.get("State", ""),
                    }
                )

        for p in call("describe_vpc_peering_connections", "VpcPeeringConnections"):
            inv["peerings"][p["VpcPeeringConnectionId"]] = {
                "id": p["VpcPeeringConnectionId"],
                "vpc_id": p.get("RequesterVpcInfo", {}).get("VpcId", ""),
                "peer_vpc_id": p.get("AccepterVpcInfo", {}).get("VpcId", ""),
                "status": (p.get("Status") or {}).get("Code", ""),
            }

        for g in call("describe_vpn_gateways", "VpnGateways"):
            inv["vgws"][g["VpnGatewayId"]] = {
                "id": g["VpnGatewayId"],
                "vpc_id": next(
                    (a["VpcId"] for a in g.get("VpcAttachments", []) or [] if a.get("VpcId")), ""
                ),
                "state": g.get("State", ""),
            }

        for e in call("describe_vpc_endpoints", "VpcEndpoints"):
            inv["endpoints"][e["VpcEndpointId"]] = {
                "id": e["VpcEndpointId"],
                "vpc_id": e.get("VpcId", ""),
                "service": (e.get("ServiceName", "") or "").split(".")[-1],
                "type": e.get("VpcEndpointType", ""),
                "subnet_ids": e.get("SubnetIds", []) or [],
                "route_table_ids": e.get("RouteTableIds", []) or [],
                "sg_ids": [g.get("GroupId", "") for g in e.get("Groups", []) or [] if g.get("GroupId")],
            }

        # network ACLs: subnet -> nacl association + rule counts
        for n in call("describe_network_acls", "NetworkAcls"):
            assoc = {a["SubnetId"]: n["NetworkAclId"] for a in n.get("Associations", []) or [] if a.get("SubnetId")}
            inv["nacls"][n["NetworkAclId"]] = {
                "id": n["NetworkAclId"],
                "vpc_id": n.get("VpcId", ""),
                "is_default": bool(n.get("IsDefault")),
                "subnet_ids": assoc,
                "in": sum(1 for e in n.get("Entries", []) or [] if not e.get("Egress")),
                "out": sum(1 for e in n.get("Entries", []) or [] if e.get("Egress")),
            }

        # security groups (the app-to-app answer)
        for sg in call("describe_security_groups", "SecurityGroups"):
            inv["sgs"][sg["GroupId"]] = {
                "id": sg["GroupId"],
                "vpc_id": sg.get("VpcId", ""),
                "name": sg.get("GroupName", ""),
                "description": sg.get("Description", ""),
                "ingress": _flatten_rules(sg.get("IpPermissions")),
                "egress": _flatten_rules(sg.get("IpPermissionsEgress")),
            }

        for eni in call("describe_network_interfaces", "NetworkInterfaces"):
            inv["enis"][eni["NetworkInterfaceId"]] = {
                "id": eni["NetworkInterfaceId"],
                "vpc_id": eni.get("VpcId", ""),
                "subnet_id": eni.get("SubnetId", ""),
                "interface_type": eni.get("InterfaceType", "interface"),
                "description": (eni.get("Description") or "").strip(),
                "sg_ids": [g["GroupId"] for g in eni.get("Groups", []) or [] if g.get("GroupId")],
            }

        # EC2 instance names -> security groups (names the "applications")
        for res in call("describe_instances", "Reservations"):
            for inst in res.get("Instances", []) or []:
                name = ""
                for t in inst.get("Tags") or []:
                    if t.get("Key") == "Name":
                        name = t.get("Value", "")
                sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", []) or [] if g.get("GroupId")]
                label = f"EC2 {name or inst['InstanceId']}"
                for sg_id in sg_ids:
                    add_member(inv, sg_id, label)

        # Load balancers + RDS names -> security groups (optional; degrade cleanly)
        self._collect_elbv2(inv, region)
        self._collect_rds(inv, region)

        # VPC flow log presence (audit note)
        for fl in call("describe_flow_logs", "FlowLogs"):
            rid = fl.get("ResourceId", "")
            inv["flow_logs"][rid] = inv["flow_logs"].get(rid, 0) + 1

    def _collect_elbv2(self, inv: dict, region: str) -> None:
        try:
            client = self.client(region, "elbv2")
            lbs = self._list(client, "describe_load_balancers", "LoadBalancers")
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"{region} elbv2: {exc}")
            return
        for lb in lbs:
            sg_ids = lb.get("SecurityGroups", []) or []
            scheme = lb.get("Scheme", "")
            label = f"ALB {lb.get('LoadBalancerName', '')}" + (" (internet-facing)" if scheme == "internet-facing" else "")
            for sg_id in sg_ids:
                add_member(inv, sg_id, label)

    def _collect_rds(self, inv: dict, region: str) -> None:
        try:
            client = self.client(region, "rds")
            dbs = self._list(client, "describe_db_instances", "DBInstances")
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"{region} rds: {exc}")
            return
        for db in dbs:
            sg_ids = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", []) or [] if g.get("VpcSecurityGroupId")]
            label = f"RDS {db.get('DBInstanceIdentifier', '')}"
            for sg_id in sg_ids:
                add_member(inv, sg_id, label)


def _norm_route(raw: dict) -> dict:
    kind, target_id = route_target(raw)
    return {
        "destination": route_dest(raw),
        "kind": kind,
        "target_id": target_id,
        "state": raw.get("State", "active"),
    }


def _norm_sg_rule(perm: dict) -> List[dict]:
    """Flatten one IpPermissions block into one rule per source."""
    proto = perm.get("IpProtocol") or "-1"
    lo = _int(perm.get("FromPort"))
    hi = _int(perm.get("ToPort"))
    desc = perm.get("Description") or ""
    sources: List[dict] = []
    for entry in perm.get("IpRanges", []) or []:
        sources.append({"cidr": entry.get("CidrIp", "") or ""})
    for entry in perm.get("Ipv6Ranges", []) or []:
        sources.append({"cidr": entry.get("CidrIpv6", "") or ""})
    for entry in perm.get("UserIdGroupPairs", []) or []:
        sources.append({"sg_id": entry.get("GroupId", "") or ""})
    for entry in perm.get("PrefixListIds", []) or []:
        sources.append({"prefix": entry.get("PrefixListId", "") or ""})
    if not sources:
        sources.append({"cidr": ""})
    return [
        {
            "protocol": proto,
            "from_port": lo,
            "to_port": hi,
            "cidr": s.get("cidr", ""),
            "sg_id": s.get("sg_id", ""),
            "prefix": s.get("prefix", ""),
            "description": desc,
        }
        for s in sources
    ]


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _flatten_rules(perms) -> List[dict]:
    """One ``IpPermissions`` block expands to one rule per source (a list of
    rules), so flatten the blocks into a single flat list of rule dicts."""
    out: List[dict] = []
    for perm in perms or []:
        out.extend(_norm_sg_rule(perm))
    return out


# --------------------------------------------------------------------------- #
# Indexing / linking
# --------------------------------------------------------------------------- #


def link(inv: dict) -> None:
    # subnet -> effective route table (explicit association wins, then main table)
    explicit: Dict[str, str] = {}
    main_by_vpc: Dict[str, str] = {}
    for rtb in inv["rtbs"].values():
        for sid in rtb["subnet_ids"]:
            explicit[sid] = rtb["id"]
        if rtb["is_main"]:
            main_by_vpc[rtb["vpc_id"]] = rtb["id"]
    for subnet in inv["subnets"].values():
        subnet["rtb_id"] = explicit.get(subnet["id"]) or main_by_vpc.get(subnet["vpc_id"], "")

    # nacl -> subnet (store the default per vpc for subnets without an explicit one)
    nacl_by_subnet: Dict[str, dict] = {}
    default_nacl_by_vpc: Dict[str, dict] = {}
    for nacl in inv["nacls"].values():
        for sid, _ in nacl["subnet_ids"].items():
            nacl_by_subnet[sid] = nacl
        if nacl["is_default"]:
            default_nacl_by_vpc[nacl["vpc_id"]] = nacl
    inv["nacl_by_subnet"] = nacl_by_subnet
    inv["default_nacl_by_vpc"] = default_nacl_by_vpc

    # endpoint / nat / eni owners -> security group members
    for ep in inv["endpoints"].values():
        for sg_id in ep["sg_ids"]:
            add_member(inv, sg_id, f"endpoint {ep['service']}")
    for eni in inv["enis"].values():
        if eni["description"] and not eni["description"].startswith(("Primary", "Elastic")):
            for sg_id in eni["sg_ids"]:
                add_member(inv, sg_id, eni["description"])

    # collapse member sets into sorted lists
    inv["members"] = {k: sorted(v) for k, v in inv["members"].items()}


def subnet_nacl(inv: dict, subnet: dict) -> Optional[dict]:
    nacl = inv["nacl_by_subnet"].get(subnet["id"])
    return nacl or inv["default_nacl_by_vpc"].get(subnet["vpc_id"])


# --------------------------------------------------------------------------- #
# The communication graph (security group references)
# --------------------------------------------------------------------------- #

INTERNET_CIDRS = ("0.0.0.0/0", "::/0")


def cidr_key(cidr: str) -> str:
    return "internet" if cidr in INTERNET_CIDRS else f"cidr-{cidr}"


def cidr_label(cidr: str) -> str:
    return "INTERNET" if cidr in INTERNET_CIDRS else cidr


def proto_name(proto) -> str:
    s = str(proto).lower()
    return {"6": "tcp", "17": "udp", "1": "icmp", "-1": "all", "all": "all"}.get(s, s)


def port_label(rule: dict) -> str:
    proto = proto_name(rule["protocol"])
    if proto == "all":
        return "all"
    if proto == "icmp":
        return "icmp"
    lo, hi = rule["from_port"], rule["to_port"]
    if lo in (-1, 0) and hi in (0, 65535):
        return f"{proto}/all"
    if lo == hi:
        return f":{lo}/{proto}"
    return f":{lo}-{hi}/{proto}"


def build_comm_graph(inv: dict) -> Tuple[Dict[str, List[dict]], set]:
    """Return (incident_edges_by_node, sg_sg_pairs).

    An edge is ``dict(src, dst, label, direction)`` where ``direction`` is
    ``in`` (traffic arriving at ``dst``) or ``out`` (traffic leaving ``src``),
    derived from the rule that authorises it. ``sg_sg_pairs`` is the set of
    security-group ids that participate in an SG<->SG reference. Edges are
    indexed under *both* endpoints, so a hub's diagram shows who can reach it
    *and* who it can reach.
    """
    edges: List[dict] = []
    seen: set = set()
    sg_sg: set = set()

    def add(src: str, dst: str, label: str, direction: str):
        if not src or not dst or src == dst:
            return
        key = (src, dst, label, direction)
        if key in seen:
            return
        seen.add(key)
        edges.append({"src": src, "dst": dst, "label": label, "direction": direction})

    for sg in inv["sgs"].values():
        me = "sg-" + sg["id"]
        for rule in sg["ingress"]:
            label = port_label(rule)
            if rule["sg_id"]:
                other = "sg-" + rule["sg_id"]
                add(other, me, label, "in")
                sg_sg.add(sg["id"])
                sg_sg.add(rule["sg_id"])
            elif rule["cidr"]:
                add(cidr_key(rule["cidr"]), me, label, "in")
            elif rule["prefix"]:
                add("pl-" + rule["prefix"], me, label, "in")
        for rule in sg["egress"]:
            label = port_label(rule)
            if rule["sg_id"]:
                other = "sg-" + rule["sg_id"]
                add(me, other, label, "out")
                sg_sg.add(sg["id"])
                sg_sg.add(rule["sg_id"])
            elif rule["cidr"]:
                add(me, cidr_key(rule["cidr"]), label, "out")
            elif rule["prefix"]:
                add(me, "pl-" + rule["prefix"], label, "out")

    incident: Dict[str, List[dict]] = defaultdict(list)
    for edge in edges:
        incident[edge["src"]].append(edge)
        incident[edge["dst"]].append(edge)
    return incident, sg_sg


def sg_is_interesting(edges_by_sg: Dict[str, List[dict]], sg_id: str) -> bool:
    """Emit a comms diagram unless the SG's only relationship is egress-to-internet."""
    for edge in edges_by_sg.get("sg-" + sg_id, []):
        if edge["direction"] == "in":
            return True
        # egress: interesting unless it goes to the bare internet
        if edge["dst"] != "internet":
            return True
    return False


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #


def render_overview(inv: dict) -> str:
    b = Mermaid("AWS network segmentation \u2014 account overview")
    b.node("internet", "INTERNET", "stadium", "internet")
    if inv["vgws"] or inv["tgws"]:
        b.node("onprem", "ON-PREMISES", "box", "onprem")

    for tgw in sorted(inv["tgws"].values(), key=lambda t: t["id"]):
        key = "tgw-" + tgw["id"]
        b.node(key, f"TRANSIT GATEWAY\n{tgw['name'] or tgw['id']}\n{tgw['state']}", "hex", "tgw", 120)
        for att in tgw["attachments"]:
            vpc_id = att.get("vpc_id", "")
            if vpc_id in inv["vpcs"] and att.get("type") == "vpc":
                b.edge(key, "vpc-" + vpc_id, "attachment")

    for pcx in sorted(inv["peerings"].values(), key=lambda p: p["id"]):
        key = "pcx-" + pcx["id"]
        b.node(key, f"VPC PEERING\n{pcx['id']}\n{pcx['status']}", "hex", "peering", 120)
        if pcx["vpc_id"] in inv["vpcs"]:
            b.edge("vpc-" + pcx["vpc_id"], key, "")
        if pcx["peer_vpc_id"] in inv["vpcs"]:
            b.edge(key, "vpc-" + pcx["peer_vpc_id"], "")

    for vgw in sorted(inv["vgws"].values(), key=lambda g: g["id"]):
        key = "vgw-" + vgw["id"]
        b.node(key, f"VPN GATEWAY\n{vgw['id']}\n{vgw['state']}", "round", "vgw", 120)
        b.edge(key, "onprem", "ipsec")
        if vgw["vpc_id"] in inv["vpcs"]:
            b.edge("vpc-" + vgw["vpc_id"], key, "")

    for vpc in sorted(inv["vpcs"].values(), key=lambda v: v["id"]):
        subs = [s for s in inv["subnets"].values() if s["vpc_id"] == vpc["id"]]
        tally = {"public": 0, "private": 0, "isolated": 0}
        for s in subs:
            cls, _ = classify(inv["rtbs"].get(s["rtb_id"]))
            tally[cls] += 1
        fl = inv["flow_logs"].get(vpc["id"], 0)
        lines = [f"VPC {vpc['name'] or vpc['id']}", vpc["id"], vpc["cidr"] or "no cidr"]
        lines.append(
            f"{tally['public']} public / {tally['private']} private / {tally['isolated']} isolated"
        )
        lines.append(f"flow logs: {'enabled' if fl else 'none'}")
        b.node("vpc-" + vpc["id"], "\n".join(lines), "round", "vpc", 140)

        # internet + TGW reachability summary edges
        if tally["public"]:
            b.edge("internet", "vpc-" + vpc["id"], "ingress (public subnets)")
        if tally["private"]:
            b.edge("vpc-" + vpc["id"], "internet", "egress (NAT)")

    return b.render()


def render_vpc_seg(inv: dict, vpc_id: str) -> str:
    vpc = inv["vpcs"][vpc_id]
    b = Mermaid(f"segmentation \u2014 {vpc['name'] or vpc['id']}")
    b.node("internet", "INTERNET", "stadium", "internet")
    if any(g["vpc_id"] == vpc_id for g in inv["vgws"].values()):
        b.node("onprem", "ON-PREMISES", "box", "onprem")

    with b.group("vpc", f"VPC {vpc['name'] or vpc['id']} \u2014 {vpc_id}\n{vpc['cidr']}"):
        # Transit gateways attached to this VPC (routes point at these).
        for tgw in sorted(inv["tgws"].values(), key=lambda t: t["id"]):
            if any(a.get("vpc_id") == vpc_id for a in tgw["attachments"]):
                b.node("tgw-" + tgw["id"], f"TRANSIT GATEWAY\n{tgw['name'] or tgw['id']}", "hex", "tgw", 120)
        for igw in sorted(
            [i for i in inv["igws"].values() if i["vpc_id"] == vpc_id], key=lambda i: i["id"]
        ):
            b.node("igw-" + igw["id"], f"INTERNET GATEWAY\n{igw['id']}", "round", "internet", 120)

        for nat in sorted(
            [n for n in inv["nats"].values() if n["vpc_id"] == vpc_id], key=lambda n: n["id"]
        ):
            b.node(
                "nat-" + nat["id"],
                f"NAT GATEWAY\n{nat['id']}\n{nat['state']} {nat['connect_type']}",
                "round",
                "private",
                120,
            )

        for vgw in sorted(
            [g for g in inv["vgws"].values() if g["vpc_id"] == vpc_id], key=lambda g: g["id"]
        ):
            b.node("vgw-" + vgw["id"], f"VPN GATEWAY\n{vgw['id']}", "round", "vgw", 120)
            b.edge("vgw-" + vgw["id"], "onprem" if inv["vgws"] else "internet", "ipsec")

        for pcx in sorted(
            [p for p in inv["peerings"].values() if p["vpc_id"] == vpc_id or p["peer_vpc_id"] == vpc_id],
            key=lambda p: p["id"],
        ):
            b.node("pcx-" + pcx["id"], f"VPC PEERING\n{pcx['id']}\n{pcx['status']}", "hex", "peering", 120)

        for ep in sorted(
            [e for e in inv["endpoints"].values() if e["vpc_id"] == vpc_id], key=lambda e: e["id"]
        ):
            b.node(
                "vpce-" + ep["id"],
                f"ENDPOINT {ep['service']}\n{ep['id']}\n{ep['type']}",
                "hex",
                "endpoint",
                120,
            )

        subs = [s for s in inv["subnets"].values() if s["vpc_id"] == vpc_id]
        for subnet in sorted(subs, key=_subnet_sort(inv)):
            cls, default = classify(inv["rtbs"].get(subnet["rtb_id"]))
            rtb = inv["rtbs"].get(subnet["rtb_id"], {})
            nacl = subnet_nacl(inv, subnet)
            lines = [
                f"{cls.upper()} \u00b7 {subnet['name'] or subnet['id']}",
                f"{subnet['id']} \u00b7 {subnet['cidr'] or 'no cidr'} \u00b7 {subnet['az'] or '?'}",
            ]
            if rtb:
                lines.append(f"rtb: {rtb['name'] or rtb['id']}")
            if nacl:
                lines.append(f"nacl: {nacl['id']} ({nacl['in']} in / {nacl['out']} out)")
            lines.append(classification_reason(cls, default))
            b.node("subnet-" + subnet["id"], "\n".join(lines), "box", cls, 200)

    # arrows: subnet -> next hop
    for subnet in sorted(subs, key=_subnet_sort(inv)):
        rtb = inv["rtbs"].get(subnet["rtb_id"])
        if not rtb:
            continue
        src = "subnet-" + subnet["id"]
        for route in rtb["routes"]:
            if route["state"] != "active":
                continue
            kind, target = route["kind"], route["target_id"]
            label = route["destination"]
            if kind == "igw" and target:
                b.edge(src, "igw-" + target, label)
                cls, _ = classify(rtb)
                if cls == "public":
                    b.edge("igw-" + target, src, f"inbound {subnet['cidr']}")
            elif kind == "nat" and target:
                b.edge(src, "nat-" + target, label)
                igw = next((i for i in inv["igws"].values() if i["vpc_id"] == vpc_id and i["attached"]), None)
                if igw:
                    b.edge("nat-" + target, "igw-" + igw["id"], "via public subnet")
            elif kind == "vgw" and target:
                b.edge(src, "vgw-" + target, label)
            elif kind == "tgw" and target:
                b.edge(src, "tgw-" + target, label)
            elif kind == "pcx" and target:
                b.edge(src, "pcx-" + target, label)
            elif kind == "vpce" and target:
                b.edge(src, "vpce-" + target, label)

    # IGW <-> internet
    for igw in inv["igws"].values():
        if igw["vpc_id"] == vpc_id:
            b.edge("igw-" + igw["id"], "internet", "egress")
            b.edge("internet", "igw-" + igw["id"], "ingress")

    return b.render()


def _subnet_sort(inv: dict):
    order = {"public": 0, "private": 1, "isolated": 2}

    def key(subnet: dict):
        cls, _ = classify(inv["rtbs"].get(subnet["rtb_id"]))
        return (order.get(cls, 3), subnet["cidr"] or "")

    return key


def _sg_members_text(inv: dict, sg_id: str) -> str:
    members = inv["members"].get(sg_id, [])
    if not members:
        return ""
    shown = members[:6]
    more = len(members) - len(shown)
    text = "used by: " + ", ".join(shown)
    if more > 0:
        text += f" (+{more})"
    return text


def render_sg_comm(inv: dict, sg_id: str, edges_by_sg: Dict[str, List[dict]]) -> str:
    sg = inv["sgs"][sg_id]
    key = "sg-" + sg_id
    b = Mermaid(f"communication \u2014 {sg['name']} ({sg_id})")

    members = _sg_members_text(inv, sg_id)
    hub = [f"SG {sg['name']}", sg_id]
    if sg["description"]:
        hub.append(sg["description"])
    if members:
        hub.append(members)
    b.node(key, "\n".join(hub), "stadium", "sghub", 160)

    for edge in edges_by_sg.get(key, []):
        other = edge["dst"] if edge["dst"] != key else edge["src"]
        _emit_comm_peer(b, inv, other)
        b.edge(edge["src"], edge["dst"], edge["label"])

    return b.render()


def _emit_comm_peer(b: Mermaid, inv: dict, key: str) -> None:
    if key == "internet":
        b.node(key, "INTERNET", "stadium", "internet")
    elif key.startswith("sg-"):
        sg_id = key[3:]
        sg = inv["sgs"].get(sg_id)
        if sg is None:
            b.node(key, f"SG {sg_id}", "stadium", "sg")
            return
        members = _sg_members_text(inv, sg_id)
        lines = [f"SG {sg['name']}", sg_id]
        if members:
            lines.append(members)
        b.node(key, "\n".join(lines), "stadium", "sg", 140)
    elif key.startswith("pl-"):
        b.node(key, f"PREFIX LIST\n{key[3:]}", "box", "cidr", 80)
    else:
        cidr = key[5:] if key.startswith("cidr-") else key
        b.node(key, cidr, "box", "cidr", 40)


def render_exposure(inv: dict, edges_by_sg: Dict[str, List[dict]]) -> str:
    b = Mermaid("internet exposure \u2014 security groups reachable from 0.0.0.0/0")
    b.node("internet", "INTERNET", "stadium", "internet")

    exposed = []
    for sg in inv["sgs"].values():
        open_ports = []
        for rule in sg["ingress"]:
            if rule["cidr"] in INTERNET_CIDRS and not rule["sg_id"]:
                open_ports.append(port_label(rule))
        if open_ports:
            exposed.append((sg, sorted(set(open_ports))))

    if not exposed:
        b.node("none", "no security group has an ingress rule from the internet", "round", "private", 120)
        return b.render()

    for sg, ports in sorted(exposed, key=lambda x: x[0]["id"]):
        key = "sg-" + sg["id"]
        members = _sg_members_text(inv, sg["id"])
        lines = [f"SG {sg['name']}", sg["id"]]
        if members:
            lines.append(members)
        b.node(key, "\n".join(lines), "stadium", "exposed", 160)
        b.edge("internet", key, ", ".join(ports))

    return b.render()


# --------------------------------------------------------------------------- #
# CSV evidence
# --------------------------------------------------------------------------- #


def write_csv(path: str, header: Sequence[str], rows: Sequence[Sequence]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    import csv

    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(list(header))
        for row in rows:
            w.writerow(list(row))


def write_evidence(inv: dict, out: str) -> None:
    rep = os.path.join(out, "reports")
    write_csv(
        os.path.join(rep, "subnets.csv"),
        ("vpc_id", "subnet_id", "name", "cidr", "az", "classification", "route_table_id", "nacl_id"),
        [
            (
                s["vpc_id"], s["id"], s["name"], s["cidr"], s["az"],
                classify(inv["rtbs"].get(s["rtb_id"]))[0],
                s["rtb_id"],
                (subnet_nacl(inv, s) or {}).get("id", ""),
            )
            for s in sorted(inv["subnets"].values(), key=lambda s: (s["vpc_id"], s["cidr"]))
        ],
    )
    write_csv(
        os.path.join(rep, "route-tables.csv"),
        ("route_table_id", "vpc_id", "name", "is_main", "subnets", "destination", "target_type", "target_id"),
        [
            (
                rtb["id"], rtb["vpc_id"], rtb["name"], rtb["is_main"],
                ", ".join(sorted(rtb["subnet_ids"])),
                r["destination"], r["kind"], r["target_id"],
            )
            for rtb in sorted(inv["rtbs"].values(), key=lambda r: r["id"])
            for r in rtb["routes"]
        ],
    )
    write_csv(
        os.path.join(rep, "security-group-rules.csv"),
        ("sg_id", "sg_name", "vpc_id", "direction", "protocol", "from_port", "to_port", "cidr", "ref_sg_id", "prefix_list", "description"),
        [
            (
                sg["id"], sg["name"], sg["vpc_id"], direction,
                rule["protocol"], rule["from_port"], rule["to_port"],
                rule["cidr"], rule["sg_id"], rule["prefix"], rule["description"],
            )
            for sg in sorted(inv["sgs"].values(), key=lambda s: s["id"])
            for direction, rules in (("ingress", sg["ingress"]), ("egress", sg["egress"]))
            for rule in rules
        ],
    )
    write_csv(
        os.path.join(rep, "security-group-members.csv"),
        ("sg_id", "sg_name", "vpc_id", "members"),
        [
            (sg["id"], sg["name"], sg["vpc_id"], "; ".join(inv["members"].get(sg["id"], [])))
            for sg in sorted(inv["sgs"].values(), key=lambda s: s["id"])
        ],
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def emit(inv: dict, out: str) -> Dict[str, int]:
    os.makedirs(out, exist_ok=True)
    link(inv)
    edges_by_sg, sg_sg = build_comm_graph(inv)

    written: List[str] = []

    def save(name: str, content: str) -> None:
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(name)

    save("00-overview.mmd", render_overview(inv))

    for vpc in sorted(inv["vpcs"].values(), key=lambda v: v["id"]):
        save(f"10-seg-{slug(vpc['name'] or vpc['id'], 40)}.mmd", render_vpc_seg(inv, vpc["id"]))

    for sg_id in sorted(sg_sg):
        if sg_is_interesting(edges_by_sg, sg_id):
            sg = inv["sgs"].get(sg_id)
            if sg is None:
                continue
            save(f"20-comms-{slug(sg['name'] or sg_id, 40)}-{sg_id}.mmd", render_sg_comm(inv, sg_id, edges_by_sg))

    save("21-internet-exposure.mmd", render_exposure(inv, edges_by_sg))

    write_evidence(inv, out)
    write_start_here(inv, out, written, sg_sg)

    return {"files": len(written), "vpc_diagrams": len(inv["vpcs"]), "comms_diagrams": len([w for w in written if w.startswith("20-")])}


def write_start_here(inv: dict, out: str, written: List[str], sg_sg: set) -> None:
    lines = [
        "# Start here",
        "",
        f"- Account: {inv['account_id'] or 'unknown'}",
        f"- Regions: {', '.join(inv['regions']) or '-'}",
        f"- VPCs {len(inv['vpcs'])}, subnets {len(inv['subnets'])}, route tables {len(inv['rtbs'])}, "
        f"security groups {len(inv['sgs'])}, transit gateways {len(inv['tgws'])}, peerings {len(inv['peerings'])}",
        "",
        "The tool splits the network into **small, loadable** Mermaid diagrams:",
        "",
        "| Family | Files | Answers |",
        "| --- | --- | --- |",
        "| Overview | `00-overview.mmd` | The whole account: VPCs, TGWs, peerings, VPN. |",
        "| Segmentation | `10-seg-*.mmd` | One per VPC. Subnets coloured public/private/isolated, "
        "with route table + NACL + the default route that proves the tier. |",
        "| Communication | `20-comms-*.mmd` | One per security group that talks to another security "
        "group. Shows *which applications can reach which* and on what port. |",
        "| Exposure | `21-internet-exposure.mmd` | Every security group with an ingress rule from "
        "0.0.0.0/0 or ::/0. |",
        "",
        "## How to read a communication diagram",
        "",
        "The hub (blue) is the security group you are inspecting. An arrow **into** the hub is a rule "
        "that lets the source reach it; an arrow **out** of the hub is a rule that lets it reach the "
        "destination. Labels are port/protocol (`:5432/tcp`, `:443/tcp`, `all`).",
        "",
        "This is **configured reachability**, not observed traffic. Route tables and security groups "
        "say what the network *allows*; only VPC Flow Logs say what actually flows.",
        "",
        "## Files",
        "",
    ]
    for name in written:
        lines.append(f"- [{name}]({name})")
    lines += [
        "",
        "## Evidence (CSV)",
        "",
        "- `reports/subnets.csv` \u2014 every subnet and its derived classification",
        "- `reports/route-tables.csv` \u2014 every route, normalised",
        "- `reports/security-group-rules.csv` \u2014 every SG rule, flattened",
        "- `reports/security-group-members.csv` \u2014 which EC2/ALB/RDS/ENI uses each SG",
        "",
    ]
    if inv["errors"]:
        lines += ["## Collection warnings", ""]
        for e in inv["errors"]:
            lines.append(f"- {e}")
        lines.append("")
    with open(os.path.join(out, "START-HERE.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# Demo (no AWS) \u2014 a small synthetic estate so the tool can be verified anywhere
# --------------------------------------------------------------------------- #


def build_demo() -> dict:
    inv = new_inventory("000000000000", ["eu-west-1"])

    def vpc(vid, name, cidr):
        inv["vpcs"][vid] = {"id": vid, "region": "eu-west-1", "name": name, "cidr": cidr, "is_default": False}

    def subnet(sid, vid, cidr, az, name):
        inv["subnets"][sid] = {"id": sid, "vpc_id": vid, "region": "eu-west-1", "cidr": cidr, "az": az, "name": name, "rtb_id": ""}

    def rtb(rid, vid, name, is_main, subnet_ids, routes):
        inv["rtbs"][rid] = {"id": rid, "vpc_id": vid, "region": "eu-west-1", "name": name, "is_main": is_main, "subnet_ids": subnet_ids, "routes": [{"destination": d, "kind": k, "target_id": t, "state": "active"} for d, k, t in routes]}

    vpc("vpc-prod", "Prod-VPC", "10.148.0.0/16")
    vpc("vpc-dev", "Dev-VPC", "10.149.0.0/16")

    subnet("subnet-pub-1", "vpc-prod", "10.148.1.0/24", "eu-west-1a", "Prod_Public_1A")
    subnet("subnet-app-1", "vpc-prod", "10.148.10.0/24", "eu-west-1a", "Prod_App_1A")
    subnet("subnet-db-1", "vpc-prod", "10.148.20.0/24", "eu-west-1a", "Prod_DB_1A")
    subnet("subnet-isol-1", "vpc-prod", "10.148.30.0/24", "eu-west-1a", "Prod_Isolated_1A")
    subnet("subnet-dev-1", "vpc-dev", "10.149.1.0/24", "eu-west-1a", "Dev_Public_1A")
    subnet("subnet-dev-app-1", "vpc-dev", "10.149.10.0/24", "eu-west-1a", "Dev_App_1A")

    inv["igws"]["igw-prod"] = {"id": "igw-prod", "vpc_id": "vpc-prod", "attached": True}
    inv["igws"]["igw-dev"] = {"id": "igw-dev", "vpc_id": "vpc-dev", "attached": True}
    inv["nats"]["nat-prod"] = {"id": "nat-prod", "vpc_id": "vpc-prod", "subnet_id": "subnet-pub-1", "state": "available", "connect_type": "public"}

    rtb("rtb-prod-public", "vpc-prod", "Prod_Public_RT", False, ["subnet-pub-1"], [("0.0.0.0/0", "igw", "igw-prod")])
    rtb("rtb-prod-app", "vpc-prod", "Prod_App_RT", False, ["subnet-app-1"], [("0.0.0.0/0", "nat", "nat-prod"), ("10.148.0.0/16", "local", "local")])
    rtb("rtb-prod-db", "vpc-prod", "Prod_DB_RT", False, ["subnet-db-1"], [("10.148.0.0/16", "local", "local")])
    rtb("rtb-prod-isol", "vpc-prod", "Prod_Isolated_RT", False, ["subnet-isol-1"], [("10.148.0.0/16", "local", "local")])
    rtb("rtb-dev-public", "vpc-dev", "Dev_Public_RT", False, ["subnet-dev-1"], [("0.0.0.0/0", "igw", "igw-dev")])
    rtb("rtb-dev-app", "vpc-dev", "Dev_App_RT", False, ["subnet-dev-app-1"], [("0.0.0.0/0", "igw", "igw-dev")])

    inv["nacls"]["acl-prod-default"] = {"id": "acl-prod-default", "vpc_id": "vpc-prod", "is_default": True, "subnet_ids": {}, "in": 2, "out": 2}
    inv["nacls"]["acl-dev-default"] = {"id": "acl-dev-default", "vpc_id": "vpc-dev", "is_default": True, "subnet_ids": {}, "in": 2, "out": 2}

    def sg(sid, vid, name, desc, ingress, egress):
        inv["sgs"][sid] = {"id": sid, "vpc_id": vid, "name": name, "description": desc, "ingress": ingress, "egress": egress}

    def rule(proto, lo, hi, cidr="", sg_id="", desc=""):
        return {"protocol": proto, "from_port": lo, "to_port": hi, "cidr": cidr, "sg_id": sg_id, "prefix": "", "description": desc}

    sg("sg-alb", "vpc-prod", "Prod-ALB", "front door", [rule("tcp", 443, 443, cidr="0.0.0.0/0")], [rule("-1", -1, -1, cidr="0.0.0.0/0")])
    sg("sg-app", "vpc-prod", "Prod-App", "app tier", [rule("tcp", 8080, 8080, sg_id="sg-alb")], [rule("-1", -1, -1, cidr="0.0.0.0/0")])
    sg("sg-db", "vpc-prod", "Prod-DB", "postgres", [rule("tcp", 5432, 5432, sg_id="sg-app")], [rule("-1", -1, -1, cidr="0.0.0.0/0")])
    sg("sg-dev-app", "vpc-dev", "Dev-App", "dev app tier", [rule("tcp", 8080, 8080, cidr="10.149.1.0/24")], [rule("-1", -1, -1, cidr="0.0.0.0/0")])

    inv["members"]["sg-alb"] = {"ALB Prod-Frontend"}
    inv["members"]["sg-app"] = {"EC2 app-01", "EC2 app-02"}
    inv["members"]["sg-db"] = {"RDS prod-postgres"}
    inv["members"]["sg-dev-app"] = {"EC2 dev-app-01"}

    link(inv)
    return inv


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dionysus",
        description="Read-only AWS network segmentation + application communication mapper "
        "(multiple small Mermaid .mmd files, one per VPC and per security group).",
        epilog="examples:\n"
        "  python3 dionysus.py --all-regions --out ./seg-comm-map\n"
        "  python3 dionysus.py --regions eu-west-1,us-east-1\n"
        "  python3 dionysus.py --demo --out ./demo   # no AWS calls",
    )
    p.add_argument("--regions", default="", help="comma separated region list")
    p.add_argument("--all-regions", action="store_true", help="scan every enabled region")
    p.add_argument("--out", default="seg-comm-map", help="output directory")
    p.add_argument("--profile", default="", help="AWS profile name (default: the CloudShell session)")
    p.add_argument("--demo", action="store_true", help="run the bundled synthetic scenario (no AWS)")
    return p


def resolve_regions(args) -> List[str]:
    import boto3

    if args.regions:
        return [r.strip() for r in args.regions.split(",") if r.strip()]
    kwargs = {"profile_name": args.profile} if args.profile else {}
    ec2 = boto3.client("ec2", **kwargs)
    regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    return sorted(regions)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo:
        inv = build_demo()
    else:
        try:
            regions = resolve_regions(args)
        except Exception as exc:  # noqa: BLE001
            print(f"error resolving regions: {exc}", file=sys.stderr)
            print("use --regions, --all-regions, or --demo", file=sys.stderr)
            return 2
        collector = Collector(regions, profile=args.profile)
        inv = collector.collect()

    result = emit(inv, args.out)

    print("=" * 70)
    print(f"Account {inv['account_id'] or 'unknown'}  regions: {', '.join(inv['regions']) or '-'}")
    print(
        f"  inventory: {len(inv['vpcs'])} VPC(s), {len(inv['subnets'])} subnet(s), "
        f"{len(inv['rtbs'])} route table(s), {len(inv['sgs'])} security group(s)"
    )
    print(
        f"  written: {result['files']} file(s) -> {result['vpc_diagrams']} segmentation "
        f"diagram(s), {result['comms_diagrams']} communication diagram(s)"
    )
    if inv["errors"]:
        print(f"  collection warnings: {len(inv['errors'])} (see START-HERE.md)")
    print(f"  output: {os.path.abspath(args.out)}")
    print("  start at: START-HERE.md")
    print("  view each .mmd by pasting it into https://mermaid.live")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
