# Zone-based Firewall

## Commons

```python
local_in  = "ZONE_LOCAL_IN"
forward   = "ZONE_FORWARD"
local_out = "ZONE_LOCAL_OUT"

root = conf (None, "zone-policy", "zone")
type = "firewall"

def get_zone_chain (zone):
	return "ZONE-$zone-IN"

def get_policy_chain (type, policy):
	return get_chain_hash (type, policy);

def append_default (chain, zone):
	if not type.startswith ("firewall"):
		return  # not a firewall table

	default = conf (root, zone, "default-action")
	if default is None:
		if chain == local_out or conf_exists (root, zone, 'local-zone'):
			return  # local default: return to main automata

		default = 'drop'  # non-local zone default

	xtc_append_entry (chain, "-j " + uc (default))
```

## Create zone input chains

```python
def create_zone_chain (zone):
	chain = get_zone_chain (zone)

	xtc_create_chain (chain)

	for iface in conf (root, zone, "interface"):
		xtc_append_entry (chain, "-i $iface -j RETURN")

	for peer in conf (root, zone, "from"):
		policy = conf (root, zone, "from", peer, "policy", type)
		if policy is None:
			continue

		target = get_policy_chain (type, policy)
		if not xtc_is_chain (target):
			die ("policy $type $policy does not exists")

		for iface in conf (root, peer, "interface"):
			xtc_append_entry (chain, "-i $iface -g $target")

	append_default (chain, zone)
```

## Connect zones

```python
def connect_transit (zone):
	target = get_zone_chain (zone)

	for iface in conf (root, zone, "interface"):
		xtc_append_entry (forward, "-o $iface -g $target")

def connect_local_in (zone):
	target = get_zone_chain (zone)

	xtc_append_entry (local_in, "-i lo -j RETURN")
	xtc_append_entry (local_in, "-g $target")

def connect_local_out (zone):
	for peer in conf (root, zone, "from"):
		policy = conf (root, peer, "from", zone, "policy", type)
		if policy is None:
			continue

		target = get_policy_chain (type, policy)
		if not xtc_is_chain (target):
			die ("policy $type $policy does not exists")

		for iface in conf (root, peer, "interface"):
			iptc_append_entry (local_out, "-o $iface -g $target")

	xtc_append_entry (local_in, "-o lo -j RETURN")
	append_default (local_out, zone)
```

## Top-level logic

```python
def zone_fini ():
	iptc_flush_entries (local_in)
	iptc_flush_entries (forward)
	iptc_flush_entries (local_out)

	for chain in xtc_get_chains ():
		if chain.startswith ("ZONE-"):
			xtc_flush_entries (chain)
			xtc_delete_chain  (chain)

def zone_init ():
	for zone in conf (root):
		create_zone_chain (zone)

	for zone in conf (root):
		if conf_exists (root, zone, "local-zone"):
			connect_local_in  (zone)
			connect_local_out (zone)
		else:
			connect_transit (zone)

	xtc_commit ()

def zone_update ():
	zone_fini ()
	zone_init ()
```

