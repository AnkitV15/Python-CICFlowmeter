from scapy.all import get_if_list, conf

print("Available interfaces (Name: Identifier) as seen by Scapy:")

# Get the list of interface identifiers
interface_identifiers = get_if_list()

# Access interface details via conf.ifaces dictionary
# conf.ifaces maps identifiers to interface objects which have a .name attribute
ifaces_details = conf.ifaces

# Iterate through the identifiers and print name and identifier
for iface_id in interface_identifiers:
    # Check if the identifier exists in conf.ifaces (should always be the case for get_if_list results)
    if iface_id in ifaces_details:
        iface_name = ifaces_details[iface_id].name
        print(f"Name: {iface_name}, Identifier: {iface_id}")
    else:
        # Fallback if for some reason an identifier isn't in conf.ifaces
        print(f"Identifier: {iface_id} (Name could not be retrieved)")

