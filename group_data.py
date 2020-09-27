
def divide_tree(groups, node):
    if node.isEntity:
        groups.append({"warnings": node.warnings, "time_start": node.warn_time_start, "time_end": node.warn_time_end})
    if node.children:
        for k, v in node.children.items():
            groups = divide_tree(groups, node.children[k])
    return groups


def merge_group(groups, group_overlap=10):
    merged_groups = [groups[0]['warnings']]
    cur_idx = 0
    cur_time = groups[0]['time_end']
    cur_device = groups[0]['warnings'][0]['ldp_host_ip']
    for g in groups[1:]:
        if g['warnings'][0]['ldp_host_ip'] != cur_device:
            merged_groups.append(g['warnings'])
            cur_idx += 1
            cur_device = g['warnings'][0]['ldp_host_ip']
            cur_time = merged_groups[cur_idx][-1]['logTime']
        else:
            # if time.mktime(time.strptime(g['time_start'], "%Y-%m-%dT%H:%M:%S.000Z")) - time.mktime(time.strptime(time_end, "%Y-%m-%dT%H:%M:%S.000Z")) <= timeslot:
            if g['time_start'] - cur_time <= group_overlap:
                merged_groups[cur_idx].extend(g['warnings'])
            else:
                merged_groups.append(g['warnings'])
                cur_idx += 1
                cur_time = merged_groups[cur_idx][-1]['logTime']

    return merged_groups

