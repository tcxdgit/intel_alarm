

def filter_invalids_and_low_priorities(syslogs, severity_bound=7, modules=['10NULL','10SHELL']):
    # syslogs with low priorities and syslogs from invalid modules
    filtered_syslogs = []
    for message in syslogs:
        if message['module'] not in modules:
            if message['severity'] < severity_bound:
                filtered_syslogs.append(message)
    print('log length:', len(filtered_syslogs))
    return filtered_syslogs


def filter_invalids(cur_warn, severity_bound=7, modules=['10NULL','10SHELL', 'NULL', 'SHELL']):
    # syslogs with low priorities and syslogs from invalid modules
    # if
    if cur_warn['module'] in modules:
        if cur_warn['severity'] >= severity_bound:
            return True
    if not cur_warn['level']:
        return True
    return False


def filter_flappings(node, cur_warn):
    # flapping syslog on the same NE in one timeslot
    # return True if it is a flapping syslog and False otherwise
    if len(node.warnings) == 0:
        return False
    last_warn = node.warnings[-1]
    if last_warn['warnType'] == cur_warn['warnType']:
        if last_warn.get('parameters', None) == cur_warn.get('parameters', None):
            return True
        else:
            return False
    else:
        return False
    # if last_warn['warnType'] == cur_warn['warnType']:
    #     try:
    #         if last_warn['Parameters'] == cur_warn['Parameters']:
    #             return True
    #         else:
    #             return False
    #     except:
    #         return True
    # else:
    #     return False
