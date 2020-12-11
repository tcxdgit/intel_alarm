import re


def check_rules(rule, proposal, warn_list):
    '''
    input:
        satisfy: string
        warn_list: list of dicts [warn1{}, warn2{}, warn3{} ...]
    output:
        res: bool, True if satisfies the whole thing
    '''
    time_range = int(rule.get('timeRange', None))
    res, oldest_warning_type = check_time_ranges(proposal, time_range)
    if res is False:
        return False

    # check match
    if warn_list[0].get('ifPrev', None) and warn_list[1].get('ifPrev', None):
        return False
    if len(warn_list) < 2:
        return False
    if not check_satisfy(rule.get('satisfy'), warn_list[0], warn_list[1]):
        return False
    # if not eval(rule.get('satisfy')):
    #     return False
    return True


def check_time_ranges(warn_tuple_list, time_range):
    val = warn_tuple_list[0][3] - warn_tuple_list[1][3]
    oldest = 0 if val < 0 else 1
    if abs(val) > time_range:
        return False, oldest
    return True, None


def check_satisfy(satisfy, warn_A, warn_B):
    # print(warn_A, warn_B)
    if eval(satisfy):
        return True
    return False


def update_new_warning(derived, warn_A, warn_B):
    for de in derived:
        exec(de)


def isMaster(slot):
    return True


def create_new_warning(rule, warn_list, new_modules):
    '''
    create a new warning according to rule and templates
    ''' 
    new_warning_name = rule.get('upstreamWarn')
    for i in new_modules:
        if i.get('warnType') == new_warning_name:
            new_warning = i.copy()
    derived = rule.get('derived')
    # for de in derived:
    #     exec(de)
    update_new_warning(derived, new_warning, warn_list[0])

    new_warning['role'] = []
    new_warning['logTime'] = int(warn_list[-1].get('logTime'))
    new_warning['ldp_host_ip'] = warn_list[-1].get('ldp_host_ip')
    for i in ['desc', 'abstract', 'influence']:
        sub_desc = new_warning.get(i, None)
        if sub_desc is not None:
            items_to_fill = re.findall(r"(?<=\$\{).*?(?=\})", sub_desc)
            for j, item in enumerate(items_to_fill):
                new_warning[i] = new_warning[i].replace('${'+item+'}', eval(item))

    return new_warning

        

