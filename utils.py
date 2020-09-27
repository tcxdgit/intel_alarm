from new_warning_modules import new_modules
import re

def warn_valid_check(warning):
    '''
    input: warning
    output: bool
    determines if a warning is valid
    '''
    return True

def decode(warn_list, code0):
    '''
    input: 
        warn_list: list of dict
        code0: string
    output:
        tuple or string as a result of decode
    '''
    dict_mark = False
    if code0[-2:] != "NE":
        dict_mark = True
    code = code0.split(".")
    # in cases like left side of warn1.NE == 4
    if len(code) == 1:
        return int(code[0]) if code[0].isdigit() else code[0]
    # else find corresponding warning and get what the code refers to
    if "warn" in code[0]:
        warn_id = int(code[0][-1]) - 1
    temp = warn_list[warn_id]
    for i in code[1:]:
        # print(temp)
        # print(i)
        if i == "NE" and dict_mark:
            temp = temp.get('dictNE')
        else:
            temp = temp.get(i)
    if isinstance(temp, str) and temp.isdigit():
        return int(temp)
    else:
        return temp

def check_rules(satisfy, warn_list):
    '''
    input: 
        satisfy: string
        warn_list: list of dicts [warn1{}, warn2{}, warn3{} ...]
    output:
        res: bool, True if satisfies the whole thing
    '''
    if len(warn_list) < 2:
        return False
    for rule in satisfy:
        # cases of equal
        if "==" in rule:
            sides = rule.replace(" ", "").split("==")
            sides1 = []
            for i in sides:
                sides1.append(decode(warn_list, i))

            for j in sides1[1:]:
                if (j != sides1[0]) or (j is None):
                    return False
        # cases of contain
        if "<" in rule:
            sides = rule.replace(" ", "").split("<")
            sides1 = []
            for i in sides:
                sides1.append(decode(warn_list, i))
            if (len(sides1[0]) <= len(sides1[1])) or (sides1[0][:len(sides1[1])] != sides1[1]):
                return False
    return True

def check_time_ranges_fs(warn_tuple_list, time_range):
    father_time = warn_tuple_list[0][3]
    oldest = 0
    for son_id in range(1, len(warn_tuple_list)):
        if father_time > warn_tuple_list[son_id][3]:
            oldest = son_id
        if abs(father_time - warn_tuple_list[son_id][3]) > time_range:
            return False, oldest
    return True, None
        
def check_time_ranges_ss(warn_tuple_list, time_range):
    val = warn_tuple_list[0][3] - warn_tuple_list[1][3]
    oldest = 0 if val < 0 else 1
    if abs(val) > time_range:
        return False, oldest
    return True, None
        
def create_new_warning(rule, warn_list):
    '''
    create a new warning according to rule and templates
    ''' 
    new_warning_name = rule.get('derivedWarn')
    for i in new_modules:
        if i.get('warnType') == new_warning_name:
            new_warning = i.copy()
    derived = rule.get('derived')
    for de in derived:
        sides = de.replace(" ", "").split("=")
        value = decode(warn_list, sides[1])
        key = sides[0].replace(" ", "").split(".")[1]
        new_warning[str(key)] = value
    if 'NE' in new_warning.keys():
        new_warning['dictNE'] = warn_list[0].get('dictNE')
    new_warning['role'] = []
    new_warning['logTime'] = int(warn_list[-1].get('logTime'))
    new_warning['ldp_host_ip'] = warn_list[-1].get('ldp_host_ip')
    if 'parameters' not in str(derived):
        new_warning['parameters'] = {}
    for i in ['desc', 'abstract', 'influence']:
        to_sub = new_warning.get(i, None)
        if to_sub is not None:
            items_to_fill = re.findall("\${[^{}]+}", to_sub)
            for j in range(len(items_to_fill)):
                key = 'warn1.' + (items_to_fill[j].replace('${', '').replace(' ', '').replace('}', ''))
                # print("(++++++++++++++++++)")
                # print(desc, key)
                value = decode(warn_list, key)
                # print(value)
                to_sub = to_sub.replace(items_to_fill[j], str(value))
            new_warning[i] = to_sub
    return new_warning

        

