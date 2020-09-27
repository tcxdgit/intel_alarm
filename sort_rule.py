import json


def get_warn_role(rules):
    warn_role = dict()
    rule_id_list = []
    for i, rule in enumerate(rules):
        correlation_mode = rule['correlation_mode']
        rule_id = rule['rule_id']
        if correlation_mode == "fatherSon":
            rule_id = rule['rule_id']
            primary_warn = rule['fatherWarn']
            secondary_warn = rule['sonWarn']
        else:
            primary_warn = rule['derivedWarn']
            secondary_warn = rule['warn']

        rule_id_list.append(rule_id)

        if primary_warn not in warn_role:
            warn_role[primary_warn] = [(rule_id, 'primary')]
        else:
            warn_role[primary_warn].append((rule_id, 'primary'))

        for w in secondary_warn:
            if w not in warn_role:
                warn_role[w] = [(rule_id, 'secondary')]
            else:
                warn_role[w].append((rule_id, 'secondary'))

    return warn_role, rule_id_list


def sort_rule(rules):
    rule_adjust = []
    warn_role, rule_id_list = get_warn_role(rules)
    for k, v in warn_role.items():
        # warn = k
        first_secondary = None
        for rule_role in v:
            # i = rule_role[0]
            rule_id = rule_role[0]
            role = rule_role[1]

            if not first_secondary and role == 'secondary':
                # 指向第一个出现的次角色对应的rule的位置
                first_secondary = rule_id

            if role == 'primary' and first_secondary:
                # 表示出现了主在次后面的情况，需要调整
                rule_adjust.append((first_secondary, rule_id))
            else:
                pass

    rule_id_sorted = rule_id_list.copy()
    for adjust in rule_adjust:
        secondary, primary = adjust

        rule_id_sorted.remove(primary)
        insert_index = rule_id_sorted.index(secondary)

        rule_id_sorted.insert(insert_index, primary)

    sorted_rules = []
    for rule_id in rule_id_sorted:
        for rule in rules:
            if rule_id == rule['rule_id']:
                sorted_rules.append(rule)
            else:
                pass

    return sorted_rules, rule_adjust


def get_rules(rule_file='data/rules.json'):
    with open(rule_file, encoding="utf-8") as f_rule:
        rules = json.load(f_rule)

    new_rules, _ = sort_rule(rules)

    _, rule_adjust = sort_rule(new_rules)

    if rule_adjust:
        print('Rules {} have problem!!!'.format(rule_adjust))

    assert rule_adjust == []

    return new_rules


if __name__ == "__main__":
    result = get_rules()
    print("---------------------")
    for r in result:
        print("{} : {}".format(r["rule_id"], r["rule_name"]))
