from utils import *


class WarningMatch:
    def __init__(self, warn_groups=[[]], rule_list=[], freq_warn_cache={}, time_window=0, new_modules=None):
        '''
        self.warn_groups: list of lists, each element is a list of warnings from the same group
        self.rule_list: list of dictionaries, each element is a dictionary expressing one rule
        
        '''
        self.warn_groups = warn_groups
        self.rule_list = rule_list
        self.time_window = time_window
        self.freq_warn_cache = freq_warn_cache
        self.matched_count = {}
        self.new_modules = new_modules

    def run(self):
        '''
        output:
            1. last_30s: a list of dicts [{}], each dict is a processed warning in last 30s
            2. self.warn_groups, a list of lists [[{}]], process result of current time window
            3. self.freq_warning_cash, a dict, to keep track of frequency warnings
        '''
        # 遍历每条rule
        self.matched_count = {}
        for rule in self.rule_list:
            if rule.get('rule_id', None) not in self.freq_warn_cache.keys() and rule.get('correlation_mode', None) == "frequency":
                self.freq_warn_cache[rule.get('rule_id', None)] = {}
            warn_type_set = rule.get('allWarnings', None)
            # if "IFNET_PORT_LINK_UPDOWN" in warn_type_set:
            #     print(warn_type_set)
            for warn_group_id in range(len(self.warn_groups)):
                # 遍历每个告警组，在每个告警组中找到所有匹配当前rule的告�?
                warn_group = self.warn_groups[warn_group_id]
                match_list = []
                for warn_id in range(len(warn_group)):
                    warn = warn_group[warn_id]
                    warn_type = warn.get('warnType', None)
                    if warn_type in warn_type_set:
                        # print(tuple((warn_group_id, warn_id, warn_type, int(warn.get('logTime', None)))))
                        roles = warn.get('role', None)
                        if roles is None:
                            warn['role'] = []
                        elif 'son' in str(roles):
                            continue
                        match_list.append(tuple((warn_group_id, warn_id, warn_type, int(warn.get('logTime', None)), self.time_window)))
                if match_list:
                    mode = rule.get('correlation_mode', None)
                    if mode == "fatherSon":
                        #self.father_son_match_new(warn_group, match_list, rule)
                        self.warningrule_match(warn_group, match_list, rule)
                    if mode == "sameSource":
                        #self.same_source_match_new(warn_group, match_list, rule)
                        self.warningrule_match(warn_group, match_list, rule)
                    if mode == "frequency":
                        # print(self.freq_warning_cash)
                        self.frequency_match(warn_group, match_list, rule)
        last_30s = []
        for i in self.warn_groups:
            for j in i:
                if int(j.get('logTime')) > self.time_window + 30:
                    if j.get('temp', None) is None:
                        try:
                            roles = j.get('role', None)
                            if 'son' in str(roles):
                                continue
                            else:
                                last_30s.append(j)
                        except:
                            last_30s.append(j)
        return last_30s, self.warn_groups, self.freq_warn_cache

    def warningrule_match(self, warn_group, match_list, rule):
        '''
        match warnings by each type (warn1_list, warn2_list, ...)
        while enough elements to pick:
            select 1st element of each type and check time range
            if time out of range:
                abandon the oldest element out of the set, go back to select
            else:
                go to matching
                if matched:
                    del elements, label the roles
                else:
                    label the elements with same num, put them to the end of each type list, go back to select
        scenarios to decide out of elements to pick:
            1. # of left warnings < len(allWarnings)
            2. all left elements share the same num label
        '''
        total_warnings = len(match_list)
        if total_warnings < 2:
            return False

        mode = rule.get('correlation_mode', None)
        # create lists of each type
        if mode == "fatherSon":
            all_warning_types = [rule.get('upstreamWarn', None)] + rule.get('downstreamWarn', None)
        elif mode == "sameSource":
            all_warning_types = rule.get('allWarnings', None)
        else:
            print("Error rule")
            return False

        pool = [[] for _ in range(len(all_warning_types))]
        for i in match_list:
            if i[2] == all_warning_types[0]:
                pool[0].append(i)

            if i[2] == all_warning_types[1]:
                pool[1].append(i)

        if any(len(i) == 0 for i in pool):
            return

        # while loop till all elements matched
        # still_proposable = True
        match_done = False

        while match_done == False:
            for typeA in pool[0]:
                ismatch = False
                for typeB in pool[1]:
                    if typeA[0] == typeB[0] and typeA[1] == typeB[1]:  # same warning
                        continue

                    proposal = [typeA, typeB]
                    proposal_id_list = [typeA[1], typeB[1]]
                    proposal_warn_list = [warn_group[typeA[1]], warn_group[typeB[1]]]

                    match_res = check_rules(rule, proposal, proposal_warn_list)
                    if match_res:
                        ismatch = True
                        if proposal[0][0] not in self.matched_count.keys():
                            self.matched_count[proposal[0][0]] = 1
                        else:
                            self.matched_count[proposal[0][0]] += 1
                        identifier = eval(str(int(self.time_window)) + '0000' + str(proposal[0][0]) + '0000' + str(self.matched_count[proposal[0][0]])) # uuid.uuid4()
                        if mode == "fatherSon":
                            proposal_tuple_list = [(j[0], j[1], self.time_window) for j in proposal]
                            warn_group[proposal_id_list[0]]['role'].append(
                                ('fatherSon', 'father', proposal_tuple_list, identifier))
                            warn_group[proposal_id_list[1]]['role'].append(
                                ('fatherSon', 'son', proposal_tuple_list, identifier))
                            pool[1].remove(typeB)
                        elif mode == "sameSource":
                            # create new warning
                            new_warning = create_new_warning(rule, proposal_warn_list, self.new_modules)
                            warn_group.append(new_warning)
                            new_warning_id = warn_group.index(new_warning)
                            proposal_tuple_list = [(j[0], j[1], self.time_window) for j in proposal]
                            proposal_tuple_list.append((typeA[0], new_warning_id, self.time_window))
                            warn_group[typeA[1]]['role'].append(
                                ('sameSource', 'son', proposal_tuple_list, identifier))
                            warn_group[typeB[1]]['role'].append(
                                ('sameSource', 'son', proposal_tuple_list, identifier))
                            warn_group[new_warning_id]['role'].append(
                                ('sameSource', 'father', proposal_tuple_list, identifier))
                            pool[0].remove(typeA)
                            pool[1].remove(typeB)
                            if typeA[2] == typeB[2]: # if same warn type, delete both warns from both pools
                                pool[0].remove(typeB)
                                pool[1].remove(typeA)
                        else:
                            print("Error rule")
                            return False

                        break
                    # elif typeA[2] == typeB[2] and mode == "fatherSon":
                    #     match_res = check_rules(rule, proposal[::-1], proposal_warn_list[::-1])
                    #     if match_res:
                    #         ismatch = True
                    #         if proposal[1][0] not in self.matched_count.keys():
                    #             self.matched_count[proposal[1][0]] = 1
                    #         else:
                    #             self.matched_count[proposal[1][0]] += 1
                    #         identifier = eval(str(int(self.time_window)) + '0000' + str(proposal[1][0]) + '0000' + str(
                    #             self.matched_count[proposal[1][0]]))  # uuid.uuid4()
                    #         if mode == "fatherSon":
                    #             proposal_tuple_list = [(j[1], j[0], self.time_window) for j in proposal]
                    #             warn_group[proposal_id_list[1]]['role'].append(
                    #                 ('fatherSon', 'father', proposal_tuple_list, identifier))
                    #             warn_group[proposal_id_list[0]]['role'].append(
                    #                 ('fatherSon', 'son', proposal_tuple_list, identifier))
                    #             pool[0].remove(typeA)

                if ismatch:
                    break
                else:
                    pool[0].remove(typeA)
                    # if typeA[2] == typeB[2]:
                    #     pool[1].remove(typeA)
                    break

            if any(len(i) == 0 for i in pool):
                match_done = True

    def frequency_match(self, warn_group, match_list, rule):
        rule_id = rule.get('rule_id', None)
        time_range = int(rule.get('timeRange', None))
        times = int(rule.get('times', None))
        for proposal in match_list:
            proposal_warn = warn_group[proposal[1]]
            if proposal_warn.get('ifPrev', None):
                continue
            cur_satisfy = eval(rule.get('satisfy'))
            if self.freq_warn_cache.get(rule_id, None) and self.freq_warn_cache.get(rule_id, None).get(cur_satisfy, None):
                self.freq_warn_cache[rule_id][cur_satisfy].append([proposal, proposal_warn])
            else:
                self.freq_warn_cache[rule_id][cur_satisfy] = [[proposal, proposal_warn]]

        for key, freq_warn_list in self.freq_warn_cache[rule_id].items():
            if len(freq_warn_list) == 0:
                continue
            [proposal_list, proposal_warn_list] = zip(*freq_warn_list)
            proposal_list = list(proposal_list)
            proposal_warn_list = list(proposal_warn_list)
            while proposal_warn_list[0]['logTime'] + time_range < proposal_warn_list[-1]['logTime']:
                proposal_warn_list.pop(0)
                proposal_list.pop(0)
                freq_warn_list.pop(0)
            if len(proposal_warn_list) < times:
                continue

            new_warning = create_new_warning(rule, proposal_warn_list, self.new_modules)
            warn_group.append(new_warning)
            new_warning_id = warn_group.index(new_warning)

            if proposal_list[0][0] not in self.matched_count.keys():
                self.matched_count[proposal_list[0][0]] = 1
            else:
                self.matched_count[proposal_list[0][0]] += 1
            identifier = eval(str(int(self.time_window)) + '0000' + str(proposal_list[0][0]) + '0000' + str(self.matched_count[proposal_list[0][0]]))  # uuid.uuid4()

            proposal_tuple_list = [(j[0], j[1], j[4]) for j in proposal_list]
            proposal_tuple_list.append((proposal_list[-1][0], new_warning_id, self.time_window))
            warn_group[new_warning_id]['role'].append(
                ('frequency', 'father', proposal_tuple_list, identifier))
            for proposal in proposal_list:
                if proposal[4] != self.time_window:
                    continue
                warn_group[proposal[1]]['role'].append(
                    ('frequency', 'son', proposal_tuple_list, identifier))
            self.freq_warn_cache[rule_id][key].clear()

