from utils import *
from new_warning_modules import new_modules
import uuid



class WarningMatch:
    def __init__(self, warn_groups=[[]], rule_list=[], freq_warning_cash={}, time_window=0, mid_time=0):
        '''
        self.warn_groups: list of lists, each element is a list of warnings from the same group
        self.rule_list: list of dictionaries, each element is a dictionary expressing one rule
        
        '''
        self.warn_groups = warn_groups
        self.rule_list = rule_list
        self.freq_warning_cash = freq_warning_cash
        self.time_window = time_window
        self.mid_time = mid_time

    def run(self):
        '''
        output:
            1. last_30s: a list of dicts [{}], each dict is a processed warning in last 30s
            2. self.warn_groups, a list of lists [[{}]], process result of current time window
            3. self.freq_warning_cash, a dict, to keep track of frequency warnings
        '''
        # 遍历每条rule
        for rule in self.rule_list:
            if rule.get('rule_id', None) not in self.freq_warning_cash.keys() and rule.get('correlation_mode', None) == "frequency":
                self.freq_warning_cash[rule.get('rule_id', None)] = []
            warn_type_set = rule.get('allWarnings', None)
            # if "IFNET_PORT_LINK_UPDOWN" in warn_type_set:
            #     print(warn_type_set)
            for warn_group_id in range(len(self.warn_groups)):
                # 遍历每个告警组，在每个告警组中找到所有匹配当前rule的告警
                warn_group = self.warn_groups[warn_group_id]
                match_list = []
                for warn_id in range(len(warn_group)):
                    warn = warn_group[warn_id]
                    if warn_valid_check(warn):
                        warn_type = warn.get('warnType', None)
                        if warn_type in warn_type_set:
                            # print(tuple((warn_group_id, warn_id, warn_type, int(warn.get('logTime', None)))))
                            roles = warn.get('role', None)
                            if roles is None:
                                warn['role'] = []
                            elif 'son' in str(roles):
                                    continue
                            match_list.append(tuple((warn_group_id, warn_id, warn_type, int(warn.get('logTime', None)))))
                if match_list:

                    mode = rule.get('correlation_mode', None)
                    if mode == "fatherSon":
                        self.father_son_match(warn_group, match_list, rule)
                    if mode == "sameSource":
                        self.same_source_match(warn_group, match_list, rule)
                    if mode == "frequency":
                        # print(self.freq_warning_cash)
                        self.frequency_match(warn_group, match_list, rule)
        last_30s = []
        for i in self.warn_groups:
            for j in i:
                if int(j.get('logTime')) > self.mid_time:
                    if j.get('temp', None) is None:
                        # last_30s.append(j)
                        try:
                            roles = j.get('role', None)
                            if 'son' in str(roles):
                                continue
                            else:
                                last_30s.append(j)
                        except:
                            last_30s.append(j)
        return last_30s, self.warn_groups, self.freq_warning_cash

    def father_son_match(self, warn_group, match_list, rule):
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
        
        
        # create lists of each type
        all_warning_types = [rule.get('fatherWarn', None)] + rule.get('sonWarn', None)
        pool = [[] for i in range(len(all_warning_types))]
        for i in match_list:
            for j in range(len(all_warning_types)):
                if i[2] == all_warning_types[j]:
                    pool[j].append(i)
        if any(len(i) == 0 for i in pool):
            return
        # while loop till all elements matched
        still_proposable = True
        mark_list = [[] for i in range(total_warnings)]
        failed_mark = 0
        while still_proposable:
            # pick 1st elements
            proposal = [pool[0][0], pool[1][0]]
            # print(rule)
            # print(proposal)
            # check time range, pop oldest item
            time_range = int(rule.get('timeRange', None))
            res, oldest_warning_type = check_time_ranges_fs(proposal, time_range)
            if res is False:
                to_pop = match_list.index(proposal[oldest_warning_type])
                match_list.pop(to_pop)
                mark_list.pop(to_pop)
                pool[oldest_warning_type].pop(0)
                continue
            # check match
            proposal_id_list = [j[1] for j in proposal]
            proposal_warn_list = [warn_group[i] for i in proposal_id_list]
            matchable = check_rules(rule.get('satisfy', None), proposal_warn_list)
            # if True, mark son roles, pop proposals out of match_list/mark_list
            # if False, mark mark_list, pop proposals to the end of each pool sublist
            proposal_match_indexes = [match_list.index(k) for k in proposal]
            if matchable is False:
                for pos in proposal_match_indexes:
                    mark_list[pos].append(failed_mark)
                failed_mark += 1
                for warning_type in pool:
                    warning_type.append(warning_type.pop(0))
            elif matchable is True:
                identifier = uuid.uuid4()
                proposal_tuple_list = [(j[0], j[1], self.time_window) for j in proposal]
                warn_group[proposal_id_list[0]]['role'].append(('fatherSon', 'father', proposal_tuple_list, identifier))
                warn_group[proposal_id_list[1]]['role'].append(('fatherSon', 'son', proposal_tuple_list, identifier))
                for pos in proposal_match_indexes[1:]:
                    match_list.pop(pos)
                    mark_list.pop(pos)
                for i in pool[1:]:
                    i.pop(0)
            # print("len of marklist: ", len(mark_list))
            # print("marklist", mark_list)
            # print("len of matchlist: ", len(match_list))
            # print(pool)
            # print("_____________________")
            # print(any(len(i) == 0 for i in pool))
            # check proposable
            if len(match_list) < 2:
                still_proposable = False
                break
            if any(len(i) == 0 for i in pool):
                still_proposable = False
                break
            if any(len(i) > total_warnings for i in mark_list):
                still_proposable = False
                break
            
    def same_source_match(self, warn_group, match_list, rule):
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
        
        # create lists of each type
        all_warning_types = rule.get('allWarnings', None)
        total_warnings = len(all_warning_types)
        pool = [[] for i in range(total_warnings)]
        for i in match_list:
            for j in range(total_warnings):
                if i[2] == all_warning_types[j]:
                    pool[j].append(i)
        # print(pool)
        # special case of same warning type
        same_mark = False
        if all_warning_types[0] == all_warning_types[1]:
            pool[0] = pool[0][::2]
            pool[1] = pool[1][1::2]
            same_mark = True
        if any(len(i) == 0 for i in pool):
            return
        # while loop till all elements matched
        still_proposable = True
        mark_list = [[] for i in range(len(match_list))]
        failed_mark  = 0
        while still_proposable:
            # pick 1st elements
            proposal = [pool[0][0], pool[1][0]]
            # check time range, pop oldest item
            time_range = int(rule.get('timeRange', None))
            res, oldest_warning_type = check_time_ranges_ss(proposal, time_range)
            if res is False:
                to_pop = match_list.index(proposal[oldest_warning_type])
                match_list.pop(to_pop)
                mark_list.pop(to_pop)
                pool[oldest_warning_type].pop(0)
                continue
            # check match
            proposal_id_list = [j[1] for j in proposal]
            proposal_warn_list = [warn_group[i] for i in proposal_id_list]
            if same_mark:
                matchable_list = [check_rules(rule.get('satisfy', None), proposal_warn_list), check_rules(rule.get('satisfy', None), proposal_warn_list[::-1])]
                matchable = any(matchable_list)
            else:
                matchable = check_rules(rule.get('satisfy', None), proposal_warn_list)
            # if True, mark son roles, pop proposals out of match_list/mark_list
            # if False, mark mark_list, pop proposals to the end of each pool sublist
            proposal_match_indexes = [match_list.index(k) for k in proposal]
            if matchable is False:
                for pos in proposal_match_indexes:
                    mark_list[pos].append(failed_mark)
                failed_mark += 1
                for warning_type in pool:
                    warning_type.append(warning_type.pop(0))
            elif matchable is True:
                identifier = uuid.uuid4()
                # create new warning
                new_warning = create_new_warning(rule, proposal_warn_list)
                warn_group.append(new_warning)
                new_warning_id = warn_group.index(new_warning)
                new_id_list = [(i[0], i[1], self.time_window) for i in proposal]
                new_id_list.append((new_id_list[-1][0], new_warning_id, self.time_window))
                # print(new_id_list)
                warn_group[new_id_list[0][1]]['role'].append(('sameSource', 'son', new_id_list, identifier))
                warn_group[new_id_list[1][1]]['role'].append(('sameSource', 'son', new_id_list, identifier))
                warn_group[new_id_list[2][1]]['role'].append(('sameSource', 'father', new_id_list, identifier))
                for pos in sorted(proposal_match_indexes, reverse=True):
                    match_list.pop(pos)
                    mark_list.pop(pos)
                for i in pool:
                    i.pop(0)
            
            # print("len of marklist: ", len(mark_list))
            # print("marklist", mark_list)
            # print("len of matchlist: ", len(match_list))
            # print(pool)
            # print("_____________________")
            # print(any(len(i) == 0 for i in pool))
            # check proposable
            if len(match_list) < 2:
                still_proposable = False
                break
            if any(len(i) == 0 for i in pool):
                still_proposable = False
                break
            if any(len(i) > total_warnings for i in mark_list):
                still_proposable = False
                break

    def frequency_match(self, warn_group, match_list, rule):
        # print(self.freq_warning_cash)
        rule_id = rule.get('rule_id', None)
        satisfies = rule.get('satisfy', None)
        time_range = int(rule.get('timeRange', None))
        questionable_1stwarning = False
        for warn_tuple in match_list:
            # print("|||||||||||||||||||||||||", warn_tuple)
            # print("_________________________", self.freq_warning_cash.get(rule_id))
            # check satisfy
            this_warning = warn_group[warn_tuple[1]]
            if this_warning.get('ifPrev'):
                continue
            if len(self.freq_warning_cash.get(rule_id)) == 0:
                this_warning['temp'] = (warn_tuple[0], warn_tuple[1], self.time_window)
                self.freq_warning_cash.get(rule_id).append(this_warning)
                continue
            next = False
            for item in satisfies:
                cur_warning_item = decode([this_warning], item.replace(" ", ""))
                grouped_warning_item = decode(self.freq_warning_cash.get(rule_id), item.replace(" ", ""))
                if cur_warning_item != grouped_warning_item:
                    next = True
                    break
            if next and match_list.index(warn_tuple) == 1:
                # if 2nd is different, check the 3rd one
                questionable_1stwarning = True
            elif next and match_list.index(warn_tuple) == 2 and questionable_1stwarning:
                # if 3rd is different from 1st, drop 1st
                self.freq_warning_cash[rule_id] = []
                self.frequency_match(warn_group, match_list[1:], rule)
                break
            elif next:
                continue
            # check previous warnings
            this_warning['temp'] = (warn_tuple[0], warn_tuple[1], self.time_window)
            curr_time = int(this_warning.get('logTime', None))
            if len(self.freq_warning_cash.get(rule_id)) + 1 >= int(rule.get('times', None)):
                # append to existing warning&continue, or start as brand new
                if (abs(int(self.freq_warning_cash.get(rule_id)[0].get('logTime', None)) - curr_time) > time_range) or (warn_tuple == match_list[-1]):
                    # create and append derived warning, get group list and append to role, empty the cash
                    # print('reach')
                    if warn_tuple == match_list[-1]:
                        self.freq_warning_cash.get(rule_id).append(this_warning)
                    derived_freq_warning = create_new_warning(rule, self.freq_warning_cash.get(rule_id))
                    warn_group.append(derived_freq_warning)
                    index_tuple_list = []
                    
                    for i in self.freq_warning_cash.get(rule_id):
                        index_tuple_list.append(i.get('temp'))
                        i.pop('temp', None)
                    identifier = uuid.uuid4()
                    index_tuple_list.append((warn_tuple[0], warn_group.index(derived_freq_warning), self.time_window))
                    for indexes in index_tuple_list[:-1]:
                        # print("++++++++++", self.time_window, "+++++++++", indexes)
                        # print(len(self.processed_data))
                        if indexes[2] < self.time_window:
                            continue
                        else:
                            self.warn_groups[indexes[0]][indexes[1]]['role'].append(('frequency', 'son', index_tuple_list, identifier))
                    self.warn_groups[index_tuple_list[-1][0]][index_tuple_list[-1][1]]['role'].append(('frequency', 'father', index_tuple_list, identifier))
                    self.freq_warning_cash[rule_id] = [this_warning] if (warn_tuple != match_list[-1]) else []
                else:
                    self.freq_warning_cash.get(rule_id).append(this_warning)
            else:
                # append to warning list while ensuring time_range
                while len(self.freq_warning_cash.get(rule_id)) > 0:
                    first_time = int(self.freq_warning_cash.get(rule_id)[0].get('logTime', None))
                    if abs(first_time - curr_time) > time_range:
                        self.freq_warning_cash.get(rule_id).pop(0)
                    else:
                        break
                self.freq_warning_cash.get(rule_id).append(this_warning)
