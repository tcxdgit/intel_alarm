from WarningMatch import WarningMatch
from sort_rule import get_rules
from new_warning_modules import new_modules
import re
# from grouped_demo_data_in_list_multi_window import *
#
#
# all_data = [tw1, tw2, tw3, tw4, tw5, tw6].copy()



class ProcessWarningMatch:
    def __init__(self, freq_cash={}, window_count=0):
        self.freq_cash = freq_cash
        self.window_count = window_count
    
    def run(self, new_time_window, mid_time):
        
        process = WarningMatch(warn_groups=new_time_window, rule_list=get_rules(),\
                freq_warning_cash=self.freq_cash, time_window=self.window_count, mid_time=mid_time)
        last_30s, process_result, self.freq_cash = process.run()
        self.window_count += 1
        summary = {}
        summary_list = []
        for warn_group in process_result:
            device = None
            events = []
            influences = []
            for warnings in warn_group:
                # if "'father'," in str(warnings.get('role', None)):
                roles = warnings.get('role', None)
                roles = [] if roles is None else roles
                if "'son'," not in str(roles):
                    if device is None:
                        device = warnings.get('ldp_host_ip')
                    events.append(warnings.get('abstract', None))
                    if warnings.get('influence', None) is not None:
                        influences.append(warnings.get('influence', None))
            if device is not None:
                key = (int(mid_time - 30), int(mid_time + 30), device)
                value = {'device': device, 'events': list(set(events)), 'influences': list(set(influences))}
                summary[key] = value
        return last_30s, process_result, summary

# try0 = ProcessWarningMatch()
# times = [1591789350.0,1591789470.0,1591789530.0,1591789590.0,1591789650,1591789710.0]
# for i in range(6):
#     _, curr_res, summary = try0.run(all_data[i], times[i])
#     # print("********************************************************")
#     orig =  [tw1, tw2, tw3, tw4, tw5, tw6]
#     orig = orig.copy()
    # for warnset_id in range(len(curr_res)):
    #     print('len of original', len(orig[i][warnset_id]))
    #     print('len of processed', len(curr_res[warnset_id]))
    #     for warn_id in range(len(curr_res[warnset_id])):
    #         if curr_res[warnset_id][warn_id].get('role', None) is not None:
    #             print("_________ warn group", warnset_id)
    #             print("********* warning", warn_id)
    #             # print("time: ", curr_res[warnset_id][warn_id].get('message')[:24])
    #             # print(orig[i][warnset_id][warn_id].get('role', None))
    #             print(curr_res[warnset_id][warn_id].get('role', None))
