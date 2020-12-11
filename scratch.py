from WarningMatch import WarningMatch
import numpy as np
import time

#
# all_data = [tw1, tw2, tw3, tw4, tw5, tw6].copy()
tw1 = [[{'timestamp': '2020-06-17T12:24:03+08:00', 'message': '<4>Jun 17 12:24:03 2020 7506X-G %%10DIAG/1/MEM_EXCEED_THRESHOLD: Memory severe threshold has been exceeded.', 'host': '77.1.1.41', 'pri': 4, 'logTime': 1592367843.0, 'loghostname': '7506X-G', 'module': 'DIAG', 'severity': 1, 'logTypeDesc': 'MEM_EXCEED_THRESHOLD', 'location': None, 'desc': 'Memory severe threshold has been exceeded.', 'ldp_host_ip': '77.1.1.41', 'ldp_uuid': 'eb318891-4714-40cb-adc0-949c2c396748', 'warnType': 'DIAG_MEM_EXCEED_THRESHOLD', 'NE': ('device=77.1.1.41', 'level=severe'), 'parameters': {}, 'dictNE': {'device': '77.1.1.41', 'level': 'severe'}, 'level': 2, 'influence': 'Memory severe threshold exceeded', 'abstract': 'Memory severe threshold exceeded', 'ifPrev': False}, {'timestamp': '2020-06-17T12:24:06+08:00', 'message': '<4>Jun 17 12:24:06 2020 7506X-G %%10DIAG/1/MEM_BELOW_THRESHOLD: Memory usage has dropped below severe threshold.', 'host': '77.1.1.41', 'pri': 4, 'logTime': 1592367846.0, 'loghostname': '7506X-G', 'module': 'DIAG', 'severity': 1, 'logTypeDesc': 'MEM_BELOW_THRESHOLD', 'location': None, 'desc': 'Memory usage has dropped below severe threshold.', 'ldp_host_ip': '77.1.1.41', 'ldp_uuid': '5078bef2-a1c4-4373-87a4-29f5e8668b13', 'warnType': 'DIAG_MEM_BELOW_THRESHOLD', 'NE': ('device=77.1.1.41', 'level=severe'), 'parameters': {}, 'dictNE': {'device': '77.1.1.41', 'level': 'severe'}, 'level': 2, 'influence': 'Memory below severe threshold', 'abstract': 'Memory below severe threshold', 'ifPrev': False}, {'timestamp': '2020-06-17T12:24:04+08:00', 'message': '<4>Jun 17 12:24:04 2020 7506X-G %%10DIAG/1/MEM_EXCEED_THRESHOLD: Memory critical threshold has been exceeded.', 'host': '77.1.1.41', 'pri': 4, 'logTime': 1592367844.0, 'loghostname': '7506X-G', 'module': 'DIAG', 'severity': 1, 'logTypeDesc': 'MEM_EXCEED_THRESHOLD', 'location': None, 'desc': 'Memory critical threshold has been exceeded.', 'ldp_host_ip': '77.1.1.41', 'ldp_uuid': '8d05a730-de7d-4ead-8aa1-d2a9e0dab21b', 'warnType': 'DIAG_MEM_EXCEED_THRESHOLD', 'NE': ('device=77.1.1.41', 'level=critical'), 'parameters': {}, 'dictNE': {'device': '77.1.1.41', 'level': 'critical'}, 'level': 2, 'influence': 'Memory critical threshold exceeded', 'abstract': 'Memory critical threshold exceeded', 'ifPrev': False}, {'timestamp': '2020-06-17T12:24:04+08:00', 'message': '<4>Jun 17 12:24:04 2020 7506X-G %%10DIAG/1/MEM_BELOW_THRESHOLD: Memory usage has dropped below critical threshold.', 'host': '77.1.1.41', 'pri': 4, 'logTime': 1592367844.0, 'loghostname': '7506X-G', 'module': 'DIAG', 'severity': 1, 'logTypeDesc': 'MEM_BELOW_THRESHOLD', 'location': None, 'desc': 'Memory usage has dropped below critical threshold.', 'ldp_host_ip': '77.1.1.41', 'ldp_uuid': '4432478c-ff04-4c5f-9f5d-3a5f63cbca9d', 'warnType': 'DIAG_MEM_BELOW_THRESHOLD', 'NE': ('device=77.1.1.41', 'level=critical'), 'parameters': {}, 'dictNE': {'device': '77.1.1.41', 'level': 'critical'}, 'level': 2, 'influence': 'Memory below critical threshold', 'abstract': 'Memory below critical threshold', 'ifPrev': False}]]

# all_data = [tw1, tw2, tw3, tw4, tw5, tw6, tw7].copy()


class ProcessWarningMatch:
    def __init__(self, freq_cache={}, time_window=0, rule_list=None, new_modules=None):
        self.freq_cache = freq_cache
        self.time_window = time_window
        self.rule_list = rule_list
        self.new_modules = new_modules
    
    def run(self, new_time_window):

        self.time_window = np.floor(new_time_window[-1][-1]['logTime'] / 60) * 60
        if new_time_window[-1][-1]['ifPrev']:
            self.time_window += 60
        # print(self.time_window)
        # print(new_time_window)
        process = WarningMatch(warn_groups=new_time_window, rule_list=self.rule_list,
                               freq_warn_cache=self.freq_cache, time_window=self.time_window, new_modules=self.new_modules)
        last_30s, process_result, self.freq_cache = process.run()

        summary = {}
        summary_list = []
        # print('111111111111')
        # print(process_result)
        for warn_group in process_result:
            device = None
            events = []
            influences = []
            for warnings in warn_group:
                # if "'father'," in str(warnings.get('role', None)):
                # if "'father'," in str(warnings.get('role', None)) and warnings.get('ifPrev'):
                #     continue
                if warnings.get('ifPrev'):
                    continue
                roles = warnings.get('role', None)
                roles = [] if roles is None else roles
                # print("wtf???????")
                # print(warnings.get('role'), "++++++", warnings.get('abstract'))
                if "'son'," not in str(roles):
                    if device is None:
                        device = warnings.get('ldp_host_ip')
                    events.append(warnings.get('abstract', None))
                    if warnings.get('influence', None) is not None:
                        influences.append(warnings.get('influence', None))
            if device is not None:
                key = (int(self.time_window), int(self.time_window + 60), device)
                if key not in summary.keys():
                    value = {'device': device, 'events': list(set(events)), 'influences': list(set(influences))}
                    summary[key] = value
                else:
                    summary[key]['events'].extend(list(set(events)))
                    summary[key]['influences'].extend(list(set(influences)))
        return last_30s, process_result, summary


def print_summary(summary):
    for key, value in summary.items():
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key[0]))
        end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key[1]-1))
        warning_set_summary = 'From {0} to {1}, device {2} encoutered \nthe following events:\n'.format(start_time, end_time,
                                                                                                        value['device'])
        events = value.get('events')
        for i in range(len(events)):
            warning_set_summary += '    ' + (str(i + 1) + '. ' + events[i] + '\n')
        influences = value.get('influences')
        if len(influences) > 0:
            warning_set_summary += 'which might have impacts on\n'
            for j in range(len(influences)):
                warning_set_summary += '    ' + (str(j + 1) + '. ' + influences[j] + '\n')
        warning_set_summary += '++++++++++++++++++++++++++++++++++++\n\n'
        print(warning_set_summary)

# import os
# print(os.path.getmtime('data/new_rules.json'))

# try0 = ProcessWarningMatch()
# # times = [1591789350.0,1591789470.0,1591789530.0,1591789590.0,1591789650,1591789710.0, 1591789770.0]
# all_data = [tw1].copy()
# for i in range(1):
#     _, curr_res, summary = try0.run(all_data[i])#     # print("**********************all_data[i], times[i])**********************************")
#     # all_data =  [tw1, tw2, tw3, tw4, tw5, tw6, tw7, tw8, tw9, tw10, tw11, tw12, tw13, tw14, tw15, tw16, tw17, tw18]
#     # all_data =  [tw1, tw2, tw3, tw4, tw5]
#     orig = all_data.copy()
#     print_summary(summary)
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
