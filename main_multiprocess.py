
import argparse
import time
import numpy as np
from datetime import datetime
from kafka import KafkaConsumer
from multiprocessing import Process, Queue, Lock

from network_element import NetworkElement
from syslog_filters import filter_invalids, filter_flappings
from group_data import divide_tree, merge_group
from logParser import parse
from scratch import ProcessWarningMatch


def add_warns(exist_warn_list, new_warn_list, prev_flag):
    for warn in new_warn_list:
        warn['ifPrev'] = prev_flag
        exist_warn_list.append(warn)
    return exist_warn_list


def process_data(syslog_dict, flapping_flag, group_overlap):
    merged_groups = []
    for key, warns in syslog_dict.items():
        root = NetworkElement(name='root')
        for s in warns:
            ne = s['NE']
            cur_node = root

            for item in ne:
                cur_node.refresh_time_range(s)
                if item in cur_node.children:
                    cur_node = cur_node.children[item]
                    continue
                else:
                    child_node = NetworkElement(name=item, parent=cur_node)
                    cur_node.add_child_node(item, child_node)
                    cur_node = child_node
                    continue

            cur_node.isEntity = True
            if flapping_flag:
                if not filter_flappings(cur_node, s):
                    cur_node.add_warnings(s)
            else:
                cur_node.add_warnings(s)
        groups = divide_tree([], root)
        cur_merged_groups = merge_group(groups, group_overlap)
        merged_groups.extend(cur_merged_groups)
    return merged_groups


def print_summary(summary):
    for key, value in summary.items():
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key[0]))
        end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key[1]-1))
        warning_set_summary = 'From {0} to {1}, device {2} encoutered \nthe following events:\n'.format(start_time, end_time,
                                                                                                        value['device'])
        events = value.get('events')
        # print(events)
        for i in range(len(events)):
            warning_set_summary += '    ' + (str(i + 1) + '. ' + events[i] + '\n')
        influences = value.get('influences')
        if len(influences) > 0:
            warning_set_summary += 'which might have impacts on\n'
            for j in range(len(influences)):
                warning_set_summary += '    ' + (str(j + 1) + '. ' + influences[j] + '\n')
        warning_set_summary += '++++++++++++++++++++++++++++++++++++\n\n'
        print(warning_set_summary)


def consumer(warn_queue, lock, timeslot, timeout, group_overlap, flapping_flag):

    cur_time_window_start = 0
    last_log_time = datetime.now()
    empty_time_range = 0
    start_warn = True
    start_group = True
    jump_window = False
    local_warn_list = []
    cur_warn_list = []
    pre_warn_list = []

    rule_matching = ProcessWarningMatch()

    f = open('data/output_log_for_matched_results.txt', 'w+')

    while True:
        # if the last warning arrives empty_time_range seconds ago, blah blah...
        if empty_time_range > timeout: continue # break
        time.sleep(1)

        lock.acquire() # lock the warn_queue to avoid conflict
        while warn_queue.qsize() > 0:
            local_warn_list.append(warn_queue.get())
        lock.release()  # finish processing with warn_queue, release the lock

        if len(local_warn_list) == 0: # empty queue
            empty_time_range = (datetime.now() - last_log_time).total_seconds() # add time to empty_time_range
            if len(cur_warn_list) > 0:
                # still have chance to receive new warnings in this time window
                if cur_warn_list[-1]['logTime'] + empty_time_range < cur_time_window_start + timeslot:
                    # print(output_summary.txt)
                    # print(local_warn_list)
                    # print(cur_warn_list)
                    # print(output_summary.txt)
                    continue
                else: cur_time_window_start += timeslot

        else:
            if start_warn: # reset the start time for the first time window
                cur_time_window_start = np.floor(local_warn_list[0]['logTime'] / timeslot) * timeslot
                cur_warn_list.append(local_warn_list.pop(0))
                start_warn = False
                last_log_time = datetime.now()
                empty_time_range = 0
            while len(local_warn_list) > 0: # iterate over all warnings in the queue
                if local_warn_list[0]['logTime'] - cur_time_window_start < timeslot: # the warning belongs to the current time window
                    cur_warn_list.append(local_warn_list.pop(0))
                    last_log_time = datetime.now()
                    empty_time_range = 0
                else:
                    cur_time_window_start += timeslot
                    jump_window = True
                    last_log_time = datetime.now()
                    empty_time_range = 0
                    # print(222)
                    # print(local_warn_list)
                    # print(cur_warn_list)
                    # print(222)
                    break
            if not jump_window: # if the last warning in the queue belongs to the current time window, wait for others
                # jump_window = False
                # print(333)
                # print(local_warn_list)
                # print(cur_warn_list)
                # print(333)
                continue
            else:
                jump_window = False

        if len(cur_warn_list) == 0: # no warnings in current time window
            pre_warn_list = []
            # print(444)
            # print(local_warn_list)
            # print(444)
            continue

        if not start_group: # not the first time window, add warnings from previous 30s
            all_warn_list = add_warns([], pre_warn_list, True) # "ifPrev":True
            all_warn_list = add_warns(all_warn_list, cur_warn_list, False)
        else:
            start_group = False
            all_warn_list = add_warns([], cur_warn_list, False)
        
        all_warn_dict = {}
        for warn in all_warn_list:
            # print(warn)
            if warn['ldp_host_ip'] in all_warn_dict:
                all_warn_dict[warn['ldp_host_ip']].append(warn)
            else:
                all_warn_dict[warn['ldp_host_ip']] = [warn]

        merged_groups = process_data(all_warn_dict, flapping_flag, group_overlap)
        # print(555)
        # f.write(str(merged_groups))
        # print([len(x) for x in merged_groups])
        # f.write('\n')
        # f.flush()
        # for x in merged_groups:
        #     print(x)
        #     print(len(x))
        # print('\n-------------------------------time window: '+str(cur_time_window_start-60)+'-'+str(cur_time_window_start))
        # print(555)
        pre_warn_list, processed_result, summary = rule_matching.run(merged_groups, cur_time_window_start-30) # from lvhong
        # pre_warn_list = [x for x in pre_warn_list if x['ifPrev'] == False]
        pre_warn_list.sort(key=lambda x:x['logTime'])
        print_summary(summary)
        # print('pre')
        # for x in pre_warn_list:
        #     print(x)
        # print('---')
        # print('processed')
        for x in processed_result:
            for y in x:
                try:
                    if y['ifPrev'] == False:
                        f.write(str(y))
                        f.write('\n')
                        f.flush()
                except:
                    f.write(str(y))
                    f.write('\n')
                    f.flush()
        # print(summary_result)
        cur_warn_list = []
        # all_warn_dict = {}


def producer(warn_queue, server, topic, low_priori_flag):

    # Kafka real-time
    # consumer = KafkaConsumer(topic, bootstrap_servers=[server], value_deserializer=bytes.decode) # collect data from Kafka
    # for msg in consumer:
    #     syslog = msg.value
    #     # print(syslog)
    #     warn = parse(eval(syslog))
    #     # warn = parse(eval(json.loads(syslog)))
    #     # print(warn)
    #     if low_priori_flag:
    #         if not filter_invalids(warn): # filter warnings with severity 7 and from SHELL module
    #             warn_queue.put(warn)
    #     else:
    #         warn_queue.put(warn)

    # file static
    with open('data/demo_multi_window.txt', 'r') as file:
        lines = file.readlines()
    print(len(lines))
    syslogs = []
    for l in lines:
        if 'timestamp' in l:
            syslogs.append(parse(eval(l.strip('\n'))))
    for warn in syslogs:
        time.sleep(0.1)
        warn_queue.put(warn)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=str, default='10.99.216.80:30091', help='syslog server')
    parser.add_argument('--topic', type=str, default='h3c_switch_final', help='syslog topic: rsyslog, security')
    parser.add_argument('--timeslot', type=int, default=60, help='timeslot')
    parser.add_argument('--timeout', type=int, default=300, help='timeout')
    parser.add_argument('--group_overlap', type=int, default=10, help='group_overlap')
    parser.add_argument('--low_prior_filter', action='store_true', default=True, help='filter for low priority syslogs')
    parser.add_argument('--flapping_filter', action='store_true', default=True, help='filter for flapping syslogs')
    args = parser.parse_args()

    server = args.server
    topic = args.topic
    low_priori_flag = args.low_prior_filter
    flapping_flag = args.flapping_filter
    timeslot = args.timeslot
    timeout = args.timeout
    group_overlap = args.group_overlap

    warn_queue = Queue()
    lock = Lock()
    p1 = Process(target=producer, args=(warn_queue, server, topic, low_priori_flag))
    c1 = Process(target=consumer, args=(warn_queue, lock, timeslot, timeout, group_overlap, flapping_flag))

    p1.start()
    c1.start()
    p1.join()
    c1.join()
