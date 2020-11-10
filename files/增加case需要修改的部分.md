# 增加case需要修改的部分

###### 理论上增加demo只需要修改解析规则logParser.py、关联规则data/rules.json和新增的告警模板（因为demo7中只有父子规则，所以不需要修改新增告警模板）

- 关联规则rules.json

```shell
diff --git a/data/rules.json b/data/rules.json
index 49dbdf8..f025920 100644
--- a/data/rules.json
+++ b/data/rules.json
@@ -189,5 +189,36 @@
     "derived": ["warn2.NE= warn1.NE"],
     "timeRange": 120,
     "times": 3
+  },
+  {
+    "rule_id":14,
+    "rule_name":"IFNET_PORT_LINK_UPDOWN -> LAGG_LAGG_INACTIVE_OTHER",
+    "description": "",
+    "correlation_mode":"fatherSon",
+    "is_enable":"true",
+    "create_by": "system",
+    "create_time": "2020-10-13 14:28:06",
+    "fatherWarn": "IFNET_PORT_LINK_UPDOWN",
+    "sonWarn": ["LAGG_LAGG_INACTIVE_OTHER"],
+    "allWarnings": ["IFNET_PORT_LINK_UPDOWN","LAGG_LAGG_INACTIVE_OTHER"],
+    "satisfy":["warn1.NE.port==warn2.parameters.memberPort",
+      "warn1.parameters.status==down",
+      "warn2.parameters.status==inactive"],
+    "timeRange": 10
+  },
+  {
+    "rule_id":15,
+    "rule_name":"LAGG_LAGG_INACTIVE_OTHER -> DRNI_DRNI_IFEVENT_DR_NOSELECTED",
+    "description": "",
+    "correlation_mode":"fatherSon",
+    "is_enable":"true",
+    "create_by": "system",
+    "create_time": "2020-10-13 14:28:06",
+    "fatherWarn": "LAGG_LAGG_INACTIVE_OTHER",
+    "sonWarn": ["DRNI_DRNI_IFEVENT_DR_NOSELECTED"],
+    "allWarnings": ["LAGG_LAGG_INACTIVE_OTHER","DRNI_DRNI_IFEVENT_DR_NOSELECTED"],
+    "satisfy":["warn1.NE.aggregationGroup==warn2.NE.localDrInterface",
+      "warn1.parameters.status==warn2.parameters.status"],
+    "timeRange": 4
   }
 ]
```



- 解析规则logParser.py 

```shell
diff --git a/logParser.py b/logParser.py
index 7854c26..379d253 100644
--- a/logParser.py
+++ b/logParser.py
@@ -172,7 +172,7 @@ def parse_event(event_json):
                     'port={}'.format(interface)
                 )
                 result['warnType'] = 'IFNET_PORT_LINK_UPDOWN'
-                abstract = "{} down".format(interface)
+                abstract = "{} link down".format(interface)
 
             # influence = None
             result['parameters'] = {"status": parsed_desc['status']}
@@ -239,11 +239,11 @@ def parse_event(event_json):
 
             if sub_inf:
                 result['dictNE'] = {'device': device,
-                                        'chassis': chassis,
-                                        'slot': slot,
-                                        'port': interface,
-                                        'subInf': sub_inf
-                                        }
+                                    'chassis': chassis,
+                                    'slot': slot,
+                                    'port': interface,
+                                    'subInf': sub_inf
+                                    }
                 result['NE'] = (
                     'device={}'.format(event['ldp_host_ip']),
                     'chassis={}'.format(chassis),
@@ -266,7 +266,7 @@ def parse_event(event_json):
                     'port={}'.format(interface)
                 )
                 result['warnType'] = 'IFNET_PORT_PHY_UPDOWN'
-                result['abstract'] = '{} down'.format(interface)
+                result['abstract'] = '{} physical down'.format(interface)
 
             result['parameters'] = {"status": parsed_desc['status']}
             result['level'] = len(result['NE'])
@@ -623,6 +623,49 @@ def parse_event(event_json):
             result['abstract'] = "MAC address {} move".format(mac_address)
 
             return result
+    elif module == "LAGG":
+        if log_type_desc == "LAGG_INACTIVE_OTHER":
+            patterns = ["Member port %{DATA:memberPort} of aggregation group %{DATA:aggregationGroup} changed to the inactive state, because other reason."]
+            # Member port XGE3/0/26 of aggregation group BAGG40 changed to the inactive state, because other reason.
+            parsed_desc = parse_patterns(patterns, desc)
+
+            aggregation_group = parsed_desc["aggregationGroup"]
+            if re.match("BAGG(\d+)", aggregation_group):
+                num = re.match("BAGG(\d+)", aggregation_group).group(1)
+                aggregation_group = "Bridge-Aggregation" + num
+
+            member_port = re.sub("XGE", "Ten-GigabitEthernet", parsed_desc["memberPort"])
+
+            result['dictNE'] = {'device': device,
+                                'aggregationGroup': aggregation_group}
+
+            result['NE'] = ('device={}'.format(device),
+                            'aggregationGroup={}'.format(aggregation_group))
+            result['parameters'] = {'memberPort': member_port,
+                                    'status': 'inactive'}
+            result['abstract'] = "hhhhh"
+            result['level'] = 2
+    elif module == "DRNI":
+        if log_type_desc == "DRNI_IFEVENT_DR_NOSELECTED":
+            patterns = ["Local DR interface %{DATA:localDrInterface} in DR group %{NUMBER:drGroup} does not have Selected member ports because %{DATA}$"]
+            # Local DR interface Bridge-Aggregation40 in DR group 40 does not have Selected member ports because the aggregate interface went down. Please check the aggregate link status.
+
+            parsed_desc = parse_patterns(patterns, desc)
+
+            local_dr_interface = parsed_desc['localDrInterface']
+            dr_group = parsed_desc['drGroup']
+
+            result['dictNE'] = {'device': device,
+                                'localDrInterface': local_dr_interface}
+
+            result['NE'] = ('device={}'.format(device),
+                            'localDrInterface={}'.format(local_dr_interface))
+            result['parameters'] = {'drGroup': dr_group,
+                                    'status': 'inactive'}
+            result['level'] = len(result['NE'])
+            result['abstract'] = "Local DR interface {} in DR group {} does not have Selected member ports".format(local_dr_interface, dr_group)
+            result['influence'] = "interface {} changed to inactive".format(local_dr_interface)
+
     else:
         result.pop('abstract')
         result.pop('influence')
@@ -662,30 +705,35 @@ def parse(log_dict):
```



###### 但由于实现规则匹配时编码要考虑的细节比较多，因此代码还存在一些缺陷，demo7加入后出现了之前的demo中没有考虑到的问题

之前的代码版本，把“向前看30s“中已经匹配好的父告警又拿出来总结了一次，为了解决这个问题，对匹配部分的代码做了修改：

```shell
diff --git a/WarningMatch.py b/WarningMatch.py
index c5d6ccb..75f24dd 100644
--- a/WarningMatch.py
+++ b/WarningMatch.py
@@ -48,12 +48,14 @@ class WarningMatch:
                                     continue
                             match_list.append(tuple((warn_group_id, warn_id, warn_type, int(warn.get('logTime', None)))))
                 if match_list:
+
                     mode = rule.get('correlation_mode', None)
                     if mode == "fatherSon":
                         self.father_son_match(warn_group, match_list, rule)
                     if mode == "sameSource":
                         self.same_source_match(warn_group, match_list, rule)
                     if mode == "frequency":
+                        # print(self.freq_warning_cash)
                         self.frequency_match(warn_group, match_list, rule)
         last_30s = []
         for i in self.warn_groups:
@@ -257,6 +259,7 @@ class WarningMatch:
                 break
 
     def frequency_match(self, warn_group, match_list, rule):
+        # print(self.freq_warning_cash)
         rule_id = rule.get('rule_id', None)
         satisfies = rule.get('satisfy', None)
         time_range = int(rule.get('timeRange', None))
@@ -266,6 +269,8 @@ class WarningMatch:
             # print("_________________________", self.freq_warning_cash.get(rule_id))
             # check satisfy
             this_warning = warn_group[warn_tuple[1]]
+            if this_warning.get('ifPrev'):
+                continue
             if len(self.freq_warning_cash.get(rule_id)) == 0:
                 this_warning['temp'] = (warn_tuple[0], warn_tuple[1], self.time_window)
                 self.freq_warning_cash.get(rule_id).append(this_warning)
```

```shell
diff --git a/scratch.py b/scratch.py
index e194cd6..be4d262 100644
--- a/scratch.py
+++ b/scratch.py
@@ -22,14 +22,20 @@ class ProcessWarningMatch:
         self.window_count += 1
         summary = {}
         summary_list = []
+        # print('111111111111')
+        # print(process_result)
         for warn_group in process_result:
             device = None
             events = []
             influences = []
             for warnings in warn_group:
                 # if "'father'," in str(warnings.get('role', None)):
+                if "'father'," in str(warnings.get('role', None)) and warnings.get('ifPrev'):
+                    continue
                 roles = warnings.get('role', None)
                 roles = [] if roles is None else roles
+                # print("wtf???????")
+                # print(warnings.get('role'), "++++++", warnings.get('abstract'))
                 if "'son'," not in str(roles):
                     if device is None:
                         device = warnings.get('ldp_host_ip')
@@ -45,8 +51,7 @@ class ProcessWarningMatch:
 # try0 = ProcessWarningMatch()
 # times = [1591789350.0,1591789470.0,1591789530.0,1591789590.0,1591789650,1591789710.0]
 # for i in range(6):
-#     _, curr_res, summary = try0.run(all_data[i], times[i])
-#     # print("********************************************************")
+#     _, curr_res, summary = try0.run(#     # print("**********************all_data[i], times[i])**********************************")
 #     orig =  [tw1, tw2, tw3, tw4, tw5, tw6]
 #     orig = orig.copy()
     # for warnset_id in range(len(curr_res)):
```

```shell
diff --git a/utils.py b/utils.py
index b26d38b..a093461 100644
--- a/utils.py
+++ b/utils.py
@@ -48,6 +48,9 @@ def check_rules(satisfy, warn_list):
     output:
         res: bool, True if satisfies the whole thing
     '''
+    if warn_list[0].get('ifPrev', None) and warn_list[1].get('ifPrev', None):
+        # print(warn_list)
+        return False
     if len(warn_list) < 2:
         return False
     for rule in satisfy:
```

###### 另外还发现一些问题，有待解决

1. demo7的匹配耗时有点久，原因待排查
2. 告警匹配完成后，返回last_30s，其中应该剔除子告警以及衍生告警和频次告警的原始告警，即MAC地址迁移的经过匹配后应只返回Many MAC addresses has moved from port XGE4/0/5:1 to port XGE4/0/5:2，但现在返回了该频次规则衍生出的新告警以及原始的5条告警。