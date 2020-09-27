import json
from pygrok import Grok
import re
import time
from dateutil import parser
import uuid


def parse_base(syslog):

    if isinstance(syslog, str):
        syslog = json.loads(syslog)
    else:
        syslog = syslog

    event = syslog.copy()

    pattern = "<%{NUMBER:pri:int}>(?<logTime>(%{MONTH} +%{MONTHDAY} %{TIME}( %{YEAR})?|%{MONTH} +%{MONTHDAY} %{YEAR} %{TIME})) %{DATA:loghostname} %%%{NUMBER}%{DATA:module}/%{NUMBER:severity:int}/%{DATA:logTypeDesc}:(( -%{DATA:location};)?|(s)?) +%{GREEDYDATA:desc}"
    grok = Grok(pattern)
    raw_log = event["message"]
    parsed_log = grok.match(raw_log)
    if parsed_log:
        # return parsed_log
        event.update(parsed_log)

        location = event['location']

        fields = re.split('-', location) if location else None

        if fields:
            for f in fields:
                k, v = re.split('=', f)
                event[k] = v

        event['ldp_host_ip'] = event['host']
        ldp_uuid = uuid.uuid4()
        event['ldp_uuid'] = str(ldp_uuid)
        return event

    else:
        raise Exception("Parse raw syslog failed!!!")


def parse_patterns(patterns, text):
    # 同一种日志，多种表现形式
    for p in patterns:
        parsed_text = Grok(p).match(text)
        if parsed_text is not None:
            return parsed_text


def parse_event(event_json):

    if isinstance(event_json, str):
        event = json.loads(event_json)
    else:
        event = event_json

    module = event['module']
    log_type_desc = event['logTypeDesc']
    desc = event['desc']
    desc = desc.strip()

    result = event.copy()

    warn_type = module + '_' + log_type_desc
    result['warnType'] = warn_type

    log_time = result['logTime']

    date = parser.parse(log_time)
    time_format = date.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    log_time_unix = time.mktime(time.strptime(time_format, "%Y-%m-%dT%H:%M:%S.000Z"))

    result['logTime'] = log_time_unix

    result['NE'] = tuple()
    result['parameters'] = dict()
    result['dictNE'] = dict()
    result['level'] = None
    result['influence'] = None
    result['abstract'] = None

    device = event['ldp_host_ip']

    if module == 'IFNET':
        if log_type_desc == "LINK_UPDOWN":

            chassis = None
            slot = None

            patterns = ["Line protocol state on the interface %{DATA:interface}(\.%{DATA:sub_inf})? changed to %{DATA:status}\.$"]
            parsed_desc = parse_patterns(patterns, desc)

            interface = parsed_desc['interface'].strip()
            sub_inf = parsed_desc.get('sub_inf')

            m_int_tnl = re.match("(Tunnel)(\d+)$", interface)
            m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
            m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
            m_interface3 = Grok("\w+%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
            # m_interface2 = re.match("\w+%{NUMBER}/%{NUMBER}$", interface)

            if m_int_tnl:
                int_tnl = m_int_tnl.group(2)
                result['dictNE'] = {'device': device,
                                    'intTnl': int_tnl}
                result['NE'] = ('device={}'.format(device),
                                'intTnl={}'.format(int_tnl))
                result['parameters'] = {"status": parsed_desc['status']}
                result['level'] = len(result['NE'])
                result['warnType'] = 'IFNET_TNL_LINK_UPDOWN'
                result['abstract'] = "interface Tunnel{} changed to up".format(int_tnl)
                return result

            elif m_int_vlan:
                int_vlan = m_int_vlan.group(2)
                result['dictNE'] = {'device': device,
                                    'intVlan': int_vlan}
                result['NE'] = ('device={}'.format(device),
                                'intVlan={}'.format(int_vlan))
                result['parameters'] = {"status": parsed_desc['status']}
                result['level'] = len(result['NE'])
                result['warnType'] = 'IFNET_INTVLAN_LINK_UPDOWN'
                result['abstract'] = "Vlan-interface{} down".format(int_vlan)
                return result

            elif m_interface4:
                chassis = m_interface4['chassis']
                slot = m_interface4['slot']
            elif m_interface3:
                slot = m_interface3['slot']
            else:
                pass

            if 'Chassis' in event:
                chassis = event['Chassis']
            if 'Slot' in event:
                slot = event['Slot']

            if not chassis:
                chassis = '0'
            if not slot:
                slot = '0'

            if sub_inf:
                result['dictNE'] = {'device': device,
                                        'chassis': chassis,
                                        'slot': slot,
                                        'port': interface,
                                        'subInf': sub_inf
                                    }
                result['NE'] = (
                    'device={}'.format(event['ldp_host_ip']),
                    'chassis={}'.format(chassis),
                    'slot={}'.format(slot),
                    'port={}'.format(interface),
                    'subInf={}'.format(sub_inf)
                    )
                result['warnType'] = 'IFNET_SUBINF_LINK_UPDOWN'
                abstract = "{} down".format(interface + "." + sub_inf)
            else:
                result['dictNE'] = {'device': device,
                                    'chassis': chassis,
                                    'slot': slot,
                                    'port': interface}
                result['NE'] = (
                    'device={}'.format(event['ldp_host_ip']),
                    'chassis={}'.format(chassis),
                    'slot={}'.format(slot),
                    'port={}'.format(interface)
                )
                result['warnType'] = 'IFNET_PORT_LINK_UPDOWN'
                abstract = "{} down".format(interface)

            # influence = None
            result['parameters'] = {"status": parsed_desc['status']}
            result['level'] = len(result['NE'])
            result['abstract'] = abstract

            return result

        elif log_type_desc == "PHY_UPDOWN":
            chassis = None
            slot = None

            patterns = ["Physical state on the interface %{DATA:interface}(\.%{DATA:subInf})? changed to %{DATA:status}\.$"]
            parsed_desc = parse_patterns(patterns, desc)

            interface = parsed_desc['interface'].strip()
            sub_inf = parsed_desc.get('subInf')

            m_int_tnl = re.match("(Tunnel)(\d+)$", interface)
            m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
            m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
            m_interface3 = Grok("\w+%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
            if m_int_tnl:
                int_tnl = m_int_tnl.group(2)
                result['dictNE'] = {'device': device,
                                        'intTnl': int_tnl}
                result['NE'] = ('device={}'.format(event['ldp_host_ip']),
                                    'intTnl={}'.format(int_tnl))
                result['parameters'] = {"status": parsed_desc['status']}
                result['level'] = len(result['NE'])
                result['warnType'] = 'IFNET_TNL_PHY_UPDOWN'
                result['abstract'] = "interface Tunnel{} changed to up".format(int_tnl)
                return result

            elif m_int_vlan:
                int_vlan = m_int_vlan.group(2)
                result['dictNE'] = {'device': event['ldp_host_ip'],
                                         'intVlan': int_vlan}
                result['NE'] = ('device={}'.format(event['ldp_host_ip']),
                                'intVlan={}'.format(int_vlan))
                result['parameters'] = {"status": parsed_desc['status']}
                result['level'] = len(result['NE'])
                result['warnType'] = 'IFNET_INTVLAN_PHY_UPDOWN'
                result['abstract'] = "Vlan-interface{} down".format(int_vlan)
                return result

            elif m_interface4:
                chassis = m_interface4['chassis']
                slot = m_interface4['slot']
            elif m_interface3:
                slot = m_interface3['slot']
            else:
                pass

            if 'Chassis' in event:
                chassis = event['Chassis']
            if 'Slot' in event:
                slot = event['Slot']

            if not chassis:
                chassis = '0'
            if not slot:
                slot = '0'

            if sub_inf:
                result['dictNE'] = {'device': device,
                                        'chassis': chassis,
                                        'slot': slot,
                                        'port': interface,
                                        'subInf': sub_inf
                                        }
                result['NE'] = (
                    'device={}'.format(event['ldp_host_ip']),
                    'chassis={}'.format(chassis),
                    'slot={}'.format(slot),
                    'port={}'.format(interface),
                    'subInf={}'.format(sub_inf)
                    )
                result['warnType'] = 'IFNET_SUBINF_PHY_UPDOWN'
                result['abstract'] = '{} down'.format(interface + "." + sub_inf)
            else:
                result['dictNE'] = {'device': device,
                                    'chassis': chassis,
                                    'slot': slot,
                                    'port': interface
                                    }
                result['NE'] = (
                    'device={}'.format(event['ldp_host_ip']),
                    'chassis={}'.format(chassis),
                    'slot={}'.format(slot),
                    'port={}'.format(interface)
                )
                result['warnType'] = 'IFNET_PORT_PHY_UPDOWN'
                result['abstract'] = '{} down'.format(interface)

            result['parameters'] = {"status": parsed_desc['status']}
            result['level'] = len(result['NE'])

            return result

    elif module == "DEV":
        if log_type_desc == "FAN_ABSENT":

            patterns = ["Fan %{NUMBER:fan} is absent.",
                        "Chassis %{NUMBER:chassis} fan %{NUMBER:fan} is absent."]
            parsed_desc = parse_patterns(patterns, desc)

            fan = parsed_desc['fan']
            chassis = parsed_desc.get('chassis')

            if 'Chassis' in event:
                chassis = event['Chassis']

            if not chassis:
                chassis = '0'

            result['dictNE'] = {'device': device,
                                'chassis': chassis,
                                'Fan': fan}
            result['NE'] = ('device={}'.format(event['ldp_host_ip']),
                            'chassis={}'.format(chassis),
                            'Fan={}'.format(fan))
            result['level'] = len(result['NE'])

            result['abstract'] = desc

            return result
        elif log_type_desc == "FAN_FAILED":
            patterns = ["Fan %{NUMBER:fan} failed.",
                        "Chassis %{NUMBER:chassis} fan %{NUMBER:fan} failed."]
            parsed_desc = parse_patterns(patterns, desc)

            fan = parsed_desc['fan']
            chassis = parsed_desc.get('chassis')

            if 'Chassis' in event:
                chassis = event['Chassis']

            if not chassis:
                chassis = '0'

            result['dictNE'] = {'device': device,
                                'chassis': chassis,
                                'Fan': fan}
            result['NE'] = ('device={}'.format(event['ldp_host_ip']),
                            'chassis={}'.format(chassis),
                            'Fan={}'.format(fan))
            result['level'] = len(result['NE'])

            result['abstract'] = desc

            return result

        elif log_type_desc == "BOARD_STATE_FAULT":
            patterns = ["Board state changed to Fault on %{DATA:board}, type is %{DATA}.$"]
            """
            Board state changed to Fault on slot 2, type is LSXM1CGQ36TD1.
            """
            parsed_desc = parse_patterns(patterns, desc)
            board = parsed_desc['board']
            m_slot = re.match("(slot )(\d+)", board)
            m_chassis = re.match("(chassis )(\d+) (slot )(\d+)", board)

            if m_chassis:
                chassis = m_chassis.group(2)
                slot = m_chassis.group(4)
            else:
                chassis = '0'
                slot = m_slot.group(2)

            result['dictNE'] = {'device': device,
                                'chassis': chassis,
                                'slot': slot}

            result['NE'] = ('device={}'.format(device),
                            'chassis={}'.format(chassis),
                            'slot={}'.format(slot))

            result['level'] = len(result['NE'])
            result['abstract'] = "Slot {} Fault".format(slot)

            return result
        elif log_type_desc == "BOARD_REBOOT":
            patterns = ["Board is rebooting on %{DATA:board}.$"]

            parsed_desc = parse_patterns(patterns, desc)
            board = parsed_desc['board']

            m_slot = re.search("(slot )(\d+)", board)
            m_chassis = re.search("(chassis )(\d+)", board)

            if m_chassis:
                chassis = m_chassis.group(2)
            else:
                chassis = '0'

            slot = m_slot.group(2)

            result['dictNE'] = {'device': device,
                                'chassis': chassis,
                                'slot': slot}

            result['NE'] = ('device={}'.format(device),
                            'chassis={}'.format(chassis),
                            'slot={}'.format(slot))

            result['level'] = len(result['NE'])

            result['abstract'] = "Slot {} Rebooting".format(slot)

            return result

    elif module == "OSPF":
        if log_type_desc == "OSPF_LAST_NBR_DOWN":
            patterns = ["OSPF %{NUMBER:ospfId} Last neighbor down event: Router ID: %{DATA:routerId} Local address: %{DATA:localAddress} Remote address: %{DATA:remoteAddress} Reason: %{DATA:reason}$"]
            parsed_desc = parse_patterns(patterns, desc)
            
            ospf_id = parsed_desc['ospfId']
            router_id = parsed_desc['routerId']
            local_address = parsed_desc['localAddress']
            remote_address = parsed_desc['remoteAddress']
            reason = parsed_desc['reason']

            result['dictNE'] = {'device': device,
                                'route': 'ospf',
                                'ospfId': ospf_id}

            result['NE'] = ('device={}'.format(device),
                            'route=ospf',
                            'ospfId={}'.format(ospf_id))

            result['parameters'] = {'routerId': router_id,
                                    'route': 'ospf',
                                    'ospfId': ospf_id,
                                    'localAddress': local_address,
                                    'remoteAddress': remote_address,
                                    'reason': reason}

            result['level'] = len(result['NE'])
            result['abstract'] = "OSPF {} Last neighbor down".format(ospf_id)
            result['influence'] = "OSPF neighbor down"

            return result
        elif log_type_desc == "OSPF_NBR_CHG_REASON":
            patterns = ["OSPF %{NUMBER:ospfId} Area %{DATA:area} Router %{DATA:routerId}\(%{DATA:interface}\) CPU usage: %{DATA}, (VPN name: %{DATA}, )?IfMTU: %{NUMBER}, Neighbor address: %{DATA:neighborAddress}, NbrID:%{DATA:nbrId} changed from %{DATA} to (?<status>\w+) %{DATA} at %{DATA}. Last 4 hello packets received at:%{DATA}Last 4 hello packets (sent|received) at:%{DATA}"]

            """
             OSPF 1 Area 0.0.0.0 Router 3.3.3.3(Vlan11) CPU usage: 4%, IfMTU: 1500, Neighbor address: 11.1.1.1, NbrID:1.2.3.4 changed from Full to DOWN because the interface went down or MTU changed at 2020-06-11 20:17:54:974. Last 4 hello packets received at:   2020-06-11 20:17:20:120   2020-06-11 20:17:30:120   2020-06-11 20:17:40:120   2020-06-11 20:17:50:120 Last 4 hello packets sent at:    2020-06-11 20:17:24:215   2020-06-11 20:17:34:215   2020-06-11 20:17:44:215   2020-06-11 20:17:54:215
             
             
             OSPF 1 Area 0.0.0.0 Router 1.1.1.1(FGE1/2/25) CPU usage: 20%, IfMTU: 1500, Neighbor address: 13.1.1.2, NbrID:4.1.1.1 changed from Full to INIT because a 1-way hello packet was received at 2004-03-17 01:51:31:774. Last 4 hello packets received at: Last 4 hello packets sent at:    2004-03-17 01:50:56:061   2004-03-17 01:51:06:061   2004-03-17 01:51:16:061   2004-03-17 01:51:26:061
            """
            parsed_desc = parse_patterns(patterns, desc)

            ospf_id = parsed_desc['ospfId']
            area = parsed_desc['area']
            router_id = parsed_desc['routerId']
            neighborAddress = parsed_desc['neighborAddress']
            nbr_id = parsed_desc['nbrId']
            status = parsed_desc['status']

            result['dictNE'] = {'device': device,
                                'route': 'ospf',
                                'ospfId': ospf_id,
                                'area': area}
            result['NE'] = ('device={}'.format(device),
                            'route=ospf',
                            'ospfId={}'.format(ospf_id),
                            'area={}'.format(area))

            result['parameters'] = {'routerId': router_id,
                                    'neighborAddress': neighborAddress,
                                    'nbrId': nbr_id,
                                    'status': status}
            result['level'] = len(result['NE'])

            return result
        elif log_type_desc == "OSPF_NBR_CHG":
            patterns = ["OSPF %{NUMBER:ospfId} Neighbor %{DATA:neighbor}\(%{DATA:interface}\) changed from %{DATA} to %{DATA:status}.$"]
            # "OSPF [UINT32] Neighbor [STRING] ([STRING]) changed from [STRING] to [STRING]."
            # "OSPF 1 Neighbor 11.1.1.1(Vlan-interface11) changed from FULL to DOWN."
            # OSPF 1 Neighbor 14.2.1.2(GigabitEthernet1/9/0/1) changed from FULL to DOWN.
            parsed_desc = parse_patterns(patterns, desc)

            interface = parsed_desc['interface']

            m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
            if m_int_vlan:
                ospf_id = parsed_desc['ospfId']
                neighbor = parsed_desc['neighbor']
                status = parsed_desc['status']
                int_vlan = m_int_vlan.group(2)

                result['dictNE'] = {'device': device,
                                    'route': 'ospf',
                                    'ospfId': ospf_id}

                result['NE'] = ('device={}'.format(device),
                                'route=ospf',
                                'ospfId={}'.format(ospf_id))

                result['parameters'] = {'neighbor': neighbor,
                                        'intVlan': int_vlan,
                                        'status': status}

                result['level'] = len(result['NE'])

                result['abstract'] = "OSPF {} Neighbor {}({}) down".format(ospf_id, neighbor, int_vlan)
                result['influence'] = "OSPF neighbor down"

            return result
    elif module == "OPTMOD":
        if log_type_desc == "PHONY_MODULE":
            patterns = ["%{DATA:interface}: This transceiver is not sold by H3C. H3C does not guarantee the correct operation of the module or assume maintenance responsibility.",
                        "%{DATA:interface}: This transceiver is NOT sold by H3C. H3C therefore shall NOT guarantee the normal function of the device or assume the maintenance responsibility thereof!"]
            """
            Ten-GigabitEthernet1/2/0/23: This transceiver is NOT sold by H3C. H3C therefore shall NOT guarantee the normal function of the device or assume the maintenance responsibility thereof!
            """

            parsed_desc = parse_patterns(patterns, desc)

            interface = parsed_desc['interface']

            # if 'Chassis' in event:
            chassis = event.get('Chassis')
            slot = event.get('Slot')

            if chassis:
                result['dictNE'] = {'device': device,
                                    'chassis': chassis,
                                    'slot': slot,
                                    'port': interface}
                result['NE'] = ('device={}'.format(device),
                                'chassis={}'.format(chassis),
                                'slot={}'.format(slot),
                                'port={}'.format(interface))

            elif slot:
                result['dictNE'] = {'device': device,
                                    'slot': slot,
                                    'port': interface}
                result['NE'] = ('device={}'.format(device),
                                'slot={}'.format(slot),
                                'port={}'.format(interface))
            result['level'] = len(result['NE'])

            result['abstract'] = "transceiver on {} is NOT sold by H3C".format(interface)
            result['influence'] = "Flow stability on {}".format(interface)

        return result

    elif module == "OSPFV3":
        if log_type_desc == "OSPFv3_NBR_CHG":
            patterns = ["OSPFv3 %{DATA:ospfv3Id} Neighbor %{DATA:neighbor}\(%{DATA:interface}\) received %{DATA} and its state from %{DATA} to %{DATA:status}.$"]
            """
            OSPFv3 [UINT32] Neighbor [STRING] ([STRING]) received [STRING] and its state from [STRING] to [STRING].
            OSPFv3 1 Neighbor 6.1.1.1(GigabitEthernet1/9/0/1) received KillNbr and its state from FULL to DOWN.
            """
            parsed_desc = parse_patterns(patterns, desc)

            interface = parsed_desc['interface']

            m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
            if m_int_vlan:
                # Vlan - interface % {NUMBER: intVlan}

                int_vlan = m_int_vlan.group(2)
                ospfv3_id = parsed_desc['ospfv3Id']
                neighbor = parsed_desc['neighbor']
                status = parsed_desc['status']

                result['dictNE'] = {'device': device,
                                    'route': 'ospfv3',
                                    'ospfv3Id': ospfv3_id}

                result['NE'] = ('device={}'.format(device),
                                'route=ospfv3',
                                'ospfv3Id={}'.format(ospfv3_id))

                result['parameters'] = {'neighbor': neighbor,
                                        'intVlan': int_vlan,
                                        'status': status}

                result['level'] = len(result['NE'])
                result['abstract'] = "OSPFv3 {} Neighbor down".format(ospfv3_id)
                result['influence'] = "OSPFv3 Neighbor down"

            return result
    elif module == "ISIS":
        if log_type_desc == "ISIS_NBR_CHG":
            patterns = ["IS-IS %{NUMBER:isisId}, %{DATA:adjacencyLevel} adjacency %{DATA:adjacencyId} \(%{DATA:interface}\), state changed to %{DATA:status}, Reason: %{DATA:reason}.$"]
            # IS-IS 1, Level-2 adjacency 0000.0000.0006 (GigabitEthernet1/9/0/1), state changed to DOWN, Reason: circuit data clean.

            parsed_desc = parse_patterns(patterns, desc)

            parsed_desc = parse_patterns(patterns, desc)

            interface = parsed_desc['interface']

            m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
            if m_int_vlan:
                int_vlan = m_int_vlan.group(2)

                isis_id = parsed_desc['isisId']
                adjacency_level = parsed_desc['adjacencyLevel']
                adjacency_id = parsed_desc['adjacencyId']
                # int_vlan = parsed_desc['intVlan']
                status = parsed_desc['status']
                reason = parsed_desc['reason']

                result['dictNE'] = {'device': device,
                                    'route': 'isis',
                                    'isisId': isis_id}
                result['NE'] = ('device={}'.format(device),
                                'route=isis',
                                'isisId={}'.format(isis_id))
                result['parameters'] = {'adjacencyLevel': adjacency_level,
                                        'adjacencyId': adjacency_id,
                                        'intVlan': int_vlan,
                                        'status': status,
                                        'reason': reason}
                result['level'] = len(result['NE'])
                result['abstract'] = "ISIS {} Neighbor down".format(isis_id)
                result['influence'] = "ISIS Neighbor down"

            return result

    elif module == "MAC":
        if log_type_desc == "MAC_NOTIFICATION":
            patterns = ["MAC address %{DATA:macAddress} in VLAN %{DATA:vlan} has moved from port %{DATA:port1} to port %{DATA:port2} for %{NUMBER} times.$"]

            parsed_desc = parse_patterns(patterns, desc)

            mac_address = parsed_desc['macAddress']
            vlan = parsed_desc['vlan']
            port1 = parsed_desc['port1']
            port2 = parsed_desc['port2']

            result['dictNE'] = {'device': device,
                                'vlan': vlan}
            result['NE'] = ('device={}'.format(device),
                            'vlan={}'.format(vlan))
            result['parameters'] = {'macAddress': mac_address,
                                    'port1': port1,
                                    'port2': port2}

            result['level'] = len(result['NE'])
            result['abstract'] = "MAC address {} move".format(mac_address)

            return result
    else:
        result.pop('abstract')
        result.pop('influence')

    return result


def test_parse_event():
    event_json = {
        "severityLevel": "信息",
        "logTime": "2020-06-11T12:17:54.000Z",
        "ldp_uuid": "7f00756a-21aa-4769-a005-4fa6a21a488c",
        "pri": 172,
        "ldp_host_ip": "0:0:0:0:0:0:0:1",
        "module": "DEV",
        "ldp_timestamp": "2020-09-01T09:36:14.392Z",
        "desc": "Board is rebooting on slot 2.",
        "loghostname": "S125G2",
        "logTypeDesc": "BOARD_REBOOT",
        "severity": 6,
        "@timestamp": "2020-09-01T09:36:14.392Z",
        "parse_success": "true"}

    _r = parse_event(event_json)
    _r = json.dumps(_r)
    print(_r)


def parse(log_dict):
    if log_dict.get('module'):
        result = parse_event(log_dict)
    else:
        event = parse_base(log_dict)
        result = parse_event(event)

    return result


if __name__ == "__main__":
    log = {
            "desc":"OSPF 1 Area 0.0.0.0 Router 3.3.3.3(Vlan11) CPU usage: 4%, IfMTU: 1500, Neighbor address: 11.1.1.1, NbrID:1.2.3.4 changed from Full to DOWN because the interface went down or MTU changed at 2020-06-11 20:17:54:974. Last 4 hello packets received at:   2020-06-11 20:17:20:120   2020-06-11 20:17:30:120   2020-06-11 20:17:40:120   2020-06-11 20:17:50:120 Last 4 hello packets sent at:    2020-06-11 20:17:24:215   2020-06-11 20:17:34:215   2020-06-11 20:17:44:215   2020-06-11 20:17:54:215",
            "createTime":"2020-09-14T17:02:20",
            "pri":172,
            "module":"OSPF",
            "loghostname":"S125G2",
            "logTypeDesc":"OSPF_NBR_CHG_REASON",
            "label":"lvhong",
            "severityLevel":"提示",
            "@version":"1",
            "tags":[
                "_grokparsefailure"
            ],
            "@timestamp":"2020-09-14T09:02:20.896Z",
            "severity":5,
            "ldp_host_ip":"192.28.200.201",
            "message":"<172>Jun 10 19:46:40 2020 S125G2 %%10OSPF/5/OSPF_NBR_CHG_REASON: OSPF 1 Area 0.0.0.0 Router 3.3.3.3(Vlan11) CPU usage: 4%, IfMTU: 1500, Neighbor address: 11.1.1.1, NbrID:1.2.3.4 changed from Full to DOWN because the interface went down or MTU changed at 2020-06-11 20:17:54:974. Last 4 hello packets received at:   2020-06-11 20:17:20:120   2020-06-11 20:17:30:120   2020-06-11 20:17:40:120   2020-06-11 20:17:50:120 Last 4 hello packets sent at:    2020-06-11 20:17:24:215   2020-06-11 20:17:34:215   2020-06-11 20:17:44:215   2020-06-11 20:17:54:215",
            "source_name":"h3c_switch_lo",
            "ldp_timestamp":"2020-09-14T09:02:20.896Z",
            "sendHost":"192.28.200.201",
            "ldp_uuid":"1c813295-e604-40ae-9841-7636448549ec",
            "parse_success":"false",
            "failure_reason":"grok解析失败",
            "logTime":"2020-06-10T11:46:40.000Z"}

    r = parse(log)

    r = json.dumps(r)
    print(r)

