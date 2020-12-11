import json
from pygrok import Grok
import re
import time
from dateutil import parser
import uuid


class LogParser:

    def parse_ARP_DUPIFIP(self, device, desc, result, event):
        patterns = ["Duplicate address %{DATA:ipAddress} on interface %{DATA:port}, sourced from %{DATA:mac}\."]
        parsed_desc = parse_patterns(patterns, desc)
        ipAddress = parsed_desc['ipAddress']
        port = parsed_desc['port']
        mac = parsed_desc['mac']

        result['dictNE'] = {'device': device,
                            'ipAddress': ipAddress}

        result['NE'] = ('device={}'.format(device),
                        'ipAddress={}'.format(ipAddress))

        result['parameters'] = {"port": port, "mac": mac}

        result['level'] = len(result['NE'])

        result['abstract'] = "Duplicate address {} on interface {}, sourced from {}".format(ipAddress, port, mac)
        result['influence'] = "IP Address conflict"

        return result

    def parse_ARP_DUPVRRPIP(self, device, desc, result, event):
        patterns = [
            "IP address %{DATA:ipAddress} conflicted with VRRP virtual IP address on interface %{DATA:l3Inf}, sourced from %{DATA:mac}\."]
        parsed_desc = parse_patterns(patterns, desc)
        ipAddress = parsed_desc['ipAddress']
        l3Inf = parsed_desc['l3Inf']
        mac = parsed_desc['mac']

        result['dictNE'] = {'device': device,
                            'ipAddress': ipAddress}

        result['NE'] = ('device={}'.format(device),
                        'ipAddress={}'.format(ipAddress))

        result['parameters'] = {"l3Inf": l3Inf, "mac": mac}

        result['level'] = len(result['NE'])

        result[
            'abstract'] = "IP address {} conflicted with VRRP virtual IP address on interface {}, sourced from {}".format(
            ipAddress, l3Inf, mac)
        result['influence'] = "Vrrp IP Address conflict"
        return result

    def parse_ARP_ARP_ENTRY_CONFLICT(self, device, desc, result, event):
        chassis = None
        slot = None
        patterns = ["The software entry for %{DATA:ip} on the public network and the hardware entry did not have the same MAC address."]
        parsed_desc = parse_patterns(patterns, desc)

        ip = parsed_desc['ip']

        if 'Chassis' in event:
            chassis = event['Chassis']
        if 'Slot' in event:
            slot = event['Slot']

        if not chassis:
            chassis = '0'
        if not slot:
            slot = '0'

        result['dictNE'] = {'device': device,
                            'chassis': chassis,
                            'slot': slot,
                            'ip': ip}
        result['NE'] = (
            'device={}'.format(event['ldp_host_ip']),
            'chassis={}'.format(chassis),
            'slot={}'.format(slot),
            'ip={}'.format(ip)
        )

        result['level'] = len(result['NE'])

        result['abstract'] = "ARP entry {} confict".format(ip)
        result['influence'] = "ARP entry {} confict".format(ip)

        return result

    def parse_ARP_ARP_MAXNUMBER(self, device, desc, result, event):
        result['dictNE'] = {'device': device}
        result['NE'] = ['device={}'.format(device)]

        result['level'] = len(result['NE'])

        result['abstract'] = "Max ARP Number reached"
        result['influence'] = "Max ARP Number reached"

        return result

    def parse_ARP_ARP_MAXNUMBER_IF(self, device, desc, result, event):
        patterns = ["The maximum number of dynamic ARP entries for interface %{DATA:l3Inf} reached."]
        parsed_desc = parse_patterns(patterns, desc)
        l3Inf = parsed_desc["l3Inf"]
        result['dictNE'] = {'device': device,
                            'l3Inf': l3Inf}
        result['NE'] = ('device={}'.format(device),
                        'l3Inf={}'.format(l3Inf))

        result['level'] = len(result['NE'])

        result['abstract'] = "ARP Maxnumber reached on {}".format(l3Inf)
        result['influence'] = "ARP Maxnumber reached"

        return result

    def parse_BFD_BFD_CHANGE_FSM(self, device, desc, result, event):
        # [ ]要转义
        patterns = [
            "Sess\[%{DATA:sess}\], Ver(%{DATA})?, Sta: %{DATA:initial_status}->%{DATA:status}, Diag: %{DATA}"]
        # Sess[21.2.1.1/21.2.1.2, LD/RD:4128/4119, Interface:Vlan202, SessType:Ctrl, LinkType:INET], Ver:1, Sta: UP->DOWN, Diag: 3 (No Diagnostic)
        parsed_desc = parse_patterns(patterns, desc)

        status = parsed_desc["status"]
        initial_status = parsed_desc["initial_status"]
        sess = parsed_desc.get('sess')
        m_sess = Grok(
            "%{DATA:session}, LD/RD:%{DATA:LD_RD}, Interface:%{DATA:interface}, SessType:%{DATA:sess_type}, LinkType:%{DATA:link_type}").match(
            sess)

        session = m_sess["session"]
        sip, dip = session.split('/')
        ldRd = m_sess["LD_RD"]
        interface = re.sub("GE", "GigabitEthernet", m_sess["interface"])
        interface = re.sub("X", "Ten-", interface)
        sess_type = m_sess["sess_type"]
        link_type = m_sess["link_type"]

        result['dictNE'] = {'device': device,
                            'session': session}

        result['NE'] = ('device={}'.format(device),
                        'session={}'.format(session))

        result['parameters'] = {"sip": sip, "dip": dip, "ldRd": ldRd,
                                "interface": interface, "sessType": sess_type,
                                "linkType": link_type,  "status": status}

        result['level'] = len(result['NE'])

        result['abstract'] = "BFD Session[{}] change from {} to {}".format(session, initial_status, status)
        # result['influence'] = "Master change"

        return result

    def parse_BGP_BGP_STATE_CHANGED(self, device, desc, result, event):
        patterns_up = ["BGP.: %{DATA:dip} state has changed from %{DATA:initial_status} to %{DATA:status}\."]
        patterns_down = ["BGP.: %{DATA:dip} state has changed from %{DATA:initial_status} to %{DATA:status} for session down event received from BFD."]
        parsed_desc = parse_patterns(patterns_down, desc)
        if not parsed_desc:
            parsed_desc = parse_patterns(patterns_up, desc)
        dip = parsed_desc['dip']
        initial_status = parsed_desc['initial_status']
        status = parsed_desc['status']
        result['dictNE'] = {'device': device}

        result['NE'] = ['device={}'.format(device)]

        result['parameters'] = {"dip": dip, "status": status}

        result['level'] = len(result['NE'])
        result['abstract'] = "BGP {} state has changed from {} to {}".format(dip, initial_status, status)
        return result

    def parse_DEV_BOARD_STATE_FAULT(self, device, desc, result, event):
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

    def parse_DEV_BOARD_STATE_NORMAL(self, device, desc, result, event):
        patterns = ["Board state changed to Normal on %{DATA:board}, type is %{DATA}."]
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
        result['abstract'] = "{} Normal".format(board)

        return result

    def parse_DEV_BOARD_REBOOT(self, device, desc, result, event):
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

    def parse_DEV_BOARD_REMOVED(self, device, desc, result, event):
        patterns = ["Board was removed from %{DATA:board}, type is %{DATA}."]
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

        result['abstract'] = "Slot {} removed".format(slot)

        return result

    def parse_DEV_FAN_ABSENT(self, device, desc, result, event):
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

    def parse_DEV_FAN_FAILED(self, device, desc, result, event):
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

    def parse_DEV_SYSTEM_REBOOT(self, device, desc, result, event):
        result['dictNE'] = {'device': device}
        result['NE'] = ['device={}'.format(device)]
        result['level'] = len(result['NE'])

        result['abstract'] = "System Reboot"
        result['influence'] = "System Reboot"

        return result

    def parse_DIAG_CPU_SEVERE_THRESHOLD(self, device, desc, result, event):
        result['dictNE'] = {'device': device}
        result['NE'] = ['device={}'.format(device)]
        result['level'] = len(result['NE'])

        result['abstract'] = "CPU usage is in severe alarm state"
        result['influence'] = "CPU usage is in severe alarm state"

        return result

    def parse_DIAG_MEM_BELOW_THRESHOLD(self, device, desc, result, event):
        patterns = ["Memory usage has dropped below %{DATA:level} threshold."]
        parsed_desc = parse_patterns(patterns, desc)
        level = parsed_desc['level']

        result['dictNE'] = {'device': device,
                            'level': level}
        result['NE'] = ('device={}'.format(device),
                        'level={}'.format(level))
        result['level'] = len(result['NE'])

        result['abstract'] = "Memory below {} threshold".format(level)
        result['influence'] = "Memory below {} threshold".format(level)

        return result

    def parse_DIAG_MEM_EXCEED_THRESHOLD(self, device, desc, result, event):
        patterns = ["Memory %{DATA:level} threshold has been exceeded."]
        parsed_desc = parse_patterns(patterns, desc)
        level = parsed_desc['level']

        result['dictNE'] = {'device': device,
                            'level': level}
        result['NE'] = ('device={}'.format(device),
                        'level={}'.format(level))
        result['level'] = len(result['NE'])

        result['abstract'] = "Memory {} threshold exceeded".format(level)
        result['influence'] = "Memory {} threshold exceeded".format(level)

        return result

    def parse_DLDP_DLDP_LINK_BIDIRECTIONAL(self, device, desc, result, event):
        chassis = None
        slot = None
        patterns = ["DLDP detected a bidirectional link on interface %{DATA:interface}\."]
        parsed_desc = parse_patterns(patterns, desc)
        interface = parsed_desc['interface']

        m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
        m_interface3 = Grok("\w+%{NUMBER:slot}\/%{NUMBER}\/%{NUMBER}$").match(interface)

        if m_interface4:
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

        # influence = None
        result['level'] = len(result['NE'])
        result['abstract'] = "DLDP detected a bidirectional link on interface {}".format(interface)

        return result

    def parse_DLDP_DLDP_LINK_UNIDIRECTIONAL(self, device, desc, result, event):

        chassis = None
        slot = None
        patterns = ["DLDP detected a unidirectional link on interface %{DATA:interface}. %{DATA}."]

        # DLDP detected a unidirectional link on interface Ten-GigabitEthernet1/0/51. DLDP automatically blocked the interface.
        parsed_desc = parse_patterns(patterns, desc)

        interface = parsed_desc['interface']

        m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
        m_interface3 = Grok("\w+%{NUMBER:slot}\/%{NUMBER}\/%{NUMBER}$").match(interface)

        if m_interface4:
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

        # influence = None
        result['level'] = len(result['NE'])
        result['abstract'] = "DLDP detected a unidirectional link on interface {}".format(interface)

        return result

    def parse_DLDP_DLDP_NEIGHBOR_CONFIRMED(self, device, desc, result, event):
        chassis = None
        slot = None
        patterns = [
            "A neighbor was confirmed on interface %{DATA:interface}. The neighbor's system MAC is %{DATA:neighborSystemMac}, and the port index is %{NUMBER:portIndex}."]
        # A neighbor was confirmed on interface Ten-GigabitEthernet1/0/51. The neighbor's system MAC is fc60-9b59-2fe8, and the port index is 1.

        parsed_desc = parse_patterns(patterns, desc)

        interface = parsed_desc['interface']
        portIndex = parsed_desc['portIndex']
        neighborSystemMac = parsed_desc['neighborSystemMac']

        m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
        m_interface3 = Grok("\w+%{NUMBER:slot}\/%{NUMBER}\/%{NUMBER}$").match(interface)

        if m_interface4:
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
        result['parameters'] = {'portIndex': portIndex,
                                'neighborSystemMac': neighborSystemMac}

        result['level'] = len(result['NE'])
        result['abstract'] = "DLDP detected a unidirectional link on interface {}".format(interface)

        return result

    def parse_DRNI_DRNI_IFEVENT_DR_NOSELECTED(self, device, desc, result, event):
        patterns = [
            "Local DR interface %{DATA:localDrInterface} in DR group %{NUMBER:drGroup} does not have Selected member ports because %{DATA}$"]
        # Local DR interface Bridge-Aggregation40 in DR group 40 does not have Selected member ports because the aggregate interface went down. Please check the aggregate link status.

        parsed_desc = parse_patterns(patterns, desc)

        local_dr_interface = parsed_desc['localDrInterface']
        dr_group = parsed_desc['drGroup']

        result['dictNE'] = {'device': device,
                            'localDrInterface': local_dr_interface}

        result['NE'] = ('device={}'.format(device),
                        'localDrInterface={}'.format(local_dr_interface))
        result['parameters'] = {'drGroup': dr_group,
                                'status': 'inactive'}
        result['level'] = len(result['NE'])
        result['abstract'] = "Local DR interface {} in DR group {} does not have Selected member ports".format(
            local_dr_interface, dr_group)
        result['influence'] = "interface {} changed to inactive".format(local_dr_interface)

        return result

    def parse_DRVPLAT_DrvDebug(self, device, desc, result, event):
        chassis = None
        slot = None
        patterns = ["Chip %{NUMBER:chip} occurs %{NUMBER:errorNum} parity/ecc errors in %{NUMBER:time} seconds."]
        parsed_desc = parse_patterns(patterns, desc)
        chip = parsed_desc['chip']
        errorNum = parsed_desc['errorNum']
        time = parsed_desc['time']

        if 'Chassis' in event:
            chassis = event['Chassis']
        if 'Slot' in event:
            slot = event['Slot']

        if not chassis:
            chassis = '0'
        if not slot:
            slot = '0'

        result['dictNE'] = {'device': device,
                            'chassis': chassis,
                            'slot': slot,
                            'chip': chip}

        result['NE'] = ('device={}'.format(device),
                        'chassis={}'.format(chassis),
                        'slot={}'.format(slot),
                        'chip={}'.format(chip))

        result['parameters'] = {'errorNum': errorNum,
                                'time': time}
        result['level'] = len(result['NE'])
        result['abstract'] = "parity/ecc errors occur on slot {} chip {}".format(slot, chip)
        result['influence'] = "parity/ecc errors occur"
        return result

    def parse_FDB_LRN(self, device, desc, result, event):

        chassis = None
        slot = None
        subslot = None

        patterns = ["The number of MAC address received in interface %{DATA:interface} reaches the upper limit."]
        parsed_desc = parse_patterns(patterns, desc)
        interface = parsed_desc['interface']

        m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER:subslot}/%{NUMBER}$").match(interface)
        m_interface3 = Grok("\w+%{NUMBER:slot}\/%{NUMBER:subslot}\/%{NUMBER}$").match(interface)

        if m_interface4:
            chassis = m_interface4['chassis']
            slot = m_interface4['slot']
            subslot = m_interface4['subslot']
        elif m_interface3:
            slot = m_interface3['slot']
            subslot = m_interface3['subslot']

        if 'Chassis' in event:
            chassis = event['Chassis']
        if 'Slot' in event:
            slot = event['Slot']

        if not chassis:
            chassis = '0'
        if not slot:
            slot = '0'
        if not subslot:
            subslot = '0'

        result['dictNE'] = {'device': device,
                            'chassis': chassis,
                            'slot': slot,
                            'subslot': subslot,
                            'port': interface}

        result['NE'] = ('device={}'.format(device),
                        'chassis={}'.format(chassis),
                        'slot={}'.format(slot),
                        'subslot={}'.format(subslot),
                        'port={}'.format(interface))

        result['level'] = len(result['NE'])

        result['abstract'] = "MAC Maxnumber reached on {}".format(interface)
        result['influence'] = "MAC Maxnumber reached"

        return result

    def parse_HA_HA_STANDBY_TO_MASTER(self, device, desc, result, event):
        patterns = ["Standby board in %{DATA:board} changed to (the )?master."]
        parsed_desc = parse_patterns(patterns, desc)
        # m_slot = re.match("(Tunnel)(\d+)$", loc)
        # m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
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

        result['abstract'] = "Standby board in {} changed to master".format(board)
        result['influence'] = "Master change"

        return result

    def parse_IFNET_LINK_UPDOWN(self, device, desc, result, event):
        chassis = None
        slot = None

        patterns = [
            "Line protocol state on the interface %{DATA:interface}(\.%{DATA:sub_inf})? changed to %{DATA:status}\.$"]
        parsed_desc = parse_patterns(patterns, desc)

        interface = parsed_desc['interface'].strip()
        sub_inf = parsed_desc.get('sub_inf')
        status = parsed_desc['status']

        m_int_tnl = re.match("(Tunnel)(\d+)$", interface)
        m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
        m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(interface)
        m_interface3 = Grok("\w+%{NUMBER:slot}\/%{NUMBER}\/%{NUMBER}$").match(interface)

        if m_int_tnl:
            int_tnl = m_int_tnl.group(2)
            result['dictNE'] = {'device': device,
                                'intTnl': int_tnl}
            result['NE'] = ('device={}'.format(device),
                            'intTnl={}'.format(int_tnl))
            result['parameters'] = {"status": status}
            result['level'] = len(result['NE'])
            result['warnType'] = 'IFNET_TNL_LINK_UPDOWN'
            result['abstract'] = "interface Tunnel{} changed to {}".format(int_tnl, status)
            return result

        elif m_int_vlan:
            int_vlan = m_int_vlan.group(2)
            result['dictNE'] = {'device': device,
                                'intVlan': int_vlan}
            result['NE'] = ('device={}'.format(device),
                            'intVlan={}'.format(int_vlan))
            result['parameters'] = {"status": status}
            result['level'] = len(result['NE'])
            result['warnType'] = 'IFNET_INTVLAN_LINK_UPDOWN'
            result['abstract'] = "Vlan-interface{} {}".format(int_vlan, status)
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
            abstract = "{} {}".format(interface + "." + sub_inf, status)
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
            abstract = "{} link {}".format(interface, status)

        # influence = None
        result['parameters'] = {"status": status}
        result['level'] = len(result['NE'])
        result['abstract'] = abstract

        return result

    def parse_IFNET_PHY_UPDOWN(self, device, desc, result, event):
        chassis = None
        slot = None

        patterns = [
            "Physical state on the interface %{DATA:interface}(\.%{DATA:subInf})? changed to %{DATA:status}\.$"]
        parsed_desc = parse_patterns(patterns, desc)

        interface = parsed_desc['interface'].strip()
        sub_inf = parsed_desc.get('subInf')
        status = parsed_desc.get('status')

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
            result['parameters'] = {"status": status}
            result['level'] = len(result['NE'])
            result['warnType'] = 'IFNET_TNL_PHY_UPDOWN'
            result['abstract'] = "interface Tunnel{} changed to physical {}".format(int_tnl, status)
            return result

        elif m_int_vlan:
            int_vlan = m_int_vlan.group(2)
            result['dictNE'] = {'device': event['ldp_host_ip'],
                                'intVlan': int_vlan}
            result['NE'] = ('device={}'.format(event['ldp_host_ip']),
                            'intVlan={}'.format(int_vlan))
            result['parameters'] = {"status": status}
            result['level'] = len(result['NE'])
            result['warnType'] = 'IFNET_INTVLAN_PHY_UPDOWN'
            result['abstract'] = "Vlan-interface{} physical {}".format(int_vlan, status)
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
            result['abstract'] = '{} physical {}'.format(interface + "." + sub_inf, status)
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
            result['abstract'] = '{} physical {}'.format(interface, status)

        result['parameters'] = {"status": parsed_desc['status']}
        result['level'] = len(result['NE'])

        return result

    def parse_ISIS_ISIS_NBR_CHG(self, device, desc, result, event):
        patterns = [
            "IS-IS %{NUMBER:isisId}, %{DATA:adjacencyLevel} adjacency %{DATA:adjacencyId} \(%{DATA:interface}\), state changed to %{DATA:status}, Reason: %{DATA:reason}.$"]
        # IS-IS 1, Level-2 adjacency 0000.0000.0006 (GigabitEthernet1/9/0/1), state changed to DOWN, Reason: circuit data clean.

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
            result['abstract'] = "ISIS {} Neighbor {}".format(isis_id, status.lower())
            result['influence'] = "ISIS Neighbor down"

        return result

    def parse_LAGG_LAGG_ACTIVE(self, device, desc, result, event):
        patterns = ["Member port %{DATA:memberPort} of aggregation group %{DATA:port} changed to the active state."]
        parsed_desc = parse_patterns(patterns, desc)
        # memberPort = parsed_desc['memberPort']
        raw_port = parsed_desc['port']
        if re.match("BAGG(\d+)", raw_port):
            num = re.match("BAGG(\d+)", raw_port).group(1)
            port = "Bridge-Aggregation" + num

        memberPort = re.sub("GE", "GigabitEthernet", parsed_desc["memberPort"])

        result['dictNE'] = {'device': device,
                            'port': port}
        result['NE'] = ('device={}'.format(device),
                        'port={}'.format(port))
        result['parameters'] = {'memberPort': memberPort}

        result['level'] = len(result['NE'])
        result['abstract'] = "Member port {} of aggregation group {} changed to the active state".format(memberPort,
                                                                                                         raw_port)

        return result

    def parse_LAGG_LAGG_INACTIVE_DUPLEX(self, device, desc, result, event):
        # Member port FGE1/0/10 of aggregation group BAGG1 changed to the inactive state, because the duplex mode of the port was different from that of the reference port.
        patterns = [
            "Member port %{DATA:member_port} of aggregation group %{DATA:aggregationGroup} changed to the inactive state, because the duplex mode of the port was different from that of the reference port."]
        parsed_desc = parse_patterns(patterns, desc)

        aggregation_group = parsed_desc["aggregationGroup"]
        if re.match("BAGG(\d+)", aggregation_group):
            num = re.match("BAGG(\d+)", aggregation_group).group(1)
            aggregation_group = "Bridge-Aggregation" + num

        member_port = re.sub("FGE", "Forty-GigabitEthernet", parsed_desc["member_port"])

        result['dictNE'] = {'device': device,
                            'aggregationGroup': aggregation_group}

        result['NE'] = ('device={}'.format(device),
                        'aggregationGroup={}'.format(aggregation_group))
        result['parameters'] = {'memberPort': member_port,
                                'status': 'inactive'}

        # result['abstract'] = "hhhhh"
        result['level'] = 2
        return result

    def parse_LAGG_LAGG_INACTIVE_OTHER(self, device, desc, result, event):
        patterns = [
            "Member port %{DATA:member_port} of aggregation group %{DATA:aggregationGroup} changed to the inactive state, because other reason."]
        # Member port XGE3/0/26 of aggregation group BAGG40 changed to the inactive state, because other reason.
        parsed_desc = parse_patterns(patterns, desc)

        aggregation_group = parsed_desc["aggregationGroup"]
        if re.match("BAGG(\d+)", aggregation_group):
            num = re.match("BAGG(\d+)", aggregation_group).group(1)
            aggregation_group = "Bridge-Aggregation" + num

        member_port = re.sub("XGE", "Ten-GigabitEthernet", parsed_desc["member_port"])

        result['dictNE'] = {'device': device,
                            'aggregationGroup': aggregation_group}

        result['NE'] = ('device={}'.format(device),
                        'aggregationGroup={}'.format(aggregation_group))
        result['parameters'] = {'memberPort': member_port,
                                'status': 'inactive'}

        # result['abstract'] = "hhhhh"
        result['level'] = 2
        return result

    def parse_LAGG_LAGG_INACTIVE_PHYSTATE(self, device, desc, result, event):
        patterns = [
            "Member port %{DATA:member_port} of aggregation group %{DATA:port} changed to the inactive state, because the physical or line protocol state of the port was down."]
        # Member port XGE1/1/1 of aggregation group BAGG3 changed to the inactive state, because the physical or line protocol state of the port was down.
        parsed_desc = parse_patterns(patterns, desc)
        raw_port = parsed_desc["port"]
        port = re.sub("BAGG", "Bridge-Aggregation", raw_port)
        # member_port = parsed_desc['member_port']
        member_port = re.sub("XGE", "Ten-GigabitEthernet", parsed_desc["member_port"])

        result['dictNE'] = {'device': device,
                            'aggregationGroup': port}

        result['NE'] = ('device={}'.format(device),
                        'aggregationGroup={}'.format(port))
        result['parameters'] = {'memberPort': member_port}

        result['level'] = len(result['NE'])
        result['abstract'] = "Member port {} of aggregation group {} changed to the inactive state".format(
            member_port, raw_port)
        return result

    def parse_LLDP_LLDP_CREATE_NEIGHBOR(self, device, desc, result, event):
        # Nearest bridge agent neighbor created on port GigabitEthernet0/5 (IfIndex 7), neighbor's chassis ID is 346b-5b57-5c89, port ID is GigabitEthernet0/5.
        patterns = ["Nearest bridge agent neighbor created on port %{DATA:port} \(IfIndex %{NUMBER:if_index}\), neighbor's chassis ID is %{DATA:neighbor_chassis_id}, port ID is %{DATA:neighbor_port_id}\."]
        parsed_desc = parse_patterns(patterns, desc)
        port = parsed_desc['port']
        if_index = parsed_desc['if_index']
        neighbor_chassis_id = parsed_desc['neighbor_chassis_id']
        neighbor_port_id = parsed_desc['neighbor_port_id']

        if 'Chassis' in event:
            chassis = event['Chassis']
        else:
            chassis = '0'

        if 'Slot' in event:
            slot = event['Slot']
        else:
            slot = '0'

        # if not chassis:
        #     chassis = '0'
        # if not slot:
        #     slot = '0'
        result['dictNE'] = {'device': device,
                            'chassis': chassis,
                            'slot': slot,
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'chassis={}'.format(chassis),
                        'slot={}'.format(slot),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['parameters'] = {"ifIndex": if_index,
                                "neighbor_chassis_id": neighbor_chassis_id,
                                "neighbor_port_id": neighbor_port_id}

        result['abstract'] = "LLDP Neighbor created on {}".format(port)

        return result

    def parse_LLDP_LLDP_DELETE_NEIGHBOR(self, device, desc, result, event):
        patterns = [
            "%{DATA} agent neighbor deleted on port %{DATA:port} \(IfIndex %{NUMBER:if_index}\), neighbor's chassis ID is %{DATA:neighbor_chassis_id}, port ID is %{DATA:neighbor_port_id}\."]
        # Nearest bridge agent neighbor deleted on port Ten-GigabitEthernet1/1/1 (IfIndex 53), neighbor's chassis ID is 0000-fc00-eab1, port ID is Ten-GigabitEthernet6/0/13.
        parsed_desc = parse_patterns(patterns, desc)
        port = parsed_desc['port']
        if_index = parsed_desc['if_index']
        neighbor_chassis_id = parsed_desc['neighbor_chassis_id']
        neighbor_port_id = parsed_desc['neighbor_port_id']

        if 'Chassis' in event:
            chassis = event['Chassis']
        else:
            chassis = '0'

        if 'Slot' in event:
            slot = event['Slot']
        else:
            slot = '0'

        # if not chassis:
        #     chassis = '0'
        # if not slot:
        #     slot = '0'
        result['dictNE'] = {'device': device,
                            'chassis': chassis,
                            'slot': slot,
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'chassis={}'.format(chassis),
                        'slot={}'.format(slot),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['parameters'] = {"ifIndex": if_index,
                                "neighbor_chassis_id": neighbor_chassis_id,
                                "neighbor_port_id": neighbor_port_id}

        result['abstract'] = "LLDP Neighbor deleted on {}".format(port)

        return result

    def parse_MAC_MAC_NOTIFICATION(self, device, desc, result, event):
        patterns = [
            "MAC address %{DATA:macAddress} in VLAN %{DATA:vlan} has moved from port %{DATA:port1} to port %{DATA:port2} for %{NUMBER} times.$"]

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

    def parse_OPTMOD_PHONY_MODULE(self, device, desc, result, event):
        patterns = [
            "%{DATA:interface}: This transceiver is not sold by H3C. H3C does not guarantee the correct operation of the module or assume maintenance responsibility.",
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

    def parse_OSPF_OSPF_IP_CONFLICT_INTRA(self, device, desc, result, event):
        patterns = ["OSPF %{NUMBER:ospfId} Received newer self-originated network-LSAs. Possible conflict of IP address %{DATA:ipAddress} in area %{DATA:area} on interface %{DATA:l3Inf}\."]
        parsed_desc = parse_patterns(patterns, desc)

        ospf_id = parsed_desc['ospfId']
        ipAddress = parsed_desc['ipAddress']
        area = parsed_desc['area']
        l3Inf = parsed_desc['l3Inf']

        result['dictNE'] = {'device': device,
                            'route': 'ospf',
                            'ospfId': ospf_id,
                            'area': area}
        result['NE'] = ('device={}'.format(device),
                        'route=ospf',
                        'ospfId={}'.format(ospf_id),
                        'area={}'.format(area))

        result['parameters'] = {'ipAddress': ipAddress,
                                'l3Inf': l3Inf}

        result['level'] = len(result['NE'])
        result['abstract'] = "OSPF Conflict IP Address {} on interface {}".format(ipAddress, l3Inf)
        result['influence'] = "OSPF Conflict IP Address {}".format(ipAddress)

        return result

    def parse_OSPF_OSPF_DUP_RTRID_NBR(self, device, desc, result, event):
        patterns = [
            "OSPF %{NUMBER:ospfId} Duplicate router ID %{DATA:routerId} on interface %{DATA:l3Inf}, sourced from IP address %{DATA:sourceIp}."]

        parsed_desc = parse_patterns(patterns, desc)

        ospf_id = parsed_desc['ospfId']
        router_id = parsed_desc['routerId']
        # local_address = parsed_desc['localAddress']
        l3Inf = parsed_desc['l3Inf']
        sourceIp = parsed_desc['sourceIp']

        result['dictNE'] = {'device': device,
                            'route': 'ospf',
                            'ospfId': ospf_id,
                            'l3Inf': l3Inf}

        result['NE'] = ('device={}'.format(device),
                        'route=ospf',
                        'ospfId={}'.format(ospf_id),
                        'l3Inf={}'.format(l3Inf))

        result['parameters'] = {'routerId': router_id,
                                'sourceIp': sourceIp}

        result['level'] = len(result['NE'])
        result['abstract'] = "OSPF Duplicate router ID {} on interface {}".format(router_id, l3Inf)
        result['influence'] = "OSPF Duplicate router ID {}".format(router_id)

        return result

    def parse_OSPF_OSPF_LAST_NBR_DOWN(self, device, desc, result, event):
        patterns = [
            "OSPF %{NUMBER:ospfId} Last neighbor down event: Router ID: %{DATA:routerId} Local address: %{DATA:localAddress} Remote address: %{DATA:remoteAddress} Reason: %{DATA:reason}$"]
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

    def parse_OSPF_OSPF_NBR_CHG(self, device, desc, result, event):
        patterns = [
            "OSPF %{NUMBER:ospfId} Neighbor %{DATA:neighbor}\(%{DATA:l3Inf}\) changed from %{DATA} to %{DATA:status}.$"]
        # "OSPF [UINT32] Neighbor [STRING] ([STRING]) changed from [STRING] to [STRING]."
        # "OSPF 1 Neighbor 11.1.1.1(Vlan-interface11) changed from FULL to DOWN."
        # OSPF 1 Neighbor 14.2.1.2(GigabitEthernet1/9/0/1) changed from FULL to DOWN.
        parsed_desc = parse_patterns(patterns, desc)

        l3Inf = parsed_desc['l3Inf']

        # m_int_vlan = re.match("(Vlan-interface)(\d+)$", interface)
        # if m_int_vlan:
        ospf_id = parsed_desc['ospfId']
        neighbor = parsed_desc['neighbor']
        status = parsed_desc['status']
        # int_vlan = m_int_vlan.group(2)

        result['dictNE'] = {'device': device,
                            'route': 'ospf',
                            'ospfId': ospf_id}

        result['NE'] = ('device={}'.format(device),
                        'route=ospf',
                        'ospfId={}'.format(ospf_id))

        result['parameters'] = {'neighbor': neighbor,
                                'l3Inf': l3Inf,
                                'status': status}

        result['level'] = len(result['NE'])

        result['abstract'] = "OSPF {} Neighbor {}({}) {}".format(ospf_id, neighbor, l3Inf, status.lower())
        result['influence'] = "OSPF neighbor down"

        return result

    def parse_OSPF_OSPF_NBR_CHG_REASON(self, device, desc, result, event):
        patterns = [
            "OSPF %{NUMBER:ospfId} Area %{DATA:area} Router %{DATA:routerId}\(%{DATA:l3Inf}\) CPU usage: %{DATA}, (VPN name: %{DATA}, )?IfMTU: %{NUMBER}, Neighbor address: %{DATA:neighborAddress}, NbrID:%{DATA:nbrId} changed from %{DATA} to (?<status>\w+) %{DATA}"]

        #         """
        #          OSPF 1 Area 0.0.0.0 Router 3.3.3.3(Vlan11) CPU usage: 4%, IfMTU: 1500, Neighbor address: 11.1.1.1, NbrID:1.2.3.4 changed from Full to DOWN because the interface went down or MTU changed at 2020-06-11 20:17:54:974. Last 4 hello packets received at:   2020-06-11 20:17:20:120   2020-06-11 20:17:30:120   2020-06-11 20:17:40:120   2020-06-11 20:17:50:120 Last 4 hello packets sent at:    2020-06-11 20:17:24:215   2020-06-11 20:17:34:215   2020-06-11 20:17:44:215   2020-06-11 20:17:54:215
        #
        #
        #          OSPF 1 Area 0.0.0.0 Router 1.1.1.1(FGE1/2/25) CPU usage: 20%, IfMTU: 1500, Neighbor address: 13.1.1.2, NbrID:4.1.1.1 changed from Full to INIT because a 1-way hello packet was received at 2004-03-17 01:51:31:774. Last 4 hello packets received at: Last 4 hello packets sent at:    2004-03-17 01:50:56:061   2004-03-17 01:51:06:061   2004-03-17 01:51:16:061   2004-03-17 01:51:26:061
        #
        #          OSPF_NBR_CHG_REASON: OSPF 1 Area 0.0.0.0 Router 3.3.3.3(Vlan11) CPU usage: 4%, IfMTU: 1500, Neighbor address: 11.1.1.1, NbrID:1.2.3.4 changed from Full to DOWN because the interface went down or MTU changed at 2020-06-11 20:17:54:974. Last 4 hello packets received at:   2020-06-11 20:17:20:120   2020-06-11 20:17:30:120   2020-06-11 20:17:40:120   2020-06-11 20:17:50:120 Last 4 hello packets sent at:    2020-06-11 20:17:24:215   2020-06-11 20:17:34:215   2020-06-11 20:17:44:215   2020-06-11 20:17:54:215
        #
        # OSPF_NBR_CHG_REASON: OSPF 1 Area 0.0.0.0 Router 11.11.11.1(XGE1/0/51) CPU usage: 25.9%, IfMTU: 1500, Neighbor address: 1.1.1.1, NbrID:5.5.5.1 changed from Init to DOWN because the dead timer expired at 2020-08-07 11:16:44:689.
        #
        #         """
        parsed_desc = parse_patterns(patterns, desc)

        ospf_id = parsed_desc['ospfId']
        area = parsed_desc['area']
        router_id = parsed_desc['routerId']
        neighborAddress = parsed_desc['neighborAddress']
        nbr_id = parsed_desc['nbrId']
        status = parsed_desc['status']
        l3Inf = parsed_desc['l3Inf']

        result['dictNE'] = {'device': device,
                            'route': 'ospf',
                            'ospfId': ospf_id,
                            'area': area}
        result['NE'] = ('device={}'.format(device),
                        'route=ospf',
                        'ospfId={}'.format(ospf_id),
                        'area={}'.format(area))

        result['parameters'] = {'routerId': router_id,
                                'l3Inf': l3Inf,
                                'neighborAddress': neighborAddress,
                                'nbrId': nbr_id,
                                'status': status}
        result['level'] = len(result['NE'])

        return result

    def parse_OSPFV3_OSPFv3_LAST_NBR_DOWN(self, device, desc, result, event):
        patterns = [
            "OSPFv3 %{NUMBER:ospfv3Id} Last neighbor down event: Router ID: %{DATA:neighbor}  Local interface ID: %{NUMBER:local_interface_id}  Remote interface ID: %{NUMBER:remote_interface_id}  Reason: %{DATA}."]
        # OSPFv3 1 Last neighbor down event: Router ID: 3.1.1.1  Local interface ID: 3492  Remote interface ID: 658  Reason: Ospfv3 ifachange.
        parsed_desc = parse_patterns(patterns, desc)
        ospfv3_id = parsed_desc['ospfv3Id']
        neighbor = parsed_desc['neighbor']
        local_interface_id = parsed_desc['local_interface_id']
        remote_interface_id = parsed_desc['remote_interface_id']

        result['dictNE'] = {'device': device,
                            'route': 'ospfv3',
                            'ospfv3Id': ospfv3_id}

        result['NE'] = ('device={}'.format(device),
                        'route=ospfv3',
                        'ospfv3Id={}'.format(ospfv3_id))

        result['parameters'] = {'neighbor': neighbor,
                                'localInterfaceId': local_interface_id,
                                'remoteInterfaceId': remote_interface_id}

        result['level'] = len(result['NE'])

        return result

    def parse_OSPFV3_OSPFv3_NBR_CHG(self, device, desc, result, event):
        patterns = [
            "OSPFv3 %{DATA:ospfv3Id} Neighbor %{DATA:neighbor}\(%{DATA:interface}\) received %{DATA} and its state from %{DATA} to %{DATA:status}.$"]
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
            result['abstract'] = "OSPFv3 {} Neighbor {}".format(ospfv3_id, status.lower())
            result['influence'] = "OSPFv3 Neighbor down"

        return result

    def parse_PIM_PIM_NBR_DOWN(self, device, desc, result, event):
        patterns = ["(%{DATA}: )?Neighbor %{DATA:neighbor}\(%{DATA:l3Inf}\) is down."]
        # Neighbor 21.0.1.2(Vlan-interface200) is down.
        parsed_desc = parse_patterns(patterns, desc)

        neighbor = parsed_desc["neighbor"]
        l3Inf = parsed_desc["l3Inf"]

        result['dictNE'] = {'device': device,
                            'route': 'PIM'}

        result['NE'] = ('device={}'.format(device),
                        'route=PIM')

        result['parameters'] = {'neighbor': neighbor,
                                'l3Inf': l3Inf,
                                'status': "down"}

        result['level'] = len(result['NE'])
        result['abstract'] = "PIM Neighbor {}({}) is down ".format(neighbor, l3Inf)

        return result

    def parse_QOS_QOS_POLICY_APPLYIF_CBFAIL(self, device, desc, result, event):
        chassis = None
        slot = None
        patterns = [
            "Failed to apply classifier-behavior %{DATA} in policy %{DATA} to the %{DATA:direction} direction of interface %{DATA:interface}. %{DATA}\."]
        parsed_desc = parse_patterns(patterns, desc)
        port = parsed_desc['interface']
        direction = parsed_desc['direction']

        if 'Chassis' in event:
            chassis = event['Chassis']
        if 'Slot' in event:
            slot = event['Slot']

        if not chassis:
            chassis = '0'
        if not slot:
            slot = '0'

        result['dictNE'] = {'device': device,
                            'chassis': chassis,
                            'slot': slot}

        result['NE'] = ('device={}'.format(device),
                        'chassis={}'.format(chassis),
                        'slot={}'.format(slot))

        result['parameters'] = {'port': port,
                                'direction': direction}

        result['level'] = len(result['NE'])
        result['abstract'] = "Not enough acl resources on {} inbound direction".format(port)
        result['influence'] = "Not enough acl resources"
        return result

    def parse_RESMON_RESMON_USEDUP(self, device, desc, result, event):
        resource = event['Resource']
        result['dictNE'] = {'device': device,
                            'resource': resource}

        result['NE'] = ('device={}'.format(device),
                        'resource={}'.format(resource))

        result['level'] = len(result['NE'])
        result['abstract'] = "Resource {} used up".format(resource)
        result['influence'] = "Resource {} used up".format(resource)
        return result

    def parse_RESMON_RESMON_USEDUP_RECOVERY(self, device, desc, result, event):
        resource = event['Resource']
        result['dictNE'] = {'device': device,
                            'resource': resource}

        result['NE'] = ('device={}'.format(device),
                        'resource={}'.format(resource))

        result['level'] = len(result['NE'])
        result['abstract'] = "Resource {} recovery".format(resource)
        result['influence'] = "Resource {} recovery".format(resource)
        return result

    def parse_STM_STM_LINK_DOWN(self, device, desc, result, event):
        patterns = ["IRF port %{NUMBER:irfPort} went down."]
        parsed_desc = parse_patterns(patterns, desc)
        irfPort = parsed_desc['irfPort']

        result['dictNE'] = {'device': device,
                            'irfPort': irfPort}

        result['NE'] = ('device={}'.format(device),
                        'irfPort={}'.format(irfPort))

        result['level'] = len(result['NE'])
        result['abstract'] = "IRF port {} went down".format(irfPort)
        result['influence'] = "IRF port down"
        return result

    def parse_STM_STM_LINK_TIMEOUT(self, device, desc, result, event):
        patterns = ["IRF port %{DATA:irfPort} went down because the heartbeat timed out."]
        parsed_desc = parse_patterns(patterns, desc)
        irfPort = parsed_desc['irfPort']

        result['dictNE'] = {'device': device,
                            'irfPort': irfPort}

        result['NE'] = ('device={}'.format(device),
                        'irfPort={}'.format(irfPort))

        result['level'] = len(result['NE'])
        result['abstract'] = "IRF port {} timeout".format(irfPort)
        result['influence'] = "IRF port timeout"
        return result

    def parse_STP_STP_DISCARDING(self, device, desc, result, event):
        patterns = ["Instance %{NUMBER:instance}'s port %{DATA:port} has been set to discarding state."]
        parsed_desc = parse_patterns(patterns, desc)
        instance = parsed_desc["instance"]
        port = parsed_desc["port"]

        result['dictNE'] = {'device': device,
                            'instance': instance,
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'instance={}'.format(instance),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['abstract'] = "STP topology change on Instance {}'s {} to discarding state".format(instance, port)

        return result

    def parse_STP_STP_DISPUTE(self, device, desc, result, event):
        patterns = [
            "%{DATA} %{NUMBER:instance}'s port %{DATA:port} received an inferior BPDU from a designated port which is in forwarding or learning state."]
        parsed_desc = parse_patterns(patterns, desc)
        instance = parsed_desc["instance"]
        port = parsed_desc["port"]

        result['dictNE'] = {'device': device,
                            'instance': instance,
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'instance={}'.format(instance),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['abstract'] = "STP topology change on Instance {}'s {} received an inferior BPDU".format(instance, port)

        return result

    def parse_STP_STP_FORWARDING(self, device, desc, result, event):
        patterns = ["Instance %{NUMBER:instance}'s port %{DATA:port} has been set to forwarding state."]
        parsed_desc = parse_patterns(patterns, desc)
        instance = parsed_desc["instance"]
        port = parsed_desc["port"]

        result['dictNE'] = {'device': device,
                            'instance': instance,
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'instance={}'.format(instance),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['abstract'] = "STP topology change on Instance {}’s {} to forwarding state".format(instance, port)

        return result

    def parse_STP_STP_NOTIFIED_TC(self, device, desc, result, event):
        patterns = ["%{DATA} %{NUMBER:instance}'s port %{DATA:port} was notified a topology change."]
        #  Instance 0's port Bridge-Aggregation3 was notified a topology change.
        parsed_desc = parse_patterns(patterns, desc)
        instance = parsed_desc["instance"]
        port = parsed_desc["port"]

        result['dictNE'] = {'device': device,
                            'instance': instance,
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'instance={}'.format(instance),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['abstract'] = "STP topology change on Instance {}'s {}".format(instance, port)

        return result

    # log parsing for KPI warnings
    def parse_KPI_TCP_SYN_ANOMALY(self, device, desc, result, event):
        # Probability fault point on the interface HundredGigE1/4/0/1 for TCP session group fault.
        patterns = ["Probability fault point on the interface %{DATA:port} for TCP session group fault."]
        parsed_desc = parse_patterns(patterns, desc)
        port = parsed_desc["port"]
        m_interface4 = Grok("\w+%{NUMBER:chassis}/%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(port)

        result['dictNE'] = {'device': device,
                            'chassis': m_interface4['chassis'],
                            'slot': m_interface4['slot'],
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'chassis={}'.format(m_interface4['chassis']),
                        'slot={}'.format(m_interface4['slot']),
                        'port={}'.format(port))
        result['level'] = len(result['NE'])
        result['abstract'] = "TCP session group fault on {}".format(port)
        result['influence'] = "TCP session fault"
        result['fault_class'] = "TCP session group fault on {}".format(port)
        result['fault_level'] = "Critical"

        return result

    def parse_KPI_CPU_HIGH_SEVERE(self, device, desc, result, event):
        # CPU high on 177.17.17.7 slot 1.
        patterns = ["CPU high on %{DATA:device} slot %{NUMBER:slot}."]
        parsed_desc = parse_patterns(patterns, desc)

        result['dictNE'] = {'device': device,
                            'chassis': 0,
                            'slot': parsed_desc['slot']}

        result['NE'] = ('device={}'.format(device),
                        'chassis=0',
                        'slot={}'.format(parsed_desc['slot']))

        result['level'] = len(result['NE'])
        result['abstract'] = "CPU high on {} slot {}.".format(device, parsed_desc['slot'])
        result['influence'] = None
        result['fault_class'] = None
        result['fault_level'] = None

        return result

    def parse_KPI_INT_DELAY_POINT(self, device, desc, result, event):
        # INT Delay on interface FGE2/0/10.
        patterns = ["INT Delay on interface %{DATA:port}\."]
        parsed_desc = parse_patterns(patterns, desc)
        port = re.sub("FGE", "Forty-GigabitEthernet", parsed_desc["port"])
        m_interface3 = Grok("\w+%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(port)
        result['dictNE'] = {'device': device,
                            'chassis': 0,
                            'slot': m_interface3['slot'],
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'chassis=0',
                        'slot={}'.format(m_interface3['slot']),
                        'port={}'.format(port))

        result['level'] = len(result['NE'])
        result['abstract'] = "INT Delay on interface {}.".format(port)
        result['influence'] = None
        result['fault_class'] = "INT Delay on interface {}.".format(port)
        result['fault_level'] = "Critical"

        return result

    def parse_KPI_EGRESS_DROP_POINT(self, device, desc, result, event):
        # Egress Drop on interface FGE2/0/10
        patterns = ["Egress Drop on interface %{DATA:port}\."]
        parsed_desc = parse_patterns(patterns, desc)
        port = re.sub("FGE", "Forty-GigabitEthernet", parsed_desc["port"])
        m_interface3 = Grok("\w+%{NUMBER:slot}/%{NUMBER}/%{NUMBER}$").match(port)
        result['dictNE'] = {'device': device,
                            'chassis': 0,
                            'slot': m_interface3['slot'],
                            'port': port}

        result['NE'] = ('device={}'.format(device),
                        'chassis=0',
                        'slot={}'.format(m_interface3['slot']),
                        'port={}'.format(port))

        result['level'] = len(result['NE'])
        result['abstract'] = "Egress Drop on interface {}.".format(port)
        result['influence'] = None
        result['fault_class'] = None
        result['fault_level'] = None
        return result


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


def parse(log_dict):
    if log_dict.get('module'):
        result = parse_event(log_dict)
    else:
        event = parse_base(log_dict)
        result = parse_event(event)

    return result


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
    try:
        result = getattr(LogParser, 'parse_' + warn_type)(0, device, desc, result, event)
    except:
        result.pop('abstract')
        result.pop('influence')
    return result


if __name__ == "__main__":
    # log = {"timestamp":"2020-06-10T19:46:40.000Z", "host":"100.11.1.35", "message":"<172>Jun 10 19:49:40 2020 S7503X %%10DRNI/6/DRNI_IFEVENT_DR_NOSELECTED: Local DR interface Bridge-Aggregation40 in DR group 40 does not have Selected member ports because the aggregate interface went down. Please check the aggregate link status."}
    # log = {"timestamp":"2020-06-10T19:46:40.000Z", "host":"100.11.1.35", "message":"<172>Jun 10 19:49:40 2020 S7503X %%10LAGG/6/LAGG_INACTIVE_OTHER: Member port XGE3/0/26 of aggregation group BAGG40 changed to the inactive state, because other reason."}
    # log = {"timestamp":"2020-06-10T19:46:40.000Z", "host":"100.11.1.35", "message":"<172>Jun 10 19:49:40 2020 S7503X %%10IFNET/5/LINK_UPDOWN: Line protocol state on the interface Ten-GigabitEthernet3/0/26 changed to down."}
    # log = {"timestamp":"2020-06-10T19:43:40.000Z", "host":"192.28.200.201", "message":"<172>Jun 10 19:46:40 2020 S125G2 %%10OSPF/5/OSPF_NBR_CHG_REASON: OSPF 1 Area 0.0.0.0 Router 3.3.3.3(Vlan11) CPU usage: 4%, IfMTU: 1500, Neighbor address: 11.1.1.1, NbrID:1.2.3.4 changed from Full to DOWN because the interface went down or MTU changed at 2020-06-11 20:17:54:974. Last 4 hello packets received at:   2020-06-11 20:17:20:120   2020-06-11 20:17:30:120   2020-06-11 20:17:40:120   2020-06-11 20:17:50:120 Last 4 hello packets sent at:    2020-06-11 20:17:24:215   2020-06-11 20:17:34:215   2020-06-11 20:17:44:215   2020-06-11 20:17:54:215"}
    # log = {"timestamp": "2020-08-16T00:02:02+08:00","message": "<174>Aug 16 00:02:02 2020 5560X_2 %%10LAGG/6/LAGG_INACTIVE_PHYSTATE: Member port XGE1/1/1 of aggregation group BAGG3 changed to the inactive state, because the physical or line protocol state of the port was down.","host": "77.1.1.43"}
    # log = {"timestamp":"2020-08-14T00:41:30+08:00","message":"<173>Aug 14 00:41:30 2020 7506X-G %%10BFD/5/BFD_CHANGE_FSM: Sess[21.2.1.1/21.2.1.2, LD/RD:4128/4119, Interface:Vlan202, SessType:Ctrl, LinkType:INET], Ver:1, Sta: UP->DOWN, Diag: 3 (No Diagnostic)","host":"77.1.1.41"}
    # log = {"timestamp": "2020-06-17T10:45:02+08:00", "message": "<4>Jun 17 10:45:02 2020 5560X_2 %%10LAGG/6/LAGG_INACTIVE_PHYSTATE: Member port XGE1/1/1 of aggregation group BAGG3 changed to the inactive state, because the physical or line protocol state of the port was down.", "host": "77.1.1.43"}

    log = {"timestamp": "2020-06-11T20:17:54.000Z",
           "message": "<172>Jun 11 20:17:54 2020 S125G2 %%10IFNET/5/LINK_UPDOWN: Line protocol state on the interface HundredGigE1/4/0/1 changed to down.",
           "host": "177.17.17.7"}
    log = {"timestamp": "2020-06-11T20:17:54.000Z",
           "message": "<172>Jun 11 20:17:54 2020 S125G2 %%10LAGG/6/LAGG_INACTIVE_DUPLEX: Member port FGE1/0/10 of aggregation group BAGG1 changed to the inactive state, because the duplex mode of the port was different from that of the reference port.",
           "host": "177.17.17.7"}
    log = {"timestamp": "2020-06-11T20:17:54.000Z",
           "message": "<172>Jun 11 20:17:54 2020 S125G2 %%10KPI/5/CPU_HIGH_SEVERE: CPU high on 177.17.17.7 slot 1.",
           "host": "177.17.17.7"}
    log = {"timestamp": "2020-06-11T20:17:54.000Z",
           "message": "<172>Jun 11 20:17:54 2020 S125G2 %%10KPI/5/TCP_SYN_ANOMALY: Probability fault point on the interface HundredGigE1/4/0/1 for TCP session group fault.",
           "host": "177.17.17.7"}
    log = {"timestamp": "2020-06-11T20:17:54.000Z",
           "message": "<172>Jun 11 20:17:54 2020 S125G2 %%10KPI/5/INT_DELAY_POINT: INT Delay on interface FGE2/0/10.",
           "host": "177.17.17.7"}
    log = {"timestamp": "2020-06-17T11:34:49+08:00",
           "message": "<4>Jun 17 11:34:49 2020 7506X-G %%10OSPF/6/OSPF_DUP_RTRID_NBR: OSPF 1 Duplicate router ID 10.10.10.10 on interface GigabitEthernet2/0/39, sourced from IP address 2.2.1.2.",
           "host": "77.1.1.41"}
    log = {"timestamp": "2020-06-17T11:34:49+08:00",
           "message": "<4>Jun 17 11:34:49 2020 7506X-G %%10BGP/5/BGP_STATE_CHANGED: BGP.: 3.3.3.2 state has changed from OPENCONFIRM to ESTABLISHED.",
           "host": "77.1.1.41"}
    # log = {"timestamp": "2020-06-17T11:34:49+08:00",
    #        "message": "<4>Jun 17 11:34:49 2020 7506X-G %%10BGP/5/BGP_STATE_CHANGED: BGP.: 3.3.3.2 state has changed from ESTABLISHED to IDLE for session down event received from BFD.",
    #        "host": "77.1.1.41"}
    log = {"timestamp": "2020-06-17T11:34:49+08:00",
           "message": "<4>Jun 17 11:34:49 2020 7506X-G %%10QOS/4/QOS_POLICY_APPLYIF_CBFAIL: -Slot=2; Failed to apply classifier-behavior wey in policy qos3 to the inbound direction of interface GigabitEthernet2/0/3. Not enough resources to complete the operation.",
           "host": "77.1.1.41"}

    r = parse(log)

    r = json.dumps(r)
    print(r)
