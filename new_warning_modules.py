new_modules = [
  {
    "module":"IFNET",
    "severity":3,
    "logTypeDesc":"PHY_UPDOWN_DERIVE",
    "desc":"Physical state on the interface Tunnel${new_warning['dictNE']['intTnl']} changed from down to up in a short time.",
    "warnType":"IFNET_TNL_PHY_UPDOWN_DERIVE",
    "abstract": "interface Tunnel${new_warning['dictNE']['intTnl']} occurs Down and UP",
    "influence": None
  },
  {
    "module":"IFNET",
    "severity":3,
    "logTypeDesc":"PHY_FLAPPING_DERIVE",
    "desc":"Physical state on the interface Tunnel${new_warning['dictNE']['intTnl']} Flapping.",
    "warnType":"IFNET_TNL_PHY_FLAPPING_DERIVE",
    "abstract": "Physical state on the interface Tunnel${new_warning['dictNE']['intTnl']} Flapping",
    "influence": "Interval interrupt on interface Tunnel${new_warning['dictNE']['intTnl']}"
  },
  {
    "module":"MAC",
    "severity":4,
    "logTypeDesc":"MAC_MOVE_BATCH",
    "desc":"Many MAC addresses has moved from port ${new_warning['parameters']['port1']} to port ${new_warning['parameters']['port2']}.",
    "warnType":"MAC_MAC_MOVE_BATCH",
    "abstract": "Many MAC addresses has moved from port ${new_warning['parameters']['port1']} to port ${new_warning['parameters']['port2']}",
    "influence": None,
    "parameters": {}
  },
  {
    "module": "BFD",
    "severity": 5,
    "logTypeDesc": "BFD_CHANGE_FSM_DOWNUP_DERIVE",
    "desc": "Sess[${new_warning['dictNE']['session']}, LD/RD:${new_warning['parameters']['ldRd']}, Interface:${new_warning['parameters']['interface']}, SessType:${new_warning['parameters']['sessType']}, LinkType:${new_warning['parameters']['linkType']}], occurs Down and UP.",
    "warnType": "BFD_BFD_CHANGE_FSM_DOWNUP_DERIVE",
    "abstract": "BFD Session[${new_warning['dictNE']['session']}] occurs Down and UP ",
    "influence": None,
    "parameters": {}
  },
  {
    "module": "BFD",
    "severity": 4,
    "logTypeDesc": "BFD_CHANGE_FSM_UP_DERIVE",
    "desc": "Sess[${new_warning['dictNE']['session']}, LD/RD:${new_warning['parameters']['ldRd']}, Interface:${new_warning['parameters']['interface']}, SessType:${new_warning['parameters']['sessType']}, LinkType:${new_warning['parameters']['linkType']}], change from Down to UP",
    "warnType": "BFD_BFD_CHANGE_FSM_UP_DERIVE",
    "abstract": "BFD Session[${new_warning['dictNE']['session']}] change from Down to UP",
    "influence": None,
    "parameters": {}
  },
  {
    "module": "STP",
    "severity": 4,
    "logTypeDesc": "STP_NOTIFIED_TC_FLAPPING",
    "desc": "Instance ${new_warning['dictNE']['instance']}'s port ${new_warning['dictNE']['port']} topology change Frequently.",
    "warnType": "STP_STP_NOTIFIED_TC_FLAPPING",
    "abstract": "STP topology change on Instance ${new_warning['dictNE']['instance']}'s ${new_warning['dictNE']['port']}",
    "influence": None,
    "parameters": {}
  },
  {
    "module": "STP",
    "severity": 4,
    "logTypeDesc": "STP_NOTIFIED_TC_FLAPPING",
    "desc": "Instance ${new_warning['dictNE']['instance']}'s port ${new_warning['dictNE']['port']} topology change Frequently.",
    "warnType": "STP_STP_NOTIFIED_TC_FLAPPING",
    "abstract": "STP state on Instance ${new_warning['dictNE']['instance']}'s ${new_warning['dictNE']['port']} Flapping",
    "influence": None,
    "parameters": {}
  },
  {
    "module": "STP",
    "severity": 4,
    "logTypeDesc": "STP_NOTIFIED_TC_STATESHAKE",
    "desc": "Instance ${new_warning['dictNE']['instance']}'s port ${new_warning['dictNE']['port']} topology change Frequently.",
    "warnType": "STP_STP_NOTIFIED_TC_STATESHAKE",
    "abstract": "STP state shake on Instance ${new_warning['dictNE']['instance']}'s ${new_warning['dictNE']['port']}",
    "influence": None,
    "parameters": {}
  },
  {
    "module": "QOS",
    "severity": 4,
    "logTypeDesc": "QOS_POLICY_APPLYIF_CBFAIL_BATCH",
    "desc": "Not enough resources to complete the operation on slot ${new_warning['dictNE']['slot']}.",
    "warnType": "QOS_QOS_POLICY_APPLYIF_CBFAIL_BATCH",
    "abstract": "Not enough resources to complete the operation on slot ${new_warning['dictNE']['slot']}.",
    "influence": None,
    "parameters": {}
  },
  {
    "module":"IFNET",
    "severity":3,
    "logTypeDesc":"PHY_UPDOWN_DERIVE",
    "desc":"Physical state on the interface Vlan-interface{new_warning['dictNE']['intVlan']} changed from down to up in a short time.",
    "warnType":"IFNET_INTVLAN_PHY_UPDOWN_DERIVE",
    "abstract": "interface Vlan-interface${new_warning['dictNE']['intVlan']} occurs Down and UP",
    "influence": None
  },
  {
    "module":"IFNET",
    "severity":3,
    "logTypeDesc":"PHY_UPDOWN_DERIVE",
    "desc":"Physical state on the port {new_warning['dictNE']['port']} changed from down to up in a short time.",
    "warnType":"IFNET_PORT_PHY_UPDOWN_DERIVE",
    "abstract": "port ${new_warning['dictNE']['port']} occurs Down and UP",
    "influence": None
  }
]