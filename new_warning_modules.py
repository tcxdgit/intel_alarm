new_modules = [
    {
        "module": "IFNET",
        "severity": 3,
        "logTypeDesc": "PHY_UPDOWN_DERIVE",
        "desc": "Physical state on the interface Tunnel${NE.intTnl} changed from down to up in a short time.",
        "warnType": "IFNET_PHY_UPDOWN_DERIVE",
        "abstract": "interface Tunnel${NE.intTnl} occurs Down and UP",
        "influence": None,
        "parameters": None
    },
    {
        "module": "IFNET",
        "severity": 3,
        "logTypeDesc": "PHY_FLAPPING_DERIVE",
        "desc": "Physical state on the interface Tunnel${NE.intTnl} Flapping.",
        "warnType": "IFNET_PHY_FLAPPING_DERIVE",
        "abstract": "Physical state on the interface Tunnel${NE.intTnl} Flapping",
        "influence": "Interval interrupt on interface Tunnel${NE.intTnl}",
        "parameters": None
    },
    {
        "module": "MAC",
        "severity": 4,
        "logTypeDesc": "MAC_MOVE_BATCH",
        "desc": "Many MAC addresses has moved from port ${parameters.port1} to port ${parameters.port2} .",
        "warnType": "MAC_MAC_MOVE_BATCH",
        "abstract": "Many MAC addresses has moved from port ${parameters.port1} to port ${parameters.port2}",
        "influence": None,
        "parameters": None
    },
    {
        "module": "BFD",
        "severity": 5,
        "logTypeDesc": "BFD_CHANGE_FSM_UP_Derive",
        "desc": "Sess[${NE.session}, LD/RD:${parameters.ldRd}, Interface:${parameters.interface}, SessType:${parameters.sessType}, LinkType:${parameters.linkType}], occurs Down and UP.",
        "warnType": "BFD_BFD_CHANGE_FSM_UP_Derive",
        "abstract": "BFD Session[${NE.session}]  occurs Down and UP ",
        "influence": None,
        "parameters": None
    },
    {
        "module": "BFD",
        "severity": 4,
        "logTypeDesc": "BFD_CHANGE_FSM_UP_Derive",
        "desc": "Sess[${NE.session}, LD/RD:${parameters.ldRd}, Interface:${parameters.interface}, SessType:${parameters.sessType}, LinkType:${parameters.linkType}], change from Down to UP",
        "warnType": "BFD_BFD_CHANGE_FSM_UP_Derive",
        "abstract": "BFD Session[${NE.session}]  change from Down to UP",
        "influence": None,
        "parameters": None
    }
]