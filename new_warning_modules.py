new_modules = [
  {
    "module":"IFNET",
    "severity":3,
    "logTypeDesc":"PHY_UPDOWN_DERIVE",
    "desc":"Physical state on the interface Tunnel${NE.intTnl} changed from down to up in a short time.",
    "warnType":"IFNET_PHY_UPDOWN_DERIVE",
    "abstract": "interface Tunnel${NE.intTnl} occurs Down and UP",
    "influence": None,
    "parameters": None
  },
  {
    "module":"IFNET",
    "severity":3,
    "logTypeDesc":"PHY_FLAPPING_DERIVE",
    "desc":"Physical state on the interface Tunnel${NE.intTnl} Flapping.",
    "warnType":"IFNET_PHY_FLAPPING_DERIVE",
    "abstract": "Physical state on the interface Tunnel${NE.intTnl} Flapping",
    "influence": "Interval interrupt on interface Tunnel${NE.intTnl}",
    "parameters": None
  },
  {
    "module":"MAC",
    "severity":4,
    "logTypeDesc":"MAC_MOVE_BATCH",
    "desc":"Many MAC addresses has moved from port ${parameters.port1} to port ${parameters.port2} .",
    "warnType":"MAC_MAC_MOVE_BATCH",
    "abstract": "Many MAC addresses has moved from port ${parameters.port1} to port ${parameters.port2}",
    "influence": None,
    "parameters": None
  }
]