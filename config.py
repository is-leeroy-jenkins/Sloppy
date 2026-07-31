'''
  ******************************************************************************************
      Assembly:                Sloppy
      Filename:                config.py
      Author:                  Terry D. Eppler
      Created:                 05-31-2022

      Last Modified By:        Terry D. Eppler
      Last Modified On:        07-30-2026
  ******************************************************************************************
  <copyright file="config.py" company="Terry D. Eppler">

	     config.py
	     Copyright ©  2022  Terry Eppler

     Permission is hereby granted, free of charge, to any person obtaining a copy
     of this software and associated documentation files (the “Software”),
     to deal in the Software without restriction,
     including without limitation the rights to use,
     copy, modify, merge, publish, distribute, sublicense,
     and/or sell copies of the Software,
     and to permit persons to whom the Software is furnished to do so,
     subject to the following conditions:

     The above copyright notice and this permission notice shall be included in all
     copies or substantial portions of the Software.

     THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
     INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
     IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
     DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
     ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
     DEALINGS IN THE SOFTWARE.

     You can contact me at:  terryeppler@gmail.com or eppler.terry@epa.gov

  </copyright>
  <summary>
    config.py
  </summary>
  ******************************************************************************************
'''

# ----- Constants ------
BLUE_DIVIDER = (
	"<div style='height:2px;align:left;background:#0078FC;"
	"margin:30px 0px 30px 0px;'></div>"
)

ICON = r'resources/images/favicon.ico'
LOGO = r'resources/images/Sloppy.png'
DB = r'stores/sqlite/sloppy.db'

# ------ Color ------
ACCENT_BLUE = '#0078FC'
LIGHT_BLUE = '#38A3FF'
CYAN = '#00C2FF'
PURPLE = '#9B7BFF'
GREEN = '#2DD4BF'
AMBER = '#F5B942'
RED = '#FF5C6C'

# ------ Page ------
PAGE_BACKGROUND = '#111111'
PANEL_BACKGROUND = '#171717'
GRID_COLOR = 'rgba( 148, 163, 184, 0.15 )'
BORDER_COLOR = 'rgba( 148, 163, 184, 0.32 )'
TEXT_COLOR = '#F8FAFC'
MUTED_TEXT_COLOR = '#94A3B8'

# ----- Analysis Modes ------
ANALYSIS_MODE_NETWORK = 'Network Analysis'
ANALYSIS_MODE_DATA_LINK = 'Data Link Analysis'
ANALYSIS_MODE_NETWORK_LAYER = 'Network Layer Analysis'
ANALYSIS_MODE_TRANSPORT = 'Transport Analysis'
ANALYSIS_MODE_SESSION = 'Session Analysis'
ANALYSIS_MODE_PRESENTATION = 'Presentation Analysis'
ANALYSIS_MODE_APPLICATION = 'Application Analysis'

ANALYSIS_MODES = [
	ANALYSIS_MODE_NETWORK,
	ANALYSIS_MODE_DATA_LINK,
	ANALYSIS_MODE_NETWORK_LAYER,
	ANALYSIS_MODE_TRANSPORT,
	ANALYSIS_MODE_SESSION,
	ANALYSIS_MODE_PRESENTATION,
	ANALYSIS_MODE_APPLICATION,
]

# ----- Protocol ------
PROTOCOL_ORDER = [
	'TCP',
	'UDP',
	'ICMP',
	'ICMPv6',
]

PROTOCOL_COLORS = {
	'TCP': ACCENT_BLUE,
	'UDP': GREEN,
	'ICMP': AMBER,
	'ICMPv6': PURPLE,
}

# ----- Data Link Analysis ------
ETHER_TYPE_IPV4 = 'IPv4'
ETHER_TYPE_ARP = 'ARP'
ETHER_TYPE_VLAN = '802.1Q VLAN'
ETHER_TYPE_IPV6 = 'IPv6'
ETHER_TYPE_OTHER = 'Other'

ETHER_TYPE_ORDER = [
	ETHER_TYPE_IPV4,
	ETHER_TYPE_ARP,
	ETHER_TYPE_VLAN,
	ETHER_TYPE_IPV6,
	ETHER_TYPE_OTHER,
]

ETHER_TYPE_COLORS = {
	ETHER_TYPE_IPV4: ACCENT_BLUE,
	ETHER_TYPE_ARP: AMBER,
	ETHER_TYPE_VLAN: PURPLE,
	ETHER_TYPE_IPV6: GREEN,
	ETHER_TYPE_OTHER: MUTED_TEXT_COLOR,
}

ETHER_TYPE_NAMES = {
	0x0800: ETHER_TYPE_IPV4,
	0x0806: ETHER_TYPE_ARP,
	0x8100: ETHER_TYPE_VLAN,
	0x86DD: ETHER_TYPE_IPV6,
}

ARP_OPERATION_REQUEST = 'Request'
ARP_OPERATION_REPLY = 'Reply'
ARP_OPERATION_OTHER = 'Other'

ARP_OPERATION_ORDER = [
	ARP_OPERATION_REQUEST,
	ARP_OPERATION_REPLY,
	ARP_OPERATION_OTHER,
]

ARP_OPERATION_COLORS = {
	ARP_OPERATION_REQUEST: ACCENT_BLUE,
	ARP_OPERATION_REPLY: GREEN,
	ARP_OPERATION_OTHER: MUTED_TEXT_COLOR,
}

FRAME_CLASS_UNICAST = 'Unicast'
FRAME_CLASS_MULTICAST = 'Multicast'
FRAME_CLASS_BROADCAST = 'Broadcast'

FRAME_CLASS_ORDER = [
	FRAME_CLASS_UNICAST,
	FRAME_CLASS_MULTICAST,
	FRAME_CLASS_BROADCAST,
]

FRAME_CLASS_COLORS = {
	FRAME_CLASS_UNICAST: ACCENT_BLUE,
	FRAME_CLASS_MULTICAST: PURPLE,
	FRAME_CLASS_BROADCAST: AMBER,
}

BROADCAST_MAC_ADDRESS = 'ff:ff:ff:ff:ff:ff'

TOP_MAC_ADDRESS_LIMIT = 10
TOP_MAC_IP_RELATIONSHIP_LIMIT = 20
TOP_ARP_RELATIONSHIP_LIMIT = 20
TOP_VLAN_LIMIT = 10
TOP_ETHER_TYPE_LIMIT = 10

# ----- Chart & Visualization -----
SUMMARY_CHART_HEIGHT = 390
FLOW_CHART_HEIGHT = 510
PACKET_EDITOR_HEIGHT = 460
PACKET_EDITOR_ROW_LIMIT = 250
TRAFFIC_WINDOW_SECONDS = 60

CHART_CONFIG = {
	'displaylogo': False,
	'responsive': True,
	'scrollZoom': False,
	'modeBarButtonsToRemove': [
		'lasso2d',
		'select2d',
	],
}

TCP_FLAG_ORDER = [
	'SYN',
	'ACK',
	'PSH',
	'FIN',
	'RST',
	'URG',
]

FLOW_COLUMNS = [
	'src_ip',
	'src_port',
	'dst_ip',
	'dst_port',
	'protocol',
]

TOP_FLAG_PORT_LIMIT = 10
TOP_MATRIX_SOURCE_LIMIT = 15
TOP_MATRIX_DESTINATION_LIMIT = 15
TOP_PORT_TREND_LIMIT = 5
TOP_ENDPOINT_CONNECTIVITY_LIMIT = 10
FLOW_SCATTER_LIMIT = 250
THROUGHPUT_ROLLING_SECONDS = 5

# ----- Network Layer Analysis -----
IP_VERSION_ORDER = [ 4, 6 ]
ADDRESS_SCOPE_ORDER = [ 'Private', 'Public', 'Multicast', 'Loopback', 'Link Local', 'Reserved', 'Documentation' ]

# ----- Presentation Analysis -----
TLS_VERSION_ORDER = [ 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3' ]
TLS_HANDSHAKE_ORDER = [ 'Client Hello', 'Server Hello', 'Certificate', 'Finished', 'Alert' ]
TLS_CIPHER_SUITES = [ 'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'ECDHE_RSA_AES128_GCM_SHA256' ]

# ----- Application Analysis -----
APPLICATION_PROTOCOL_ORDER = [ 'DNS', 'HTTP', 'DHCP', 'NTP' ]
DNS_QUERY_TYPE_ORDER = [ 'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT', 'SRV' ]
HTTP_METHOD_ORDER = [ 'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE' ]
DHCP_MESSAGE_ORDER = [ 'Discover', 'Offer', 'Request', 'Decline', 'Acknowledge', 'Negative Acknowledge', 'Release', 'Inform' ]
NTP_MODE_ORDER = [ 'Symmetric Active', 'Symmetric Passive', 'Client', 'Server', 'Broadcast' ]
DEMO_DNS_NAMES = [ 'api.example.com', 'login.example.com', 'portal.example.org', 'cdn.example.net' ]


# ----- Extended Parser Metadata -----
TLS_CIPHER_NAMES = {
	0x1301: 'TLS_AES_128_GCM_SHA256',
	0x1302: 'TLS_AES_256_GCM_SHA384',
	0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
	0xC02F: 'ECDHE_RSA_AES128_GCM_SHA256',
}

TOP_SUBNET_RELATIONSHIP_LIMIT = 20
TOP_SESSION_LIMIT = 20
SESSION_IDLE_SECONDS = 30
