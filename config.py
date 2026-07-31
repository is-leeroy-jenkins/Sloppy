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
]

PROTOCOL_COLORS = {
	'TCP': ACCENT_BLUE,
	'UDP': GREEN,
	'ICMP': AMBER,
}

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