'''
  ******************************************************************************************
      Assembly:                Sloppy
      Filename:                app.py
      Author:                  Terry D. Eppler
      Created:                 05-31-2022

      Last Modified By:        Terry D. Eppler
      Last Modified On:        07-30-2026
  ******************************************************************************************
  <copyright file="app.py" company="Terry D. Eppler">

	     app.py
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

     You can contact me at: terryeppler@gmail.com or eppler.terry@epa.gov

  </copyright>
  <summary>
    app.py
  </summary>
  ******************************************************************************************
'''
from __future__ import annotations

# ==========================================================================================
# PART 1 — Imports, Configuration, and Guardrails
# ==========================================================================================

import queue
import random
import threading
import time
from datetime import datetime
from typing import Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ------------------------------------------------------------------------------------------
# Sloppy Core (existing, unmodified)
# ------------------------------------------------------------------------------------------
from __init__ import Ethernet, IPv4, TCP, UDP, ICMP, HTTP
import config

# ------------------------------------------------------------------------------------------
# Optional Live Capture Backend
# ------------------------------------------------------------------------------------------
try:
	from scapy.all import Ether as ScapyEther
	from scapy.all import sniff
	
	SCAPY_AVAILABLE = True
	SCAPY_IMPORT_ERROR = ''
except Exception as e:
	SCAPY_AVAILABLE = False
	SCAPY_IMPORT_ERROR = str( e )

# ------------------------------------------------------------------------------------------
# Theme and Visualization Constants
# ------------------------------------------------------------------------------------------
ACCENT_BLUE = '#0078FC'
LIGHT_BLUE = '#38A3FF'
CYAN = '#00C2FF'
PURPLE = '#9B7BFF'
GREEN = '#2DD4BF'
AMBER = '#F5B942'
RED = '#FF5C6C'

PAGE_BACKGROUND = '#111111'
PANEL_BACKGROUND = '#171717'
GRID_COLOR = 'rgba( 148, 163, 184, 0.15 )'
BORDER_COLOR = 'rgba( 148, 163, 184, 0.32 )'
TEXT_COLOR = '#F8FAFC'
MUTED_TEXT_COLOR = '#94A3B8'

PROTOCOL_COLORS = { 'TCP': ACCENT_BLUE, 'UDP': GREEN, 'ICMP': AMBER, }

CHART_CONFIG = { 'displaylogo': False, 'responsive': True, 'scrollZoom': False,
	'modeBarButtonsToRemove': [ 'lasso2d', 'select2d', ], }

BLUE_DIVIDER = ("<div style='height:2px;align:left;background:#0078FC;"
                "margin:6px 0 10px 0;'></div>")

# ------------------------------------------------------------------------------------------
# Streamlit Configuration
# ------------------------------------------------------------------------------------------
st.set_page_config( page_title='Sloppy Joe', page_icon=config.ICON, layout='wide', )

# ------------------------------------------------------------------------------------------
# Application Styling
# ------------------------------------------------------------------------------------------
st.markdown( f"""
	<style>
		[data-testid="stAppViewContainer"] {{
			background-color: {PAGE_BACKGROUND};
		}}

		[data-testid="stSidebar"] {{
			background-color: #353535;
			border-right: 1px solid {BORDER_COLOR};
		}}

		[data-testid="stMetric"] {{
			background-color: {PANEL_BACKGROUND};
			border: 1px solid {BORDER_COLOR};
			border-radius: 10px;
			padding: 14px 16px;
		}}

		[data-testid="stMetricLabel"] {{
			color: {MUTED_TEXT_COLOR};
		}}

		[data-testid="stMetricValue"] {{
			color: {TEXT_COLOR};
		}}

		[data-testid="stDataEditor"] {{
			border: 1px solid {BORDER_COLOR};
			border-radius: 10px;
			overflow: hidden;
		}}

		.sloppy-section-title {{
			font-size: 1.05rem;
			font-weight: 600;
			color: {TEXT_COLOR};
			margin: 0 0 0.25rem 0;
		}}

		.sloppy-section-caption {{
			font-size: 0.85rem;
			color: {MUTED_TEXT_COLOR};
			margin: 0 0 0.75rem 0;
		}}

		.sloppy-status {{
			background-color: {PANEL_BACKGROUND};
			border: 1px solid {BORDER_COLOR};
			border-left: 4px solid {ACCENT_BLUE};
			border-radius: 8px;
			padding: 0.75rem 1rem;
			margin: 0.25rem 0 0.75rem 0;
		}}
	</style>
	""", unsafe_allow_html=True, )

# ==========================================================================================
# PART 2 — Input Guards
# ==========================================================================================

def throw_if( name: str, value: object ) -> None:
	"""
	Input guard.

	Purpose:
	    Validates that a required argument contains a usable value before the surrounding
	    workflow continues.

	Args:
	    name (str): Name of the argument being validated.
	    value (object): Argument value being validated.

	Returns:
	    None: This function raises an exception when validation fails.
	"""
	if not name:
		raise ValueError( 'Argument "name" cannot be empty.' )
	
	if value is None:
		raise ValueError( f'Argument "{name}" cannot be null.' )

# ==========================================================================================
# PART 3 — Session State Initialization
# ==========================================================================================

if 'packets' not in st.session_state:
	st.session_state.packets: List[ Dict ] = [ ]

if 'running' not in st.session_state:
	st.session_state.running = False

if 'capture_mode' not in st.session_state:
	st.session_state.capture_mode = ''

if 'session_id' not in st.session_state:
	st.session_state.session_id = datetime.utcnow( ).strftime( '%Y%m%d_%H%M%S' )

if 'live_queue' not in st.session_state:
	st.session_state.live_queue = queue.Queue( maxsize=5000 )

if 'capture_error_queue' not in st.session_state:
	st.session_state.capture_error_queue = queue.Queue( maxsize=100 )

if 'live_stop_event' not in st.session_state:
	st.session_state.live_stop_event = threading.Event( )

if 'live_thread' not in st.session_state:
	st.session_state.live_thread = None

if 'capture_error' not in st.session_state:
	st.session_state.capture_error = ''

if 'captured_packet_count' not in st.session_state:
	st.session_state.captured_packet_count = 0

# ==========================================================================================
# PART 4 — Packet Normalization and Demo Generation
# ==========================================================================================

def normalize_packet( record: Dict, session_id: str ) -> Dict:
	"""
	Normalize a packet record.

	Purpose:
	    Converts a partially populated packet record into the schema consumed by the
	    dashboard and associates it with the active capture session.

	Args:
	    record (Dict): Packet values produced by the demo generator or Scapy callback.
	    session_id (str): Identifier assigned to the active capture session.

	Returns:
	    Dict: Normalized packet record.
	"""
	throw_if( 'record', record )
	throw_if( 'session_id', session_id )
	
	return { 'timestamp': record.get( 'timestamp', datetime.utcnow( ) ),
		'src_ip': record.get( 'src_ip' ), 'dst_ip': record.get( 'dst_ip' ),
		'protocol': record.get( 'protocol' ), 'src_port': record.get( 'src_port' ),
		'dst_port': record.get( 'dst_port' ), 'flags': record.get( 'flags', '' ),
		'length': record.get( 'length', 0 ), 'session': session_id, }

def generate_demo_packet( session_id: str ) -> Dict:
	"""
	Generate a demonstration packet.

	Purpose:
	    Produces a normalized TCP, UDP, or ICMP packet record for replay and interface
	    validation when live packet capture is not required.

	Args:
	    session_id (str): Identifier assigned to the active capture session.

	Returns:
	    Dict: Normalized demonstration packet record.
	"""
	throw_if( 'session_id', session_id )
	
	protocol = random.choice( [ 'TCP', 'UDP', 'ICMP' ] )
	
	record = { 'timestamp': datetime.utcnow( ), 'src_ip': f'192.168.1.{random.randint( 1, 50 )}',
		'dst_ip': f'10.0.0.{random.randint( 1, 50 )}', 'protocol': protocol,
		'length': random.randint( 64, 1514 ), 'src_port': None, 'dst_port': None, 'flags': '', }
	
	if protocol == 'TCP':
		record.update( { 'src_port': random.randint( 1024, 65535 ),
			'dst_port': random.choice( [ 22, 80, 443, 3389, 8080 ] ),
			'flags': random.choice( [ 'SYN', 'ACK', 'PSH', 'FIN', 'RST' ] ), } )
	elif protocol == 'UDP':
		record.update( { 'src_port': random.randint( 1024, 65535 ),
			'dst_port': random.choice( [ 53, 67, 68, 123, 161, 5353 ] ), } )
	else:
		record[ 'flags' ] = random.choice(
			[ 'ECHO_REQUEST', 'ECHO_REPLY', 'DEST_UNREACH', 'TTL_EXCEEDED', ] )
	
	return normalize_packet( record, session_id )

# ==========================================================================================
# PART 5 — Live Packet Capture
# ==========================================================================================

def write_capture_error( capture_error_queue: queue.Queue, exception: Exception, ) -> None:
	"""
	Write a live-capture error.

	Purpose:
	    Places a background-thread exception into the capture error queue so the Streamlit
	    thread can display it safely.

	Args:
	    capture_error_queue (queue.Queue): Thread-safe queue used for capture errors.
	    exception (Exception): Exception raised by packet capture or parsing.

	Returns:
	    None: This function writes the error message into the supplied queue.
	"""
	throw_if( 'capture_error_queue', capture_error_queue )
	throw_if( 'exception', exception )
	
	try:
		capture_error_queue.put_nowait( str( exception ) )
	except queue.Full:
		return

def scapy_callback( packet: object, packet_queue: queue.Queue,
	capture_error_queue: queue.Queue, ) -> None:
	"""
	Process a Scapy packet.

	Purpose:
	    Parses supported Ethernet and IPv4 packets into plain packet records and writes
	    them to a thread-safe queue without accessing Streamlit session state.

	Args:
	    packet (object): Packet supplied by Scapy.
	    packet_queue (queue.Queue): Thread-safe queue receiving parsed packet records.
	    capture_error_queue (queue.Queue): Thread-safe queue receiving parsing errors.

	Returns:
	    None: This function writes supported packet records into the packet queue.
	"""
	try:
		throw_if( 'packet', packet )
		throw_if( 'packet_queue', packet_queue )
		throw_if( 'capture_error_queue', capture_error_queue )
		
		if not packet.haslayer( ScapyEther ):
			return
		
		raw = bytes( packet )
		ethernet = Ethernet( raw )
		
		if ethernet.proto not in (8, 0x0800, 2048):
			return
		
		ipv4 = IPv4( ethernet.data )
		
		record = { 'timestamp': datetime.utcnow( ), 'src_ip': ipv4.src, 'dst_ip': ipv4.target,
			'protocol': None, 'src_port': None, 'dst_port': None, 'flags': '',
			'length': len( raw ), }
		
		if ipv4.proto == 6:
			tcp = TCP( ipv4.data )
			
			record.update( { 'protocol': 'TCP', 'src_port': tcp.src_port, 'dst_port':
				tcp.dest_port,
				'flags': ''.join( [ flag for flag, enabled in
					{ 'SYN': tcp.flag_syn, 'ACK': tcp.flag_ack, 'FIN': tcp.flag_fin,
						'RST': tcp.flag_rst, 'PSH': tcp.flag_psh, 'URG': tcp.flag_urg, }.items(
						
					) if
					enabled ] ), } )
		elif ipv4.proto == 17:
			udp = UDP( ipv4.data )
			
			record.update(
				{ 'protocol': 'UDP', 'src_port': udp.src_port, 'dst_port': udp.dest_port, } )
		elif ipv4.proto == 1:
			icmp = ICMP( ipv4.data )
			
			record.update( { 'protocol': 'ICMP', 'flags': f'TYPE_{icmp.type}', } )
		else:
			return
		
		packet_queue.put_nowait( record )
	except queue.Full:
		return
	except Exception as e:
		write_capture_error( capture_error_queue, e )

def start_live_capture( packet_queue: queue.Queue, capture_error_queue: queue.Queue,
	stop_event: threading.Event, ) -> None:
	"""
	Start live packet capture.

	Purpose:
	    Runs Scapy capture in bounded intervals so the background thread can observe the
	    stop event and terminate cleanly.

	Args:
	    packet_queue (queue.Queue): Thread-safe queue receiving parsed packet records.
	    capture_error_queue (queue.Queue): Thread-safe queue receiving capture errors.
	    stop_event (threading.Event): Signal used to terminate live capture.

	Returns:
	    None: This function runs until capture is stopped or fails.
	"""
	try:
		throw_if( 'packet_queue', packet_queue )
		throw_if( 'capture_error_queue', capture_error_queue )
		throw_if( 'stop_event', stop_event )
		
		while not stop_event.is_set( ):
			sniff( prn=lambda packet: scapy_callback( packet, packet_queue, capture_error_queue, ),
				store=False, timeout=1, )
	except Exception as e:
		write_capture_error( capture_error_queue, e )
		stop_event.set( )

def start_capture_thread( ) -> None:
	"""
	Start the background capture thread.

	Purpose:
	    Creates and starts a live-capture thread when no active capture thread currently
	    exists.

	Returns:
	    None: This function updates session state and starts the capture thread.
	"""
	live_thread = st.session_state.live_thread
	
	if live_thread is not None and live_thread.is_alive( ):
		if st.session_state.live_stop_event.is_set( ):
			st.session_state.capture_error = (
				'The previous capture thread is still stopping. Select Start again momentarily.')
		
		return
	
	st.session_state.live_stop_event.clear( )
	
	st.session_state.live_thread = threading.Thread( target=start_live_capture,
		args=(st.session_state.live_queue, st.session_state.capture_error_queue,
			st.session_state.live_stop_event,), daemon=True, name='sloppy-live-capture', )
	
	st.session_state.live_thread.start( )

def stop_capture_thread( ) -> None:
	"""
	Stop the background capture thread.

	Purpose:
	    Signals the live-capture thread to stop without blocking Streamlit while Scapy
	    completes its current bounded capture interval.

	Returns:
	    None: This function signals the capture thread through session state.
	"""
	st.session_state.live_stop_event.set( )

def drain_packet_queue( session_id: str ) -> int:
	"""
	Drain captured packets from the live queue.

	Purpose:
	    Transfers all currently available background-thread records into Streamlit session
	    state and normalizes each record on the Streamlit thread.

	Args:
	    session_id (str): Identifier assigned to the active capture session.

	Returns:
	    int: Number of packet records transferred from the queue.
	"""
	throw_if( 'session_id', session_id )
	
	packet_count = 0
	
	while True:
		try:
			record = st.session_state.live_queue.get_nowait( )
			normalized = normalize_packet( record, session_id )
			st.session_state.packets.append( normalized )
			packet_count += 1
		except queue.Empty:
			break
	
	return packet_count

def drain_capture_errors( ) -> str:
	"""
	Drain capture errors from the error queue.

	Purpose:
	    Transfers background capture failures to the Streamlit thread and returns the most
	    recent error message for display.

	Returns:
	    str: Most recent capture error or an empty string.
	"""
	capture_error = ''
	
	while True:
		try:
			capture_error = st.session_state.capture_error_queue.get_nowait( )
		except queue.Empty:
			break
	
	return capture_error

# ==========================================================================================
# PART 6 — Visualization Helpers
# ==========================================================================================

def configure_figure( figure: go.Figure, height: int, show_legend: bool = True, ) -> go.Figure:
	"""
	Configure a Plotly figure.

	Purpose:
	    Applies common dark-mode typography, margins, grid styling, legend placement, and
	    responsive dimensions across all network visualizations.

	Args:
	    figure (go.Figure): Plotly figure to configure.
	    height (int): Rendered figure height in pixels.
	    show_legend (bool): Indicates whether the figure legend is displayed.

	Returns:
	    go.Figure: Configured Plotly figure.
	"""
	throw_if( 'figure', figure )
	throw_if( 'height', height )
	
	figure.update_layout( height=height, margin={ 'l': 18, 'r': 18, 't': 52, 'b': 24, },
		paper_bgcolor=PANEL_BACKGROUND, plot_bgcolor=PANEL_BACKGROUND,
		font={ 'color': TEXT_COLOR, 'family': 'Arial, sans-serif', 'size': 12, },
		title={ 'font': { 'color': TEXT_COLOR, 'size': 16, }, 'x': 0.02, 'xanchor': 'left', },
		hoverlabel={ 'bgcolor': '#252525', 'bordercolor': BORDER_COLOR,
			'font': { 'color': TEXT_COLOR, }, },
		legend={ 'orientation': 'h', 'yanchor': 'bottom', 'y': 1.02, 'xanchor': 'right', 'x': 1,
			'bgcolor': 'rgba( 0, 0, 0, 0 )', }, showlegend=show_legend, )
	
	figure.update_xaxes( showgrid=True, gridcolor=GRID_COLOR, zeroline=False,
		linecolor=BORDER_COLOR, tickfont={ 'color': MUTED_TEXT_COLOR, },
		title_font={ 'color': MUTED_TEXT_COLOR, }, )
	
	figure.update_yaxes( showgrid=True, gridcolor=GRID_COLOR, zeroline=False,
		linecolor=BORDER_COLOR, tickfont={ 'color': MUTED_TEXT_COLOR, },
		title_font={ 'color': MUTED_TEXT_COLOR, }, )
	
	return figure

def create_protocol_figure( df_packets: pd.DataFrame ) -> go.Figure:
	"""
	Create the protocol-composition figure.

	Purpose:
	    Displays packet counts and percentage share for each protocol in a compact donut
	    visualization.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Protocol-composition donut chart.
	"""
	throw_if( 'df_packets', df_packets )
	
	df_protocols = (df_packets.groupby( 'protocol', dropna=False ).size( ).rename(
		'packets' ).reset_index( ).sort_values( 'packets', ascending=False ))
	
	figure = go.Figure( data=[
		go.Pie( labels=df_protocols[ 'protocol' ], values=df_protocols[ 'packets' ], hole=0.62,
			sort=False, textinfo='label+percent', textposition='outside', marker={
				'colors': [ PROTOCOL_COLORS.get( protocol, PURPLE ) for protocol in
					df_protocols[ 'protocol' ] ],
				'line': { 'color': PANEL_BACKGROUND, 'width': 3, }, },
			hovertemplate=('<b>%{label}</b><br>'
			               'Packets: %{value:,}<br>'
			               'Share: %{percent}'
			               '<extra></extra>'), ) ] )
	
	figure.add_annotation( text=f'<b>{len( df_packets ):,}</b><br><span>Packets</span>', x=0.5,
		y=0.5, showarrow=False, font={ 'color': TEXT_COLOR, 'size': 16, }, )
	
	figure.update_layout( title='Protocol Composition', )
	
	return configure_figure( figure, height=390, show_legend=False, )

def create_traffic_figure( df_packets: pd.DataFrame ) -> go.Figure:
	"""
	Create the traffic-over-time figure.

	Purpose:
	    Displays packets per second by protocol using an interactive stacked area chart.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Protocol-level packet traffic over time.
	"""
	throw_if( 'df_packets', df_packets )
	
	df_time = df_packets.copy( )
	df_time[ 'timestamp' ] = pd.to_datetime( df_time[ 'timestamp' ], errors='coerce', )
	
	df_time = df_time.dropna( subset=[ 'timestamp', 'protocol' ] )
	
	if df_time.empty:
		return configure_figure( go.Figure( ), height=390, show_legend=False, )
	
	current_time = df_time[ 'timestamp' ].max( )
	start_time = current_time - pd.Timedelta( seconds=60 )
	
	df_time = df_time[ df_time[ 'timestamp' ] >= start_time ]
	
	df_time = (
		df_time.set_index( 'timestamp' ).groupby( 'protocol' ).resample( '1s' ).size( ).rename(
			'packets' ).reset_index( ))
	
	figure = px.area( df_time, x='timestamp', y='packets', color='protocol',
		color_discrete_map=PROTOCOL_COLORS,
		category_orders={ 'protocol': [ 'TCP', 'UDP', 'ICMP' ], }, )
	
	figure.update_traces( line={ 'width': 2, }, hovertemplate=('<b>%{fullData.name}</b><br>'
	                                                           'Time: %{x|%H:%M:%S}<br>'
	                                                           'Packets: %{y:,}'
	                                                           '<extra></extra>'), )
	
	figure.update_layout( title='Traffic Over Time', xaxis_title='Time — Last 60 Seconds',
		yaxis_title='Packets / Second', hovermode='x unified', )
	
	return configure_figure( figure, height=390, show_legend=True, )

def create_endpoint_figure( df_packets: pd.DataFrame, column_name: str, title: str, ) -> go.Figure:
	"""
	Create a ranked endpoint figure.

	Purpose:
	    Displays the most active source or destination IP addresses as a ranked horizontal
	    bar chart.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.
	    column_name (str): Endpoint column used to calculate packet counts.
	    title (str): Figure title.

	Returns:
	    go.Figure: Ranked endpoint activity chart.
	"""
	throw_if( 'df_packets', df_packets )
	throw_if( 'column_name', column_name )
	throw_if( 'title', title )
	
	df_endpoints = (
		df_packets.dropna( subset=[ column_name ] ).groupby( column_name ).size( ).rename(
			'packets' ).reset_index( ).nlargest( 10, 'packets' ).sort_values( 'packets',
			ascending=True ))
	
	figure = go.Figure( data=[
		go.Bar( x=df_endpoints[ 'packets' ], y=df_endpoints[ column_name ], orientation='h',
			marker={ 'color': df_endpoints[ 'packets' ],
				'colorscale': [ [ 0.0, '#153E75' ], [ 0.5, ACCENT_BLUE ], [ 1.0, CYAN ], ],
				'line': { 'color': 'rgba( 255, 255, 255, 0.12 )', 'width': 1, }, },
			text=df_endpoints[ 'packets' ], textposition='outside', cliponaxis=False,
			hovertemplate=('<b>%{y}</b><br>'
			               'Packets: %{x:,}'
			               '<extra></extra>'), ) ] )
	
	figure.update_layout( title=title, xaxis_title='Packet Count', yaxis_title='', )
	
	return configure_figure( figure, height=390, show_legend=False, )

def create_port_heatmap( df_packets: pd.DataFrame ) -> go.Figure:
	"""
	Create the destination-port heatmap.

	Purpose:
	    Displays packet concentration across the most active destination ports and
	    transport protocols.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Destination-port activity heatmap.
	"""
	throw_if( 'df_packets', df_packets )
	
	df_ports = df_packets.dropna( subset=[ 'dst_port', 'protocol' ], ).copy( )
	
	if df_ports.empty:
		return configure_figure( go.Figure( ), height=390, show_legend=False, )
	
	df_ports[ 'dst_port' ] = df_ports[ 'dst_port' ].astype( int )
	
	top_ports = (df_ports.groupby( 'dst_port' ).size( ).nlargest( 15 ).index)
	
	df_ports = df_ports[ df_ports[ 'dst_port' ].isin( top_ports ) ]
	
	df_heatmap = (df_ports.groupby( [ 'protocol', 'dst_port' ] ).size( ).rename(
		'packets' ).reset_index( ).pivot( index='protocol', columns='dst_port',
		values='packets', ).fillna( 0 ))
	
	df_heatmap = df_heatmap.reindex( index=[ protocol for protocol in [ 'TCP', 'UDP', 'ICMP' ] if
		protocol in df_heatmap.index ] )
	
	df_heatmap = df_heatmap[ sorted( df_heatmap.columns ) ]
	
	figure = go.Figure( data=[
		go.Heatmap( z=df_heatmap.values, x=[ str( port ) for port in df_heatmap.columns ],
			y=df_heatmap.index,
			colorscale=[ [ 0.0, '#101820' ], [ 0.25, '#153E75' ], [ 0.55, ACCENT_BLUE ],
				[ 0.8, CYAN ], [ 1.0, '#D9F8FF' ], ],
			colorbar={ 'title': 'Packets', 'thickness': 12, 'outlinewidth': 0, },
			hovertemplate=('<b>%{y}</b><br>'
			               'Destination Port: %{x}<br>'
			               'Packets: %{z:,}'
			               '<extra></extra>'), ) ] )
	
	figure.update_layout( title='Destination Port Activity', xaxis_title='Destination Port',
		yaxis_title='Protocol', )
	
	return configure_figure( figure, height=390, show_legend=False, )

def create_packet_size_figure( df_packets: pd.DataFrame ) -> go.Figure:
	"""
	Create the packet-size distribution figure.

	Purpose:
	    Displays the frequency distribution of packet lengths with average and median
	    reference markers.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Packet-size histogram.
	"""
	throw_if( 'df_packets', df_packets )
	
	df_sizes = df_packets.dropna( subset=[ 'length', 'protocol' ], ).copy( )
	
	figure = px.histogram( df_sizes, x='length', color='protocol', nbins=35, barmode='overlay',
		opacity=0.72, color_discrete_map=PROTOCOL_COLORS,
		category_orders={ 'protocol': [ 'TCP', 'UDP', 'ICMP' ], }, )
	
	average_size = df_sizes[ 'length' ].mean( )
	median_size = df_sizes[ 'length' ].median( )
	
	figure.add_vline( x=average_size, line_width=2, line_dash='dash', line_color=RED,
		annotation_text=f'Average {average_size:,.0f}', annotation_position='top right', )
	
	figure.add_vline( x=median_size, line_width=2, line_dash='dot', line_color=AMBER,
		annotation_text=f'Median {median_size:,.0f}', annotation_position='top left', )
	
	figure.update_traces( hovertemplate=('<b>%{fullData.name}</b><br>'
	                                     'Packet Size: %{x:,} bytes<br>'
	                                     'Frequency: %{y:,}'
	                                     '<extra></extra>'), )
	
	figure.update_layout( title='Packet Size Distribution', xaxis_title='Packet Size — Bytes',
		yaxis_title='Frequency', bargap=0.04, )
	
	return configure_figure( figure, height=390, show_legend=True, )

def create_flow_figure( df_packets: pd.DataFrame ) -> go.Figure:
	"""
	Create the network-flow figure.

	Purpose:
	    Displays the strongest source-to-destination communication paths using a Sankey
	    diagram weighted by packet count.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Source-to-destination network-flow diagram.
	"""
	throw_if( 'df_packets', df_packets )
	
	df_flows = (df_packets.dropna( subset=[ 'src_ip', 'dst_ip' ] ).groupby(
		[ 'src_ip', 'dst_ip' ] ).size( ).rename( 'packets' ).reset_index( ).nlargest( 20,
		'packets' ))
	
	source_labels = [ f'Source: {value}' for value in df_flows[ 'src_ip' ].unique( ) ]
	
	destination_labels = [ f'Destination: {value}' for value in df_flows[ 'dst_ip' ].unique( ) ]
	
	labels = source_labels + destination_labels
	
	label_indexes = { label: index for index, label in enumerate( labels ) }
	
	source_indexes = [ label_indexes[ f'Source: {value}' ] for value in df_flows[ 'src_ip' ] ]
	
	destination_indexes = [ label_indexes[ f'Destination: {value}' ] for value in
		df_flows[ 'dst_ip' ] ]
	
	figure = go.Figure( data=[ go.Sankey( arrangement='snap',
		node={ 'pad': 18, 'thickness': 16, 'line': { 'color': BORDER_COLOR, 'width': 1, },
			'label': labels,
			'color': [ ACCENT_BLUE if label.startswith( 'Source:' ) else GREEN for label in
				labels ], 'hovertemplate': ('<b>%{label}</b><br>'
			                                'Total Packets: %{value:,}'
			                                '<extra></extra>'), },
		link={ 'source': source_indexes, 'target': destination_indexes,
			'value': df_flows[ 'packets' ], 'color': 'rgba( 0, 120, 252, 0.28 )',
			'hovertemplate': ('%{source.label}<br>'
			                  '→ %{target.label}<br>'
			                  'Packets: %{value:,}'
			                  '<extra></extra>'), }, ) ] )
	
	figure.update_layout( title='Network Flow Relationships', )
	
	return configure_figure( figure, height=510, show_legend=False, )

def prepare_packet_editor( df_packets: pd.DataFrame ) -> pd.DataFrame:
	"""
	Prepare packet records for the data editor.

	Purpose:
	    Formats, orders, and enriches packet records for read-only display through
	    st.data_editor().

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    pd.DataFrame: Display-ready packet records.
	"""
	throw_if( 'df_packets', df_packets )
	
	df_editor = df_packets.copy( )
	
	df_editor[ 'timestamp' ] = pd.to_datetime( df_editor[ 'timestamp' ], errors='coerce', )
	
	df_editor[ 'src_port' ] = df_editor[ 'src_port' ].astype( 'Int64' )
	df_editor[ 'dst_port' ] = df_editor[ 'dst_port' ].astype( 'Int64' )
	df_editor[ 'length' ] = df_editor[ 'length' ].astype( 'Int64' )
	
	df_editor = df_editor.sort_values( 'timestamp', ascending=False, )
	
	column_order = [ 'timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'flags',
		'length', 'session', ]
	
	existing_columns = [ column_name for column_name in column_order if
		column_name in df_editor.columns ]
	
	return df_editor[ existing_columns ]

# ==========================================================================================
# PART 7 — Thread State Maintenance
# ==========================================================================================

current_thread = st.session_state.live_thread

if current_thread is not None and not current_thread.is_alive( ):
	st.session_state.live_thread = None

capture_error = drain_capture_errors( )

if capture_error:
	st.session_state.capture_error = capture_error
	st.session_state.running = False
	stop_capture_thread( )

# ==========================================================================================
# PART 8 — Header / Branding
# ==========================================================================================

with st.container( ):
	col_logo, col_title = st.columns( [ 5, 1 ] )
	
	with col_logo:
		st.markdown( '### Network Analyzer' )
		st.caption( 'Packet Metadata • Flow Analytics • Protocol Intelligence' )
	
	with col_title:
		st.caption( '' )

# ==========================================================================================
# PART 9 — Sidebar Controls
# ==========================================================================================

with st.sidebar:
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
	st.subheader( 'Controls' )
	
	mode = st.radio( ' ', options=[ 'Demo / Replay', 'Live (Scapy)', ], )
	
	if mode == 'Live (Scapy)' and not SCAPY_AVAILABLE:
		st.error( 'Scapy is not available. Install Scapy and run the application with '
		          'administrator/root privileges.' )
		
		if SCAPY_IMPORT_ERROR:
			st.caption( SCAPY_IMPORT_ERROR )
	
	c1, c2 = st.columns( 2 )
	
	with c1:
		if st.button( '▶ Start', use_container_width=True, ):
			st.session_state.capture_error = ''
			st.session_state.capture_mode = mode
			
			if mode == 'Live (Scapy)':
				if not SCAPY_AVAILABLE:
					st.session_state.running = False
					st.session_state.capture_error = (
						'Live capture cannot start because Scapy is unavailable.')
				else:
					st.session_state.running = True
					start_capture_thread( )
			else:
				stop_capture_thread( )
				st.session_state.running = True
			
			st.rerun( )
	
	with c2:
		if st.button( '■ Stop', use_container_width=True, ):
			st.session_state.running = False
			stop_capture_thread( )
			st.rerun( )
	
	if st.session_state.running:
		st.success( f'Capture running: {st.session_state.capture_mode}' )
	else:
		st.caption( 'Capture stopped.' )
	
	if st.session_state.capture_error:
		st.error( st.session_state.capture_error )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
	st.subheader( 'Filters' )
	
	proto_filter = st.multiselect( 'Protocols', options=[ 'TCP', 'UDP', 'ICMP', ],
		default=[ 'TCP', 'UDP', 'ICMP', ], )
	
	port_range = st.slider( 'Destination Port Range', 0, 65535, (0, 65535), )
	
	window_size = st.slider( 'Rolling Window (Packets)', 50, 2000, 500, 50, )

# ==========================================================================================
# PART 10 — Packet Ingestion
# ==========================================================================================

if st.session_state.running:
	if st.session_state.capture_mode == 'Demo / Replay':
		for _ in range( random.randint( 5, 15 ) ):
			packet = generate_demo_packet( st.session_state.session_id )
			
			st.session_state.packets.append( packet )
	
	elif (st.session_state.capture_mode == 'Live (Scapy)' and SCAPY_AVAILABLE):
		captured_packet_count = drain_packet_queue( st.session_state.session_id )
		
		st.session_state.captured_packet_count += captured_packet_count
		
		capture_error = drain_capture_errors( )
		
		if capture_error:
			st.session_state.capture_error = capture_error
			st.session_state.running = False
			stop_capture_thread( )
	
	st.session_state.packets = st.session_state.packets[ -window_size: ]

# ==========================================================================================
# PART 11 — DataFrame Assembly and Filtering
# ==========================================================================================

df_packets = pd.DataFrame( st.session_state.packets )

if not df_packets.empty:
	df_packets[ 'timestamp' ] = pd.to_datetime( df_packets[ 'timestamp' ], errors='coerce', )
	
	df_packets = df_packets[ df_packets[ 'protocol' ].isin( proto_filter ) ]
	
	df_packets = df_packets[ df_packets[ 'dst_port' ].isna( ) | (
			(df_packets[ 'dst_port' ] >= port_range[ 0 ]) & (
				df_packets[ 'dst_port' ] <= port_range[ 1 ])) ]

# ==========================================================================================
# PART 12 — Executive Metrics
# ==========================================================================================

with st.container( ):
	m1, m2, m3, m4, m5 = st.columns( 5 )
	
	packet_count = len( df_packets )
	
	source_count = (df_packets[ 'src_ip' ].nunique( ) if not df_packets.empty else 0)
	
	destination_count = (df_packets[ 'dst_ip' ].nunique( ) if not df_packets.empty else 0)
	
	average_packet_size = (int( df_packets[ 'length' ].mean( ) ) if not df_packets.empty else 0)
	
	protocol_count = (df_packets[ 'protocol' ].nunique( ) if not df_packets.empty else 0)
	
	m1.metric( 'Packets', f'{packet_count:,}', )
	
	m2.metric( 'Unique Src IPs', f'{source_count:,}', )
	
	m3.metric( 'Unique Dst IPs', f'{destination_count:,}', )
	
	m4.metric( 'Avg Packet Size', f'{average_packet_size:,} B', )
	
	m5.metric( 'Protocols Seen', f'{protocol_count:,}', )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )

# ==========================================================================================
# PART 13 — Analytical Visualizations
# ==========================================================================================

if not df_packets.empty:
	# --------------------------------------------------------------------------------------
	# Protocol Composition and Traffic Trend
	# --------------------------------------------------------------------------------------
	protocol_column, traffic_column = st.columns( [ 0.82, 1.38 ], gap='medium', )
	
	with protocol_column:
		figure_protocol = create_protocol_figure( df_packets )
		
		st.plotly_chart( figure_protocol, use_container_width=True, config=CHART_CONFIG,
			key='protocol-composition-chart', )
	
	with traffic_column:
		figure_traffic = create_traffic_figure( df_packets )
		
		st.plotly_chart( figure_traffic, use_container_width=True, config=CHART_CONFIG,
			key='traffic-over-time-chart', )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
	
	# --------------------------------------------------------------------------------------
	# Endpoint Activity
	# --------------------------------------------------------------------------------------
	source_column, destination_column = st.columns( 2, gap='medium', )
	
	with source_column:
		figure_sources = create_endpoint_figure( df_packets, 'src_ip', 'Top Source IP Addresses', )
		
		st.plotly_chart( figure_sources, use_container_width=True, config=CHART_CONFIG,
			key='top-source-chart', )
	
	with destination_column:
		figure_destinations = create_endpoint_figure( df_packets, 'dst_ip',
			'Top Destination IP Addresses', )
		
		st.plotly_chart( figure_destinations, use_container_width=True, config=CHART_CONFIG,
			key='top-destination-chart', )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
	
	# --------------------------------------------------------------------------------------
	# Port Activity and Packet Sizes
	# --------------------------------------------------------------------------------------
	port_column, size_column = st.columns( 2, gap='medium', )
	
	with port_column:
		df_port_packets = df_packets.dropna( subset=[ 'dst_port' ], )
		
		if not df_port_packets.empty:
			figure_ports = create_port_heatmap( df_packets )
			
			st.plotly_chart( figure_ports, use_container_width=True, config=CHART_CONFIG,
				key='destination-port-heatmap', )
		else:
			st.info( 'No destination-port data is available for the current filters.' )
	
	with size_column:
		figure_sizes = create_packet_size_figure( df_packets )
		
		st.plotly_chart( figure_sizes, use_container_width=True, config=CHART_CONFIG,
			key='packet-size-histogram', )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
	
	# --------------------------------------------------------------------------------------
	# Source-to-Destination Network Flow
	# --------------------------------------------------------------------------------------
	df_flow_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ], )
	
	if not df_flow_packets.empty:
		figure_flow = create_flow_figure( df_packets )
		
		st.plotly_chart( figure_flow, use_container_width=True, config=CHART_CONFIG,
			key='network-flow-sankey', )
	else:
		st.info( 'No source-to-destination flow data is available.' )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
else:
	empty_left, empty_right = st.columns( 2 )
	
	with empty_left:
		st.info( 'No protocol data is available.' )
	
	with empty_right:
		st.info( 'No time-series data is available.' )
	
	st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )

# ==========================================================================================
# PART 14 — Live Packet Stream
# ==========================================================================================

st.markdown( """
	<div class="sloppy-section-title">Live Packet Stream</div>
	<div class="sloppy-section-caption">
		Most recent normalized packets matching the active protocol and port filters.
	</div>
	""", unsafe_allow_html=True, )

if not df_packets.empty:
	df_packet_editor = prepare_packet_editor( df_packets )
	
	st.data_editor( df_packet_editor, disabled=True, hide_index=True, use_container_width=True,
		height=460,
		column_order=[ 'timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
			'flags',
			'length', 'session', ], column_config={
			'timestamp': st.column_config.DatetimeColumn( 'Timestamp',
				help='UTC packet-capture time.', format='HH:mm:ss.SSS', ),
			'protocol': st.column_config.TextColumn( 'Protocol',
				help='Detected transport or control protocol.', width='small', ),
			'src_ip': st.column_config.TextColumn( 'Source IP', help='Packet source IPv4 address.',
				width='medium', ), 'src_port': st.column_config.NumberColumn( 'Source Port',
				help='Source transport-layer port.', format='%d', width='small', ),
			'dst_ip': st.column_config.TextColumn( 'Destination IP',
				help='Packet destination IPv4 address.', width='medium', ),
			'dst_port': st.column_config.NumberColumn( 'Destination Port',
				help='Destination transport-layer port.', format='%d', width='small', ),
			'flags': st.column_config.TextColumn( 'Flags', help='TCP flags or ICMP message type.',
				width='medium', ), 'length': st.column_config.NumberColumn( 'Packet Size',
				help='Captured packet length in bytes.', format='%d bytes', width='small', ),
			'session': st.column_config.TextColumn( 'Session', help='Capture-session identifier.',
				width='medium', ), }, key='live-packet-editor', )
else:
	st.info( 'Waiting for packets…' )

st.caption( 'Sloppy Network Analyzer — Live capture via Scapy enabled. '
            'Run with administrator/root privileges for full functionality.' )

# ==========================================================================================
# PART 15 — Active Refresh Cycle
# ==========================================================================================

if st.session_state.running:
	time.sleep( 0.25 )
	st.rerun( )
