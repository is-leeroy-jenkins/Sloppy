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
import config as cfg
import queue
import random
import threading
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
# Application Styling
# ------------------------------------------------------------------------------------------
st.markdown( f"""
	<style>
		[data-testid="stAppViewContainer"] {{
			background-color: {cfg.PAGE_BACKGROUND};
		}}

		[data-testid="stSidebar"] {{
			background-color: #353535;
			border-right: 1px solid {cfg.BORDER_COLOR};
		}}

		[data-testid="stMetric"] {{
			background-color: {cfg.PANEL_BACKGROUND};
			border: 1px solid {cfg.BORDER_COLOR};
			border-radius: 10px;
			padding: 14px 16px;
		}}

		[data-testid="stMetricLabel"] {{
			color: {cfg.MUTED_TEXT_COLOR};
		}}

		[data-testid="stMetricValue"] {{
			color: {cfg.TEXT_COLOR};
		}}

		[data-testid="stDataEditor"] {{
			border: 1px solid {cfg.BORDER_COLOR};
			border-radius: 10px;
			overflow: hidden;
		}}

		.sloppy-section-title {{
			font-size: 1.05rem;
			font-weight: 600;
			color: {cfg.TEXT_COLOR};
			margin: 0 0 0.25rem 0;
		}}

		.sloppy-section-caption {{
			font-size: 0.85rem;
			color: {cfg.MUTED_TEXT_COLOR};
			margin: 0 0 0.75rem 0;
		}}
	</style>
	""", unsafe_allow_html=True, )

# ==========================================================================================
#  Session State Initialization
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

if 'packet_version' not in st.session_state:
	st.session_state.packet_version = 0

# ----- Constants -----

REALTIME_REFRESH_INTERVAL = (1.0 if st.session_state.running else None)

ANALYSIS_REFRESH_INTERVAL = (2.0 if st.session_state.running else None)

FLOW_REFRESH_INTERVAL = (5.0 if st.session_state.running else None)

# ---- Packet Normalization and Demo Generation -----

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

def normalize_packet( record: Dict, session_id: str, ) -> Dict:
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
	return { 'timestamp': record.get( 'timestamp', datetime.utcnow( ), ),
		'src_ip': record.get( 'src_ip' ), 'dst_ip': record.get( 'dst_ip' ),
		'protocol': record.get( 'protocol' ), 'src_port': record.get( 'src_port' ),
		'dst_port': record.get( 'dst_port' ), 'flags': record.get( 'flags', '' ),
		'length': record.get( 'length', 0 ), 'session': session_id, }

def generate_demo_packet( session_id: str, ) -> Dict:
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
	protocol = random.choice( cfg.PROTOCOL_ORDER )
	record = { 'timestamp': datetime.utcnow( ), 'src_ip': f'192.168.1.{random.randint( 1, 50 )}',
		'dst_ip': f'10.0.0.{random.randint( 1, 50 )}', 'protocol': protocol,
		'length': random.randint( 64, 1514 ), 'src_port': None, 'dst_port': None, 'flags': '', }
	
	if protocol == 'TCP':
		record.update( { 'src_port': random.randint( 1024, 65535, ),
			'dst_port': random.choice( [ 22, 80, 443, 3389, 8080, ] ),
			'flags': random.choice( [ 'SYN', 'ACK', 'PSH', 'FIN', 'RST', ] ), } )
	elif protocol == 'UDP':
		record.update( { 'src_port': random.randint( 1024, 65535, ),
			'dst_port': random.choice( [ 53, 67, 68, 123, 161, 5353, ] ), } )
	else:
		record[ 'flags' ] = random.choice(
			[ 'ECHO_REQUEST', 'ECHO_REPLY', 'DEST_UNREACH', 'TTL_EXCEEDED', ] )
	
	return normalize_packet( record, session_id, )

# ---- Live Packet Capture -----

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
	throw_if( 'capture_error_queue', capture_error_queue, )
	throw_if( 'exception', exception, )
	
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
		throw_if( 'packet', packet, )
		throw_if( 'packet_queue', packet_queue, )
		throw_if( 'capture_error_queue', capture_error_queue, )
		if not packet.haslayer( ScapyEther ):
			return
		
		raw = bytes( packet )
		ethernet = Ethernet( raw )
		if ethernet.proto not in (8, 0x0800, 2048,):
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
		write_capture_error( capture_error_queue, e, )

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
		throw_if( 'packet_queue', packet_queue, )
		throw_if( 'capture_error_queue', capture_error_queue, )
		throw_if( 'stop_event', stop_event, )
		while not stop_event.is_set( ):
			sniff( prn=lambda packet: scapy_callback( packet, packet_queue, capture_error_queue, ),
				store=False, timeout=1, )
	except Exception as e:
		write_capture_error( capture_error_queue, e, )
		
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
	if (live_thread is not None and live_thread.is_alive( )):
		if st.session_state.live_stop_event.is_set( ):
			st.session_state.capture_error = ('The previous capture thread is still stopping. '
			                                  'Select Start again momentarily.')
		
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

def drain_packet_queue( session_id: str, ) -> int:
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
	throw_if( 'session_id', session_id, )
	packet_count = 0
	while True:
		try:
			record = st.session_state.live_queue.get_nowait( )
			normalized = normalize_packet( record, session_id, )
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
			capture_error = (st.session_state.capture_error_queue.get_nowait( ))
		except queue.Empty:
			break
	
	return capture_error

# ----- Packet Ingestion Utilities -----

def ingest_packets( window_size: int, ) -> int:
	"""
	Ingest available packet records.

	Purpose:
	    Generates demonstration packets or drains the live capture queue, retains the
	    configured rolling window, and increments the packet snapshot version when data
	    changes.

	Args:
	    window_size (int): Maximum number of packet records retained in session state.

	Returns:
	    int: Number of packet records added during the current ingestion cycle.
	"""
	throw_if( 'window_size', window_size, )
	if not st.session_state.running:
		return 0
	
	packet_count = 0
	if st.session_state.capture_mode == 'Demo / Replay':
		packet_count = random.randint( 5, 15, )
		
		for _ in range( packet_count ):
			packet = generate_demo_packet( st.session_state.session_id )
			st.session_state.packets.append( packet )
	
	elif (st.session_state.capture_mode == 'Live (Scapy)' and SCAPY_AVAILABLE):
		packet_count = drain_packet_queue( st.session_state.session_id )
		st.session_state.captured_packet_count += (packet_count)
	
	capture_error = drain_capture_errors( )
	if capture_error:
		st.session_state.capture_error = capture_error
		st.session_state.running = False
		stop_capture_thread( )
	
	st.session_state.packets = (st.session_state.packets[ -window_size: ])
	if packet_count > 0:
		st.session_state.packet_version += 1
	
	return packet_count

def create_packet_snapshot( packets: List[ Dict ], proto_filter: List[ str ],
	port_range: tuple[ int, int ], ) -> pd.DataFrame:
	"""
	Create a filtered packet snapshot.

	Purpose:
	    Converts retained packet records into a typed DataFrame and applies the active
	    protocol and destination-port filters without modifying session-state records.

	Args:
	    packets (List[Dict]): Retained normalized packet records.
	    proto_filter (List[str]): Protocol values included in the snapshot.
	    port_range (tuple[int, int]): Inclusive destination-port range.

	Returns:
	    pd.DataFrame: Filtered packet snapshot.
	"""
	throw_if( 'packets', packets, )
	throw_if( 'proto_filter', proto_filter, )
	throw_if( 'port_range', port_range, )
	df_packets = pd.DataFrame( packets )
	if df_packets.empty:
		return df_packets
	
	df_packets[ 'timestamp' ] = pd.to_datetime( df_packets[ 'timestamp' ], errors='coerce', )
	df_packets = df_packets[ df_packets[ 'protocol' ].isin( proto_filter ) ]
	df_packets = df_packets[ df_packets[ 'dst_port' ].isna( ) | (
			(df_packets[ 'dst_port' ] >= port_range[ 0 ]) & (
			df_packets[ 'dst_port' ] <= port_range[ 1 ])) ]
	
	return df_packets.copy( )

# ----- Visualization Helpers -------

def configure_figure( figure: go.Figure, height: int, show_legend: bool = True, ) -> go.Figure:
	"""
	Configure a Plotly figure.

	Purpose:
	    Applies common dark-mode typography, margins, grid styling, legend placement,
	    stable rendering behavior, and responsive dimensions across all network
	    visualizations.

	Args:
	    figure (go.Figure): Plotly figure to configure.
	    height (int): Rendered figure height in pixels.
	    show_legend (bool): Indicates whether the figure legend is displayed.

	Returns:
	    go.Figure: Configured Plotly figure.
	"""
	throw_if( 'figure', figure, )
	
	throw_if( 'height', height, )
	
	figure.update_layout( height=height, margin={ 'l': 18, 'r': 18, 't': 52, 'b': 24, },
		paper_bgcolor=cfg.PANEL_BACKGROUND, plot_bgcolor=cfg.PANEL_BACKGROUND,
		font={ 'color': cfg.TEXT_COLOR, 'family': 'Arial, sans-serif', 'size': 12, },
		title={ 'font': { 'color': cfg.TEXT_COLOR, 'size': 16, }, 'x': 0.02, 'xanchor': 'left', },
		hoverlabel={ 'bgcolor': '#252525', 'bordercolor': cfg.BORDER_COLOR,
			'font': { 'color': cfg.TEXT_COLOR, }, },
		legend={ 'orientation': 'h', 'yanchor': 'bottom', 'y': 1.02, 'xanchor': 'right', 'x': 1,
			'bgcolor': 'rgba( 0, 0, 0, 0 )', }, showlegend=show_legend,
		transition={ 'duration': 0, }, )
	
	figure.update_xaxes( showgrid=True, gridcolor=cfg.GRID_COLOR, zeroline=False,
		linecolor=cfg.BORDER_COLOR, tickfont={ 'color': cfg.MUTED_TEXT_COLOR, },
		title_font={ 'color': cfg.MUTED_TEXT_COLOR, }, )
	
	figure.update_yaxes( showgrid=True, gridcolor=cfg.GRID_COLOR, zeroline=False,
		linecolor=cfg.BORDER_COLOR, tickfont={ 'color': cfg.MUTED_TEXT_COLOR, },
		title_font={ 'color': cfg.MUTED_TEXT_COLOR, }, )
	
	return figure

def create_protocol_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the protocol-composition figure.

	Purpose:
	    Displays packet counts and percentage share for each protocol in a compact donut
	    visualization with deterministic protocol ordering.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Protocol-composition donut chart.
	"""
	throw_if( 'df_packets', df_packets, )
	
	df_protocols = (
		df_packets.groupby( 'protocol', dropna=False, ).size( ).rename( 'packets' ).reset_index( ))
	
	df_protocols[ 'protocol' ] = pd.Categorical( df_protocols[ 'protocol' ],
		categories=cfg.PROTOCOL_ORDER, ordered=True, )
	df_protocols = (df_protocols.sort_values( 'protocol' ).dropna( subset=[ 'protocol' ] ))
	figure = go.Figure( data=[
		go.Pie( labels=df_protocols[ 'protocol' ], values=df_protocols[ 'packets' ], hole=0.62,
			sort=False, direction='clockwise', textinfo='label+percent', textposition='outside',
			marker={ 'colors': [ cfg.PROTOCOL_COLORS.get( str( protocol ), cfg.PURPLE, ) for protocol in
				df_protocols[ 'protocol' ] ], 'line': { 'color': cfg.PANEL_BACKGROUND, 'width': 3,
			}, },
			hovertemplate=('<b>%{label}</b><br>'
			               'Packets: %{value:,}<br>'
			               'Share: %{percent}'
			               '<extra></extra>'), ) ] )
	
	figure.add_annotation( text=(f'<b>{len( df_packets ):,}</b>'
	                             '<br><span>Packets</span>'), x=0.5, y=0.5, showarrow=False,
		font={ 'color': cfg.TEXT_COLOR, 'size': 16, }, )
	
	figure.update_layout( title='Protocol Composition', uirevision='protocol-composition', )
	
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_traffic_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the traffic-over-time figure.

	Purpose:
	    Displays packets per second by protocol across a fixed rolling time window using
	    an interactive stacked-area chart.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Protocol-level packet traffic over time.
	"""
	throw_if( 'df_packets', df_packets, )
	df_time = df_packets.copy( )
	df_time[ 'timestamp' ] = pd.to_datetime( df_time[ 'timestamp' ], errors='coerce', )
	df_time = df_time.dropna( subset=[ 'timestamp', 'protocol', ] )
	
	if df_time.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	current_time = df_time[ 'timestamp' ].max( )
	start_time = (current_time - pd.Timedelta( seconds=cfg.TRAFFIC_WINDOW_SECONDS ))
	df_time = df_time[ df_time[ 'timestamp' ] >= start_time ]
	
	df_time = (
		df_time.set_index( 'timestamp' ).groupby( 'protocol' ).resample( '1s' ).size( ).rename(
			'packets' ).reset_index( ))
	
	figure = px.area( df_time, x='timestamp', y='packets', color='protocol',
		color_discrete_map=cfg.PROTOCOL_COLORS, category_orders={ 'protocol': cfg.PROTOCOL_ORDER, }, )
	
	figure.update_traces( line={ 'width': 2, }, hovertemplate=('<b>%{fullData.name}</b><br>'
	                                                           'Time: %{x|%H:%M:%S}<br>'
	                                                           'Packets: %{y:,}'
	                                                           '<extra></extra>'), )
	
	figure.update_layout( title='Traffic Over Time', xaxis_title='Time — Last 60 Seconds',
		yaxis_title='Packets / Second', hovermode='x unified', uirevision='traffic-over-time', )
	
	figure.update_xaxes( range=[ start_time, current_time, ], )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, True, )

def create_throughput_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the network-throughput figure.

	Purpose:
	    Aggregates packet lengths into one-second intervals and displays raw network
	    throughput alongside a rolling average for the active sixty-second window.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Kilobytes-per-second throughput chart.
	"""
	throw_if( 'df_packets', df_packets, )
	df_throughput = df_packets.copy( )
	df_throughput[ 'timestamp' ] = pd.to_datetime( df_throughput[ 'timestamp' ], errors='coerce', )
	df_throughput[ 'length' ] = pd.to_numeric( df_throughput[ 'length' ], errors='coerce', )
	df_throughput = df_throughput.dropna( subset=[ 'timestamp', 'length', ] )
	
	if df_throughput.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	current_time = df_throughput[ 'timestamp' ].max( )
	start_time = (current_time - pd.Timedelta( seconds=cfg.TRAFFIC_WINDOW_SECONDS ))
	df_throughput = df_throughput[ df_throughput[ 'timestamp' ] >= start_time ]
	
	df_throughput = (
		df_throughput.set_index( 'timestamp' )[ 'length' ].resample( '1s' ).sum( ).rename(
			'bytes_per_second' ).to_frame( ))
	
	full_index = pd.date_range( start=start_time.floor( 's' ), end=current_time.ceil( 's' ),
		freq='1s', )
	
	df_throughput = (df_throughput.reindex( full_index, fill_value=0, ).rename_axis(
		'timestamp' ).reset_index( ))
	
	df_throughput[ 'kilobytes_per_second' ] = (df_throughput[ 'bytes_per_second' ] / 1024.0)
	df_throughput[ 'rolling_average' ] = (
		df_throughput[ 'kilobytes_per_second' ].rolling( window=cfg.THROUGHPUT_ROLLING_SECONDS,
			min_periods=1, ).mean( ))
	
	figure = go.Figure( )
	
	figure.add_trace(
		go.Scatter( x=df_throughput[ 'timestamp' ], y=df_throughput[ 'kilobytes_per_second' ],
			name='Throughput', mode='lines', line={ 'color': cfg.ACCENT_BLUE, 'width': 1.5, },
			fill='tozeroy', fillcolor='rgba( 0, 120, 252, 0.16 )',
			hovertemplate=('<b>Throughput</b><br>'
			               'Time: %{x|%H:%M:%S}<br>'
			               'Rate: %{y:,.2f} KB/s'
			               '<extra></extra>'), ) )
	
	figure.add_trace(
		go.Scatter( x=df_throughput[ 'timestamp' ], y=df_throughput[ 'rolling_average' ],
			name=f'{cfg.THROUGHPUT_ROLLING_SECONDS}-Second Average', mode='lines',
			line={ 'color': cfg.CYAN, 'width': 3, }, hovertemplate=('<b>Rolling Average</b><br>'
			                                                    'Time: %{x|%H:%M:%S}<br>'
			                                                    'Rate: %{y:,.2f} KB/s'
			                                                    '<extra></extra>'), ) )
	
	figure.update_layout( title='Network Throughput', xaxis_title='Time — Last 60 Seconds',
		yaxis_title='Kilobytes / Second', hovermode='x unified', uirevision='network-throughput', )
	
	figure.update_xaxes( range=[ start_time, current_time, ], )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, True, )

def create_endpoint_figure( df_packets: pd.DataFrame, column_name: str, title: str, ) -> go.Figure:
	"""
	Create a ranked endpoint figure.

	Purpose:
	    Displays the most active source or destination IP addresses as a deterministic
	    ranked horizontal bar chart.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.
	    column_name (str): Endpoint column used to calculate packet counts.
	    title (str): Figure title.

	Returns:
	    go.Figure: Ranked endpoint activity chart.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'column_name', column_name, )
	throw_if( 'title', title, )
	
	df_endpoints = (
		df_packets.dropna( subset=[ column_name ] ).groupby( column_name ).size( ).rename(
			'packets' ).reset_index( ).nlargest( 10, 'packets', ).sort_values(
			[ 'packets', column_name, ], ascending=[ True, True, ], ))
	
	maximum_packets = (
		max( int( df_endpoints[ 'packets' ].max( ) ), 1, ) if not df_endpoints.empty else 1)
	
	category_order = (df_endpoints[ column_name ].astype( str ).tolist( ))
	
	figure = go.Figure( data=[
		go.Bar( x=df_endpoints[ 'packets' ], y=df_endpoints[ column_name ], orientation='h',
			marker={ 'color': df_endpoints[ 'packets' ],
				'colorscale': [ [ 0.0, '#153E75', ], [ 0.5, cfg.ACCENT_BLUE, ], [ 1.0, cfg.CYAN, ], ],
				'line': { 'color': 'rgba( 255, 255, 255, 0.12 )', 'width': 1, }, },
			text=df_endpoints[ 'packets' ], textposition='outside', cliponaxis=False,
			hovertemplate=('<b>%{y}</b><br>'
			               'Packets: %{x:,}'
			               '<extra></extra>'), ) ] )
	
	figure.update_layout( title=title, xaxis_title='Packet Count', yaxis_title='',
		uirevision=title, )
	
	figure.update_xaxes( range=[ 0, maximum_packets * 1.18, ], )
	figure.update_yaxes( categoryorder='array', categoryarray=category_order, )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_port_heatmap( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the destination-port heatmap.

	Purpose:
	    Displays packet concentration across the most active destination ports and
	    transport protocols using stable protocol and port ordering.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Destination-port activity heatmap.
	"""
	throw_if( 'df_packets', df_packets, )
	df_ports = df_packets.dropna( subset=[ 'dst_port', 'protocol', ], ).copy( )
	if df_ports.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	df_ports[ 'dst_port' ] = pd.to_numeric( df_ports[ 'dst_port' ], errors='coerce', )
	df_ports = df_ports.dropna( subset=[ 'dst_port' ] )
	df_ports[ 'dst_port' ] = (df_ports[ 'dst_port' ].astype( int ))
	top_ports = (df_ports.groupby( 'dst_port' ).size( ).nlargest( 15 ).index)
	df_ports = df_ports[ df_ports[ 'dst_port' ].isin( top_ports ) ]
	df_heatmap = (df_ports.groupby( [ 'protocol', 'dst_port', ] ).size( ).rename(
		'packets' ).reset_index( ).pivot( index='protocol', columns='dst_port',
		values='packets', ).fillna( 0 ))
	
	protocol_rows = [ protocol for protocol in cfg.PROTOCOL_ORDER if protocol in df_heatmap.index ]
	df_heatmap = df_heatmap.reindex( index=protocol_rows )
	df_heatmap = df_heatmap[ sorted( df_heatmap.columns ) ]
	maximum_packets = max( float( df_heatmap.to_numpy( ).max( ) ), 1.0, )
	figure = go.Figure( data=[
		go.Heatmap( z=df_heatmap.values, x=[ str( port ) for port in df_heatmap.columns ],
			y=df_heatmap.index, zmin=0, zmax=maximum_packets,
			colorscale=[ [ 0.0, '#101820', ], [ 0.25, '#153E75', ], [ 0.55, cfg.ACCENT_BLUE, ],
				[ 0.8, cfg.CYAN, ], [ 1.0, '#D9F8FF', ], ],
			colorbar={ 'title': 'Packets', 'thickness': 12, 'outlinewidth': 0, },
			hovertemplate=('<b>%{y}</b><br>'
			               'Destination Port: %{x}<br>'
			               'Packets: %{z:,}'
			               '<extra></extra>'), ) ] )
	
	figure.update_layout( title='Destination Port Activity', xaxis_title='Destination Port',
		yaxis_title='Protocol', uirevision='destination-port-activity', )
	
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_packet_size_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the packet-size distribution figure.

	Purpose:
	    Displays the frequency distribution of packet lengths with fixed bin boundaries
	    and average and median reference markers.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Packet-size histogram.
	"""
	throw_if( 'df_packets', df_packets, )
	df_sizes = df_packets.dropna( subset=[ 'length', 'protocol', ], ).copy( )
	df_sizes[ 'length' ] = pd.to_numeric( df_sizes[ 'length' ], errors='coerce', )
	df_sizes = df_sizes.dropna( subset=[ 'length' ] )
	figure = go.Figure( )
	for protocol in cfg.PROTOCOL_ORDER:
		df_protocol_sizes = df_sizes[ df_sizes[ 'protocol' ] == protocol ]
		
		if df_protocol_sizes.empty:
			continue
		
		figure.add_trace(
			go.Histogram( x=df_protocol_sizes[ 'length' ], name=protocol, opacity=0.72,
				marker={ 'color': cfg.PROTOCOL_COLORS[ protocol ], },
				xbins={ 'start': 0, 'end': 1600, 'size': 50, },
				hovertemplate=(f'<b>{protocol}</b><br>'
				               'Packet Size: %{x:,} bytes<br>'
				               'Frequency: %{y:,}'
				               '<extra></extra>'), ) )
	
	if not df_sizes.empty:
		average_size = df_sizes[ 'length' ].mean( )
		median_size = df_sizes[ 'length' ].median( )
		figure.add_vline( x=average_size, line_width=2, line_dash='dash', line_color=cfg.RED,
			annotation_text=f'Average {average_size:,.0f}', annotation_position='top right', )
		
		figure.add_vline( x=median_size, line_width=2, line_dash='dot', line_color=cfg.AMBER,
			annotation_text=f'Median {median_size:,.0f}', annotation_position='top left', )
	
	figure.update_layout( title='Packet Size Distribution', xaxis_title='Packet Size — Bytes',
		yaxis_title='Frequency', barmode='overlay', bargap=0.04,
		uirevision='packet-size-distribution', )
	
	figure.update_xaxes( range=[ 0, 1600, ], )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, True, )

def create_flow_figure( df_packets: pd.DataFrame, ) -> go.Figure:
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
	throw_if( 'df_packets', df_packets, )
	df_flows = (df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] ).groupby(
		[ 'src_ip', 'dst_ip', ] ).size( ).rename( 'packets' ).reset_index( ).sort_values(
		[ 'packets', 'src_ip', 'dst_ip', ], ascending=[ False, True, True, ], ).head( 20 ))
	
	source_values = sorted( df_flows[ 'src_ip' ].astype( str ).unique( ) )
	destination_values = sorted( df_flows[ 'dst_ip' ].astype( str ).unique( ) )
	source_labels = [ f'Source: {value}' for value in source_values ]
	destination_labels = [ f'Destination: {value}' for value in destination_values ]
	labels = (source_labels + destination_labels)
	label_indexes = { label: index for index, label in enumerate( labels ) }
	source_indexes = [ label_indexes[ f'Source: {value}' ] for value in df_flows[ 'src_ip' ] ]
	destination_indexes = [ label_indexes[ f'Destination: {value}' ] for value in
		df_flows[ 'dst_ip' ] ]
	
	figure = go.Figure( data=[ go.Sankey( arrangement='snap',
		node={ 'pad': 18, 'thickness': 16, 'line': { 'color': cfg.BORDER_COLOR, 'width': 1, },
			'label': labels,
			'color': [ cfg.ACCENT_BLUE if label.startswith( 'Source:' ) else cfg.GREEN for label in
				labels ], 'hovertemplate': ('<b>%{label}</b><br>'
			                                'Total Packets: %{value:,}'
			                                '<extra></extra>'), },
		link={ 'source': source_indexes, 'target': destination_indexes,
			'value': df_flows[ 'packets' ], 'color': 'rgba( 0, 120, 252, 0.28 )',
			'hovertemplate': ('%{source.label}<br>'
			                  '→ %{target.label}<br>'
			                  'Packets: %{value:,}'
			                  '<extra></extra>'), }, ) ] )
	
	figure.update_layout( title='Network Flow Relationships',
		uirevision='network-flow-relationships', )
	
	return configure_figure( figure, cfg.FLOW_CHART_HEIGHT, False, )

def create_tcp_flag_heatmap( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the TCP flag activity heatmap.

	Purpose:
	    Expands combined TCP flag values into individual flag observations and displays
	    their frequency across the most active destination ports.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: TCP flag-by-destination-port heatmap.
	"""
	throw_if( 'df_packets', df_packets, )
	df_tcp = df_packets[ df_packets[ 'protocol' ] == 'TCP' ].copy( )
	df_tcp = df_tcp.dropna( subset=[ 'dst_port', 'flags', ] )
	if df_tcp.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	df_tcp[ 'dst_port' ] = pd.to_numeric( df_tcp[ 'dst_port' ], errors='coerce', )
	df_tcp = df_tcp.dropna( subset=[ 'dst_port' ] )
	df_tcp[ 'dst_port' ] = (df_tcp[ 'dst_port' ].astype( int ))
	top_ports = (df_tcp.groupby( 'dst_port' ).size( ).nlargest( cfg.TOP_FLAG_PORT_LIMIT ).index)
	df_tcp = df_tcp[ df_tcp[ 'dst_port' ].isin( top_ports ) ]
	flag_records: List[ Dict ] = [ ]
	for _, packet in df_tcp.iterrows( ):
		flag_value = str( packet[ 'flags' ] ).upper( )
		
		for flag in cfg.TCP_FLAG_ORDER:
			if flag in flag_value:
				flag_records.append( { 'flag': flag, 'dst_port': int( packet[ 'dst_port' ] ), } )
	
	df_flags = pd.DataFrame( flag_records )
	if df_flags.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	df_flag_matrix = (df_flags.groupby( [ 'flag', 'dst_port', ] ).size( ).rename(
		'packets' ).reset_index( ).pivot( index='flag', columns='dst_port',
		values='packets', ).fillna( 0 ))
	
	flag_rows = [ flag for flag in cfg.TCP_FLAG_ORDER if flag in df_flag_matrix.index ]
	df_flag_matrix = df_flag_matrix.reindex( index=flag_rows )
	df_flag_matrix = df_flag_matrix[ sorted( df_flag_matrix.columns ) ]
	maximum_packets = max( float( df_flag_matrix.to_numpy( ).max( ) ), 1.0, )
	
	figure = go.Figure( data=[
		go.Heatmap( z=df_flag_matrix.values, x=[ str( port ) for port in df_flag_matrix.columns ],
			y=df_flag_matrix.index, zmin=0, zmax=maximum_packets,
			colorscale=[ [ 0.0, '#101820', ], [ 0.25, '#3B174F', ], [ 0.55, cfg.PURPLE, ],
				[ 0.8, cfg.AMBER, ], [ 1.0, '#FFF2C2', ], ],
			colorbar={ 'title': 'Packets', 'thickness': 12, 'outlinewidth': 0, },
			hovertemplate=('<b>%{y}</b><br>'
			               'Destination Port: %{x}<br>'
			               'Packets: %{z:,}'
			               '<extra></extra>'), ) ] )
	
	figure.update_layout( title='TCP Flag Activity', xaxis_title='Destination Port',
		yaxis_title='TCP Flag', uirevision='tcp-flag-activity', )
	
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_traffic_matrix_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the source-destination traffic matrix.

	Purpose:
	    Displays packet concentration between the most active source and destination IP
	    addresses to reveal fan-out, fan-in, and concentrated communication patterns.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Source-by-destination packet-count heatmap.
	"""
	throw_if( 'df_packets', df_packets, )
	
	df_matrix = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] ).copy( )
	if df_matrix.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	top_sources = (df_matrix.groupby( 'src_ip' ).size( ).nlargest( cfg.TOP_MATRIX_SOURCE_LIMIT ).index)
	
	top_destinations = (
		df_matrix.groupby( 'dst_ip' ).size( ).nlargest( cfg.TOP_MATRIX_DESTINATION_LIMIT ).index)
	
	df_matrix = df_matrix[
		df_matrix[ 'src_ip' ].isin( top_sources ) & df_matrix[ 'dst_ip' ].isin( top_destinations
		) ]
	
	df_matrix = (df_matrix.groupby( [ 'src_ip', 'dst_ip', ] ).size( ).rename(
		'packets' ).reset_index( ).pivot( index='src_ip', columns='dst_ip',
		values='packets', ).fillna( 0 ))
	
	df_matrix = df_matrix.reindex( index=sorted( df_matrix.index.astype( str ) ) )
	df_matrix = df_matrix.reindex( columns=sorted( df_matrix.columns.astype( str ) ) )
	maximum_packets = max( float( df_matrix.to_numpy( ).max( ) ), 1.0, )
	
	figure = go.Figure( data=[
		go.Heatmap( z=df_matrix.values, x=df_matrix.columns, y=df_matrix.index, zmin=0,
			zmax=maximum_packets,
			colorscale=[ [ 0.0, '#101820', ], [ 0.25, '#153E75', ], [ 0.55, cfg.ACCENT_BLUE, ],
				[ 0.8, cfg.GREEN, ], [ 1.0, '#D7FFF7', ], ],
			colorbar={ 'title': 'Packets', 'thickness': 12, 'outlinewidth': 0, },
			hovertemplate=('<b>Source:</b> %{y}<br>'
			               '<b>Destination:</b> %{x}<br>'
			               'Packets: %{z:,}'
			               '<extra></extra>'), ) ] )
	
	figure.update_layout( title='Source–Destination Traffic Matrix', xaxis_title='Destination IP',
		yaxis_title='Source IP', uirevision='source-destination-traffic-matrix', )
	
	figure.update_xaxes( tickangle=-35, )
	
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_port_activity_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the destination-port activity figure.

	Purpose:
	    Displays one-second packet activity for the five most active destination ports
	    across the current sixty-second analysis window.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Destination-port packet activity over time.
	"""
	throw_if( 'df_packets', df_packets, )
	df_ports = df_packets.dropna( subset=[ 'timestamp', 'dst_port', ] ).copy( )
	df_ports[ 'timestamp' ] = pd.to_datetime( df_ports[ 'timestamp' ], errors='coerce', )
	df_ports[ 'dst_port' ] = pd.to_numeric( df_ports[ 'dst_port' ], errors='coerce', )
	df_ports = df_ports.dropna( subset=[ 'timestamp', 'dst_port', ] )
	
	if df_ports.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	
	df_ports[ 'dst_port' ] = (df_ports[ 'dst_port' ].astype( int ))
	current_time = df_ports[ 'timestamp' ].max( )
	start_time = (current_time - pd.Timedelta( seconds=cfg.TRAFFIC_WINDOW_SECONDS ))
	df_ports = df_ports[ df_ports[ 'timestamp' ] >= start_time ]
	
	top_ports = (
		df_ports.groupby( 'dst_port' ).size( ).nlargest( cfg.TOP_PORT_TREND_LIMIT ).index.tolist( ))
	
	figure = go.Figure( )
	for destination_port in sorted( top_ports ):
		df_port = df_ports[ df_ports[ 'dst_port' ] == destination_port ]
		
		df_port = (df_port.set_index( 'timestamp' ).resample( '1s' ).size( ).rename(
			'packets' ).to_frame( ).reindex(
			pd.date_range( start=start_time.floor( 's' ), end=current_time.ceil( 's' ),
				freq='1s', ), fill_value=0, ).rename_axis( 'timestamp' ).reset_index( ))
		
		figure.add_trace( go.Scatter( x=df_port[ 'timestamp' ], y=df_port[ 'packets' ],
			name=f'Port {destination_port}', mode='lines', line={ 'width': 2, },
			hovertemplate=(f'<b>Port {destination_port}</b><br>'
			               'Time: %{x|%H:%M:%S}<br>'
			               'Packets: %{y:,}'
			               '<extra></extra>'), ) )
	
	figure.update_layout( title='Port Activity Over Time', xaxis_title='Time — Last 60 Seconds',
		yaxis_title='Packets / Second', hovermode='x unified',
		uirevision='port-activity-over-time', )
	
	figure.update_xaxes( range=[ start_time, current_time, ], )
	
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, True, )

def create_fan_out_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the source fan-out figure.

	Purpose:
	    Ranks source IP addresses by the number of unique destination IP addresses each
	    source contacted within the current packet window.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Source fan-out ranking.
	"""
	throw_if( 'df_packets', df_packets, )
	
	df_fan_out = (df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] ).groupby( 'src_ip' )[
		'dst_ip' ].nunique( ).rename( 'unique_destinations' ).reset_index( ).sort_values(
		[ 'unique_destinations', 'src_ip', ], ascending=[ False, True, ], ).head(
		cfg.TOP_ENDPOINT_CONNECTIVITY_LIMIT ).sort_values( [ 'unique_destinations', 'src_ip', ],
		ascending=[ True, True, ], ))
	
	maximum_value = (
		max( int( df_fan_out[ 'unique_destinations' ].max( ) ), 1, ) if not df_fan_out.empty
		else 1)
	
	figure = go.Figure( data=[
		go.Bar( x=df_fan_out[ 'unique_destinations' ], y=df_fan_out[ 'src_ip' ], orientation='h',
			marker={ 'color': cfg.ACCENT_BLUE, }, text=df_fan_out[ 'unique_destinations' ],
			textposition='outside', cliponaxis=False, hovertemplate=('<b>%{y}</b><br>'
			                                                         'Unique Destinations: %{x:,}'
			                                                         '<extra></extra>'), ) ] )
	
	figure.update_layout( title='Source Fan-Out', xaxis_title='Unique Destination IPs',
		yaxis_title='Source IP', uirevision='source-fan-out', )
	
	figure.update_xaxes( range=[ 0, maximum_value * 1.18, ], dtick=1, )
	figure.update_yaxes( categoryorder='array', categoryarray=df_fan_out[ 'src_ip' ].tolist( ), )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_fan_in_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the destination fan-in figure.

	Purpose:
	    Ranks destination IP addresses by the number of unique source IP addresses that
	    contacted each destination within the current packet window.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Destination fan-in ranking.
	"""
	throw_if( 'df_packets', df_packets, )
	
	df_fan_in = (df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] ).groupby( 'dst_ip' )[
		'src_ip' ].nunique( ).rename( 'unique_sources' ).reset_index( ).sort_values(
		[ 'unique_sources', 'dst_ip', ], ascending=[ False, True, ], ).head(
		cfg.TOP_ENDPOINT_CONNECTIVITY_LIMIT ).sort_values( [ 'unique_sources', 'dst_ip', ],
		ascending=[ True, True, ], ))
	
	maximum_value = (
		max( int( df_fan_in[ 'unique_sources' ].max( ) ), 1, ) if not df_fan_in.empty else 1)
	
	figure = go.Figure( data=[
		go.Bar( x=df_fan_in[ 'unique_sources' ], y=df_fan_in[ 'dst_ip' ], orientation='h',
			marker={ 'color': cfg.GREEN, }, text=df_fan_in[ 'unique_sources' ], textposition='outside',
			cliponaxis=False, hovertemplate=('<b>%{y}</b><br>'
			                                 'Unique Sources: %{x:,}'
			                                 '<extra></extra>'), ) ] )
	
	figure.update_layout( title='Destination Fan-In', xaxis_title='Unique Source IPs',
		yaxis_title='Destination IP', uirevision='destination-fan-in', )
	
	figure.update_xaxes( range=[ 0, maximum_value * 1.18, ], dtick=1, )
	figure.update_yaxes( categoryorder='array', categoryarray=df_fan_in[ 'dst_ip' ].tolist( ), )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_flow_scatter_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the flow duration-versus-volume figure.

	Purpose:
	    Aggregates packets into five-tuple network flows and compares flow duration with
	    total transferred bytes while encoding protocol and packet count.

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    go.Figure: Flow duration-versus-volume scatter plot.
	"""
	throw_if( 'df_packets', df_packets, )
	df_flows = df_packets.copy( )
	df_flows[ 'timestamp' ] = pd.to_datetime( df_flows[ 'timestamp' ], errors='coerce', )
	df_flows[ 'length' ] = pd.to_numeric( df_flows[ 'length' ], errors='coerce', )
	df_flows = df_flows.dropna( subset=[ 'timestamp', 'length', 'src_ip', 'dst_ip', 'protocol', ] )
	
	if df_flows.empty:
		return configure_figure( go.Figure( ), cfg.FLOW_CHART_HEIGHT, False, )
	
	df_flow_summary = (
		df_flows.groupby( cfg.FLOW_COLUMNS, dropna=False, ).agg( first_seen=('timestamp', 'min'),
			last_seen=('timestamp', 'max'), packet_count=('timestamp', 'size'),
			total_bytes=('length', 'sum'), average_packet_size=('length', 'mean'),
		).reset_index( ))
	
	df_flow_summary[ 'duration_seconds' ] = (
			df_flow_summary[ 'last_seen' ] - df_flow_summary[ 'first_seen' ]).dt.total_seconds( )
	
	df_flow_summary = (df_flow_summary.sort_values( [ 'total_bytes', 'packet_count', ],
		ascending=[ False, False, ], ).head( cfg.FLOW_SCATTER_LIMIT ))
	
	if df_flow_summary.empty:
		return configure_figure( go.Figure( ), cfg.FLOW_CHART_HEIGHT, False, )
	
	maximum_packet_count = max( int( df_flow_summary[ 'packet_count' ].max( ) ), 1, )
	marker_sizes = (12 + (df_flow_summary[ 'packet_count' ] / maximum_packet_count * 28))
	figure = go.Figure( )
	
	for protocol in cfg.PROTOCOL_ORDER:
		protocol_mask = (df_flow_summary[ 'protocol' ] == protocol)
		
		df_protocol_flows = df_flow_summary[ protocol_mask ]
		
		if df_protocol_flows.empty:
			continue
		
		figure.add_trace( go.Scatter( x=df_protocol_flows[ 'duration_seconds' ],
			y=df_protocol_flows[ 'total_bytes' ], name=protocol, mode='markers',
			marker={ 'color': cfg.PROTOCOL_COLORS[ protocol ], 'size': marker_sizes[ protocol_mask ],
				'opacity': 0.72, 'line': { 'color': 'rgba( 255, 255, 255, 0.28 )', 'width': 1,
				}, },
			customdata=df_protocol_flows[
				[ 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'packet_count',
					'average_packet_size', ] ], hovertemplate=('<b>%{fullData.name} Flow</b><br>'
			                                                   'Source: %{customdata[0]}:%{'
			                                                   'customdata[1]}<br>'
			                                                   'Destination: %{customdata[2]}:%{'
			                                                   'customdata[3]}<br>'
			                                                   'Duration: %{x:,.3f} seconds<br>'
			                                                   'Total Bytes: %{y:,.0f}<br>'
			                                                   'Packets: %{customdata[4]:,.0f}<br>'
			                                                   'Average Packet: %{customdata[5]:,'
			                                                   '.1f} bytes'
			                                                   '<extra></extra>'), ) )
	
	figure.update_layout( title='Flow Duration vs. Volume', xaxis_title='Flow Duration — Seconds',
		yaxis_title='Total Bytes', uirevision='flow-duration-versus-volume', )
	
	return configure_figure( figure, cfg.FLOW_CHART_HEIGHT, True, )

def prepare_packet_editor( df_packets: pd.DataFrame, ) -> pd.DataFrame:
	"""
	Prepare packet records for the data editor.

	Purpose:
	    Formats, orders, and limits packet records for read-only display through
	    st.data_editor().

	Args:
	    df_packets (pd.DataFrame): Filtered packet records.

	Returns:
	    pd.DataFrame: Display-ready packet records.
	"""
	throw_if( 'df_packets', df_packets, )
	
	df_editor = df_packets.copy( )
	
	df_editor[ 'timestamp' ] = pd.to_datetime( df_editor[ 'timestamp' ], errors='coerce', )
	
	df_editor[ 'src_port' ] = pd.to_numeric( df_editor[ 'src_port' ], errors='coerce', ).astype(
		'Int64' )
	
	df_editor[ 'dst_port' ] = pd.to_numeric( df_editor[ 'dst_port' ], errors='coerce', ).astype(
		'Int64' )
	
	df_editor[ 'length' ] = pd.to_numeric( df_editor[ 'length' ], errors='coerce', ).astype(
		'Int64' )
	
	df_editor = (
		df_editor.sort_values( 'timestamp', ascending=False, ).head( cfg.PACKET_EDITOR_ROW_LIMIT ))
	
	column_order = [ 'timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'flags',
		'length', 'session', ]
	
	existing_columns = [ column_name for column_name in column_order if
		column_name in df_editor.columns ]
	
	return df_editor[ existing_columns ]

# ==========================================================================================
# Thread State Maintenance
# ==========================================================================================
current_thread = (st.session_state.live_thread)
if (current_thread is not None and not current_thread.is_alive( )):
	st.session_state.live_thread = None

capture_error = drain_capture_errors( )
if capture_error:
	st.session_state.capture_error = capture_error
	st.session_state.running = False
	stop_capture_thread( )

# ------------------------------------------------------------------------------------------
# Streamlit Configuration
# ------------------------------------------------------------------------------------------
st.set_page_config( page_title='Sloppy Joe', page_icon=cfg.ICON, layout='wide', )
st.logo( cfg.LOGO, size='large', )


# ==========================================================================================
#  Header & Sidebar Controls
# ==========================================================================================
with st.container( ):
	col_logo, col_title = st.columns( [ 5, 1, ] )
	with col_logo:
		st.markdown( '### Network Analyzer' )
		st.caption( 'Packet Metadata • Flow Analytics • Protocol Intelligence' )
	
	with col_title:
		st.caption( '' )
		
with st.sidebar:
	# ----------------------------------------------------
	# Expander - Sidebar Controls
	# ----------------------------------------------------
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	with st.expander( label='Controls', expanded=True ):
		mode = st.radio( ' ', options=[ 'Demo / Replay', 'Live (Scapy)', ], )
		if (mode == 'Live (Scapy)' and not SCAPY_AVAILABLE):
			st.error( 'Scapy is not available. Install Scapy and run the application with '
			          'administrator/root privileges.' )
			
			if SCAPY_IMPORT_ERROR:
				st.caption( SCAPY_IMPORT_ERROR )
		
		st.divider( )
		
		c1, c2 = st.columns( 2  )
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
		
		st.divider( )
		
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
	
	# ----------------------------------------------------
	# Expander - Sidebar Filters
	# ----------------------------------------------------
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=False, )
	with st.expander( label='Filters', expanded=True ):
		proto_filter = st.multiselect( 'Protocols', options=cfg.PROTOCOL_ORDER, default=cfg.PROTOCOL_ORDER, )
		st.divider( )
		port_range = st.slider( 'Destination Port Range', 0, 65535, (0, 65535,), )
		st.divider( )
		window_size = st.slider( 'Rolling Window (Packets)', 50, 2000, 500, 50, )

# ----- Real-Time Summary Fragment ------
@st.fragment( run_every=REALTIME_REFRESH_INTERVAL )
def render_realtime_summary( protocols: List[ str ], destination_ports: tuple[ int, int ],
	packet_window_size: int, ) -> None:
	"""
	Render the real-time dashboard summary.

	Purpose:
	    Ingests newly available packet records and refreshes executive metrics, packet-rate
	    activity, and network-throughput analysis independently from the application shell.

	Args:
	    protocols (List[str]): Protocol values included in the rendered snapshot.
	    destination_ports (tuple[int, int]): Inclusive destination-port range.
	    packet_window_size (int): Maximum number of retained packet records.

	Returns:
	    None: This function renders Streamlit components.
	"""
	throw_if( 'protocols', protocols, )
	throw_if( 'destination_ports', destination_ports, )
	throw_if( 'packet_window_size', packet_window_size, )
	ingest_packets( packet_window_size )
	df_packets = create_packet_snapshot( st.session_state.packets, protocols, destination_ports, )
	with st.container( ):
		m1, m2, m3, m4, m5 = st.columns( 5 )
		packet_count = len( df_packets )
		source_count = (df_packets[ 'src_ip' ].nunique( ) if not df_packets.empty else 0)
		destination_count = (df_packets[ 'dst_ip' ].nunique( ) if not df_packets.empty else 0)
		average_packet_size = (int( df_packets[ 'length' ].mean( ) ) if not df_packets.empty
		                       else 0)
		
		protocol_count = (df_packets[ 'protocol' ].nunique( ) if not df_packets.empty else 0)
		m1.metric( 'Packets', f'{packet_count:,}', )
		m2.metric( 'Unique Src IPs', f'{source_count:,}', )
		m3.metric( 'Unique Dst IPs', f'{destination_count:,}', )
		m4.metric( 'Avg Packet Size', f'{average_packet_size:,} B', )
		m5.metric( 'Protocols Seen', f'{protocol_count:,}', )
		
		st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	traffic_column, throughput_column = st.columns( 2, gap='medium', border=True )
	with traffic_column:
		if not df_packets.empty:
			figure_traffic = create_traffic_figure( df_packets )
			st.plotly_chart( figure_traffic, use_container_width=True, config=cfg.CHART_CONFIG,
				key='traffic-over-time-chart', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No time-series data is available.' )
	
	with throughput_column:
		df_throughput_packets = (df_packets.dropna(
			subset=[ 'timestamp', 'length', ] ) if not df_packets.empty else pd.DataFrame( ))
		
		if not df_throughput_packets.empty:
			figure_throughput = create_throughput_figure( df_packets )
			st.plotly_chart( figure_throughput, use_container_width=True, config=cfg.CHART_CONFIG,
				key='network-throughput-chart', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No throughput data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

render_realtime_summary( proto_filter, port_range, window_size, )

# -----  Packet Analysis Fragment  -----

@st.fragment( run_every=ANALYSIS_REFRESH_INTERVAL )
def render_packet_analysis( protocols: List[ str ], destination_ports: tuple[ int, int ], ) -> None:
	"""
	Render packet-level analytical visualizations.

	Purpose:
	    Refreshes protocol composition, endpoint rankings, packet-size distribution, and
	    the read-only packet editor independently from real-time ingestion.

	Args:
	    protocols (List[str]): Protocol values included in the rendered snapshot.
	    destination_ports (tuple[int, int]): Inclusive destination-port range.

	Returns:
	    None: This function renders Streamlit components.
	"""
	throw_if( 'protocols', protocols, )
	throw_if( 'destination_ports', destination_ports, )
	df_packets = create_packet_snapshot( st.session_state.packets, protocols, destination_ports, )
	if not df_packets.empty:
		protocol_column, size_column = st.columns( [ 0.82, 1.38, ], gap='medium', border=True )
		with protocol_column:
			figure_protocol = create_protocol_figure( df_packets )
			st.plotly_chart( figure_protocol, use_container_width=True, config=cfg.CHART_CONFIG,
				key='protocol-composition-chart', )
		
		with size_column:
			figure_sizes = create_packet_size_figure( df_packets )
			st.plotly_chart( figure_sizes, use_container_width=True, config=cfg.CHART_CONFIG,
				key='packet-size-histogram', )
		
		st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
		source_column, destination_column = st.columns( 2, gap='medium', border=True )
		with source_column:
			figure_sources = create_endpoint_figure( df_packets, 'src_ip', 'Top Source IP Addresses', )
			st.plotly_chart( figure_sources, use_container_width=True, config=cfg.CHART_CONFIG,
				key='top-source-chart', )
		
		with destination_column:
			figure_destinations = create_endpoint_figure( df_packets, 'dst_ip',
				'Top Destination IP Addresses', )
			
			st.plotly_chart( figure_destinations, use_container_width=True, config=cfg.CHART_CONFIG,
				key='top-destination-chart', )
		
		st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	else:
		empty_left, empty_right = st.columns( 2, border=True )
		with empty_left:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No protocol data is available.' )
		
		with empty_right:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No packet-size data is available.' )
		
		st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	st.markdown( """
		<div class="sloppy-section-title">Live Packet Stream</div>
		<div class="sloppy-section-caption">
			Most recent normalized packets matching the active protocol and port filters.
		</div>
		""", unsafe_allow_html=True, )
	
	if not df_packets.empty:
		df_packet_editor = prepare_packet_editor( df_packets )
		st.data_editor( df_packet_editor, disabled=True, hide_index=True, use_container_width=True,
			height=cfg.PACKET_EDITOR_HEIGHT,
			column_order=[ 'timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
				'flags', 'length', 'session', ], column_config={
				'timestamp': st.column_config.DatetimeColumn( 'Timestamp',
					help='UTC packet-capture time.', format='HH:mm:ss.SSS', ),
				'protocol': st.column_config.TextColumn( 'Protocol',
					help='Detected transport or control protocol.', width='small', ),
				'src_ip': st.column_config.TextColumn( 'Source IP',
					help='Packet source IPv4 address.', width='medium', ),
				'src_port': st.column_config.NumberColumn( 'Source Port',
					help='Source transport-layer port.', format='%d', width='small', ),
				'dst_ip': st.column_config.TextColumn( 'Destination IP',
					help='Packet destination IPv4 address.', width='medium', ),
				'dst_port': st.column_config.NumberColumn( 'Destination Port',
					help='Destination transport-layer port.', format='%d', width='small', ),
				'flags': st.column_config.TextColumn( 'Flags',
					help='TCP flags or ICMP message type.', width='medium', ),
				'length': st.column_config.NumberColumn( 'Packet Size',
					help='Captured packet length in bytes.', format='%d bytes', width='small', ),
				'session': st.column_config.TextColumn( 'Session',
					help='Capture-session identifier.', width='medium', ), },
			key='live-packet-editor', )
	else:
		with st.container( height=cfg.PACKET_EDITOR_HEIGHT, border=True ):
			st.info( 'Waiting for packets…' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

render_packet_analysis( proto_filter, port_range, )

# ----- Flow Analysis Fragment -----

@st.fragment( run_every=FLOW_REFRESH_INTERVAL )
def render_flow_analysis( protocols: List[ str ], destination_ports: tuple[ int, int ], ) -> None:
	"""
	Render flow and connectivity analysis.

	Purpose:
	    Refreshes destination-port concentration, source-to-destination relationships,
	    TCP flag behavior, endpoint traffic concentration, destination-port trends,
	    endpoint connectivity, and five-tuple flow analysis on a reduced cadence to
	    limit browser redraw and Plotly reconstruction costs.

	Args:
	    protocols (List[str]): Protocol values included in the rendered snapshot.
	    destination_ports (tuple[int, int]): Inclusive destination-port range.

	Returns:
	    None: This function renders Streamlit components.
	"""
	throw_if( 'protocols', protocols, )
	throw_if( 'destination_ports', destination_ports, )
	df_packets = create_packet_snapshot( st.session_state.packets, protocols, destination_ports, )
	if not df_packets.empty:
		df_port_packets = df_packets.dropna( subset=[ 'dst_port', ] )
		if not df_port_packets.empty:
			figure_ports = create_port_heatmap( df_packets )
			st.plotly_chart( figure_ports, use_container_width=True, config=cfg.CHART_CONFIG,
				key='destination-port-heatmap', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No destination-port data is available for the current filters.' )
	else:
		with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
			st.info( 'No destination-port activity is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	if not df_packets.empty:
		df_flow_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
		if not df_flow_packets.empty:
			figure_flow = create_flow_figure( df_packets )
			st.plotly_chart( figure_flow, use_container_width=True, config=cfg.CHART_CONFIG,
				key='network-flow-sankey', )
		else:
			with st.container( height=cfg.FLOW_CHART_HEIGH, border=True ):
				st.info( 'No source-to-destination flow data is available.' )
	else:
		with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True ):
			st.info( 'No source-to-destination flow data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	flag_column, matrix_column = st.columns( 2, gap='medium', border=True )
	with flag_column:
		if not df_packets.empty:
			df_tcp_flag_packets = df_packets[
				(df_packets[ 'protocol' ] == 'TCP') & (df_packets[ 'dst_port' ].notna( )) & (
					df_packets[ 'flags' ].notna( )) ]
			
			if not df_tcp_flag_packets.empty:
				figure_tcp_flags = create_tcp_flag_heatmap( df_packets )
				st.plotly_chart( figure_tcp_flags, use_container_width=True, config=cfg.CHART_CONFIG,
					key='tcp-flag-activity-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
					st.info( 'No TCP flag activity is available for the current filters.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No TCP flag activity is available for the current filters.' )
	
	with matrix_column:
		if not df_packets.empty:
			df_matrix_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
			if not df_matrix_packets.empty:
				figure_matrix = create_traffic_matrix_figure( df_packets )
				st.plotly_chart( figure_matrix, use_container_width=True, config=cfg.CHART_CONFIG,
					key='source-destination-matrix-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
					st.info( 'No source-to-destination matrix data is available.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No source-to-destination matrix data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	if not df_packets.empty:
		df_port_trend_packets = df_packets.dropna( subset=[ 'timestamp', 'dst_port', ] )
		if not df_port_trend_packets.empty:
			figure_port_activity = create_port_activity_figure( df_packets )
			st.plotly_chart( figure_port_activity, use_container_width=True, config=cfg.CHART_CONFIG,
				key='port-activity-over-time-chart', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No destination-port trend data is available for the current filters.' )
	else:
		with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
			st.info( 'No destination-port trend data is available for the current filters.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	fan_out_column, fan_in_column = st.columns( 2, gap='medium', border=True )
	with fan_out_column:
		if not df_packets.empty:
			df_fan_out_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
			if not df_fan_out_packets.empty:
				figure_fan_out = create_fan_out_figure( df_packets )
				st.plotly_chart( figure_fan_out, use_container_width=True, config=cfg.CHART_CONFIG,
					key='source-fan-out-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
					st.info( 'No source fan-out data is available.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIG, border=True ):
				st.info( 'No source fan-out data is available.' )
	
	with fan_in_column:
		if not df_packets.empty:
			df_fan_in_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
			if not df_fan_in_packets.empty:
				figure_fan_in = create_fan_in_figure( df_packets )
				st.plotly_chart( figure_fan_in, use_container_width=True, config=cfg.CHART_CONFIG,
					key='destination-fan-in-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
					st.info( 'No destination fan-in data is available.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True ):
				st.info( 'No destination fan-in data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	# ----- Flow Duration Versus Volume ------
	if not df_packets.empty:
		df_scatter_packets = df_packets.dropna(
			subset=[ 'timestamp', 'length', 'src_ip', 'dst_ip', 'protocol', ] )
		
		if not df_scatter_packets.empty:
			figure_flow_scatter = create_flow_scatter_figure( df_packets )
			st.plotly_chart( figure_flow_scatter, use_container_width=True, config=cfg.CHART_CONFIG,
				key='flow-duration-volume-chart', )
		else:
			with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True ):
				st.info( 'No five-tuple flow data is available for the current filters.' )
	else:
		with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True ):
			st.info( 'No five-tuple flow data is available for the current filters.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

render_flow_analysis( proto_filter, port_range, )

# ==========================================================================================
# Footer
# ==========================================================================================

st.caption( 'Sloppy Network Analyzer — Live capture via Scapy enabled. '
            'Run with administrator/root privileges for full functionality.' )
