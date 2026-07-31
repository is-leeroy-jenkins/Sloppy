'''
  ******************************************************************************************
      Assembly:                Sloppy
      Filename:                app.py
      Author:                  Terry D. Eppler
      Created:                 05-31-2022

      Last Modified By:        Terry D. Eppler
      Last Modified On:        07-31-2026
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
import ipaddress
import queue
import random
import threading
from datetime import datetime
from typing import Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ==========================================================================================
# OSI Protocol Parsing and Analysis Utilities
# ==========================================================================================

def decode_dns_query_type( query_type: int, ) -> str:
	"""
	Decode a DNS query type.

	Purpose:
	    Converts a DNS numeric query type into the same labels used by demo traffic.

	Args:
	    query_type (int): DNS query type number.

	Returns:
	    str: DNS query type label.
	"""
	throw_if( 'query_type', query_type, )
	query_types = { 1: 'A', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', }
	return query_types.get( query_type, f'TYPE_{query_type}', )

def decode_dhcp_message_type( message_type: object, ) -> str:
	"""
	Decode a DHCP message type.

	Purpose:
	    Converts Scapy DHCP option values into stable readable categories.

	Args:
	    message_type (object): DHCP message type value.

	Returns:
	    str: DHCP message type label.
	"""
	throw_if( 'message_type', message_type, )
	if isinstance( message_type, bytes ):
		message_type = int.from_bytes( message_type, byteorder='big', )
	if isinstance( message_type, str ):
		labels = { value.lower( ): value for value in cfg.DHCP_MESSAGE_ORDER }
		return labels.get( message_type.lower( ), message_type.title( ), )
	labels = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'Acknowledge',
		6: 'Negative Acknowledge', 7: 'Release', 8: 'Inform', }
	return labels.get( int( message_type ), f'Type {message_type}', )

def parse_ntp_metadata( payload: bytes, ) -> Dict:
	"""
	Parse NTP metadata.

	Purpose:
	    Validates a complete standard NTP header and extracts version and mode metadata.

	Args:
	    payload (bytes): UDP payload.

	Returns:
	    Dict: NTP metadata or an empty dictionary for invalid payloads.
	"""
	throw_if( 'payload', payload, )
	if len( payload ) < 48:
		return { }
	first_byte = payload[ 0 ]
	version = (first_byte >> 3) & 0x07
	mode_number = first_byte & 0x07
	if version not in (1, 2, 3, 4,):
		return { }
	modes = { 1: 'Symmetric Active', 2: 'Symmetric Passive', 3: 'Client', 4: 'Server',
		5: 'Broadcast', }
	if mode_number not in modes:
		return { }
	return { 'application_protocol': 'NTP', 'ntp_version': version,
		'ntp_mode': modes[ mode_number ], }

def parse_http_metadata( payload: bytes, ) -> Dict:
	"""
	Parse unencrypted HTTP metadata.

	Purpose:
	    Extracts metadata from a complete HTTP start line and headers contained in one TCP
	    payload without claiming stream reassembly.

	Args:
	    payload (bytes): TCP payload.

	Returns:
	    Dict: HTTP request or response metadata.
	"""
	throw_if( 'payload', payload, )
	if not payload:
		return { }
	text = payload.decode( 'iso-8859-1', errors='ignore', )
	lines = text.split( '\r\n' )
	if not lines:
		return { }
	first_line = lines[ 0 ].strip( )
	headers = { }
	for line in lines[ 1: ]:
		if ':' not in line:
			continue
		name, value = line.split( ':', 1, )
		headers[ name.strip( ).lower( ) ] = value.strip( )
	if first_line.startswith( 'HTTP/' ):
		parts = first_line.split( ' ', 2, )
		if len( parts ) < 2 or not parts[ 1 ].isdigit( ):
			return { }
		return { 'application_protocol': 'HTTP', 'http_status': int( parts[ 1 ] ),
			'http_host': headers.get( 'host', '' ), }
	parts = first_line.split( ' ', 2, )
	if len( parts ) < 3 or parts[ 0 ] not in cfg.HTTP_METHOD_ORDER or not parts[ 2 ].startswith(
			'HTTP/' ):
		return { }
	return { 'application_protocol': 'HTTP', 'http_method': parts[ 0 ], 'http_path': parts[ 1 ],
		'http_host': headers.get( 'host', '' ), }

def _tls_version_name( major: int, minor: int, ) -> str:
	"""
	Resolve a TLS version.

	Purpose:
	    Converts a TLS wire-version pair into a readable protocol label.

	Args:
	    major (int): TLS major version byte.
	    minor (int): TLS minor version byte.

	Returns:
	    str: TLS version label.
	"""
	throw_if( 'major', major, )
	throw_if( 'minor', minor, )
	versions = { (3, 1): 'TLS 1.0', (3, 2): 'TLS 1.1', (3, 3): 'TLS 1.2', (3, 4): 'TLS 1.3', }
	return versions.get( (major, minor), f'{major}.{minor}', )

def _parse_tls_extensions( extensions: bytes, metadata: Dict, client_hello: bool, ) -> None:
	"""
	Parse TLS extensions.

	Purpose:
	    Extracts observable server-name, ALPN, and supported-version metadata from a
	    validated ClientHello or ServerHello extension vector.

	Args:
	    extensions (bytes): TLS extension vector.
	    metadata (Dict): Metadata record updated in place.
	    client_hello (bool): Indicates whether the extensions belong to a ClientHello.

	Returns:
	    None: This function updates the supplied metadata record.
	"""
	throw_if( 'extensions', extensions, )
	throw_if( 'metadata', metadata, )
	throw_if( 'client_hello', client_hello, )
	position = 0
	while position + 4 <= len( extensions ):
		extension_type = int.from_bytes( extensions[ position:position + 2 ], 'big', )
		extension_length = int.from_bytes( extensions[ position + 2:position + 4 ], 'big', )
		position += 4
		if position + extension_length > len( extensions ):
			return
		value = extensions[ position:position + extension_length ]
		position += extension_length
		if extension_type == 0 and len( value ) >= 5:
			name_length = int.from_bytes( value[ 3:5 ], 'big', )
			if 5 + name_length <= len( value ):
				metadata[ 'tls_server_name' ] = value[ 5:5 + name_length ].decode(
					errors='ignore', )
		elif extension_type == 16 and len( value ) >= 3:
			protocol_length = value[ 2 ]
			if 3 + protocol_length <= len( value ):
				metadata[ 'tls_alpn' ] = value[ 3:3 + protocol_length ].decode( errors='ignore', )
		elif extension_type == 43:
			if client_hello and len( value ) >= 3:
				versions_length = value[ 0 ]
				versions = value[ 1:1 + versions_length ]
				for index in range( 0, len( versions ) - 1, 2, ):
					if versions[ index:index + 2 ] == b'\x03\x04':
						metadata[ 'tls_version' ] = 'TLS 1.3'
						break
			elif not client_hello and len( value ) == 2:
				metadata[ 'tls_version' ] = _tls_version_name( value[ 0 ], value[ 1 ], )

def parse_tls_metadata( payload: bytes, ) -> Dict:
	"""
	Parse observable TLS metadata.

	Purpose:
	    Validates one complete TLS record and extracts record, handshake, negotiated-version,
	    SNI, ALPN, and cipher-suite metadata without decryption or TCP reassembly.

	Args:
	    payload (bytes): TCP payload beginning at a TLS record boundary.

	Returns:
	    Dict: Observable TLS metadata or an empty dictionary.
	"""
	throw_if( 'payload', payload, )
	if len( payload ) < 5 or payload[ 0 ] not in (20, 21, 22, 23,):
		return { }
	record_length = int.from_bytes( payload[ 3:5 ], 'big', )
	if record_length <= 0 or len( payload ) != 5 + record_length:
		return { }
	metadata = { 'tls_record_type': str( payload[ 0 ] ),
		'tls_version': _tls_version_name( payload[ 1 ], payload[ 2 ], ), }
	if payload[ 0 ] == 21:
		metadata[ 'tls_handshake_type' ] = 'Alert'
		return metadata
	if payload[ 0 ] != 22:
		return metadata
	if record_length < 4:
		return { }
	handshake_type = payload[ 5 ]
	handshake_length = int.from_bytes( payload[ 6:9 ], 'big', )
	if handshake_length + 4 != record_length or len( payload ) != 9 + handshake_length:
		return { }
	handshake_names = { 1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 20: 'Finished', }
	metadata[ 'tls_handshake_type' ] = handshake_names.get( handshake_type,
		f'Handshake {handshake_type}', )
	body = payload[ 9: ]
	if handshake_type == 1 and len( body ) >= 34:
		position = 34
		if position >= len( body ):
			return metadata
		session_length = body[ position ]
		position += 1 + session_length
		if position + 2 > len( body ):
			return metadata
		cipher_length = int.from_bytes( body[ position:position + 2 ], 'big', )
		position += 2 + cipher_length
		if position >= len( body ):
			return metadata
		compression_length = body[ position ]
		position += 1 + compression_length
		if position + 2 > len( body ):
			return metadata
		extensions_length = int.from_bytes( body[ position:position + 2 ], 'big', )
		position += 2
		if position + extensions_length <= len( body ):
			_parse_tls_extensions( body[ position:position + extensions_length ], metadata, True, )
	elif handshake_type == 2 and len( body ) >= 38:
		position = 34
		session_length = body[ position ]
		position += 1 + session_length
		if position + 3 > len( body ):
			return metadata
		cipher_code = int.from_bytes( body[ position:position + 2 ], 'big', )
		metadata[ 'tls_cipher_suite' ] = cfg.TLS_CIPHER_NAMES.get( cipher_code,
			f'0x{cipher_code:04X}', )
		position += 3
		if position + 2 <= len( body ):
			extensions_length = int.from_bytes( body[ position:position + 2 ], 'big', )
			position += 2
			if position + extensions_length <= len( body ):
				_parse_tls_extensions( body[ position:position + extensions_length ], metadata,
					False, )
	return metadata

def identify_transport_indicators( df_packets: pd.DataFrame, ) -> pd.DataFrame:
	"""
	Identify transport indicators.

	Purpose:
	    Marks later repeated TCP sequences, conservative duplicate acknowledgments, and
	    descending sequence observations within directional flows.

	Args:
	    df_packets (pd.DataFrame): Transport packet records.

	Returns:
	    pd.DataFrame: Packet records with indicator columns.
	"""
	throw_if( 'df_packets', df_packets, )
	df_transport = df_packets.copy( )
	for column in [ 'possible_retransmission', 'duplicate_ack', 'out_of_order', ]:
		df_transport[ column ] = False
	df_tcp = df_transport[ df_transport[ 'protocol' ] == 'TCP' ].copy( )
	if df_tcp.empty:
		return df_transport
	df_tcp = df_tcp.sort_values( 'timestamp' )
	flow_columns = [ 'src_ip', 'src_port', 'dst_ip', 'dst_port', ]
	df_tcp[ 'possible_retransmission' ] = df_tcp.duplicated(
		subset=flow_columns + [ 'tcp_sequence', 'tcp_payload_length', ], keep='first', ) & (
		                                      df_tcp[ 'tcp_sequence' ].notna( ))
	ack_only = df_tcp[ 'flags' ].fillna( '' ).astype( str ).str.contains( 'A' ) & ~(
		df_tcp[ 'flags' ].fillna( '' ).astype( str ).str.contains( 'S|F|R', regex=True, )) & (
			           pd.to_numeric( df_tcp[ 'tcp_payload_length' ], errors='coerce', ).fillna(
				           0 ) == 0)
	df_tcp[ 'duplicate_ack' ] = ack_only & df_tcp.duplicated(
		subset=flow_columns + [ 'tcp_acknowledgment', ], keep='first', ) & (
			                            pd.to_numeric( df_tcp[ 'tcp_acknowledgment' ],
				                            errors='coerce', ).fillna( 0 ) > 0)
	df_tcp[ 'previous_sequence' ] = df_tcp.groupby( flow_columns, dropna=False, )[
		'tcp_sequence' ].shift( 1 )
	df_tcp[ 'out_of_order' ] = (df_tcp[ 'tcp_sequence' ].notna( ) & df_tcp[
		'previous_sequence' ].notna( ) & (
			                           df_tcp[ 'tcp_sequence' ] < df_tcp[ 'previous_sequence' ]) &
	                            ~ \
	                           df_tcp[ 'possible_retransmission' ])
	for column in [ 'possible_retransmission', 'duplicate_ack', 'out_of_order', ]:
		df_transport.loc[ df_tcp.index, column ] = df_tcp[ column ]
	return df_transport

def format_endpoint( address: object, port: object, ) -> str:
	"""
	Format a session endpoint.

	Purpose:
	    Produces a stable address-and-port endpoint key.

	Args:
	    address (object): IP address value.
	    port (object): Port value.

	Returns:
	    str: Endpoint key.
	"""
	throw_if( 'address', address, )
	return f'{address}:{int( port )}' if pd.notna( port ) else str( address )

def create_conversation_snapshot( df_packets: pd.DataFrame,
	reference_time: datetime, ) -> pd.DataFrame:
	"""
	Create a bidirectional conversation snapshot.

	Purpose:
	    Builds direction-aware conversations, directional totals, handshake and close state,
	    and activity state using the configured inactivity threshold.

	Args:
	    df_packets (pd.DataFrame): Complete packet records.
	    reference_time (datetime): Time used for activity-state evaluation.

	Returns:
	    pd.DataFrame: Conversation summary.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'reference_time', reference_time, )
	if df_packets.empty:
		return pd.DataFrame( )
	df = df_packets.dropna( subset=[ 'timestamp', 'src_ip', 'dst_ip', 'protocol', ] ).copy( )
	if df.empty:
		return pd.DataFrame( )
	df[ 'source_endpoint' ] = [ format_endpoint( row.src_ip, row.src_port, ) for row in
		df.itertuples( ) ]
	df[ 'destination_endpoint' ] = [ format_endpoint( row.dst_ip, row.dst_port, ) for row in
		df.itertuples( ) ]
	df[ 'endpoint_a' ] = [ min( source, destination ) for source, destination in
		zip( df[ 'source_endpoint' ], df[ 'destination_endpoint' ] ) ]
	df[ 'endpoint_b' ] = [ max( source, destination ) for source, destination in
		zip( df[ 'source_endpoint' ], df[ 'destination_endpoint' ] ) ]
	df[ 'direction' ] = [ 'A → B' if source == endpoint_a else 'B → A' for source, endpoint_a in
		zip( df[ 'source_endpoint' ], df[ 'endpoint_a' ] ) ]
	df[ 'length' ] = pd.to_numeric( df[ 'length' ], errors='coerce', ).fillna( 0 )
	df[ 'flags' ] = df[ 'flags' ].fillna( '' ).astype( str )
	df[ 'packets_a_to_b' ] = (df[ 'direction' ] == 'A → B').astype( int )
	df[ 'packets_b_to_a' ] = (df[ 'direction' ] == 'B → A').astype( int )
	df[ 'bytes_a_to_b' ] = df[ 'length' ].where( df[ 'direction' ] == 'A → B', 0 )
	df[ 'bytes_b_to_a' ] = df[ 'length' ].where( df[ 'direction' ] == 'B → A', 0 )
	rows: List[ Dict ] = [ ]
	for (protocol, endpoint_a, endpoint_b), group in df.groupby(
			[ 'protocol', 'endpoint_a', 'endpoint_b', ], dropna=False, ):
		group = group.sort_values( 'timestamp' )
		a_to_b = group[ group[ 'direction' ] == 'A → B' ]
		b_to_a = group[ group[ 'direction' ] == 'B → A' ]
		initiator_direction = ''
		if protocol == 'TCP':
			syn_rows = group[
				group[ 'flags' ].str.contains( 'S' ) & ~group[ 'flags' ].str.contains( 'A' ) ]
			if not syn_rows.empty:
				initiator_direction = syn_rows.iloc[ 0 ][ 'direction' ]
		syn_seen = initiator_direction != ''
		response = b_to_a if initiator_direction == 'A → B' else a_to_b
		initiator = a_to_b if initiator_direction == 'A → B' else b_to_a
		syn_ack_seen = syn_seen and bool(
			response[ 'flags' ].str.contains( 'S' ).any( ) and response[ 'flags' ].str.contains(
				'A' ).any( ) )
		ack_seen = syn_ack_seen and bool( initiator[ 'flags' ].str.contains( 'A' ).any( ) )
		rst_seen = bool( group[ 'flags' ].str.contains( 'R' ).any( ) )
		fin_a = bool( a_to_b[ 'flags' ].str.contains( 'F' ).any( ) )
		fin_b = bool( b_to_a[ 'flags' ].str.contains( 'F' ).any( ) )
		if protocol != 'TCP':
			session_state = 'Observed'
		elif rst_seen:
			session_state = 'Reset'
		elif fin_a and fin_b:
			session_state = 'Closed'
		elif syn_seen and syn_ack_seen and ack_seen:
			session_state = 'Established'
		elif syn_seen:
			session_state = 'SYN Only'
		else:
			session_state = 'Observed'
		last_seen = group[ 'timestamp' ].max( )
		idle_seconds = max(
			(pd.Timestamp( reference_time ) - pd.Timestamp( last_seen )).total_seconds( ), 0.0, )
		activity_state = 'Active' if idle_seconds <= cfg.SESSION_IDLE_SECONDS else 'Idle'
		rows.append( { 'protocol': protocol, 'endpoint_a': endpoint_a, 'endpoint_b': endpoint_b,
			'first_seen': group[ 'timestamp' ].min( ), 'last_seen': last_seen,
			'duration_seconds': (last_seen - group[ 'timestamp' ].min( )).total_seconds( ),
			'total_packets': len( group ), 'total_bytes': group[ 'length' ].sum( ),
			'packets_a_to_b': int( (group[ 'direction' ] == 'A → B').sum( ) ),
			'packets_b_to_a': int( (group[ 'direction' ] == 'B → A').sum( ) ),
			'bytes_a_to_b': group[ 'bytes_a_to_b' ].sum( ),
			'bytes_b_to_a': group[ 'bytes_b_to_a' ].sum( ),
			'is_bidirectional': bool( not a_to_b.empty and not b_to_a.empty ),
			'directionality': 'Bidirectional' if not a_to_b.empty and not b_to_a.empty else
			'One-Way',
			'session_state': session_state, 'activity_state': activity_state,
			'idle_seconds': idle_seconds, } )
	return pd.DataFrame( rows )

def create_http_transaction_snapshot( df_packets: pd.DataFrame, ) -> pd.DataFrame:
	"""
	Create HTTP request-response transactions.

	Purpose:
	    Associates each observable HTTP response with the nearest unmatched preceding
	    request in the reverse five-tuple direction. Only metadata contained in captured
	    packet payloads is used; TCP reassembly is not performed.

	Args:
	    df_packets (pd.DataFrame): Complete packet records.

	Returns:
	    pd.DataFrame: Correlated HTTP transactions and unmatched requests or responses.
	"""
	throw_if( 'df_packets', df_packets, )
	if df_packets.empty:
		return pd.DataFrame( )
	df_http = df_packets[ df_packets[ 'application_protocol' ] == 'HTTP' ].copy( )
	if df_http.empty:
		return pd.DataFrame( )
	df_http = df_http.sort_values( 'timestamp' )
	pending: Dict[ tuple, List[ Dict ] ] = { }
	transactions: List[ Dict ] = [ ]
	for row in df_http.to_dict( orient='records', ):
		forward_key = (row.get( 'src_ip' ), row.get( 'src_port' ), row.get( 'dst_ip' ),
			row.get( 'dst_port' ))
		reverse_key = (row.get( 'dst_ip' ), row.get( 'dst_port' ), row.get( 'src_ip' ),
			row.get( 'src_port' ))
		if row.get( 'http_method' ):
			pending.setdefault( forward_key, [ ] ).append( row )
			continue
		if row.get( 'http_status' ) is None:
			continue
		requests = pending.get( reverse_key, [ ] )
		request = requests.pop( 0 ) if requests else None
		transactions.append( { 'request_time': request.get( 'timestamp' ) if request else pd.NaT,
			'response_time': row.get( 'timestamp' ),
			'client_ip': request.get( 'src_ip' ) if request else row.get( 'dst_ip' ),
			'server_ip': request.get( 'dst_ip' ) if request else row.get( 'src_ip' ),
			'http_method': request.get( 'http_method', '' ) if request else '',
			'http_host': request.get( 'http_host', '' ) if request else '',
			'http_path': request.get( 'http_path', '' ) if request else '',
			'http_status': row.get( 'http_status' ), 'response_seconds': ((pd.Timestamp(
				row.get( 'timestamp' ) ) - pd.Timestamp(
				request.get( 'timestamp' ) )).total_seconds( ) if request else None),
			'transaction_state': 'Matched' if request else 'Unmatched Response', } )
	for requests in pending.values( ):
		for request in requests:
			transactions.append(
				{ 'request_time': request.get( 'timestamp' ), 'response_time': pd.NaT,
					'client_ip': request.get( 'src_ip' ), 'server_ip': request.get( 'dst_ip' ),
					'http_method': request.get( 'http_method', '' ),
					'http_host': request.get( 'http_host', '' ),
					'http_path': request.get( 'http_path', '' ), 'http_status': None,
					'response_seconds': None, 'transaction_state': 'Unmatched Request', } )
	return pd.DataFrame( transactions )

# ------------------------------------------------------------------------------------------
# Streamlit Configuration
# ------------------------------------------------------------------------------------------
st.set_page_config( page_title='Sloppy Joe', page_icon=cfg.ICON, layout='wide', )

# ------------------------------------------------------------------------------------------
# Optional Live Capture Backend
# ------------------------------------------------------------------------------------------
try:
	from scapy.all import ARP as ScapyARP
	from scapy.all import DHCP as ScapyDHCP
	from scapy.all import DNS as ScapyDNS
	from scapy.all import DNSQR as ScapyDNSQR
	from scapy.all import Dot1Q as ScapyDot1Q
	from scapy.all import Ether as ScapyEther
	from scapy.all import ICMP as ScapyICMP
	from scapy.all import IP as ScapyIP
	from scapy.all import IPv6 as ScapyIPv6
	from scapy.all import Raw as ScapyRaw
	from scapy.all import TCP as ScapyTCP
	from scapy.all import UDP as ScapyUDP
	from scapy.all import sniff
	
	SCAPY_AVAILABLE = True
	SCAPY_IMPORT_ERROR = ''
except Exception as e:
	SCAPY_AVAILABLE = False
	SCAPY_IMPORT_ERROR = str( e )

try:
	from scapy.layers.inet6 import ICMPv6DestUnreach as ScapyICMPv6DestUnreach
	from scapy.layers.inet6 import ICMPv6EchoReply as ScapyICMPv6EchoReply
	from scapy.layers.inet6 import ICMPv6EchoRequest as ScapyICMPv6EchoRequest
	from scapy.layers.inet6 import ICMPv6TimeExceeded as ScapyICMPv6TimeExceeded
	from scapy.layers.inet6 import ICMPv6PacketTooBig as ScapyICMPv6PacketTooBig
	from scapy.layers.inet6 import ICMPv6ParamProblem as ScapyICMPv6ParamProblem
	from scapy.layers.inet6 import ICMPv6ND_RS as ScapyICMPv6RouterSolicitation
	from scapy.layers.inet6 import ICMPv6ND_RA as ScapyICMPv6RouterAdvertisement
	from scapy.layers.inet6 import ICMPv6ND_NS as ScapyICMPv6NeighborSolicitation
	from scapy.layers.inet6 import ICMPv6ND_NA as ScapyICMPv6NeighborAdvertisement
	from scapy.layers.inet6 import ICMPv6ND_Redirect as ScapyICMPv6Redirect
	from scapy.layers.inet6 import IPv6ExtHdrFragment as ScapyIPv6Fragment
	
	SCAPY_IPV6_CONTROL_AVAILABLE = True
except Exception:
	SCAPY_IPV6_CONTROL_AVAILABLE = False

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
	    Converts packet metadata into the stable superset schema used by every analysis
	    mode while preserving the original Network Analysis members.

	Args:
	    record (Dict): Packet metadata to normalize.
	    session_id (str): Active capture-session identifier.

	Returns:
	    Dict: Normalized packet record.
	"""
	throw_if( 'record', record )
	throw_if( 'session_id', session_id )
	return { 'timestamp': record.get( 'timestamp', datetime.utcnow( ) ),
		'src_mac': record.get( 'src_mac', '' ), 'dst_mac': record.get( 'dst_mac', '' ),
		'ether_type': record.get( 'ether_type', 0 ),
		'ether_type_name': record.get( 'ether_type_name', cfg.ETHER_TYPE_OTHER ),
		'inner_ether_type': record.get( 'inner_ether_type' ),
		'inner_ether_type_name': record.get( 'inner_ether_type_name', '' ),
		'frame_class': record.get( 'frame_class', cfg.FRAME_CLASS_UNICAST ),
		'is_broadcast': record.get( 'is_broadcast', False ),
		'is_multicast': record.get( 'is_multicast', False ), 'vlan_id': record.get( 'vlan_id' ),
		'vlan_priority': record.get( 'vlan_priority' ),
		'arp_operation': record.get( 'arp_operation', '' ),
		'arp_sender_ip': record.get( 'arp_sender_ip', '' ),
		'arp_target_ip': record.get( 'arp_target_ip', '' ),
		'ip_version': record.get( 'ip_version' ), 'src_ip': record.get( 'src_ip' ),
		'dst_ip': record.get( 'dst_ip' ), 'ttl': record.get( 'ttl' ),
		'hop_limit': record.get( 'hop_limit' ), 'ipv6_flow_label': record.get( 'ipv6_flow_label' ),
		'dscp': record.get( 'dscp' ), 'ecn': record.get( 'ecn' ),
		'ip_identification': record.get( 'ip_identification' ),
		'ip_flags': record.get( 'ip_flags', '' ),
		'fragment_offset': record.get( 'fragment_offset', 0 ),
		'ipv6_fragment_id': record.get( 'ipv6_fragment_id' ),
		'ipv6_more_fragments': record.get( 'ipv6_more_fragments', False ),
		'ipv6_fragment_next_header': record.get( 'ipv6_fragment_next_header' ),
		'is_fragmented': record.get( 'is_fragmented', False ),
		'icmp_type': record.get( 'icmp_type' ), 'icmp_code': record.get( 'icmp_code' ),
		'address_scope': record.get( 'address_scope', '' ), 'protocol': record.get( 'protocol' ),
		'src_port': record.get( 'src_port' ), 'dst_port': record.get( 'dst_port' ),
		'flags': record.get( 'flags', '' ), 'tcp_sequence': record.get( 'tcp_sequence' ),
		'tcp_acknowledgment': record.get( 'tcp_acknowledgment' ),
		'tcp_window': record.get( 'tcp_window' ),
		'tcp_header_length': record.get( 'tcp_header_length' ),
		'udp_length': record.get( 'udp_length' ),
		'tcp_payload_length': record.get( 'tcp_payload_length', 0 ),
		'tls_record_type': record.get( 'tls_record_type', '' ),
		'tls_version': record.get( 'tls_version', '' ),
		'tls_handshake_type': record.get( 'tls_handshake_type', '' ),
		'tls_server_name': record.get( 'tls_server_name', '' ),
		'tls_alpn': record.get( 'tls_alpn', '' ),
		'tls_cipher_suite': record.get( 'tls_cipher_suite', '' ),
		'application_protocol': record.get( 'application_protocol', '' ),
		'dns_query': record.get( 'dns_query', '' ),
		'dns_query_type': record.get( 'dns_query_type', '' ),
		'dns_response_code': record.get( 'dns_response_code' ),
		'dns_question_count': record.get( 'dns_question_count', 0 ),
		'dns_answer_count': record.get( 'dns_answer_count', 0 ),
		'dns_authority_count': record.get( 'dns_authority_count', 0 ),
		'dns_additional_count': record.get( 'dns_additional_count', 0 ),
		'dns_is_response': record.get( 'dns_is_response', False ),
		'dns_recursion_desired': record.get( 'dns_recursion_desired', False ),
		'dns_recursion_available': record.get( 'dns_recursion_available', False ),
		'dns_authoritative': record.get( 'dns_authoritative', False ),
		'dns_truncated': record.get( 'dns_truncated', False ),
		'http_method': record.get( 'http_method', '' ), 'http_host': record.get( 'http_host', '' ),
		'http_path': record.get( 'http_path', '' ), 'http_status': record.get( 'http_status' ),
		'dhcp_message_type': record.get( 'dhcp_message_type', '' ),
		'ntp_mode': record.get( 'ntp_mode', '' ), 'ntp_version': record.get( 'ntp_version' ),
		'length': record.get( 'length', 0 ), 'session': session_id, }

def classify_destination_mac( destination_mac: str, ) -> tuple[ str, bool, bool ]:
	"""
	Classify a destination MAC address.

	Purpose:
	    Determines whether a destination MAC address represents unicast, multicast, or
	    Ethernet broadcast traffic.

	Args:
	    destination_mac (str): Destination MAC address.

	Returns:
	    tuple[str, bool, bool]: Frame classification, broadcast indicator, and multicast
	        indicator.
	"""
	throw_if( 'destination_mac', destination_mac, )
	value = destination_mac.lower( )
	if value == cfg.BROADCAST_MAC_ADDRESS:
		return cfg.FRAME_CLASS_BROADCAST, True, False
	if int( value.split( ':' )[ 0 ], 16, ) & 1:
		return cfg.FRAME_CLASS_MULTICAST, False, True
	return cfg.FRAME_CLASS_UNICAST, False, False

def resolve_ether_type_name( ether_type: int, ) -> str:
	"""
	Resolve an EtherType name.

	Purpose:
	    Maps a numeric Ethernet protocol identifier to the configured display value.

	Args:
	    ether_type (int): Numeric Ethernet protocol identifier.

	Returns:
	    str: Configured EtherType display value.
	"""
	throw_if( 'ether_type', ether_type, )
	return cfg.ETHER_TYPE_NAMES.get( ether_type, cfg.ETHER_TYPE_OTHER, )

def resolve_arp_operation( operation: int, ) -> str:
	"""
	Resolve an ARP operation.

	Purpose:
	    Maps an ARP operation number to its configured request, reply, or other label.

	Args:
	    operation (int): Numeric ARP operation value.

	Returns:
	    str: Readable ARP operation.
	"""
	throw_if( 'operation', operation, )
	if operation == 1:
		return cfg.ARP_OPERATION_REQUEST
	if operation == 2:
		return cfg.ARP_OPERATION_REPLY
	return cfg.ARP_OPERATION_OTHER

def generate_demo_mac_address( host_id: int, ) -> str:
	"""
	Generate a demonstration MAC address.

	Purpose:
	    Creates a deterministic locally administered MAC address from a host identifier.

	Args:
	    host_id (int): Host identifier encoded into the final MAC octet.

	Returns:
	    str: Colon-delimited demonstration MAC address.
	"""
	throw_if( 'host_id', host_id, )
	return f'02:00:00:00:00:{host_id:02x}'

def classify_ip_scope( address: str, ) -> str:
	"""
	Classify an IP address scope.

	Purpose:
	    Assigns a private, public, multicast, loopback, link-local, reserved, or
	    documentation classification to an IPv4 or IPv6 address.

	Args:
	    address (str): IPv4 or IPv6 address.

	Returns:
	    str: Address-scope classification.
	"""
	throw_if( 'address', address, )
	ip_address = ipaddress.ip_address( address )
	if ip_address in ipaddress.ip_network( '192.0.2.0/24' ) or ip_address in ipaddress.ip_network(
		'198.51.100.0/24' ) or ip_address in ipaddress.ip_network(
		'203.0.113.0/24' ) or ip_address in ipaddress.ip_network( '2001:db8::/32' ):
		return 'Documentation'
	if ip_address.is_private:
		return 'Private'
	if ip_address.is_multicast:
		return 'Multicast'
	if ip_address.is_loopback:
		return 'Loopback'
	if ip_address.is_link_local:
		return 'Link Local'
	if ip_address.is_reserved:
		return 'Reserved'
	return 'Public'

def create_demo_record( base_record: Dict, values: Dict, session_id: str, offset_ms: int, ) -> Dict:
	"""
	Create one demonstration record.

	Purpose:
	    Applies scenario-specific values to a controlled base record and normalizes the
	    result at a deterministic offset from the scenario start time.

	Args:
	    base_record (Dict): Controlled base packet metadata.
	    values (Dict): Scenario-specific packet values.
	    session_id (str): Active capture-session identifier.
	    offset_ms (int): Millisecond offset from the scenario base timestamp.

	Returns:
	    Dict: Normalized demonstration packet record.
	"""
	throw_if( 'base_record', base_record, )
	throw_if( 'values', values, )
	throw_if( 'session_id', session_id, )
	record = base_record.copy( )
	record[ 'timestamp' ] = base_record[ 'timestamp' ] + pd.Timedelta( milliseconds=offset_ms )
	record.update( values )
	return normalize_packet( record, session_id, )

def generate_demo_scenario( session_id: str, ) -> List[ Dict ]:
	"""
	Generate a coherent demonstration scenario.

	Purpose:
	    Produces internally consistent Layer 2 through Layer 7 request-response and
	    connection-lifecycle traffic without relying on unrelated random packets.

	Args:
	    session_id (str): Active capture-session identifier.

	Returns:
	    List[Dict]: Related normalized packet records.
	"""
	throw_if( 'session_id', session_id, )
	scenario = random.choice(
		[ 'ARP', 'TCP', 'DNS', 'HTTP', 'DHCP', 'NTP', 'TLS', 'IPv6', 'VLAN', 'FRAGMENT', ] )
	source_host = random.randint( 2, 50 )
	destination_host = random.randint( 51, 100 )
	source_ip = f'192.168.1.{source_host}'
	destination_ip = f'10.0.0.{destination_host}'
	source_mac = generate_demo_mac_address( source_host, )
	destination_mac = generate_demo_mac_address( destination_host, )
	base = { 'timestamp': datetime.utcnow( ), 'src_mac': source_mac, 'dst_mac': destination_mac,
		'ether_type': 0x0800, 'ether_type_name': cfg.ETHER_TYPE_IPV4,
		'frame_class': cfg.FRAME_CLASS_UNICAST, 'ip_version': 4, 'src_ip': source_ip,
		'dst_ip': destination_ip, 'ttl': 64, 'dscp': 0, 'ecn': 0,
		'ip_identification': random.randint( 0, 65535 ), 'fragment_offset': 0,
		'is_fragmented': False, 'address_scope': classify_ip_scope( destination_ip, ),
		'length': random.randint( 64, 900 ), }
	reverse = { 'src_mac': destination_mac, 'dst_mac': source_mac, 'src_ip': destination_ip,
		'dst_ip': source_ip, 'address_scope': classify_ip_scope( source_ip, ), }
	if scenario == 'ARP':
		return [ create_demo_record( base,
			{ 'dst_mac': cfg.BROADCAST_MAC_ADDRESS, 'ether_type': 0x0806,
				'ether_type_name': cfg.ETHER_TYPE_ARP, 'frame_class': cfg.FRAME_CLASS_BROADCAST,
				'is_broadcast': True, 'ip_version': None, 'src_ip': None, 'dst_ip': None,
				'arp_operation': cfg.ARP_OPERATION_REQUEST, 'arp_sender_ip': source_ip,
				'arp_target_ip': destination_ip, }, session_id, 0, ), create_demo_record( base,
			reverse | { 'ether_type': 0x0806, 'ether_type_name': cfg.ETHER_TYPE_ARP,
				'ip_version': None, 'src_ip': None, 'dst_ip': None,
				'arp_operation': cfg.ARP_OPERATION_REPLY, 'arp_sender_ip': destination_ip,
				'arp_target_ip': source_ip, }, session_id, 15, ), ]
	if scenario == 'TCP':
		source_port = random.randint( 49152, 65535 )
		destination_port = random.choice( [ 22, 443, 3389, 8080, ] )
		client_sequence = random.randint( 1000, 100000 )
		server_sequence = random.randint( 1000, 100000 )
		return [ create_demo_record( base,
			{ 'protocol': 'TCP', 'src_port': source_port, 'dst_port': destination_port,
				'flags': 'S', 'tcp_sequence': client_sequence, 'tcp_acknowledgment': 0,
				'tcp_window': 64240, 'tcp_header_length': 20, }, session_id, 0, ),
			create_demo_record( base, reverse | { 'protocol': 'TCP', 'src_port': destination_port,
				'dst_port': source_port, 'flags': 'SA', 'tcp_sequence': server_sequence,
				'tcp_acknowledgment': client_sequence + 1, 'tcp_window': 65535,
				'tcp_header_length': 20, }, session_id, 20, ), create_demo_record( base,
				{ 'protocol': 'TCP', 'src_port': source_port, 'dst_port': destination_port,
					'flags': 'A', 'tcp_sequence': client_sequence + 1,
					'tcp_acknowledgment': server_sequence + 1, 'tcp_window': 64240,
					'tcp_header_length': 20, }, session_id, 35, ), create_demo_record( base,
				{ 'protocol': 'TCP', 'src_port': source_port, 'dst_port': destination_port,
					'flags': 'FA', 'tcp_sequence': client_sequence + 1,
					'tcp_acknowledgment': server_sequence + 1, 'tcp_window': 64240,
					'tcp_header_length': 20, }, session_id, 150, ), create_demo_record( base,
				reverse | { 'protocol': 'TCP', 'src_port': destination_port,
					'dst_port': source_port, 'flags': 'A', 'tcp_sequence': server_sequence + 1,
					'tcp_acknowledgment': client_sequence + 2, 'tcp_window': 65535,
					'tcp_header_length': 20, }, session_id, 165, ), create_demo_record( base,
				reverse | { 'protocol': 'TCP', 'src_port': destination_port,
					'dst_port': source_port, 'flags': 'FA', 'tcp_sequence': server_sequence + 1,
					'tcp_acknowledgment': client_sequence + 2, 'tcp_window': 65535,
					'tcp_header_length': 20, }, session_id, 180, ), create_demo_record( base,
				{ 'protocol': 'TCP', 'src_port': source_port, 'dst_port': destination_port,
					'flags': 'A', 'tcp_sequence': client_sequence + 2,
					'tcp_acknowledgment': server_sequence + 2, 'tcp_window': 64240,
					'tcp_header_length': 20, }, session_id, 195, ), ]
	if scenario == 'DNS':
		query = random.choice( cfg.DEMO_DNS_NAMES )
		query_type = random.choice( cfg.DNS_QUERY_TYPE_ORDER )
		source_port = random.randint( 49152, 65535 )
		return [ create_demo_record( base,
			{ 'protocol': 'UDP', 'src_port': source_port, 'dst_port': 53, 'udp_length': 60,
				'application_protocol': 'DNS', 'dns_query': query, 'dns_query_type': query_type,
				'dns_response_code': 0, }, session_id, 0, ), create_demo_record( base,
			reverse | { 'protocol': 'UDP', 'src_port': 53, 'dst_port': source_port,
				'udp_length': 110, 'application_protocol': 'DNS', 'dns_query': query,
				'dns_query_type': query_type, 'dns_response_code': 0, }, session_id, 18, ), ]
	if scenario == 'HTTP':
		source_port = random.randint( 49152, 65535 )
		host = random.choice( cfg.DEMO_DNS_NAMES )
		path = random.choice( [ '/', '/api/items', '/login', '/health', ] )
		return [ create_demo_record( base,
			{ 'protocol': 'TCP', 'src_port': source_port, 'dst_port': 80, 'flags': 'PA',
				'tcp_sequence': 1001, 'tcp_acknowledgment': 5001, 'tcp_window': 64240,
				'tcp_header_length': 20, 'tcp_payload_length': 64, 'application_protocol': 'HTTP',
				'http_method': 'GET', 'http_host': host, 'http_path': path, }, session_id, 0, ),
			create_demo_record( base,
				reverse | { 'protocol': 'TCP', 'src_port': 80, 'dst_port': source_port,
					'flags': 'PA', 'tcp_sequence': 5001, 'tcp_acknowledgment': 1065,
					'tcp_window': 65535, 'tcp_header_length': 20, 'tcp_payload_length': 128,
					'application_protocol': 'HTTP',
					'http_status': random.choice( [ 200, 201, 301, 404, 500, ] ), }, session_id,
				35, ), ]
	if scenario == 'DHCP':
		client_ip = '0.0.0.0'
		server_ip = destination_ip
		broadcast = { 'dst_mac': cfg.BROADCAST_MAC_ADDRESS, 'dst_ip': '255.255.255.255',
			'frame_class': cfg.FRAME_CLASS_BROADCAST, 'is_broadcast': True,
			'address_scope': 'Reserved', }
		return [ create_demo_record( base,
			broadcast | { 'src_ip': client_ip, 'protocol': 'UDP', 'src_port': 68, 'dst_port': 67,
				'udp_length': 300, 'application_protocol': 'DHCP',
				'dhcp_message_type': 'Discover', }, session_id, 0, ), create_demo_record( base,
			{ 'src_mac': destination_mac, 'dst_mac': cfg.BROADCAST_MAC_ADDRESS, 'src_ip':
				server_ip,
				'dst_ip': '255.255.255.255', 'frame_class': cfg.FRAME_CLASS_BROADCAST,
				'is_broadcast': True, 'address_scope': 'Reserved', 'protocol': 'UDP',
				'src_port': 67, 'dst_port': 68, 'udp_length': 300, 'application_protocol': 'DHCP',
				'dhcp_message_type': 'Offer', }, session_id, 30, ), create_demo_record( base,
			broadcast | { 'src_ip': client_ip, 'protocol': 'UDP', 'src_port': 68, 'dst_port': 67,
				'udp_length': 300, 'application_protocol': 'DHCP',
				'dhcp_message_type': 'Request', }, session_id, 60, ), create_demo_record( base,
			{ 'src_mac': destination_mac, 'dst_mac': source_mac, 'src_ip': server_ip,
				'dst_ip': source_ip, 'address_scope': classify_ip_scope( source_ip, ),
				'protocol': 'UDP', 'src_port': 67, 'dst_port': 68, 'udp_length': 300,
				'application_protocol': 'DHCP', 'dhcp_message_type': 'Acknowledge', }, session_id,
			90, ), ]
	if scenario == 'NTP':
		source_port = random.randint( 49152, 65535 )
		return [ create_demo_record( base,
			{ 'protocol': 'UDP', 'src_port': source_port, 'dst_port': 123, 'udp_length': 48,
				'application_protocol': 'NTP', 'ntp_version': 4, 'ntp_mode': 'Client', },
			session_id, 0, ), create_demo_record( base,
			reverse | { 'protocol': 'UDP', 'src_port': 123, 'dst_port': source_port,
				'udp_length': 48, 'application_protocol': 'NTP', 'ntp_version': 4,
				'ntp_mode': 'Server', }, session_id, 25, ), ]
	if scenario == 'VLAN':
		return [ create_demo_record( base,
			{ 'ether_type': 0x8100, 'ether_type_name': cfg.ETHER_TYPE_VLAN,
				'inner_ether_type': 0x0800, 'inner_ether_type_name': cfg.ETHER_TYPE_IPV4,
				'vlan_id': random.choice( [ 10, 20, 30, 40, 100, ] ),
				'vlan_priority': random.randint( 0, 7 ), 'protocol': 'TCP',
				'src_port': random.randint( 49152, 65535 ), 'dst_port': 443, 'flags': 'A',
				'tcp_sequence': random.randint( 1000, 100000 ), 'tcp_acknowledgment': 5001,
				'tcp_window': 64240, 'tcp_header_length': 20, }, session_id, 0, ) ]
	if scenario == 'FRAGMENT':
		identification = random.randint( 0, 65535 )
		return [ create_demo_record( base,
			{ 'ip_identification': identification, 'ip_flags': 'MF', 'fragment_offset': 0,
				'is_fragmented': True, 'protocol': 'UDP', 'src_port': 40000, 'dst_port': 50000,
				'udp_length': 1480, }, session_id, 0, ), create_demo_record( base,
			{ 'ip_identification': identification, 'ip_flags': '', 'fragment_offset': 185,
				'is_fragmented': True, 'protocol': None, 'src_port': None, 'dst_port': None,
				'udp_length': None, }, session_id, 8, ), ]
	if scenario == 'TLS':
		source_port = random.randint( 49152, 65535 )
		server_name = random.choice( cfg.DEMO_DNS_NAMES )
		return [ create_demo_record( base,
			{ 'protocol': 'TCP', 'src_port': source_port, 'dst_port': 443, 'flags': 'PA',
				'tcp_sequence': 1001, 'tcp_acknowledgment': 5001, 'tcp_window': 64240,
				'tcp_header_length': 20, 'tcp_payload_length': 180, 'tls_record_type': '22',
				'tls_version': 'TLS 1.3', 'tls_handshake_type': 'Client Hello',
				'tls_server_name': server_name, 'tls_alpn': 'h2', }, session_id, 0, ),
			create_demo_record( base,
				reverse | { 'protocol': 'TCP', 'src_port': 443, 'dst_port': source_port,
					'flags': 'PA', 'tcp_sequence': 5001, 'tcp_acknowledgment': 1181,
					'tcp_window': 65535, 'tcp_header_length': 20, 'tcp_payload_length': 120,
					'tls_record_type': '22', 'tls_version': 'TLS 1.3',
					'tls_handshake_type': 'Server Hello',
					'tls_cipher_suite': random.choice( cfg.TLS_CIPHER_SUITES ), }, session_id,
				30, ), ]
	return [ create_demo_record( base,
		{ 'ether_type': 0x86DD, 'ether_type_name': cfg.ETHER_TYPE_IPV6, 'ip_version': 6,
			'src_ip': f'2001:db8::{source_host}', 'dst_ip': f'2001:db8:1::{destination_host}',
			'ttl': None, 'hop_limit': 64, 'ipv6_flow_label': random.randint( 0, 1048575 ),
			'address_scope': 'Documentation', 'protocol': 'ICMPv6', 'flags': 'TYPE_128',
			'icmp_type': 128, 'icmp_code': 0, }, session_id, 0, ) ]

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
	    Captures Layer 2 through Layer 7 metadata from supported Scapy packets and writes
	    plain dictionaries to the packet queue without accessing Streamlit session state.

	Args:
	    packet (object): Packet supplied by Scapy.
	    packet_queue (queue.Queue): Thread-safe queue receiving parsed packet records.
	    capture_error_queue (queue.Queue): Thread-safe queue receiving parsing errors.

	Returns:
	    None: This function queues one supported packet record.
	"""
	try:
		throw_if( 'packet', packet, )
		throw_if( 'packet_queue', packet_queue, )
		throw_if( 'capture_error_queue', capture_error_queue, )
		if not SCAPY_AVAILABLE or not packet.haslayer( ScapyEther ):
			return
		raw = bytes( packet )
		ethernet = packet.getlayer( ScapyEther )
		destination_mac = str( ethernet.dst ).lower( )
		frame_class, is_broadcast, is_multicast = classify_destination_mac( destination_mac, )
		outer_ether_type = int( ethernet.type )
		record = { 'timestamp': datetime.utcnow( ), 'src_mac': str( ethernet.src ).lower( ),
			'dst_mac': destination_mac, 'ether_type': outer_ether_type,
			'ether_type_name': resolve_ether_type_name( outer_ether_type, ),
			'inner_ether_type': None, 'inner_ether_type_name': '', 'frame_class': frame_class,
			'is_broadcast': is_broadcast, 'is_multicast': is_multicast, 'length': len( raw ), }
		if packet.haslayer( ScapyDot1Q ):
			vlan = packet.getlayer( ScapyDot1Q )
			inner_ether_type = int( vlan.type )
			record.update( { 'vlan_id': int( vlan.vlan ), 'vlan_priority': int( vlan.prio ),
				'inner_ether_type': inner_ether_type,
				'inner_ether_type_name': resolve_ether_type_name( inner_ether_type, ), } )
		if packet.haslayer( ScapyARP ):
			arp = packet.getlayer( ScapyARP )
			record.update( { 'arp_operation': resolve_arp_operation( int( arp.op ), ),
				'arp_sender_ip': str( arp.psrc ), 'arp_target_ip': str( arp.pdst ), } )
		elif packet.haslayer( ScapyIP ):
			ipv4 = packet.getlayer( ScapyIP )
			record.update( { 'ip_version': 4, 'src_ip': str( ipv4.src ), 'dst_ip': str( ipv4.dst ),
				'ttl': int( ipv4.ttl ), 'dscp': int( ipv4.tos ) >> 2, 'ecn': int( ipv4.tos ) & 3,
				'ip_identification': int( ipv4.id ), 'ip_flags': str( ipv4.flags ),
				'fragment_offset': int( ipv4.frag ),
				'is_fragmented': bool( int( ipv4.frag ) or 'MF' in str( ipv4.flags ) ),
				'address_scope': classify_ip_scope( str( ipv4.dst ), ), } )
		elif packet.haslayer( ScapyIPv6 ):
			ipv6 = packet.getlayer( ScapyIPv6 )
			record.update( { 'ip_version': 6, 'src_ip': str( ipv6.src ), 'dst_ip': str( ipv6.dst ),
				'hop_limit': int( ipv6.hlim ), 'dscp': int( ipv6.tc ) >> 2,
				'ecn': int( ipv6.tc ) & 3, 'ipv6_flow_label': int( ipv6.fl ),
				'address_scope': classify_ip_scope( str( ipv6.dst ), ), } )
			if SCAPY_IPV6_CONTROL_AVAILABLE and packet.haslayer( ScapyIPv6Fragment ):
				fragment = packet.getlayer( ScapyIPv6Fragment )
				record.update( { 'fragment_offset': int( fragment.offset ), 'is_fragmented': True,
					'ipv6_fragment_id': int( fragment.id ),
					'ipv6_more_fragments': bool( fragment.m ),
					'ipv6_fragment_next_header': int( fragment.nh ), } )
		non_initial_fragment = bool( record.get( 'fragment_offset', 0 ) > 0 )
		if packet.haslayer( ScapyTCP ) and not non_initial_fragment:
			tcp = packet.getlayer( ScapyTCP )
			record.update(
				{ 'protocol': 'TCP', 'src_port': int( tcp.sport ), 'dst_port': int( tcp.dport ),
					'flags': str( tcp.flags ), 'tcp_sequence': int( tcp.seq ),
					'tcp_acknowledgment': int( tcp.ack ), 'tcp_window': int( tcp.window ),
					'tcp_header_length': int( tcp.dataofs or 5 ) * 4,
					'tcp_payload_length': len( bytes( tcp.payload ) ), } )
		elif packet.haslayer( ScapyUDP ) and not non_initial_fragment:
			udp = packet.getlayer( ScapyUDP )
			record.update(
				{ 'protocol': 'UDP', 'src_port': int( udp.sport ), 'dst_port': int( udp.dport ),
					'udp_length': int( udp.len or 0 ), } )
		elif packet.haslayer( ScapyICMP ):
			icmp = packet.getlayer( ScapyICMP )
			record.update( { 'protocol': 'ICMP', 'flags': f'TYPE_{int( icmp.type )}',
				'icmp_type': int( icmp.type ), 'icmp_code': int( icmp.code ), } )
		elif SCAPY_IPV6_CONTROL_AVAILABLE:
			for layer_class, type_number in ((ScapyICMPv6DestUnreach, 1),
				(ScapyICMPv6PacketTooBig, 2), (ScapyICMPv6TimeExceeded, 3),
				(ScapyICMPv6ParamProblem, 4), (ScapyICMPv6EchoRequest, 128),
				(ScapyICMPv6EchoReply, 129), (ScapyICMPv6RouterSolicitation, 133),
				(ScapyICMPv6RouterAdvertisement, 134), (ScapyICMPv6NeighborSolicitation, 135),
				(ScapyICMPv6NeighborAdvertisement, 136), (ScapyICMPv6Redirect, 137),):
				if packet.haslayer( layer_class ):
					layer = packet.getlayer( layer_class )
					record.update( { 'protocol': 'ICMPv6', 'flags': f'TYPE_{type_number}',
						'icmp_type': type_number,
						'icmp_code': int( getattr( layer, 'code', 0 ) ), } )
					break
		if packet.haslayer( ScapyDNS ):
			dns = packet.getlayer( ScapyDNS )
			query_names: List[ str ] = [ ]
			query_types: List[ str ] = [ ]
			question = dns.qd
			for _ in range( int( dns.qdcount or 0 ) ):
				if question is None or not hasattr( question, 'qname' ):
					break
				query_names.append(
					bytes( question.qname ).decode( errors='ignore', ).rstrip( '.' ) )
				query_types.append( decode_dns_query_type( int( question.qtype ), ) )
				question = getattr( question, 'payload', None )
			record.update( { 'application_protocol': 'DNS', 'dns_query': ', '.join( query_names ),
				'dns_query_type': ', '.join( query_types ), 'dns_response_code': int( dns.rcode ),
				'dns_question_count': int( dns.qdcount or 0 ),
				'dns_answer_count': int( dns.ancount or 0 ),
				'dns_authority_count': int( dns.nscount or 0 ),
				'dns_additional_count': int( dns.arcount or 0 ), 'dns_is_response': bool( dns.qr ),
				'dns_recursion_desired': bool( dns.rd ), 'dns_recursion_available': bool( dns.ra ),
				'dns_authoritative': bool( dns.aa ), 'dns_truncated': bool( dns.tc ), } )
		if packet.haslayer( ScapyDHCP ):
			dhcp = packet.getlayer( ScapyDHCP )
			message_type = ''
			for option in dhcp.options:
				if isinstance( option, tuple ) and option[ 0 ] == 'message-type':
					message_type = decode_dhcp_message_type( option[ 1 ], )
					break
			record.update( { 'application_protocol': 'DHCP', 'dhcp_message_type': message_type, } )
		if packet.haslayer( ScapyRaw ):
			payload = bytes( packet.getlayer( ScapyRaw ).load )
			if record.get( 'protocol' ) == 'TCP':
				http_metadata = parse_http_metadata( payload, )
				tls_metadata = parse_tls_metadata( payload, )
				if http_metadata:
					record.update( http_metadata )
				elif tls_metadata:
					record.update( tls_metadata )
			elif record.get( 'protocol' ) == 'UDP' and (
					record.get( 'src_port' ) == 123 or record.get( 'dst_port' ) == 123):
				record.update( parse_ntp_metadata( payload, ) )
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
		target_count = random.randint( 5, 15, )
		demo_packets: List[ Dict ] = [ ]
		while len( demo_packets ) < target_count:
			demo_packets.extend( generate_demo_scenario( st.session_state.session_id, ) )
		demo_packets = demo_packets[ :target_count ]
		st.session_state.packets.extend( demo_packets )
		packet_count = len( demo_packets )
	
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
			marker={
				'colors': [ cfg.PROTOCOL_COLORS.get( str( protocol ), cfg.PURPLE, ) for protocol in
					df_protocols[ 'protocol' ] ],
				'line': { 'color': cfg.PANEL_BACKGROUND, 'width': 3, }, },
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
		color_discrete_map=cfg.PROTOCOL_COLORS,
		category_orders={ 'protocol': cfg.PROTOCOL_ORDER, }, )
	
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
				'colorscale': [ [ 0.0, '#153E75', ], [ 0.5, cfg.ACCENT_BLUE, ],
					[ 1.0, cfg.CYAN, ], ],
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
	
	top_sources = (
		df_matrix.groupby( 'src_ip' ).size( ).nlargest( cfg.TOP_MATRIX_SOURCE_LIMIT ).index)
	
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
		df_ports.groupby( 'dst_port' ).size( ).nlargest( cfg.TOP_PORT_TREND_LIMIT
		).index.tolist( ))
	
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
		              'dst_ip' ].nunique( ).rename(
		'unique_destinations' ).reset_index( ).sort_values( [ 'unique_destinations', 'src_ip', ],
		ascending=[ False, True, ], ).head( cfg.TOP_ENDPOINT_CONNECTIVITY_LIMIT ).sort_values(
		[ 'unique_destinations', 'src_ip', ], ascending=[ True, True, ], ))
	
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
			marker={ 'color': cfg.GREEN, }, text=df_fan_in[ 'unique_sources' ],
			textposition='outside', cliponaxis=False, hovertemplate=('<b>%{y}</b><br>'
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
			marker={ 'color': cfg.PROTOCOL_COLORS[ protocol ],
				'size': marker_sizes[ protocol_mask ], 'opacity': 0.72,
				'line': { 'color': 'rgba( 255, 255, 255, 0.28 )', 'width': 1, }, },
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
# Data Link Analysis Helpers
# ==========================================================================================

def create_data_link_snapshot( packets: List[ Dict ], ether_types: List[ str ],
	frame_classes: List[ str ], ) -> pd.DataFrame:
	"""
	Create a Data Link packet snapshot.

	Purpose:
	    Converts retained packet records into a typed Layer 2 DataFrame and applies the
	    active EtherType and frame-class filters without modifying session state.

	Args:
	    packets (List[Dict]): Retained normalized packet records.
	    ether_types (List[str]): Included EtherType names.
	    frame_classes (List[str]): Included frame classifications.

	Returns:
	    pd.DataFrame: Filtered Data Link packet snapshot.
	"""
	throw_if( 'packets', packets, )
	throw_if( 'ether_types', ether_types, )
	throw_if( 'frame_classes', frame_classes, )
	df_packets = pd.DataFrame( packets )
	if df_packets.empty:
		return df_packets
	defaults = { 'timestamp': pd.NaT, 'src_mac': '', 'dst_mac': '', 'ether_type': 0,
		'ether_type_name': cfg.ETHER_TYPE_OTHER, 'inner_ether_type': pd.NA,
		'inner_ether_type_name': '', 'frame_class': cfg.FRAME_CLASS_UNICAST, 'is_broadcast': False,
		'is_multicast': False, 'vlan_id': pd.NA, 'vlan_priority': pd.NA, 'arp_operation': '',
		'arp_sender_ip': '', 'arp_target_ip': '', 'src_ip': pd.NA, 'dst_ip': pd.NA, 'length': 0,
		'session': '', }
	for column_name, default_value in defaults.items( ):
		if column_name not in df_packets.columns:
			df_packets[ column_name ] = default_value
	df_packets[ 'timestamp' ] = pd.to_datetime( df_packets[ 'timestamp' ], errors='coerce', )
	df_packets = df_packets[ df_packets[ 'ether_type_name' ].isin( ether_types ) ]
	df_packets = df_packets[ df_packets[ 'frame_class' ].isin( frame_classes ) ]
	return df_packets.copy( )

def create_data_link_pie( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the EtherType composition figure.

	Purpose:
	    Displays the share of captured Ethernet frames by outer EtherType.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    go.Figure: EtherType composition chart.
	"""
	throw_if( 'df_packets', df_packets, )
	df_values = (df_packets.groupby( 'ether_type_name' ).size( ).rename( 'frames' ).reset_index( ))
	figure = px.pie( df_values, names='ether_type_name', values='frames', hole=0.58,
		color='ether_type_name', color_discrete_map=cfg.ETHER_TYPE_COLORS,
		category_orders={ 'ether_type_name': cfg.ETHER_TYPE_ORDER, }, )
	figure.update_layout( title='EtherType Composition', uirevision='data-link-ether-types', )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_data_link_bar( df_packets: pd.DataFrame, column_name: str, title: str, ) -> go.Figure:
	"""
	Create a ranked Data Link figure.

	Purpose:
	    Ranks nonempty Layer 2 values by captured frame count.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.
	    column_name (str): Column used for ranking.
	    title (str): Figure title.

	Returns:
	    go.Figure: Ranked horizontal bar chart.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'column_name', column_name, )
	throw_if( 'title', title, )
	df_values = df_packets[ df_packets[ column_name ].fillna( '' ).astype( str ).str.len( ) > 0 ]
	df_values = (
		df_values.groupby( column_name ).size( ).rename( 'frames' ).reset_index( ).nlargest(
			cfg.TOP_MAC_ADDRESS_LIMIT, 'frames', ).sort_values( 'frames' ))
	figure = go.Figure( data=[
		go.Bar( x=df_values[ 'frames' ], y=df_values[ column_name ], orientation='h',
			marker={ 'color': cfg.ACCENT_BLUE, }, text=df_values[ 'frames' ],
			textposition='outside', ) ] )
	figure.update_layout( title=title, xaxis_title='Frames', yaxis_title='', uirevision=title, )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_frame_class_chart( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the frame-class figure.

	Purpose:
	    Compares unicast, multicast, and broadcast Ethernet frame activity.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    go.Figure: Frame-class bar chart.
	"""
	throw_if( 'df_packets', df_packets, )
	df_values = (df_packets.groupby( 'frame_class' ).size( ).rename( 'frames' ).reset_index( ))
	figure = px.bar( df_values, x='frame_class', y='frames', color='frame_class',
		color_discrete_map=cfg.FRAME_CLASS_COLORS,
		category_orders={ 'frame_class': cfg.FRAME_CLASS_ORDER, }, )
	figure.update_layout( title='Frame Classification', xaxis_title='Frame Class',
		yaxis_title='Frames', uirevision='data-link-frame-class', )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_arp_chart( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create the ARP operation figure.

	Purpose:
	    Compares ARP request, reply, and other operation counts.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    go.Figure: ARP operation bar chart.
	"""
	throw_if( 'df_packets', df_packets, )
	df_values = df_packets[ df_packets[ 'arp_operation' ].astype( str ).str.len( ) > 0 ]
	df_values = (df_values.groupby( 'arp_operation' ).size( ).rename( 'frames' ).reset_index( ))
	figure = px.bar( df_values, x='arp_operation', y='frames', color='arp_operation',
		color_discrete_map=cfg.ARP_OPERATION_COLORS,
		category_orders={ 'arp_operation': cfg.ARP_OPERATION_ORDER, }, )
	figure.update_layout( title='ARP Operations', xaxis_title='Operation', yaxis_title='Frames',
		uirevision='data-link-arp', )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_data_link_timeline( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create Data Link activity over time.

	Purpose:
	    Displays one-second unicast, multicast, and broadcast frame rates across the active
	    rolling analysis window.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    go.Figure: Data Link activity timeline.
	"""
	throw_if( 'df_packets', df_packets, )
	df_time = df_packets.dropna( subset=[ 'timestamp', ] ).copy( )
	if df_time.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	current_time = df_time[ 'timestamp' ].max( )
	start_time = current_time - pd.Timedelta( seconds=cfg.TRAFFIC_WINDOW_SECONDS )
	df_time = (df_time[ df_time[ 'timestamp' ] >= start_time ].set_index( 'timestamp' ).groupby(
		'frame_class' ).resample( '1s' ).size( ).rename( 'frames' ).reset_index( ))
	figure = px.area( df_time, x='timestamp', y='frames', color='frame_class',
		color_discrete_map=cfg.FRAME_CLASS_COLORS,
		category_orders={ 'frame_class': cfg.FRAME_CLASS_ORDER, }, )
	figure.update_layout( title='Data Link Activity Over Time', xaxis_title='Time',
		yaxis_title='Frames / Second', uirevision='data-link-timeline', )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, True, )

def create_mac_ip_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create a MAC-to-IP relationship figure.

	Purpose:
	    Displays the strongest observed source MAC-to-source IP bindings as a Sankey
	    diagram for endpoint correlation and duplicate-IP investigation.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    go.Figure: MAC-to-IP relationship Sankey diagram.
	"""
	throw_if( 'df_packets', df_packets, )
	df_bindings = df_packets.dropna( subset=[ 'src_ip', ] ).copy( )
	df_bindings = df_bindings[ df_bindings[ 'src_mac' ].astype( str ).str.len( ) > 0 ]
	df_bindings = (df_bindings.groupby( [ 'src_mac', 'src_ip', ] ).size( ).rename(
		'frames' ).reset_index( ).sort_values( 'frames', ascending=False, ).head(
		cfg.TOP_MAC_IP_RELATIONSHIP_LIMIT ))
	if df_bindings.empty:
		return configure_figure( go.Figure( ), cfg.FLOW_CHART_HEIGHT, False, )
	mac_labels = [ f'MAC: {value}' for value in sorted( df_bindings[ 'src_mac' ].unique( ) ) ]
	ip_labels = [ f'IP: {value}' for value in sorted( df_bindings[ 'src_ip' ].unique( ) ) ]
	labels = mac_labels + ip_labels
	indexes = { label: index for index, label in enumerate( labels ) }
	figure = go.Figure( go.Sankey( node={ 'label': labels, 'pad': 16, 'thickness': 15,
		'color': [ cfg.ACCENT_BLUE ] * len( mac_labels ) + [ cfg.GREEN ] * len( ip_labels ), },
		link={ 'source': [ indexes[ f'MAC: {value}' ] for value in df_bindings[ 'src_mac' ] ],
			'target': [ indexes[ f'IP: {value}' ] for value in df_bindings[ 'src_ip' ] ],
			'value': df_bindings[ 'frames' ], 'color': 'rgba( 0, 120, 252, 0.28 )', }, ) )
	figure.update_layout( title='MAC-to-IP Relationships', uirevision='data-link-mac-ip', )
	return configure_figure( figure, cfg.FLOW_CHART_HEIGHT, False, )

def create_arp_matrix_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create an ARP sender-to-target matrix.

	Purpose:
	    Displays concentration among observed ARP sender and target IPv4 addresses.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    go.Figure: ARP relationship heatmap.
	"""
	throw_if( 'df_packets', df_packets, )
	df_arp = df_packets[ (df_packets[ 'arp_sender_ip' ].astype( str ).str.len( ) > 0) & (
				df_packets[ 'arp_target_ip' ].astype( str ).str.len( ) > 0) ]
	if df_arp.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	df_matrix = (df_arp.groupby( [ 'arp_sender_ip', 'arp_target_ip', ] ).size( ).rename(
		'frames' ).reset_index( ).sort_values( 'frames', ascending=False, ).head(
		cfg.TOP_ARP_RELATIONSHIP_LIMIT ).pivot( index='arp_sender_ip', columns='arp_target_ip',
		values='frames', ).fillna( 0 ))
	figure = go.Figure(
		go.Heatmap( z=df_matrix.values, x=df_matrix.columns, y=df_matrix.index, colorscale='Blues',
			colorbar={ 'title': 'Frames', }, ) )
	figure.update_layout( title='ARP Sender → Target Matrix', xaxis_title='Target IP',
		yaxis_title='Sender IP', uirevision='data-link-arp-matrix', )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def prepare_data_link_editor( df_packets: pd.DataFrame, ) -> pd.DataFrame:
	"""
	Prepare Data Link records for display.

	Purpose:
	    Orders and limits Layer 2 packet records for the read-only frame editor.

	Args:
	    df_packets (pd.DataFrame): Data Link packet records.

	Returns:
	    pd.DataFrame: Display-ready Data Link records.
	"""
	throw_if( 'df_packets', df_packets, )
	columns = [ 'timestamp', 'src_mac', 'dst_mac', 'ether_type_name', 'inner_ether_type_name',
		'frame_class', 'vlan_id', 'vlan_priority', 'arp_operation', 'arp_sender_ip',
		'arp_target_ip', 'length', 'session', ]
	return (
	df_packets.sort_values( 'timestamp', ascending=False, ).head( cfg.PACKET_EDITOR_ROW_LIMIT )[
		columns ])

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
	# Expander - Analysis Mode
	# ----------------------------------------------------
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	with st.expander( label='Analysis Mode', expanded=True, ):
		analysis_mode = st.radio( 'Analysis Mode', options=cfg.ANALYSIS_MODES, key='analysis_mode',
			label_visibility='collapsed', )
	
	# ----------------------------------------------------
	# Expander - Sidebar Controls
	# ----------------------------------------------------
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	with st.expander( label='Controls', expanded=False, ):
		mode = st.radio( 'Capture Mode', options=[ 'Demo / Replay', 'Live (Scapy)', ],
			label_visibility='collapsed', )
		
		if (mode == 'Live (Scapy)' and not SCAPY_AVAILABLE):
			st.error( 'Scapy is not available. Install Scapy and run the application with '
			          'administrator/root privileges.' )
			
			if SCAPY_IMPORT_ERROR:
				st.caption( SCAPY_IMPORT_ERROR )
		
		st.divider( )
		
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
		
		st.divider( )
		
		if st.session_state.running:
			st.success( f'Capture running: {st.session_state.capture_mode}' )
		else:
			st.caption( 'Capture stopped.' )
		
		if st.session_state.capture_error:
			st.error( st.session_state.capture_error )
	
	# ----------------------------------------------------
	# Expander - Sidebar Filters
	# ----------------------------------------------------
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	proto_filter = cfg.PROTOCOL_ORDER.copy( )
	port_range = (0, 65535,)
	ether_type_filter = cfg.ETHER_TYPE_ORDER.copy( )
	frame_class_filter = cfg.FRAME_CLASS_ORDER.copy( )
	ip_version_filter = cfg.IP_VERSION_ORDER.copy( )
	address_scope_filter = cfg.ADDRESS_SCOPE_ORDER.copy( )
	transport_protocol_filter = [ 'TCP', 'UDP', ]
	session_direction_filter = [ 'Bidirectional', 'One-Way', ]
	minimum_session_duration = 0.0
	tls_version_filter = cfg.TLS_VERSION_ORDER.copy( )
	tls_handshake_filter = cfg.TLS_HANDSHAKE_ORDER.copy( )
	application_protocol_filter = cfg.APPLICATION_PROTOCOL_ORDER.copy( )
	dns_query_type_filter = cfg.DNS_QUERY_TYPE_ORDER.copy( )
	http_method_filter = cfg.HTTP_METHOD_ORDER.copy( )
	
	with st.expander( label='Filters', expanded=False, ):
		if analysis_mode == cfg.ANALYSIS_MODE_DATA_LINK:
			ether_type_filter = st.multiselect( 'EtherTypes', options=cfg.ETHER_TYPE_ORDER,
				default=cfg.ETHER_TYPE_ORDER, )
			st.divider( )
			frame_class_filter = st.multiselect( 'Frame Classification',
				options=cfg.FRAME_CLASS_ORDER, default=cfg.FRAME_CLASS_ORDER, )
		elif analysis_mode == cfg.ANALYSIS_MODE_NETWORK_LAYER:
			ip_version_filter = st.multiselect( 'IP Version', options=cfg.IP_VERSION_ORDER,
				default=cfg.IP_VERSION_ORDER, )
			st.divider( )
			address_scope_filter = st.multiselect( 'Destination Address Scope',
				options=cfg.ADDRESS_SCOPE_ORDER, default=cfg.ADDRESS_SCOPE_ORDER, )
		elif analysis_mode == cfg.ANALYSIS_MODE_TRANSPORT:
			transport_protocol_filter = st.multiselect( 'Transport Protocols',
				options=[ 'TCP', 'UDP', ], default=[ 'TCP', 'UDP', ], )
			st.divider( )
			port_range = st.slider( 'Destination Port Range', 0, 65535, (0, 65535,), )
		elif analysis_mode == cfg.ANALYSIS_MODE_SESSION:
			transport_protocol_filter = st.multiselect( 'Session Protocols',
				options=[ 'TCP', 'UDP', 'ICMP', 'ICMPv6', ],
				default=[ 'TCP', 'UDP', 'ICMP', 'ICMPv6', ], )
			st.divider( )
			session_direction_filter = st.multiselect( 'Directionality',
				options=[ 'Bidirectional', 'One-Way', ], default=[ 'Bidirectional', 'One-Way', ], )
			st.divider( )
			minimum_session_duration = st.number_input( 'Minimum Duration — Seconds',
				min_value=0.0,
				value=0.0, step=0.1, )
		elif analysis_mode == cfg.ANALYSIS_MODE_PRESENTATION:
			tls_version_filter = st.multiselect( 'TLS Versions', options=cfg.TLS_VERSION_ORDER,
				default=cfg.TLS_VERSION_ORDER, )
			st.divider( )
			tls_handshake_filter = st.multiselect( 'TLS Handshake Types',
				options=cfg.TLS_HANDSHAKE_ORDER, default=cfg.TLS_HANDSHAKE_ORDER, )
		elif analysis_mode == cfg.ANALYSIS_MODE_APPLICATION:
			application_protocol_filter = st.multiselect( 'Application Protocols',
				options=cfg.APPLICATION_PROTOCOL_ORDER, default=cfg.APPLICATION_PROTOCOL_ORDER, )
			st.divider( )
			dns_query_type_filter = st.multiselect( 'DNS Query Types',
				options=cfg.DNS_QUERY_TYPE_ORDER, default=cfg.DNS_QUERY_TYPE_ORDER, )
			st.divider( )
			http_method_filter = st.multiselect( 'HTTP Methods', options=cfg.HTTP_METHOD_ORDER,
				default=cfg.HTTP_METHOD_ORDER, )
		else:
			proto_filter = st.multiselect( 'Protocols', options=cfg.PROTOCOL_ORDER,
				default=cfg.PROTOCOL_ORDER, )
			st.divider( )
			port_range = st.slider( 'Destination Port Range', 0, 65535, (0, 65535,), )
		st.divider( )
		window_size = st.slider( 'Rolling Window (Packets)', 50, 2000, 500, 50, )

# ==========================================================================================
# Packet Capture Maintenance Fragment
# ==========================================================================================

@st.fragment( run_every=REALTIME_REFRESH_INTERVAL )
def maintain_packet_capture( packet_window_size: int, ) -> None:
	"""
	Maintain packet capture.

	Purpose:
	    Ingests available demonstration or live packet records independently from the
	    selected analysis mode so capture continues while any supported mode is active.

	Args:
	    packet_window_size (int): Maximum number of packet records retained in session
	        state.

	Returns:
	    None: This function updates the retained packet collection.
	"""
	throw_if( 'packet_window_size', packet_window_size, )
	
	ingest_packets( packet_window_size )

# ==========================================================================================
# Network Analysis - Real-Time Summary Fragment
# ==========================================================================================

@st.fragment( run_every=REALTIME_REFRESH_INTERVAL )
def render_realtime_summary( protocols: List[ str ], destination_ports: tuple[ int, int ],
	packet_window_size: int, ) -> None:
	"""
	Render the real-time dashboard summary.

	Purpose:
	    Refreshes executive metrics, packet-rate activity, and network-throughput analysis
	    independently from capture ingestion and the application shell.

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
	
	traffic_column, throughput_column = st.columns( 2, gap='medium', border=True, )
	
	with traffic_column:
		if not df_packets.empty:
			figure_traffic = create_traffic_figure( df_packets )
			
			st.plotly_chart( figure_traffic, use_container_width=True, config=cfg.CHART_CONFIG,
				key='traffic-over-time-chart', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No time-series data is available.' )
	
	with throughput_column:
		df_throughput_packets = (df_packets.dropna(
			subset=[ 'timestamp', 'length', ] ) if not df_packets.empty else pd.DataFrame( ))
		
		if not df_throughput_packets.empty:
			figure_throughput = create_throughput_figure( df_packets )
			
			st.plotly_chart( figure_throughput, use_container_width=True, config=cfg.CHART_CONFIG,
				key='network-throughput-chart', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No throughput data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

# ==========================================================================================
# Network Analysis - Packet Analysis Fragment
# ==========================================================================================

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
		protocol_column, size_column = st.columns( [ 0.82, 1.38, ], gap='medium', border=True, )
		
		with protocol_column:
			figure_protocol = create_protocol_figure( df_packets )
			
			st.plotly_chart( figure_protocol, use_container_width=True, config=cfg.CHART_CONFIG,
				key='protocol-composition-chart', )
		
		with size_column:
			figure_sizes = create_packet_size_figure( df_packets )
			
			st.plotly_chart( figure_sizes, use_container_width=True, config=cfg.CHART_CONFIG,
				key='packet-size-histogram', )
		
		st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
		
		source_column, destination_column = st.columns( 2, gap='medium', border=True, )
		
		with source_column:
			figure_sources = create_endpoint_figure( df_packets, 'src_ip',
				'Top Source IP Addresses', )
			
			st.plotly_chart( figure_sources, use_container_width=True, config=cfg.CHART_CONFIG,
				key='top-source-chart', )
		
		with destination_column:
			figure_destinations = create_endpoint_figure( df_packets, 'dst_ip',
				'Top Destination IP Addresses', )
			
			st.plotly_chart( figure_destinations, use_container_width=True,
				config=cfg.CHART_CONFIG,
				key='top-destination-chart', )
		
		st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	else:
		empty_left, empty_right = st.columns( 2, border=True, )
		
		with empty_left:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No protocol data is available.' )
		
		with empty_right:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
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
		with st.container( height=cfg.PACKET_EDITOR_HEIGHT, border=True, ):
			st.info( 'Waiting for packets…' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

# ==========================================================================================
# Network Analysis - Flow Analysis Fragment
# ==========================================================================================

@st.fragment( run_every=FLOW_REFRESH_INTERVAL )
def render_flow_analysis( protocols: List[ str ], destination_ports: tuple[ int, int ], ) -> None:
	"""
	Render flow and connectivity analysis.

	Purpose:
	    Refreshes destination-port concentration, source-to-destination relationships,
	    TCP flag behavior, endpoint traffic concentration, destination-port trends,
	    endpoint connectivity, and five-tuple flow analysis on a reduced cadence.

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
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No destination-port data is available for the current filters.' )
	else:
		with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
			st.info( 'No destination-port activity is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	if not df_packets.empty:
		df_flow_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
		
		if not df_flow_packets.empty:
			figure_flow = create_flow_figure( df_packets )
			
			st.plotly_chart( figure_flow, use_container_width=True, config=cfg.CHART_CONFIG,
				key='network-flow-sankey', )
		else:
			with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True, ):
				st.info( 'No source-to-destination flow data is available.' )
	else:
		with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True, ):
			st.info( 'No source-to-destination flow data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	flag_column, matrix_column = st.columns( 2, gap='medium', border=True, )
	
	with flag_column:
		if not df_packets.empty:
			df_tcp_flag_packets = df_packets[
				(df_packets[ 'protocol' ] == 'TCP') & (df_packets[ 'dst_port' ].notna( )) & (
					df_packets[ 'flags' ].notna( )) ]
			
			if not df_tcp_flag_packets.empty:
				figure_tcp_flags = create_tcp_flag_heatmap( df_packets )
				
				st.plotly_chart( figure_tcp_flags, use_container_width=True,
					config=cfg.CHART_CONFIG, key='tcp-flag-activity-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
					st.info( 'No TCP flag activity is available for the current filters.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No TCP flag activity is available for the current filters.' )
	
	with matrix_column:
		if not df_packets.empty:
			df_matrix_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
			
			if not df_matrix_packets.empty:
				figure_matrix = create_traffic_matrix_figure( df_packets )
				
				st.plotly_chart( figure_matrix, use_container_width=True, config=cfg.CHART_CONFIG,
					key='source-destination-matrix-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
					st.info( 'No source-to-destination matrix data is available.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No source-to-destination matrix data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	if not df_packets.empty:
		df_port_trend_packets = df_packets.dropna( subset=[ 'timestamp', 'dst_port', ] )
		
		if not df_port_trend_packets.empty:
			figure_port_activity = create_port_activity_figure( df_packets )
			
			st.plotly_chart( figure_port_activity, use_container_width=True,
				config=cfg.CHART_CONFIG, key='port-activity-over-time-chart', )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No destination-port trend data is available for the current filters.' )
	else:
		with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
			st.info( 'No destination-port trend data is available for the current filters.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	fan_out_column, fan_in_column = st.columns( 2, gap='medium', border=True, )
	
	with fan_out_column:
		if not df_packets.empty:
			df_fan_out_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
			
			if not df_fan_out_packets.empty:
				figure_fan_out = create_fan_out_figure( df_packets )
				
				st.plotly_chart( figure_fan_out, use_container_width=True, config=cfg.CHART_CONFIG,
					key='source-fan-out-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
					st.info( 'No source fan-out data is available.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No source fan-out data is available.' )
	
	with fan_in_column:
		if not df_packets.empty:
			df_fan_in_packets = df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] )
			
			if not df_fan_in_packets.empty:
				figure_fan_in = create_fan_in_figure( df_packets )
				
				st.plotly_chart( figure_fan_in, use_container_width=True, config=cfg.CHART_CONFIG,
					key='destination-fan-in-chart', )
			else:
				with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
					st.info( 'No destination fan-in data is available.' )
		else:
			with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
				st.info( 'No destination fan-in data is available.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	
	# ----- Flow Duration Versus Volume ------
	if not df_packets.empty:
		df_scatter_packets = df_packets.dropna(
			subset=[ 'timestamp', 'length', 'src_ip', 'dst_ip', 'protocol', ] )
		
		if not df_scatter_packets.empty:
			figure_flow_scatter = create_flow_scatter_figure( df_packets )
			
			st.plotly_chart( figure_flow_scatter, use_container_width=True,
				config=cfg.CHART_CONFIG,
				key='flow-duration-volume-chart', )
		else:
			with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True, ):
				st.info( 'No five-tuple flow data is available for the current filters.' )
	else:
		with st.container( height=cfg.FLOW_CHART_HEIGHT, border=True, ):
			st.info( 'No five-tuple flow data is available for the current filters.' )
	
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

# ==========================================================================================
# Data Link Analysis Fragment
# ==========================================================================================

@st.fragment( run_every=ANALYSIS_REFRESH_INTERVAL )
def render_data_link_analysis( ether_types: List[ str ], frame_classes: List[ str ], ) -> None:
	"""
	Render Data Link analysis.

	Purpose:
	    Displays Ethernet composition, MAC endpoints, frame classes, ARP relationships,
	    VLAN activity, MAC-to-IP bindings, timelines, and Layer 2 frame records.

	Args:
	    ether_types (List[str]): Included outer EtherType names.
	    frame_classes (List[str]): Included frame classifications.

	Returns:
	    None: This function renders Data Link analysis.
	"""
	throw_if( 'ether_types', ether_types, )
	throw_if( 'frame_classes', frame_classes, )
	df_packets = create_data_link_snapshot( st.session_state.packets, ether_types, frame_classes, )
	st.markdown( '## Data Link Analysis' )
	st.caption( 'OSI Layer 2 • Ethernet • MAC • EtherType • ARP • VLAN • Broadcast • Multicast' )
	m1, m2, m3, m4, m5, m6 = st.columns( 6 )
	m1.metric( 'Frames', f'{len( df_packets ):,}' )
	m2.metric( 'Source MACs',
		f"{df_packets[ 'src_mac' ].replace( '', pd.NA ).nunique( ):,}" if not df_packets.empty
		else '0' )
	m3.metric( 'Destination MACs',
		f"{df_packets[ 'dst_mac' ].replace( '', pd.NA ).nunique( ):,}" if not df_packets.empty
		else '0' )
	m4.metric( 'Broadcast',
		f"{int( df_packets[ 'is_broadcast' ].sum( ) ):,}" if not df_packets.empty else '0' )
	m5.metric( 'Multicast',
		f"{int( df_packets[ 'is_multicast' ].sum( ) ):,}" if not df_packets.empty else '0' )
	m6.metric( 'VLANs', f"{df_packets[ 'vlan_id' ].nunique( ):,}" if not df_packets.empty else
	'0' )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	if df_packets.empty:
		with st.container( height=cfg.SUMMARY_CHART_HEIGHT, border=True, ):
			st.info( 'No Data Link records match the active filters.' )
		return
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_data_link_pie( df_packets ), use_container_width=True,
			config=cfg.CHART_CONFIG, key='data-link-ether-types', )
	with right:
		st.plotly_chart( create_frame_class_chart( df_packets ), use_container_width=True,
			config=cfg.CHART_CONFIG, key='data-link-frame-classes', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_data_link_bar( df_packets, 'src_mac', 'Top Source MAC '
		                                                              'Addresses', ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='data-link-source-macs', )
	with right:
		st.plotly_chart(
			create_data_link_bar( df_packets, 'dst_mac', 'Top Destination MAC Addresses', ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='data-link-destination-macs', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_arp_chart( df_packets ), use_container_width=True,
			config=cfg.CHART_CONFIG, key='data-link-arp', )
	with right:
		st.plotly_chart( create_data_link_timeline( df_packets ), use_container_width=True,
			config=cfg.CHART_CONFIG, key='data-link-timeline', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_arp_matrix_figure( df_packets ), use_container_width=True,
			config=cfg.CHART_CONFIG, key='data-link-arp-matrix', )
	with right:
		st.plotly_chart( create_category_figure( df_packets, 'vlan_id', 'VLAN Activity' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='data-link-vlan', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart(
		create_category_figure( df_packets, 'vlan_priority', 'VLAN Priority Activity' ),
		use_container_width=True, config=cfg.CHART_CONFIG, key='data-link-vlan-priority', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart( create_mac_ip_figure( df_packets ), use_container_width=True,
		config=cfg.CHART_CONFIG, key='data-link-mac-ip', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.markdown( '<div class="sloppy-section-title">Data Link Frame Stream</div>'
	             '<div class="sloppy-section-caption">Most recent Layer 2 records matching the '
	             'active filters.</div>',
		unsafe_allow_html=True, )
	st.data_editor( prepare_data_link_editor( df_packets ), disabled=True, hide_index=True,
		use_container_width=True, height=cfg.PACKET_EDITOR_HEIGHT, key='data-link-editor', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )

# ==========================================================================================
# Additional OSI Analysis Modes
# ==========================================================================================

def create_complete_snapshot( packets: List[ Dict ], ) -> pd.DataFrame:
	"""
	Create a complete packet snapshot.

	Purpose:
	    Converts retained packet dictionaries into a typed DataFrame used by the additional
	    OSI analysis modes without modifying session-state data.

	Args:
	    packets (List[Dict]): Retained normalized packet records.

	Returns:
	    pd.DataFrame: Complete packet snapshot.
	"""
	throw_if( 'packets', packets, )
	df_packets = pd.DataFrame( packets )
	if df_packets.empty:
		return df_packets
	df_packets[ 'timestamp' ] = pd.to_datetime( df_packets[ 'timestamp' ], errors='coerce', )
	return df_packets.copy( )

def create_category_figure( df_packets: pd.DataFrame, column_name: str, title: str, ) -> go.Figure:
	"""
	Create a categorical count figure.

	Purpose:
	    Ranks nonempty categorical values by packet count using a deterministic horizontal
	    bar chart.

	Args:
	    df_packets (pd.DataFrame): Packet or conversation records.
	    column_name (str): Column containing category values.
	    title (str): Figure title.

	Returns:
	    go.Figure: Configured categorical count figure.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'column_name', column_name, )
	throw_if( 'title', title, )
	if column_name not in df_packets.columns:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	df_values = df_packets.copy( )
	df_values[ column_name ] = df_values[ column_name ].fillna( '' ).astype( str ).str.strip( )
	df_values.loc[ df_values[ column_name ] == '', column_name ] = 'Unknown'
	df_values = (
		df_values.groupby( column_name ).size( ).rename( 'packets' ).reset_index( ).sort_values(
			[ 'packets', column_name, ], ascending=[ True, True, ] ).tail( 15 ))
	figure = go.Figure(
		go.Bar( x=df_values[ 'packets' ], y=df_values[ column_name ], orientation='h',
			marker={ 'color': cfg.ACCENT_BLUE, }, text=df_values[ 'packets' ],
			textposition='outside', ) )
	figure.update_layout( title=title, xaxis_title='Packet Count', yaxis_title='',
		uirevision=title, )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_numeric_histogram( df_packets: pd.DataFrame, column_name: str,
	title: str, ) -> go.Figure:
	"""
	Create a numeric distribution figure.

	Purpose:
	    Displays the frequency distribution of a numeric packet or conversation member.

	Args:
	    df_packets (pd.DataFrame): Packet or conversation records.
	    column_name (str): Numeric column to analyze.
	    title (str): Figure title.

	Returns:
	    go.Figure: Configured histogram.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'column_name', column_name, )
	throw_if( 'title', title, )
	if column_name not in df_packets.columns:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	df_values = df_packets.copy( )
	df_values[ column_name ] = pd.to_numeric( df_values[ column_name ], errors='coerce', )
	df_values = df_values.dropna( subset=[ column_name ] )
	figure = go.Figure(
		go.Histogram( x=df_values[ column_name ], nbinsx=30, marker={ 'color': cfg.CYAN, }, ) )
	figure.update_layout( title=title, xaxis_title=column_name.replace( '_', ' ' ).title( ),
		yaxis_title='Frequency', uirevision=title, )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, False, )

def create_timeline_figure( df_packets: pd.DataFrame, category_column: str,
	title: str, ) -> go.Figure:
	"""
	Create a packet-activity timeline.

	Purpose:
	    Aggregates packet records into one-second intervals by a selected category.

	Args:
	    df_packets (pd.DataFrame): Packet records.
	    category_column (str): Category used to split the timeline.
	    title (str): Figure title.

	Returns:
	    go.Figure: Configured time-series figure.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'category_column', category_column, )
	throw_if( 'title', title, )
	if df_packets.empty or category_column not in df_packets.columns:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	df_time = df_packets.dropna( subset=[ 'timestamp', category_column, ] ).copy( )
	if df_time.empty:
		return configure_figure( go.Figure( ), cfg.SUMMARY_CHART_HEIGHT, False, )
	df_time[ 'timestamp' ] = pd.to_datetime( df_time[ 'timestamp' ], errors='coerce', )
	df_time = (
		df_time.set_index( 'timestamp' ).groupby( category_column ).resample( '1s' ).size(
		
		).rename(
			'packets' ).reset_index( ))
	figure = px.line( df_time, x='timestamp', y='packets', color=category_column, markers=True, )
	figure.update_layout( title=title, xaxis_title='Time', yaxis_title='Packets / Second',
		hovermode='x unified', uirevision=title, )
	return configure_figure( figure, cfg.SUMMARY_CHART_HEIGHT, True, )

def render_mode_editor( df_packets: pd.DataFrame, columns: List[ str ], key: str, ) -> None:
	"""
	Render a mode-specific data editor.

	Purpose:
	    Displays the most recent packet or conversation records using only the columns
	    relevant to the selected analysis mode.

	Args:
	    df_packets (pd.DataFrame): Packet or conversation records.
	    columns (List[str]): Ordered editor columns.
	    key (str): Unique Streamlit widget key.

	Returns:
	    None: This function renders a read-only data editor.
	"""
	throw_if( 'df_packets', df_packets, )
	throw_if( 'columns', columns, )
	throw_if( 'key', key, )
	if df_packets.empty:
		with st.container( height=cfg.PACKET_EDITOR_HEIGHT, border=True, ):
			st.info( 'No records are available for the active filters.' )
		return
	existing_columns = [ column for column in columns if column in df_packets.columns ]
	sort_column = 'timestamp' if 'timestamp' in df_packets.columns else 'first_seen'
	df_editor = (
		df_packets.sort_values( sort_column, ascending=False, ).head(
			cfg.PACKET_EDITOR_ROW_LIMIT ))
	st.data_editor( df_editor[ existing_columns ], disabled=True, hide_index=True,
		use_container_width=True, height=cfg.PACKET_EDITOR_HEIGHT, key=key, )

def create_subnet_matrix_figure( df_packets: pd.DataFrame, ) -> go.Figure:
	"""
	Create a source-subnet to destination-subnet matrix.

	Purpose:
	    Aggregates IPv4 traffic into /24 networks and IPv6 traffic into /64 networks to
	    reveal routed communication concentration.

	Args:
	    df_packets (pd.DataFrame): Network Layer packet records.

	Returns:
	    go.Figure: Subnet relationship heatmap.
	"""
	throw_if( 'df_packets', df_packets, )
	rows: List[ Dict ] = [ ]
	for packet in df_packets.dropna( subset=[ 'src_ip', 'dst_ip', ] ).itertuples( ):
		try:
			source = ipaddress.ip_address( packet.src_ip )
			destination = ipaddress.ip_address( packet.dst_ip )
			source_prefix = 24 if source.version == 4 else 64
			destination_prefix = 24 if destination.version == 4 else 64
			rows.append( { 'source_subnet': str(
				ipaddress.ip_network( f'{source}/{source_prefix}', strict=False, ) ),
				'destination_subnet': str(
					ipaddress.ip_network( f'{destination}/{destination_prefix}',
						strict=False, ) ), } )
		except ValueError:
			continue
	df_rows = pd.DataFrame( rows )
	if df_rows.empty:
		return configure_figure( go.Figure( ), cfg.FLOW_CHART_HEIGHT, False, )
	df_matrix = (df_rows.groupby( [ 'source_subnet', 'destination_subnet', ] ).size( ).rename(
		'packets' ).reset_index( ).sort_values( 'packets', ascending=False, ).head(
		cfg.TOP_SUBNET_RELATIONSHIP_LIMIT ).pivot( index='source_subnet',
		columns='destination_subnet', values='packets', ).fillna( 0 ))
	figure = go.Figure(
		go.Heatmap( z=df_matrix.values, x=df_matrix.columns, y=df_matrix.index, colorscale='Blues',
			colorbar={ 'title': 'Packets', }, ) )
	figure.update_layout( title='Source Subnet → Destination Subnet',
		xaxis_title='Destination Subnet', yaxis_title='Source Subnet',
		uirevision='network-subnet-matrix', )
	return configure_figure( figure, cfg.FLOW_CHART_HEIGHT, False, )

@st.fragment( run_every=ANALYSIS_REFRESH_INTERVAL )
def render_network_layer_analysis( ip_versions: List[ int ], address_scopes: List[ str ], ) -> None:
	"""
	Render Network Layer analysis.

	Purpose:
	    Displays IPv4 and IPv6 composition, TTL and hop-limit behavior, DSCP and ECN,
	    fragmentation, ICMP activity, address scopes, subnet relationships, and packet data.

	Args:
	    ip_versions (List[int]): Included IP versions.
	    address_scopes (List[str]): Included destination address scopes.

	Returns:
	    None: This function renders Network Layer analysis.
	"""
	throw_if( 'ip_versions', ip_versions, )
	throw_if( 'address_scopes', address_scopes, )
	df_packets = create_complete_snapshot( st.session_state.packets, )
	if not df_packets.empty:
		df_packets = df_packets[
			df_packets[ 'ip_version' ].isin( ip_versions ) & df_packets[ 'address_scope' ].isin(
				address_scopes ) ]
	st.markdown( '## Network Layer Analysis' )
	st.caption( 'OSI Layer 3 • IPv4 • IPv6 • TTL • Hop Limit • DSCP • ECN • Fragmentation • ICMP' )
	m1, m2, m3, m4, m5, m6 = st.columns( 6 )
	m1.metric( 'Packets', f'{len( df_packets ):,}' )
	m2.metric( 'IPv4',
		f"{int( (df_packets[ 'ip_version' ] == 4).sum( ) ):,}" if not df_packets.empty else '0' )
	m3.metric( 'IPv6',
		f"{int( (df_packets[ 'ip_version' ] == 6).sum( ) ):,}" if not df_packets.empty else '0' )
	m4.metric( 'Source IPs',
		f"{df_packets[ 'src_ip' ].nunique( ):,}" if not df_packets.empty else '0' )
	m5.metric( 'Fragments',
		f"{int( df_packets[ 'is_fragmented' ].fillna( False ).sum( ) ):,}" if not df_packets.empty
		else '0' )
	m6.metric( 'ICMP / ICMPv6',
		f"{int( df_packets[ 'protocol' ].isin( [ 'ICMP', 'ICMPv6', ] ).sum( ) ):,}" if not
		df_packets.empty else '0' )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	if df_packets.empty:
		st.info( 'No Network Layer records match the active filters.' )
		return
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart(
			create_category_figure( df_packets, 'ip_version', 'IP Version Composition' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l3-ip-version', )
	with right:
		df_hops = df_packets.copy( )
		df_hops[ 'effective_hop_limit' ] = df_hops[ 'ttl' ].fillna( df_hops[ 'hop_limit' ] )
		st.plotly_chart( create_numeric_histogram( df_hops, 'effective_hop_limit',
			'TTL / Hop-Limit Distribution' ), use_container_width=True, config=cfg.CHART_CONFIG,
			key='l3-hop-limit', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart(
			create_category_figure( df_packets, 'address_scope', 'Destination Address Scope' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l3-scope', )
	with right:
		st.plotly_chart( create_category_figure( df_packets, 'dscp', 'DSCP Activity' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l3-dscp', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart( create_category_figure( df_packets, 'ecn', 'ECN Activity' ),
		use_container_width=True, config=cfg.CHART_CONFIG, key='l3-ecn', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_timeline_figure( df_packets, 'is_fragmented',
			'Fragmentation Activity Over Time' ), use_container_width=True,
			config=cfg.CHART_CONFIG,
			key='l3-fragment-timeline', )
	with right:
		df_icmp = df_packets[ df_packets[ 'protocol' ].isin( [ 'ICMP', 'ICMPv6', ] ) ]
		st.plotly_chart( create_category_figure( df_icmp, 'icmp_type', 'ICMP Type Activity' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l3-icmp-types', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart( create_subnet_matrix_figure( df_packets ), use_container_width=True,
		config=cfg.CHART_CONFIG, key='l3-subnet-matrix', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	render_mode_editor( df_packets,
		[ 'timestamp', 'ip_version', 'src_ip', 'dst_ip', 'ttl', 'hop_limit', 'ipv6_flow_label',
			'dscp', 'ecn', 'ip_identification', 'ip_flags', 'fragment_offset', 'ipv6_fragment_id',
			'ipv6_more_fragments', 'ipv6_fragment_next_header', 'is_fragmented', 'icmp_type',
			'icmp_code', 'address_scope', 'length', ], 'network-layer-editor', )

@st.fragment( run_every=ANALYSIS_REFRESH_INTERVAL )
def render_transport_analysis( protocols: List[ str ],
	destination_ports: tuple[ int, int ], ) -> None:
	"""
	Render Transport Layer analysis.

	Purpose:
	    Displays TCP and UDP composition, flags, windows, source and destination ports,
	    sequencing indicators, lifecycle activity, and datagram lengths.

	Args:
	    protocols (List[str]): Included transport protocols.
	    destination_ports (tuple[int, int]): Inclusive destination-port range.

	Returns:
	    None: This function renders Transport Layer analysis.
	"""
	throw_if( 'protocols', protocols, )
	throw_if( 'destination_ports', destination_ports, )
	df_packets = create_complete_snapshot( st.session_state.packets, )
	if not df_packets.empty:
		df_packets = df_packets[ df_packets[ 'protocol' ].isin( protocols ) ]
		df_packets = df_packets[ df_packets[ 'dst_port' ].isna( ) | (
				(df_packets[ 'dst_port' ] >= destination_ports[ 0 ]) & (
					df_packets[ 'dst_port' ] <= destination_ports[ 1 ])) ]
	df_packets = identify_transport_indicators( df_packets )
	st.markdown( '## Transport Analysis' )
	st.caption( 'OSI Layer 4 • TCP • UDP • Ports • Flags • Windows • Sequencing Indicators' )
	m1, m2, m3, m4, m5, m6 = st.columns( 6 )
	m1.metric( 'Packets', f'{len( df_packets ):,}' )
	m2.metric( 'TCP',
		f"{int( (df_packets[ 'protocol' ] == 'TCP').sum( ) ):,}" if not df_packets.empty else '0' )
	m3.metric( 'UDP',
		f"{int( (df_packets[ 'protocol' ] == 'UDP').sum( ) ):,}" if not df_packets.empty else '0' )
	m4.metric( 'Possible Retransmissions',
		f"{int( df_packets[ 'possible_retransmission' ].sum( ) ):,}" if not df_packets.empty else
		'0' )
	m5.metric( 'Duplicate ACKs',
		f"{int( df_packets[ 'duplicate_ack' ].sum( ) ):,}" if not df_packets.empty else '0' )
	m6.metric( 'Out-of-Order',
		f"{int( df_packets[ 'out_of_order' ].sum( ) ):,}" if not df_packets.empty else '0' )
	st.caption(
		'Sequencing findings are indicators; capture loss and NIC offload can affect '
		'interpretation.' )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	if df_packets.empty:
		st.info( 'No Transport Layer records match the active filters.' )
		return
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_category_figure( df_packets, 'flags', 'TCP Flag Combinations' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l4-flags', )
	with right:
		st.plotly_chart(
			create_numeric_histogram( df_packets, 'tcp_window', 'TCP Window Distribution' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l4-window', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_category_figure( df_packets, 'src_port', 'Top Source Ports' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l4-source-ports', )
	with right:
		st.plotly_chart( create_category_figure( df_packets, 'dst_port', 'Top Destination Ports' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l4-destination-ports', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart(
			create_timeline_figure( df_packets[ df_packets[ 'protocol' ] == 'TCP' ], 'flags',
				'TCP Lifecycle Activity' ), use_container_width=True, config=cfg.CHART_CONFIG,
			key='l4-lifecycle', )
	with right:
		st.plotly_chart(
			create_numeric_histogram( df_packets[ df_packets[ 'protocol' ] == 'UDP' ],
				'udp_length',
				'UDP Length Distribution' ), use_container_width=True, config=cfg.CHART_CONFIG,
			key='l4-udp-length', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	render_mode_editor( df_packets,
		[ 'timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'flags',
			'tcp_sequence', 'tcp_acknowledgment', 'tcp_window', 'tcp_header_length', 'udp_length',
			'possible_retransmission', 'duplicate_ack', 'out_of_order', 'length', ],
		'transport-editor', )

@st.fragment( run_every=FLOW_REFRESH_INTERVAL )
def render_session_analysis( protocols: List[ str ], directionality: List[ str ],
	minimum_duration: float, ) -> None:
	"""
	Render Session Layer analysis.

	Purpose:
	    Displays bidirectional conversation duration, directional packets and bytes,
	    connection lifecycle, volume, timelines, and conversation-level data.

	Args:
	    protocols (List[str]): Included conversation protocols.
	    directionality (List[str]): Included directionality classifications.
	    minimum_duration (float): Minimum conversation duration in seconds.

	Returns:
	    None: This function renders Session Layer analysis.
	"""
	throw_if( 'protocols', protocols, )
	throw_if( 'directionality', directionality, )
	throw_if( 'minimum_duration', minimum_duration, )
	df_conversations = create_conversation_snapshot(
		create_complete_snapshot( st.session_state.packets, ), datetime.utcnow( ), )
	if not df_conversations.empty:
		df_conversations = df_conversations[
			df_conversations[ 'protocol' ].isin( protocols ) & df_conversations[
				'directionality' ].isin( directionality ) & (
						df_conversations[ 'duration_seconds' ] >= minimum_duration) ]
	st.markdown( '## Session Analysis' )
	st.caption( 'OSI Layer 5 • Bidirectional Conversations • Lifecycle • Directionality • Volume' )
	m1, m2, m3, m4, m5, m6 = st.columns( 6 )
	m1.metric( 'Conversations', f'{len( df_conversations ):,}' )
	m2.metric( 'Bidirectional',
		f"{int( df_conversations[ 'is_bidirectional' ].sum( ) ):,}" if not df_conversations.empty
		else '0' )
	m3.metric( 'One-Way',
		f"{int( (~df_conversations[ 'is_bidirectional' ]).sum( ) ):,}" if not
		df_conversations.empty else '0' )
	m4.metric( 'Avg Duration',
		f"{df_conversations[ 'duration_seconds' ].mean( ):,.2f}s" if not df_conversations.empty
		else '0.00s' )
	m5.metric( 'Longest',
		f"{df_conversations[ 'duration_seconds' ].max( ):,.2f}s" if not df_conversations.empty
		else '0.00s' )
	m6.metric( 'Total Bytes',
		f"{int( df_conversations[ 'total_bytes' ].sum( ) ):,}" if not df_conversations.empty else
		'0' )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	if df_conversations.empty:
		st.info( 'No conversations match the active filters.' )
		return
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_numeric_histogram( df_conversations, 'duration_seconds',
			'Session Duration Distribution' ), use_container_width=True, config=cfg.CHART_CONFIG,
			key='l5-duration', )
	with right:
		st.plotly_chart(
			create_category_figure( df_conversations, 'session_state', 'TCP Session State' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l5-state', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart(
		create_category_figure( df_conversations, 'activity_state', 'Session Activity State' ),
		use_container_width=True, config=cfg.CHART_CONFIG, key='l5-activity-state', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	figure = px.scatter( df_conversations, x='bytes_a_to_b', y='bytes_b_to_a',
		size='total_packets',
		color='protocol',
		hover_data=[ 'endpoint_a', 'endpoint_b', 'duration_seconds', 'session_state', ], )
	figure.update_layout( title='Directional Bytes: A → B vs. B → A', xaxis_title='Bytes A → B',
		yaxis_title='Bytes B → A', uirevision='session-directional-bytes', )
	st.plotly_chart( configure_figure( figure, cfg.FLOW_CHART_HEIGHT, True, ),
		use_container_width=True, config=cfg.CHART_CONFIG, key='l5-directional-bytes', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	render_mode_editor( df_conversations,
		[ 'protocol', 'endpoint_a', 'endpoint_b', 'first_seen', 'last_seen', 'duration_seconds',
			'packets_a_to_b', 'packets_b_to_a', 'bytes_a_to_b', 'bytes_b_to_a', 'total_packets',
			'total_bytes', 'directionality', 'session_state', 'activity_state', 'idle_seconds', ],
		'session-editor', )

@st.fragment( run_every=ANALYSIS_REFRESH_INTERVAL )
def render_presentation_analysis( tls_versions: List[ str ],
	handshake_types: List[ str ], ) -> None:
	"""
	Render Presentation Layer analysis.

	Purpose:
	    Displays observable TLS records, versions, handshake types, SNI, ALPN, selected
	    cipher suites, and capture limitations without decrypting payloads. Certificate
	    parsing is intentionally outside the supported metadata scope.

	Args:
	    tls_versions (List[str]): Included TLS versions.
	    handshake_types (List[str]): Included TLS handshake types.

	Returns:
	    None: This function renders Presentation Layer analysis.
	"""
	throw_if( 'tls_versions', tls_versions, )
	throw_if( 'handshake_types', handshake_types, )
	df_packets = create_complete_snapshot( st.session_state.packets, )
	if not df_packets.empty:
		df_packets = df_packets[ df_packets[ 'tls_version' ].isin( tls_versions ) ]
		handshake_value = df_packets[ 'tls_handshake_type' ].fillna( '' )
		df_packets = df_packets[ (handshake_value == '') | handshake_value.isin( handshake_types
		) ]
	st.markdown( '## Presentation Analysis' )
	st.caption( 'OSI Layer 6 • Observable TLS Record and Handshake Metadata • No Decryption' )
	m1, m2, m3, m4, m5 = st.columns( 5 )
	m1.metric( 'TLS Records', f'{len( df_packets ):,}' )
	m2.metric( 'Versions',
		f"{df_packets[ 'tls_version' ].nunique( ):,}" if not df_packets.empty else '0' )
	m3.metric( 'Server Names',
		f"{df_packets[ 'tls_server_name' ].replace( '', pd.NA ).nunique( ):,}" if not
		df_packets.empty else '0' )
	m4.metric( 'ALPN Values',
		f"{df_packets[ 'tls_alpn' ].replace( '', pd.NA ).nunique( ):,}" if not df_packets.empty
		else '0' )
	m5.metric( 'Cipher Suites',
		f"{df_packets[ 'tls_cipher_suite' ].replace( '', pd.NA ).nunique( ):,}" if not
		df_packets.empty else '0' )
	st.warning(
		'TLS parsing accepts only complete records contained in one TCP payload. It does not '
		'decrypt data or reassemble TLS records split across TCP segments.' )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	if df_packets.empty:
		st.info( 'No observable TLS metadata matches the active filters.' )
		return
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart(
			create_category_figure( df_packets, 'tls_version', 'TLS Version Composition' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l6-version', )
	with right:
		st.plotly_chart(
			create_category_figure( df_packets, 'tls_handshake_type', 'TLS Handshake Types' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l6-handshake', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart(
			create_category_figure( df_packets, 'tls_server_name', 'Top TLS Server Names' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l6-sni', )
	with right:
		st.plotly_chart( create_category_figure( df_packets, 'tls_alpn', 'ALPN Protocols' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l6-alpn', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart( create_category_figure( df_packets, 'tls_cipher_suite', 'TLS Cipher Suites' ),
		use_container_width=True, config=cfg.CHART_CONFIG, key='l6-cipher', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	render_mode_editor( df_packets,
		[ 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'tls_record_type',
			'tls_version',
			'tls_handshake_type', 'tls_server_name', 'tls_alpn', 'tls_cipher_suite', ],
		'presentation-editor', )

@st.fragment( run_every=ANALYSIS_REFRESH_INTERVAL )
def render_application_analysis( application_protocols: List[ str ], dns_query_types: List[ str ],
	http_methods: List[ str ], ) -> None:
	"""
	Render Application Layer analysis.

	Purpose:
	    Displays DNS, unencrypted HTTP, DHCP, and NTP metadata, protocol activity, response
	    conditions, and application-specific packet records.

	Args:
	    application_protocols (List[str]): Included application protocols.
	    dns_query_types (List[str]): Included DNS query types.
	    http_methods (List[str]): Included HTTP request methods.

	Returns:
	    None: This function renders Application Layer analysis.
	"""
	throw_if( 'application_protocols', application_protocols, )
	throw_if( 'dns_query_types', dns_query_types, )
	throw_if( 'http_methods', http_methods, )
	df_packets = create_complete_snapshot( st.session_state.packets, )
	if not df_packets.empty:
		df_packets = df_packets[
			df_packets[ 'application_protocol' ].isin( application_protocols ) ]
		dns_mask = (df_packets[ 'application_protocol' ] != 'DNS') | (
			df_packets[ 'dns_query_type' ].isin( dns_query_types ))
		http_mask = (df_packets[ 'application_protocol' ] != 'HTTP') | (
				(df_packets[ 'http_method' ] == '') | df_packets[ 'http_method' ].isin(
			http_methods ))
		df_packets = df_packets[ dns_mask & http_mask ]
	st.markdown( '## Application Analysis' )
	st.caption( 'OSI Layer 7 • DNS • Unencrypted HTTP • DHCP • NTP' )
	st.warning(
		'HTTP metadata is parsed only when a complete start line and headers are present in one '
		'TCP payload; TCP stream reassembly is not performed; request-response correlation is '
		'limited to observable five-tuple metadata.' )
	m1, m2, m3, m4, m5 = st.columns( 5 )
	m1.metric( 'Application Records', f'{len( df_packets ):,}' )
	m2.metric( 'DNS',
		f"{int( (df_packets[ 'application_protocol' ] == 'DNS').sum( ) ):,}" if not
		df_packets.empty else '0' )
	m3.metric( 'HTTP',
		f"{int( (df_packets[ 'application_protocol' ] == 'HTTP').sum( ) ):,}" if not
		df_packets.empty else '0' )
	m4.metric( 'DHCP',
		f"{int( (df_packets[ 'application_protocol' ] == 'DHCP').sum( ) ):,}" if not
		df_packets.empty else '0' )
	m5.metric( 'NTP',
		f"{int( (df_packets[ 'application_protocol' ] == 'NTP').sum( ) ):,}" if not
		df_packets.empty else '0' )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	if df_packets.empty:
		st.info( 'No Application Layer metadata matches the active filters.' )
		return
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart( create_category_figure( df_packets, 'application_protocol',
			'Application Protocol Composition' ), use_container_width=True,
			config=cfg.CHART_CONFIG,
			key='l7-protocol', )
	with right:
		st.plotly_chart( create_timeline_figure( df_packets, 'application_protocol',
			'Application Activity Over Time' ), use_container_width=True, config=cfg.CHART_CONFIG,
			key='l7-timeline', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		df_dns = df_packets[ df_packets[ 'application_protocol' ] == 'DNS' ]
		st.plotly_chart( create_category_figure( df_dns, 'dns_query', 'Top DNS Queries' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l7-dns-query', )
	with right:
		st.plotly_chart(
			create_category_figure( df_dns, 'dns_response_code', 'DNS Response Codes' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l7-dns-rcode', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	st.plotly_chart( create_category_figure( df_dns, 'dns_query_type', 'DNS Query Types' ),
		use_container_width=True, config=cfg.CHART_CONFIG, key='l7-dns-type', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		df_http = df_packets[ df_packets[ 'application_protocol' ] == 'HTTP' ]
		st.plotly_chart( create_category_figure( df_http, 'http_method', 'HTTP Methods' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l7-http-method', )
	with right:
		st.plotly_chart( create_category_figure( df_http, 'http_status', 'HTTP Status Codes' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l7-http-status', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	left, right = st.columns( 2, gap='medium', border=True, )
	with left:
		st.plotly_chart(
			create_category_figure( df_packets, 'dhcp_message_type', 'DHCP Message Types' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l7-dhcp', )
	with right:
		st.plotly_chart( create_category_figure( df_packets, 'ntp_mode', 'NTP Modes' ),
			use_container_width=True, config=cfg.CHART_CONFIG, key='l7-ntp', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	df_http_transactions = create_http_transaction_snapshot( df_packets, )
	if not df_http_transactions.empty:
		st.markdown( '<div class="sloppy-section-title">HTTP Transactions</div>',
			unsafe_allow_html=True, )
		render_mode_editor( df_http_transactions,
			[ 'request_time', 'response_time', 'client_ip', 'server_ip', 'http_method',
				'http_host',
				'http_path', 'http_status', 'response_seconds', 'transaction_state', ],
			'http-transaction-editor', )
	st.markdown( cfg.BLUE_DIVIDER, unsafe_allow_html=True, )
	render_mode_editor( df_packets,
		[ 'timestamp', 'application_protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
			'dns_query', 'dns_query_type', 'dns_response_code', 'dns_question_count',
			'dns_answer_count', 'dns_authority_count', 'dns_additional_count', 'dns_is_response',
			'dns_recursion_desired', 'dns_recursion_available', 'dns_authoritative',
			'dns_truncated', 'http_method', 'http_host', 'http_path', 'http_status',
			'dhcp_message_type', 'ntp_version', 'ntp_mode', ], 'application-editor', )

# ==========================================================================================
# Analysis Mode Router
# ==========================================================================================

def render_analysis_mode( selected_analysis_mode: str, protocols: List[ str ],
	destination_ports: tuple[ int, int ], packet_window_size: int, ether_types: List[ str ],
	frame_classes: List[ str ], ip_versions: List[ int ], address_scopes: List[ str ],
	transport_protocols: List[ str ], session_directionality: List[ str ],
	minimum_session_duration: float, tls_versions: List[ str ], tls_handshake_types: List[ str ],
	application_protocols: List[ str ], dns_query_types: List[ str ],
	http_methods: List[ str ], ) -> None:
	"""
	Render the selected analysis mode.

	Purpose:
	    Routes the application to Network Analysis or the selected OSI-layer analysis while
	    preserving one packet-ingestion writer and mode-specific filters.

	Args:
	    selected_analysis_mode (str): Selected analysis mode.
	    protocols (List[str]): Network Analysis protocols.
	    destination_ports (tuple[int, int]): Inclusive destination-port range.
	    packet_window_size (int): Maximum retained packet count.
	    ether_types (List[str]): Included EtherType names.
	    frame_classes (List[str]): Included frame classifications.
	    ip_versions (List[int]): Included IP versions.
	    address_scopes (List[str]): Included address scopes.
	    transport_protocols (List[str]): Included transport/session protocols.
	    session_directionality (List[str]): Included session directionality classes.
	    minimum_session_duration (float): Minimum session duration.
	    tls_versions (List[str]): Included TLS versions.
	    tls_handshake_types (List[str]): Included TLS handshake types.
	    application_protocols (List[str]): Included application protocols.
	    dns_query_types (List[str]): Included DNS query types.
	    http_methods (List[str]): Included HTTP methods.

	Returns:
	    None: This function renders the selected mode.
	"""
	throw_if( 'selected_analysis_mode', selected_analysis_mode, )
	throw_if( 'protocols', protocols, )
	throw_if( 'destination_ports', destination_ports, )
	throw_if( 'packet_window_size', packet_window_size, )
	throw_if( 'ether_types', ether_types, )
	throw_if( 'frame_classes', frame_classes, )
	throw_if( 'ip_versions', ip_versions, )
	throw_if( 'address_scopes', address_scopes, )
	throw_if( 'transport_protocols', transport_protocols, )
	throw_if( 'session_directionality', session_directionality, )
	throw_if( 'minimum_session_duration', minimum_session_duration, )
	throw_if( 'tls_versions', tls_versions, )
	throw_if( 'tls_handshake_types', tls_handshake_types, )
	throw_if( 'application_protocols', application_protocols, )
	throw_if( 'dns_query_types', dns_query_types, )
	throw_if( 'http_methods', http_methods, )
	if selected_analysis_mode == cfg.ANALYSIS_MODE_NETWORK:
		render_realtime_summary( protocols, destination_ports, packet_window_size, )
		render_packet_analysis( protocols, destination_ports, )
		render_flow_analysis( protocols, destination_ports, )
	elif selected_analysis_mode == cfg.ANALYSIS_MODE_DATA_LINK:
		render_data_link_analysis( ether_types, frame_classes, )
	elif selected_analysis_mode == cfg.ANALYSIS_MODE_NETWORK_LAYER:
		render_network_layer_analysis( ip_versions, address_scopes, )
	elif selected_analysis_mode == cfg.ANALYSIS_MODE_TRANSPORT:
		render_transport_analysis( transport_protocols, destination_ports, )
	elif selected_analysis_mode == cfg.ANALYSIS_MODE_SESSION:
		render_session_analysis( transport_protocols, session_directionality,
			minimum_session_duration, )
	elif selected_analysis_mode == cfg.ANALYSIS_MODE_PRESENTATION:
		render_presentation_analysis( tls_versions, tls_handshake_types, )
	elif selected_analysis_mode == cfg.ANALYSIS_MODE_APPLICATION:
		render_application_analysis( application_protocols, dns_query_types, http_methods, )
	else:
		raise ValueError( f'Unsupported analysis mode: {selected_analysis_mode}' )

# ==========================================================================================
# Application Rendering
# ==========================================================================================

maintain_packet_capture( window_size )

render_analysis_mode( analysis_mode, proto_filter, port_range, window_size, ether_type_filter,
	frame_class_filter, ip_version_filter, address_scope_filter, transport_protocol_filter,
	session_direction_filter, minimum_session_duration, tls_version_filter, tls_handshake_filter,
	application_protocol_filter, dns_query_type_filter, http_method_filter, )

# ==========================================================================================
# Footer
# ==========================================================================================

st.caption( 'Sloppy Network Analyzer — Live capture via Scapy enabled. '
            'Run with administrator/root privileges for full functionality.' )
