'''
  ******************************************************************************************
      Assembly:                Name
      Filename:                name.py
      Author:                  Terry D. Eppler
      Created:                 05-31-2022

      Last Modified By:        Terry D. Eppler
      Last Modified On:        05-01-2025
  ******************************************************************************************
  <copyright file="guro.py" company="Terry D. Eppler">

	     name.py
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
    name.py
  </summary>
  ******************************************************************************************
'''
from __future__ import annotations

# ==========================================================================================
# PART 1 — Imports, Configuration, and Guardrails
# ==========================================================================================

import random
import time
import threading
import queue
import sqlite3
import scapy
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

# ------------------------------------------------------------------------------------------
# Sloppy Core (existing, unmodified)
# ------------------------------------------------------------------------------------------
from __init__ import Ethernet, IPv4, TCP, UDP, ICMP, HTTP
import config

# ------------------------------------------------------------------------------------------
# Optional Live Capture Backend  
# ------------------------------------------------------------------------------------------
try:
	from scapy.all import sniff, Ether as ScapyEther
	
	SCAPY_AVAILABLE = True
except Exception:
	SCAPY_AVAILABLE = False

BLUE_DIVIDER = "<div style='height:2px;align:left;background:#0078FC;margin:6px 0 10px 0;'></div>"

# ------------------------------------------------------------------------------------------
# Streamlit + Visualization Configuration
# ------------------------------------------------------------------------------------------
st.set_page_config( page_title='Sloppy Joe',
	page_icon=config.ICON, layout='wide' )

sns.set_theme( style='darkgrid' )

# -------------------------------------
# Session State Initialization
# -------------------------------------
if 'packets' not in st.session_state:
	st.session_state.packets: List[ Dict ] = [ ]

if 'running' not in st.session_state:
	st.session_state.running = False

if 'session_id' not in st.session_state:
	st.session_state.session_id = datetime.utcnow( ).strftime( '%Y%m%d_%H%M%S' )

if 'live_queue' not in st.session_state:
	st.session_state.live_queue = queue.Queue( maxsize=5000 )

if 'live_thread' not in st.session_state:
	st.session_state.live_thread = None

# -------------------------------------
# Normalized Packet Record Schema
# -------------------------------------
def normalize_packet( record: Dict ) -> Dict:
	return {
			'timestamp': record.get( 'timestamp', datetime.utcnow( ) ),
			'src_ip': record.get( 'src_ip' ),
			'dst_ip': record.get( 'dst_ip' ),
			'protocol': record.get( 'protocol' ),
			'src_port': record.get( 'src_port' ),
			'dst_port': record.get( 'dst_port' ),
			'flags': record.get( 'flags', "" ),
			'length': record.get( 'length', 0 ),
			'session': st.session_state.session_id,
	}

# -------------------------------------
# Demo Packet Generator
# -------------------------------------
def generate_demo_packet( ) -> Dict:
	proto = random.choice( [ 'TCP',
	                         'UDP',
	                         'ICMP' ] )
	
	record = {
			'timestamp': datetime.utcnow( ),
			'src_ip': f'192.168.1.{random.randint( 1, 50 )}',
			'dst_ip': f'10.0.0.{random.randint( 1, 50 )}',
			'protocol': proto,
			'length': random.randint( 64, 1514 ),
			'src_port': None,
			'dst_port': None,
			'flags': "",
	}
	
	if proto == 'TCP':
		record.update( {
				'src_port': random.randint( 1024, 65535 ),
				'dst_port': random.choice( [ 22,
				                             80,
				                             443,
				                             3389 ] ),
				'flags': random.choice( [ 'SYN',
				                          'ACK',
				                          'PSH',
				                          'FIN',
				                          'RST' ] ),
		} )
	
	elif proto == 'UDP':
		record.update( {
				'src_port': random.randint( 1024, 65535 ),
				'dst_port': random.choice( [ 53,
				                             123,
				                             161 ] ),
		} )
	
	else:
		record[ 'flags' ] = random.choice( [
				'ECHO_REQUEST',
				'ECHO_REPLY',
				'DEST_UNREACH',
				'TTL_EXCEEDED',
		] )
	
	return normalize_packet( record )

# -------------------------------------
# LIVE Capture Callback
# -------------------------------------
def scapy_callback( packet ) -> None:
	try:
		if not packet.haslayer( ScapyEther ):
			return
		
		raw = bytes( packet )
		eth = Ethernet( raw )
		
		if eth.proto != 8:  # IPv4
			return
		
		ip = IPv4( eth.data )
		base = {
				'timestamp': datetime.utcnow( ),
				'src_ip': ip.src,
				'dst_ip': ip.target,
				'length': len( raw ),
		}
		
		if ip.proto == 6:
			tcp = TCP( ip.data )
			base.update( {
					'protocol': 'TCP',
					'src_port': tcp.src_port,
					'dst_port': tcp.dest_port,
					'flags': "".join( [
							f for f, v in {
									'SYN': tcp.flag_syn,
									'ACK': tcp.flag_ack,
									'FIN': tcp.flag_fin,
									'RST': tcp.flag_rst,
									'PSH': tcp.flag_psh,
									'URG': tcp.flag_urg,
							}.items( ) if v
					] )
			} )
		elif ip.proto == 17:
			udp = UDP( ip.data )
			base.update( {
					'protocol': 'UDP',
					'src_port': udp.src_port,
					'dst_port': udp.dest_port,
			} )
		elif ip.proto == 1:
			icmp = ICMP( ip.data )
			base.update( {
					'protocol': 'ICMP',
					'flags': f'TYPE_{icmp.type}',
			} )
		else:
			return
		
		st.session_state.live_queue.put_nowait( normalize_packet( base ) )
	except Exception:
		pass

# -------------------------------------
# LIVE Capture Thread Controller
# -------------------------------------
def start_live_capture():
    sniff(prn=scapy_callback, store=False)


# -------------------------------------
# Header / Branding
# -------------------------------------
with st.container():
    col_logo, col_title = st.columns([5, 1])

    with col_logo:
        st.markdown('###  Network Analyzer')
        st.caption('Packet Metadata • Flow Analytics • Protocol Intelligence')

    with col_title:
	    st.caption('')


# -------------------------------------
# Sidebar Controls
# -------------------------------------
with st.sidebar:
    st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )
    st.subheader('Controls')
    mode = st.radio( ' ', options=['Demo / Replay', 'Live (Scapy)'] )

    if mode == 'Live (Scapy)' and not SCAPY_AVAILABLE:
        st.error( 'Scapy not available. Install scapy and run with admin/root privileges.' )

    c1, c2 = st.columns(2)

    with c1:
        if st.button('▶ Start', use_container_width=True):
            st.session_state.running = True

            if (
                mode == 'Live (Scapy)'
                and SCAPY_AVAILABLE
                and st.session_state.live_thread is None
            ):
                st.session_state.live_thread = threading.Thread(
                    target=start_live_capture,
                    daemon=True
                )
                st.session_state.live_thread.start()

    with c2:
        if st.button('■ Stop', use_container_width=True):
            st.session_state.running = False

    st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )

    st.subheader('Filters')

    proto_filter = st.multiselect(
        'Protocols',
        options=['TCP', 'UDP', 'ICMP'],
        default=['TCP', 'UDP', 'ICMP'],
    )

    port_range = st.slider(
        'Destination Port Range',
        0, 65535, (0, 65535)
    )

    window_size = st.slider( 'Rolling Window (Packets)',
        50, 2000, 500, 50 )


# -------------------------------------
# Ingestion Loop
# -------------------------------------
if st.session_state.running:

    if mode == 'Demo / Replay':
        for _ in range(random.randint(5, 15)):
            st.session_state.packets.append(
                generate_demo_packet()
            )

    elif mode == 'Live (Scapy)' and SCAPY_AVAILABLE:
        while not st.session_state.live_queue.empty():
            st.session_state.packets.append(
                st.session_state.live_queue.get()
            )

    st.session_state.packets = (
        st.session_state.packets[-window_size:]
    )

    time.sleep(0.2)


# -------------------------------------
# DataFrame Assembly & Filtering
# -------------------------------------
df = pd.DataFrame(st.session_state.packets)

if not df.empty:
    df = df[df['protocol'].isin(proto_filter)]
    df = df[
        df['dst_port'].isna()
        | (
            (df['dst_port'] >= port_range[0])
            & (df['dst_port'] <= port_range[1])
        )
    ]


# -------------------------------------
# Executive Metrics
# -------------------------------------
with st.container():
    m1, m2, m3, m4, m5 = st.columns( 5, border=True )

    m1.metric('Packets', len(df))
    m2.metric(
        'Unique Src IPs',
        df['src_ip'].nunique() if not df.empty else 0
    )
    m3.metric(
        'Unique Dst IPs',
        df['dst_ip'].nunique() if not df.empty else 0
    )
    m4.metric(
        'Avg Packet Size',
        int(df['length'].mean()) if not df.empty else 0
    )
    m5.metric(
        'Protocols Seen',
        df['protocol'].nunique() if not df.empty else 0
    )

    st.markdown(BLUE_DIVIDER, unsafe_allow_html=True)


# -------------------------------------
# Visualizations
# -------------------------------------
with st.container():
    left, right = st.columns( 2, border=True, vertical_alignment='center' )

    with left:
        st.text('Protocol Distribution')
        if not df.empty:
            fig, ax = plt.subplots()
            sns.countplot(data=df, x='protocol', ax=ax)
            st.pyplot(fig)
        else:
            st.info('No protocol data available.')

    with right:
        st.text('Traffic Over Time')
        if not df.empty:
            now = df['timestamp'].max()
            window_seconds = 60

            df_recent = df[
                df['timestamp']
                >= (now - pd.Timedelta(seconds=window_seconds))
            ]

            if not df_recent.empty:
                fig, ax = plt.subplots()

                (
                    df_recent
                    .set_index('timestamp')
                    .resample('1S')
                    .size()
                    .plot(ax=ax)
                )

                ax.set_ylabel('Packets / Second')
                ax.set_xlabel('Time (last 60s)')
                st.pyplot(fig)
            else:
                st.info('No recent packets in time window.')
        else:
            st.info('No time-series data available.')

    st.markdown( BLUE_DIVIDER, unsafe_allow_html=True )


# -------------------------------------
# Packet Stream
# -------------------------------------
st.text('Live Packet Stream')

if not df.empty:
    st.dataframe(
        df.sort_values('timestamp', ascending=False),
        use_container_width=True,
        height=400
    )
else:
    st.info('Waiting for packets…')

st.caption(
    'Sloppy Network Analyzer — Live capture via Scapy enabled. '
    'Run with administrator/root privileges for full functionality.'
)
