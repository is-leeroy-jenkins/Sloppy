'''
  ******************************************************************************************
      Assembly:                Sloppy
      Filename:                __init__.py
      Author:                  Terry D. Eppler
      Created:                 05-31-2022

      Last Modified By:        Terry D. Eppler
      Last Modified On:        05-01-2025
  ******************************************************************************************
  <copyright file="__init__.py" company="Terry D. Eppler">

	    __init__.py
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
    __init__.py
  </summary>
  ******************************************************************************************
'''
import textwrap
import socket
import struct
import time
from typing import Any

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def get_mac_addr( mac_raw ):
	'''
		
		Purpose:
		_______
		Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
	
	'''
	byte_str = map( '{:02x}'.format, mac_raw )
	mac_addr = ':'.join( byte_str ).upper( )
	return mac_addr


def format_multi_line( prefix, string, size=80 ):
    '''
	    
	    Purpose:
	    _______
	    Formats multi-line data
	    
    '''
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join( [ prefix + line for line in textwrap.wrap( string, size ) ] )

def throw_if( name: str, value: Any ) -> None:
	'''

		Purpose:
		-----------
		Simple guard which raises ValueError when `value` is falsy (None, empty).

		Parameters:
		-----------
		name (str): Variable name used in the raised message.
		value (Any): Value to validate.

		Returns:
		-----------
		None: Raises ValueError when `value` is falsy.

	'''
	if value is None:
		raise ValueError( f"Argument '{name}' cannot be empty!" )

class Ethernet( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		dest, src, prototype = struct.unpack( '! 6s 6s H', raw_data[ :14 ] )
		
		self.dest_mac = get_mac_addr( dest )
		self.src_mac = get_mac_addr( src )
		self.proto = socket.htons( prototype )
		self.data = raw_data[ 14: ]

class Pcap( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, filename, link_type=1 ):
		self.pcap_file = open( filename, 'wb' )
		self.pcap_file.write( struct.pack( '@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type
		) )
	
	def write( self, data ):
		ts_sec, ts_usec = map( int, str( time.time( ) ).split( '.' ) )
		length = len( data )
		self.pcap_file.write( struct.pack( '@ I I I I', ts_sec, ts_usec, length, length ) )
		self.pcap_file.write( data )
	
	def close( self ):
		self.pcap_file.close( )

class IPv4( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		version_header_length = raw_data[ 0 ]
		self.version = version_header_length >> 4
		self.header_length = (version_header_length & 15) * 4
		self.ttl, self.proto, src, target = struct.unpack( '! 8x B B 2x 4s 4s', raw_data[ :20 ] )
		self.src = self.ipv4( src )
		self.target = self.ipv4( target )
		self.data = raw_data[ self.header_length: ]
	
	def ipv4( self, addr ):
		return '.'.join( map( str, addr ) )

class ICMP( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		self.type, self.code, self.checksum = struct.unpack( '! B B H', raw_data[ :4 ] )
		self.data = raw_data[ 4: ]

class TCP( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		(self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = (
				struct.unpack(
			'! H H L L H', raw_data[ :14 ] ))
		offset = (offset_reserved_flags >> 12) * 4
		self.flag_urg = (offset_reserved_flags & 32) >> 5
		self.flag_ack = (offset_reserved_flags & 16) >> 4
		self.flag_psh = (offset_reserved_flags & 8) >> 3
		self.flag_rst = (offset_reserved_flags & 4) >> 2
		self.flag_syn = (offset_reserved_flags & 2) >> 1
		self.flag_fin = offset_reserved_flags & 1
		self.data = raw_data[ offset: ]

class UDP( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		self.src_port, self.dest_port, self.size = struct.unpack( '! H H 2x H', raw_data[ :8 ] )
		self.data = raw_data[ 8: ]

class HTTP( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		try:
			self.data = raw_data.decode( 'utf-8' )
		except:
			self.data = raw_data

class ICMP( ):
	'''
	
		Purpose:
		_______
	
	
	'''
	def __init__( self, raw_data ):
		self.type, self.code, self.checksum = struct.unpack( '! B B H', raw_data[ :4 ] )
		self.data = raw_data[ 4: ]
