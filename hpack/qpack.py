# -*- coding: utf-8 -*-
"""
hpack/qpack
~~~~~~~~~~~

Implements the QPACK header compression algorithm as detailed by the IETF.
"""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future.utils import raise_from


import logging
import struct

from .table import QPACKHeaderTable, table_entry_size
from .compat import to_byte, to_bytes
from .exceptions import (
    QPACKStreamError, QPACKDecodingError, QPACKOverflowError, QPACKInvalidTableSizeError,
    
)
from .huffman import HuffmanEncoder
from .huffman_constants import (
    REQUEST_CODES, REQUEST_CODES_LENGTH
)
from .huffman_table import decode_huffman
from .struct import HeaderTuple, NeverIndexedHeaderTuple, LinkedList
from .hpack import (
    DEFAULT_MAX_HEADER_LIST_SIZE,
    decode_integer, _unicode_if_needed
)

log = logging.getLogger(__name__)

def encode_quic_int(integer):
    if integer < 0:
        raise ValueError(
            "Can only encode positive integers, got %s" % integer
        )
    word_length = (((integer).bit_length() + 2 + 7) // 8)
    if word_length == 1:
        f = "!B"
        size = 0
    if word_length <= 2:
        f = "!H"
        size = 1
    elif word_length <= 4:
        word_length = 4
        f = "!I"
        size = 2
    elif word_length <= 8:
        word_length = 8
        f = "!L"
        size = 3
    else:
        raise ValueError(
            "Integer can not be encoded in 8 bytes"
        )
    # Alternative
    # n -= 1
    # n |= n>>1
    # n |= n>>2
    # n += 1
    elements = bytearray(word_length)
    struct.pack_into(f,elements,0,integer)
    f[0] |= (size) << 6
    return elements
def decode_quic_int(data):
    size = (data[0] >> 6 )
    if size == 0:
        f = "!B"
        word_length = 1
    if size == 1:
        f = "!H"
        word_length = 2
    elif size == 2:
        f = "!I"
        word_length = 4
    elif size == 3:
        f = "!I"
        word_length = 8
    integer = struct.unpack(f, data)
    integer -= size << (8*word_length-2)
    return integer

class Encoder(object):
    """
    An HPACK encoder object. This object takes HTTP headers and emits encoded
    HTTP/2 header blocks.
    """

    def __init__(self):
        self.header_table = QPACKHeaderTable()
        self.huffman_coder = HuffmanEncoder(
            REQUEST_CODES, REQUEST_CODES_LENGTH
        )
        self.table_size_changes = []
        self.unacked_streams = LinkedList()

    @property
    def header_table_size(self):
        """
        Controls the size of the HPACK header table.
        """
        return self.header_table.maxsize

    @header_table_size.setter
    def header_table_size(self, value):
        minsize = self.header_table.largest_ref - self.unacked_streams.head.value 
        if value < minsize:
            raise QPACKOverflowError("Cannot resize because of unacknowledged headers")
        self.header_table.maxsize = value
        if self.header_table.resized:
            self.table_size_changes.append(value)

    
    def encode(self, headers, huffman=True, can_block=False):
        """
        Takes a set of headers and encodes them into atwo QPACK-encoded header
        blocks, an update block for the control stream and a decode block for
        the data stream

        :param headers: The headers to encode. Must be either an iterable of
                        tuples, an iterable of :class:`HeaderTuple
                        <hpack.struct.HeaderTuple>`, or a ``dict``.

                        If an iterable of tuples, the tuples may be either
                        two-tuples or three-tuples. If they are two-tuples, the
                        tuples must be of the format ``(name, value)``. If they
                        are three-tuples, they must be of the format
                        ``(name, value, sensitive)``, where ``sensitive`` is a
                        boolean value indicating whether the header should be
                        added to header tables anywhere. If not present,
                        ``sensitive`` defaults to ``False``.

                        If an iterable of :class:`HeaderTuple
                        <hpack.struct.HeaderTuple>`, the tuples must always be
                        two-tuples. Instead of using ``sensitive`` as a third
                        tuple entry, use :class:`NeverIndexedHeaderTuple
                        <hpack.struct.NeverIndexedHeaderTuple>` to request that
                        the field never be indexed.

                        .. warning:: QUIC-HTTP requires that all special headers
                            (headers whose names begin with ``:`` characters)
                            appear at the *start* of the header block. While
                            this method will ensure that happens for ``dict``
                            subclasses, callers using any other iterable of
                            tuples **must** ensure they place their special
                            headers at the start of the iterable.

                            For efficiency reasons users should prefer to use
                            iterables of two-tuples: fixing the ordering of
                            dictionary headers is an expensive operation that
                            should be avoided if possible.

        :param huffman: (optional) Whether to Huffman-encode any header sent as
                        a literal value. Except for use when debugging, it is
                        recommended that this be left enabled.

        :returns: A bytestring containing the HPACK-encoded header block.
        """
        # Transforming the headers into a header block is a procedure that can
        # be modeled as a chain or pipe. First, the headers are encoded. This
        # encoding can be done a number of ways. If the header name-value pair
        # are already in the header table we can represent them using the
        # indexed representation: the same is true if they are in the static
        # table. Otherwise, a literal representation will be used.
        log.debug("QPACK encoding %s", headers)
        header_block = []

        # Turn the headers into a list of tuples if possible. This is the
        # natural way to interact with them in HPACK. Because dictionaries are
        # un-ordered, we need to make sure we grab the "special" headers first.
        if isinstance(headers, dict):
            headers = _dict_to_iterable(headers)

        # Before we begin, if the header table size has been changed we need
        # to signal all changes since last emission appropriately.
        if self.header_table.resized:
            header_block.append(self._encode_table_size_change())
            self.header_table.resized = False

       # Add each header to the header block
        for header in headers:
            sensitive = False
            if isinstance(header, HeaderTuple):
                sensitive = not header.indexable
            elif len(header) > 2:
                sensitive = header[2]

            header = (_to_bytes(header[0]), _to_bytes(header[1]))
            header_block.append(self._encode_one(header, sensitive, can_block, huffman))

        header_block = b''.join(header_block)

        log.debug("Encoded header block to %s", header_block)

        return header_block

    def _encode_one(self, header, sensitive, can_block, huffman=False):
        name, value = header
        start = None if can_block else  self.largest_ack_ref

        match = self.header_table.search(name,value, start)

        if match is None:
            encoded = self._encode_literal(name, value, sensitive, huffman)
            if not sensitive:
                self._try_add(name, value)

class Decoder(object):
    """
    An QPACK decoder object.

    .. versionchanged:: 2.3.0
       Added ``max_header_list_size`` argument.

    :param max_header_list_size: The maximum decompressed size we will allow
        for any single header block. This is a protection against DoS attacks
        that attempt to force the application to expand a relatively small
        amount of data into a really large header list, allowing enormous
        amounts of memory to be allocated.

        If this amount of data is exceeded, a `OversizedHeaderListError
        <hpack.OversizedHeaderListError>` exception will be raised. At this
        point the connection should be shut down, as the HPACK state will no
        longer be useable.

        Defaults to 64kB.
    :type max_header_list_size: ``int``
    """

    def __init__(self, max_header_list_size=DEFAULT_MAX_HEADER_LIST_SIZE):
        self.header_table = QPACKHeaderTable()

        #: The maximum decompressed size we will allow for any single header
        #: block. This is a protection against DoS attacks that attempt to
        #: force the application to expand a relatively small amount of data
        #: into a really large header list, allowing enormous amounts of memory
        #: to be allocated.
        #:
        #: If this amount of data is exceeded, a `OversizedHeaderListError
        #: <hpack.OversizedHeaderListError>` exception will be raised. At this
        #: point the connection should be shut down, as the HPACK state will no
        #: longer be usable.
        #:
        #: Defaults to 64kB.
        #:
        #: .. versionadded:: 2.3.0
        self.max_header_list_size = max_header_list_size

        #: Maximum allowed header table size.
        #:
        #: A HTTP/2 implementation should set this to the most recent value of
        #: SETTINGS_HEADER_TABLE_SIZE that it sent *and has received an ACK
        #: for*. Once this setting is set, the actual header table size will be
        #: checked at the end of each decoding run and whenever it is changed,
        #: to confirm that it fits in this size.
        self.max_allowed_table_size = self.header_table.maxsize
        self.blocking_streams = LinkedList()

    @property
    def header_table_size(self):
        """
        Controls the size of the HPACK header table.
        """
        return self.header_table.maxsize

    @header_table_size.setter
    def header_table_size(self, value):
        self.header_table.maxsize = value        



    def update(self, data):
        log.debug("Updating %s", data)

        data_mem = memoryview(data)
        data_len = len(data)
        current_index = 0         

        try:
            while current_index < data_len:
                # Work out what kind of header we're decoding.
                current = to_byte(data[current_index])
                if current & 0x80 == 0x80:
                    # 0b1 - Insert with name reference
                    consumed = self._insert_name_ref(data_mem[current_index:])
                elif current & 0xC0 == 0x40:
                    # 0b01 - Insert without name reference
                    consumed = self._insert_wo_name_ref(data_mem[current_index:])
                elif current & 0xE0 == 0x20:
                    # 0b001 - dynamic table size update
                    consumed = self._dynamic_table_size_update(data_mem[current_index:])
                elif current & 0xE0 == 0x00:
                    # 0b000 - Duplicate
                    consumed = self._insert_dup(data_mem[current_index:])
                else:
                    raise QPACKDecodingError("Invalid instruction")
                current_index += consumed
            self._assert_valid_table_size()
            return self._generate_ack(0), self._resume_streams()
        except QPACKStreamError as e:
            raise
        except Exception as e:
            raise_from(QPACKDecodingError("Error in decoding process",e))

    def decode(self, data, stream_id,  raw=False):
        log.debug("Decoding %s", data)
            
        data_mem = memoryview(data)
        headers = []
        data_len = len(data)
        inflated_size = 0
        current_index = 0   
        discard_headers = False     

        try:
            largest_ref, base, consumed = self._decode_prefix(data_mem)
            current_index += consumed
            if self._check_blocking(stream_id, largest_ref):
                return None, None

            while current_index < data_len:
                # Work out what kind of header we're decoding.
                # If the high bit is 1, it's an indexed field.
                current = to_byte(data[current_index])

                if current & 0x80 == 0x80:
                    # 0b1 - Indexed static or dynamic base ref
                    header, consumed = self._decode_indexed(data_mem[current_index:], largest_ref, base,False)
                elif current & 0xC0 == 0x00:
                    # 0b00 - Literal with name indexed from static or dynamic base ref
                    header, consumed = self._decode_literal_name_ref(data_mem[current_index:], largest_ref, base, False)
                elif current & 0xE0 == 0x30:
                    # 0b011 - literal
                    header, consumed = self._decode_literal_wo_name_ref(data_mem[current_index:])
                elif current & 0xF0 == 0x50:
                    # 0b0101 - literal with indexed name, post base ref
                    header, consumed = self._decode_literal_name_ref(data_mem[current_index:], largest_ref, base, True)
                elif current & 0xF0 == 0x40:
                    # 0b0100 - indexed post base ref
                    header, consumed = self._decode_indexed(data_mem[current_index:], largest_ref, base, True)
                else:
                    raise QPACKDecodingError("Invalid instruction")
                current_index += consumed
                if not discard_headers:
                    if not header:
                        # Header was too large, discard all headers
                        discard_headers = True
                        headers = None
                    else:
                        inflated_size += table_entry_size(*header)
                        if inflated_size > self.max_header_list_size:
                            discard_headers = True
                            headers = None
                        else:
                            headers.append(header)
            self._assert_valid_table_size()
            if not discard_headers:
                try:
                    return (self._generate_ack(stream_id), 
                            [_unicode_if_needed(h, raw) for h in headers])
                except UnicodeDecodeError:
                    raise QPACKDecodingError("Unable to decode headers as UTF-8")
            else:
                raise QPACKOverflowError("A header list larger than %d has been received" % self.max_header_list_size)
        except QPACKStreamError as e:
            # Allow other streams to continue by generating an acknologment
            e.ack = self._generate_ack(stream_id)
            raise
        except Exception as e:
            # Wrap errors in a DecodingError
            raise raise_from(QPACKDecodingError("Error in decoding", self._generate_ack(stream_id)),e)

    def _assert_valid_table_size(self):
        """
        Check that the table size set by the encoder is lower than the maximum
        we expect to have.
        """
        if self.header_table_size > self.max_allowed_table_size:
            raise QPACKInvalidTableSizeError(
                "Encoder did not shrink table size to within the max"
            )            
    def _decode_prefix(self, data_mem):
        current_index = 0
        largest_ref, consumed = decode_integer(data_mem, 8)
        current_index += consumed
        sign = data_mem[current_index] & 0x80
        base_delta, consumed = decode_integer(data_mem[current_index:], 7)
        current_index += consumed
        if sign == 0:
            base = largest_ref + base_delta
        elif base_delta != 0:
            base = largest_ref - base_delta
        else:
            # Illegal: Sign == 1 and base_delta == 0
            raise QPACKDecodingError("Invalid base delta: -0", None)
        return largest_ref, base, current_index
    def _generate_ack(self, stream_id):
        return encode_quic_int(stream_id)
    def _check_blocking(self, stream_id, largest_ref):
        if largest_ref > self.header_table.largest_ref:
            # need to block
            self.blocking_streams.insert(stream_id, largest_ref)
            return True

        return False
    def _resume_streams(self):
        return [i for i,v in self.blocking_streams.popMany(self.header_table.largest_ref)]
    def _decode_indexed(self, data, largest_ref, base, post_base):
        if post_base:
            index, static, current_index = decode_index_post(data, 4, largest_ref, base)
        else:
            index, static, current_index = decode_index(data, 7, largest_ref, base)
        header = self.header_table.get_by_index(index, static)
        return HeaderTuple(*header), current_index
    
    def _decode_literal_wo_name_ref(self, data):
        never_index = data[0] & 0x10
        name, current_index = decode_literal(data, 4)
        value, consumed = decode_literal(data[current_index:], 8)
        current_index += consumed
        if never_index:
            header = NeverIndexedHeaderTuple(name,value)
        else:
            header = HeaderTuple(name,value)
        return header, current_index


    def _decode_literal_name_ref(self, data, largest_ref, base, post_base):
        if post_base:
            never_index = data[0] & 0x08
            index, static, current_index = decode_index_post(data, 3, largest_ref, base)
        else:
            never_index = data[0] & 0x20
            index, static, current_index = decode_index(data, 5, largest_ref, base)
        name = self.header_table.get_by_index(index, static)[0]
        value, consumed = decode_literal(data[current_index:], 8)
        current_index += consumed
        if never_index:
            header = NeverIndexedHeaderTuple(name,value)
        else:
            header = HeaderTuple(name,value)
        return header, current_index        

    def _insert_name_ref(self, data):
        largest_ref = self.header_table.largest_ref
        index, static, current_index = decode_index(data,7,largest_ref, largest_ref )
        name = self.header_table.get_by_index(index, static)[0]
        value, consumed = decode_literal(data[current_index:], 8)
        current_index += consumed
        self.header_table.add(name,value)
        return current_index

    def _insert_wo_name_ref(self, data):   
        name, current_index = decode_literal(data, 6)
        value, consumed = decode_literal(data[current_index:], 8)
        current_index += consumed
        self.header_table.add(name, value)
        return current_index
    def _insert_dup(self, data):
        index, current_index = decode_integer(data, 5)
        index = self.header_table.largest_ref - index
        name,value = self.header_table.get_by_index(index, False)
        self.header_table.add(name,value)
        return current_index
    def _dynamic_table_size_update(self, data):
        size, current_index = decode_integer(data, 5)
        if size > self.max_allowed_table_size:
            raise QPACKInvalidTableSizeError(
                "Encoder exceeded max allowable table size"
            )
        self.header_table_size = size
        return current_index

def decode_literal(data, prefix):
    prefix -= 1
    huff = data[0] & (1<<prefix)
    length, current_index = decode_integer(data, prefix)
    value = data[current_index:current_index + length]
    if len(value) != length:
        raise QPACKDecodingError("Truncated header block")
    if huff:
        value = decode_huffman(value)
    return value, current_index+length
                    
def decode_index(data, prefix, largest_ref, base):
    prefix -= 1
    static = data[0] & (1<<prefix)
    index, consumed = decode_integer(data, prefix)
    if not static:
        index = base - index
        if index > largest_ref:
            raise QPACKDecodingError("Ref (%d) greater than declared largest ref (%d)"%(index,largest_ref))                
    return index, static, consumed            

def decode_index_post(data, prefix, largest_ref, base):
    index, consumed = decode_integer(data, prefix)
    index += base + 1
    if index > largest_ref:
        raise QPACKDecodingError("Ref (%d) greater than declared largest ref (%d)"%(index,largest_ref))                
    return index, False, consumed
