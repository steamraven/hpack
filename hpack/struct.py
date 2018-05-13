# -*- coding: utf-8 -*-
"""
hpack/struct
~~~~~~~~~~~~

Contains utility structures including those representing header fields with associated metadata.
"""


class HeaderTuple(tuple):
    """
    A data structure that stores a single header field.

    HTTP headers can be thought of as tuples of ``(field name, field value)``.
    A single header block is a sequence of such tuples.

    In HTTP/2, however, certain bits of additional information are required for
    compressing these headers: in particular, whether the header field can be
    safely added to the HPACK compression context.

    This class stores a header that can be added to the compression context. In
    all other ways it behaves exactly like a tuple.
    """
    __slots__ = ()

    indexable = True

    def __new__(_cls, *args):
        return tuple.__new__(_cls, args)


class NeverIndexedHeaderTuple(HeaderTuple):
    """
    A data structure that stores a single header field that cannot be added to
    a HTTP/2 header compression context.
    """
    __slots__ = ()

    indexable = False


class LLNode(object):
    __slots__ = ("next","key","value")
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None
class LinkedList(object):
    def __init__(self):
        self.head = None
        self.tail = None

    def popSmallest(self):
        node = self.head
        self.head = node.next
        if node.next is None:
            self.tail = self.head 
        return node
    def popMany(self, value):
        # TODO: handle tail
        results = []
        node = self.head
        while node:
            if node.value > value:
                break
            results.append((node.key, node.value))
            node = node.next
        self.head = node


    def insert(self, key, value):
        new_node = LLNode(key,value)
        if self.head is None:
            self.tail = self.head = new_node
            return
        if value >= self.tail.value:
            self.tail.next = new_node
            self.tail = new_node
            return
        prev = self.head
        if value < prev.value:
            new_node.next = prev
            self.head = new_node
            return
        node = prev.next
        while (node):
            if node.value >= value:
                prev.next = new_node
                new_node.next = node
                return
            prev = node
            node = prev.next
        assert False, "Should not get here"
    def __delitem__(self, key):
        if self.head is None:
            raise KeyError("%s not found" % key)
        prev = self.head
        if prev.key == key:
            self.head = prev.next
            if prev.next is None:
                self.tail = self.head
            return prev.key, prev.value
        node = prev.next
        while (node):
            if node.key == key:
                prev.next = node.next
                if node.next == None:
                    self.tail = prev
                return node.key, node.value
            prev = node
            node = prev.next
        raise KeyError("%s not found" % key)
    def __getitem__(self, key):
        node = self.head
        while node:
            if node.key == key:
                return node.value
        raise KeyError("%s not found" % key)
    def __setitem__(self, key, value):
        node = self.head
        while node:
            if node.key == key:
                prev = node.value
                node.value = value
                return prev
        raise KeyError("%s not found" % key)        
    
        