#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import pyparsing as pp
from base64 import b64decode

class P1735Parser:
    
    def __init__(self):
        self.session_keys = {}
        self.encrypted_data = None
        self.info = {}
        self.base64_buf = []
        self.key_block = False
        self.data_block = False
        self.p1735 = False

        protect_kw = pp.Keyword('`protect').suppress()
        identifier = pp.Word(pp.alphas, pp.alphanums + "_")
        number = pp.Word(pp.nums).setParseAction(lambda t: int(t[0]))
        string = pp.dblQuotedString().setParseAction(pp.removeQuotes)
        equals = pp.Suppress("=")
        lbrace = pp.Suppress('(')
        rbrace = pp.Suppress(')')
        simpleAssignment = (identifier + equals + (number | string)).setParseAction(self.assignment_action)
        multiAssignment = simpleAssignment + pp.ZeroOrMore(',' + simpleAssignment)
        tupleAssignment = identifier + equals + lbrace + multiAssignment + rbrace
        assignment = protect_kw + (multiAssignment | tupleAssignment)
        
        PSTART = (protect_kw + pp.CaselessLiteral('begin_protected')).setParseAction(self.begin)
        PFINISH = (protect_kw + pp.CaselessLiteral('end_protected')).setParseAction(self.finish)

        key_block = (protect_kw + pp.CaselessLiteral('key_block')).setParseAction(self.begin_key_block)
        data_block = (protect_kw + pp.CaselessLiteral('data_block')).setParseAction(self.begin_data_block)
    
        base64_string = pp.Word(pp.alphanums + "+-/=").setParseAction(self.base64_action)
        emptyLine = (pp.LineStart() + pp.LineEnd()).suppress()
        
        self.parser = (PSTART | assignment | key_block | data_block | base64_string | emptyLine | PFINISH)
        
    def feed(self, line):
        self.parser.parseString(line)
        
    def begin(self):
        """
        Triggered at "protect begin_protected" string
        """
        self.p1735 = True
        
    def finish(self):
        """
        Indicates end pf parsing
        """
        self.p1735 = False
        self.finish_data_block()

    def begin_key_block(self):
        self.key_block = True

    def finish_key_block(self):
        if self.key_block:
            self.key_block = False
            key = self.info['key_keyname']
            value = b64decode(''.join(self.base64_buf))
            self.session_keys.update({key: value})
            self.base64_buf = []
            assert self.info['key_method'].lower() == 'rsa'
            
    def begin_data_block(self):
        self.data_block = True

    def finish_data_block(self):
        if self.data_block:
            self.data_block = False
            self.encrypted_data = b64decode(''.join(self.base64_buf))
            self.base64_buf = []
            assert self.info['data_method'].lower() == 'aes128-cbc'
            
    def assignment_action(self, toks):
        assert self.p1735 == True
        assert len(toks) == 2
        key = toks[0]
        value = toks[1]
        self.info.update({key: value})
        self.finish_key_block()

    def base64_action(self, tok):
        self.base64_buf.append(tok[0])

    def __repr__(self):
        s = []
        s.append("Available keys:")
        i = 0
        for keyname, key in self.session_keys.iteritems():
            s.append("%2i.    keylength = %4i, keyname = %s" % (i, len(key), keyname))
            i += 1
        s.append("Data block length = %i bytes" % len(self.encrypted_data))
        return '\n'.join(s)

if __name__ == "__main__":
    import sys
    p = P1735Parser()
    with open(sys.argv[1], "r") as fd:
        for line in fd.readlines():
            try:
                p.feed(line)
            except pp.ParseException:
                print "Failed at : %s" % line
                sys.exit(1)
    print p
