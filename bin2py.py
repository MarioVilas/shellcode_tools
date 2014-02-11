#!/usr/bin/env python

# Convert binary files to data embedded in Python sources
# by Mario Vilas (mvilas at gmail.com)

# Copyright (c) 2009-2011, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import glob
import string
import base64
import zlib
import gzip

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO


helpMessage = '''Convert binary files to data embedded in Python sources
by Mario Vilas (mvilas at gmail.com)

Usage:

    ./%s {input} [switches]

Where "input" is a glob-style filename list, and "switches" can be a combination of the following:

    -a                  Append output instead of overwriting
    -b                  Encode with base64
    -d                  Add python code to decode the string
    -g                  Compress with gzip
    -o filename         Specify a single output file
    -x                  Convert to hexadecimal, instead of using repr()
    -z                  Compress with zlib'''


def showHelp(e = None):
    if e: print "Error: %s\n" % e
    print helpMessage % os.path.basename(sys.argv[0])


def parseCommandLine():
    
    argv = []
    for i in range(1, len(sys.argv)):
        token = sys.argv[i]
        if token[0] in ('-', '/'):
            for c in token[1:]:
                argv.append('-' + c)
        else:
            argv.append(token)
    
    if not argv: raise Exception, "no parameters supplied"
    
    input       = []
    output      = []
    
    appendflag  = False
    hexaflag    = False
    zlibflag    = False
    gzipflag    = False
    base64flag  = False
    decoderflag = False
    
    i = 0
    while i < len(argv):
        token = argv[i]
        if token[0] == '-':
            s = token[1].lower()
            if s == 'o':                                                                    # output filename
                if output: raise Exception, "inconsistent switch: %s" % s
                i += 1
                if i >= len(argv): raise Exception, "expected parameter after switch -%s" % s
                output_filename = argv[i]
                if output_filename[0] == '-': raise Exception, "unexpected argument: %r" % token
                output_filename = os.path.abspath(output_filename)
                output.append(output_filename)
            elif s == 'a':                                                                  # append output
                appendflag = True
            elif s == 'b':                                                                  # base64 encoding
                base64flag = True
            elif s == 'd':                                                                  # write decoder
                decoderflag = True
            elif s == 'g':                                                                  # gzip compression
                if zlibflag: raise Exception, "inconsistent switch -%s" % s
                gzipflag = True
            elif s == 'x':                                                                  # use hexadecimal
                hexaflag = True
            elif s == 'z':                                                                  # zlib compression
                if gzipflag: raise Exception, "inconsistent switch -%s" % s
                zlibflag = True
            else:
                raise Exception, "unknown switch -%s" % s
        else:                                                                               # input filename list
            filelist = glob.glob(token)
            if not filelist: raise Exception, "can't find file(s): %r" % token
            input += filelist
        i += 1
    
    if decoderflag and not (gzipflag or zlibflag or base64flag): decoderflag = False
    
    return input, output, appendflag, hexaflag, zlibflag, gzipflag, base64flag, decoderflag


def gzipCompress(data):
    sf = StringIO.StringIO()
    gf = gzip.GzipFile('', 'wb', 9, sf)
    gf.write(data)
    gf.close()
    sf.seek(0)
    data = sf.read()
    sf.close()
    return data


def sanitizeVariableName(dirty):
    valid  = string.digits
    valid += string.letters
    valid += '_'
    clean = ''
    for c in dirty:
        if not c in valid:
            c = '_'
        clean += c
    return clean


def hexData(data, varname = 'document', align = 32):
    hexdata  = '%s  = ""\n' % varname
    if align > 0:
        r = range(0, len(data), align)
    else:
        r = range(0, len(data))
    for i in r:
        hexdata += '%s += "' % varname
        for c in data[i:i+align]:
            hexdata += r'\x%s' % hex(ord(c))[2:].zfill(2)
        hexdata += '"\n'
    return hexdata


def reprData(data, varname = 'document', max = 32):
    reprdata = '%s  = %r\n' % (varname, '')
    prefix   = '%s += ' % varname
    suffix   = '\n'
    if max > 0:
        for i in range(0, len(data), max):
            reprdata += prefix + repr(data[i:i+max]) + suffix
    else:
        reprdata += prefix + repr(data) + suffix
    return reprdata


def putDecoder(zlibflag, gzipflag, base64flag):
    code = ''
    if zlibflag:
        code += 'import zlib\n'
    if gzipflag:
        code += 'import gzip\n'
        code += 'import StringIO\n'
    if base64flag:
        code += 'import base64\n'
    code += '\n'
    code += 'def decode(data):\n'
    if base64flag:
        code += '    data = base64.decodestring(data)\n'
    if zlibflag:
        code += '    data = zlib.decompress(data)\n'
    elif gzipflag:
        code += '    sf = StringIO.StringIO()\n'
        code += '    sf.write(data)\n'
        code += '    sf.seek(0)\n'
        code += '    gf = gzip.GzipFile("", "rb", 9, sf)\n'
        code += '    data = gf.read()\n'
        code += '    gf.close()\n'
        code += '    sf.close()\n'
    code += '    return data\n'
    code += '\n'
    return code


def main():
    
    try:
        input, output, appendflag, hexaflag, zlibflag, gzipflag, base64flag, decoderflag = parseCommandLine()
    except Exception, e:
        showHelp(e)
        return
    
    single_output = bool(output)
    
    if single_output:
        if appendflag:
            ofile = open(output[0], 'a')
        else:
            ofile = open(output[0], 'w')
        if decoderflag:
            ofile.write(putDecoder(zlibflag, gzipflag, base64flag))
    
    count = 0
    for filename in input:
        
        filename = os.path.abspath(filename)
        
        if filename in output: continue
        
        data = open(filename, 'rb').read()
        
        if zlibflag:
            data = zlib.compress(data, 9)
        elif gzipflag:
            data = gzipCompress(data)
        
        if single_output:
            varname = os.path.splitext(os.path.basename(filename))[0]
            varname = sanitizeVariableName(varname)
        else:
            varname = 'document'
        
        if base64flag:
            data = '%s = %r\n' % (varname, base64.encodestring(data))
        elif hexaflag:
            data = hexData(data, varname)
        else:
            data = reprData(data, varname)
        
        if decoderflag:
            data += '%s = decode(%s)\n' % (varname, varname)
        
        if single_output:
            data += '\n'
            ofile.write(data)
        else:
            filename += '.py'
            if decoderflag:
                data = putDecoder(zlibflag, gzipflag, base64flag) + data
            if appendflag:
                open(filename, 'a').write(data)
            else:
                open(filename, 'w').write(data)
            output.append(filename)
        
        count += 1
    
    if single_output:
        ofile.close()
    
    if count == 1:
        print "1 file processed."
    else:
        print "%i files processed." % count


if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main()
