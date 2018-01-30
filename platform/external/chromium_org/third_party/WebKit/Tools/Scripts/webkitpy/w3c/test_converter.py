#!/usr/bin/env python

# Copyright (C) 2013 Adobe Systems Incorporated. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer.
# 2. Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following
#    disclaimer in the documentation and/or other materials
#    provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import logging
import re

from webkitpy.common.host import Host
from webkitpy.common.webkit_finder import WebKitFinder
from webkitpy.thirdparty.BeautifulSoup import BeautifulSoup, Tag


_log = logging.getLogger(__name__)


class W3CTestConverter(object):

    def __init__(self):
        self._host = Host()
        self._filesystem = self._host.filesystem
        self._webkit_root = WebKitFinder(self._filesystem).webkit_base()

        # These settings might vary between WebKit and Blink
        self._css_property_file = self.path_from_webkit_root('Source', 'core', 'css', 'CSSPropertyNames.in')
        self._css_property_split_string = 'alias_for='

        self.prefixed_properties = self.read_webkit_prefixed_css_property_list()

        prop_regex = '([\s{]|^)(' + "|".join(prop.replace('-webkit-', '') for prop in self.prefixed_properties) + ')(\s+:|:)'
        self.prop_re = re.compile(prop_regex)

    def path_from_webkit_root(self, *comps):
        return self._filesystem.abspath(self._filesystem.join(self._webkit_root, *comps))

    def read_webkit_prefixed_css_property_list(self):
        prefixed_properties = []
        unprefixed_properties = set()

        contents = self._filesystem.read_text_file(self._css_property_file)
        for line in contents.splitlines():
            if re.match('^(#|//)', line):
                # skip comments and preprocessor directives
                continue
            fields = line.split(self._css_property_split_string)
            for prop in fields:
                # Find properties starting with the -webkit- prefix.
                match = re.match('-webkit-([\w|-]*)', prop)
                if match:
                    prefixed_properties.append(match.group(1))
                else:
                    unprefixed_properties.add(prop.strip())

        # Ignore any prefixed properties for which an unprefixed version is supported
        return [prop for prop in prefixed_properties if prop not in unprefixed_properties]

    def convert_for_webkit(self, new_path, filename):
        """ Converts a file's |contents| so it will function correctly in its |new_path| in Webkit.

        Returns the list of modified properties and the modified text if the file was modifed, None otherwise."""
        contents = self._filesystem.read_binary_file(filename)
        if filename.endswith('.css'):
            return self.convert_css(contents, filename)
        return self.convert_html(new_path, contents, filename)

    def convert_css(self, contents, filename):
        return self.add_webkit_prefix_to_unprefixed_properties(contents, filename)

    def convert_html(self, new_path, contents, filename):
        doc = BeautifulSoup(contents)
        did_modify_paths = self.convert_testharness_paths(doc, new_path, filename)
        converted_properties_and_content = self.convert_prefixed_properties(doc, filename)
        return converted_properties_and_content if (did_modify_paths or converted_properties_and_content[0]) else None

    def convert_testharness_paths(self, doc, new_path, filename):
        """ Update links to testharness.js in the BeautifulSoup |doc| to point to the copy in |new_path|.

        Returns whether the document was modified."""

        # Look for the W3C-style path to any testharness files - scripts (.js) or links (.css)
        pattern = re.compile('/resources/testharness')
        script_tags = doc.findAll(src=pattern)
        link_tags = doc.findAll(href=pattern)
        testharness_tags = script_tags + link_tags

        if not testharness_tags:
            return False

        resources_path = self.path_from_webkit_root('LayoutTests', 'resources')
        resources_relpath = self._filesystem.relpath(resources_path, new_path)

        for tag in testharness_tags:
            # FIXME: We need to handle img, audio, video tags also.
            attr = 'src'
            if tag.name != 'script':
                attr = 'href'

            if not attr in tag.attrMap:
                # FIXME: Figure out what to do w/ invalid tags. For now, we return False
                # and leave the document unmodified, which means that it'll probably fail to run.
                _log.error("Missing an attr in %s" % filename)
                return False

            old_path = tag[attr]
            new_tag = Tag(doc, tag.name, tag.attrs)
            new_tag[attr] = re.sub(pattern, resources_relpath + '/testharness', old_path)

            self.replace_tag(tag, new_tag)

        return True

    def convert_prefixed_properties(self, doc, filename):
        """ Searches a BeautifulSoup |doc| for any CSS properties requiring the -webkit- prefix and converts them.

        Returns the list of converted properties and the modified document as a string """

        converted_properties = []

        # Look for inline and document styles.
        inline_styles = doc.findAll(style=re.compile('.*'))
        style_tags = doc.findAll('style')
        all_styles = inline_styles + style_tags

        for tag in all_styles:

            # Get the text whether in a style tag or style attribute.
            style_text = ''
            if tag.name == 'style':
                if not tag.contents:
                    continue
                style_text = tag.contents[0]
            else:
                style_text = tag['style']

            updated_style_text = self.add_webkit_prefix_to_unprefixed_properties(style_text, filename)

            # Rewrite tag only if changes were made.
            if updated_style_text[0]:
                converted_properties.extend(list(updated_style_text[0]))

                new_tag = Tag(doc, tag.name, tag.attrs)
                new_tag.insert(0, updated_style_text[1])

                self.replace_tag(tag, new_tag)

        # FIXME: Doing the replace in the parsed document and then writing it back out
        # is normalizing the HTML, which may in fact alter the intent of some tests.
        # We should probably either just do basic string-replaces, or have some other
        # way of flagging tests that are sensitive to being rewritten.
        # https://bugs.webkit.org/show_bug.cgi?id=119159

        return (converted_properties, doc.prettify())

    def add_webkit_prefix_to_unprefixed_properties(self, text, filename):
        """ Searches |text| for instances of properties requiring the -webkit- prefix and adds the prefix to them.

        Returns the list of converted properties and the modified text."""

        converted_properties = set()
        text_chunks = []
        cur_pos = 0
        for m in self.prop_re.finditer(text):
            text_chunks.extend([text[cur_pos:m.start()], m.group(1), '-webkit-', m.group(2), m.group(3)])
            converted_properties.add(m.group(2))
            cur_pos = m.end()
        text_chunks.append(text[cur_pos:])

        for prop in converted_properties:
            _log.info('  converting %s', prop)

        # FIXME: Handle the JS versions of these properties and GetComputedStyle, too.
        return (converted_properties, text)

    def replace_tag(self, old_tag, new_tag):
        index = old_tag.parent.contents.index(old_tag)
        old_tag.parent.insert(index, new_tag)
        old_tag.extract()
