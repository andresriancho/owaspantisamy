/*
 * Copyright (c) 2007-2010, Arshan Dabirsiaghi, Jason Li
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.validator.html.scan;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import org.apache.xerces.util.XMLStringBuffer;
import org.apache.xerces.xni.Augmentations;
import org.apache.xerces.xni.QName;
import org.apache.xerces.xni.XMLAttributes;
import org.apache.xerces.xni.XMLString;
import org.apache.xerces.xni.XNIException;
import org.apache.xerces.xni.parser.XMLDocumentFilter;
import org.cyberneko.html.filters.DefaultFilter;
import org.owasp.validator.html.Policy;

/**
 * Correctly handles empty tags.
 */
public class EmptyTagFilter extends DefaultFilter implements XMLDocumentFilter {

	private Policy policy;
	private StringWriter writer;
	
	public EmptyTagFilter(Policy policy, StringWriter writer) {
		this.policy = policy;
		this.writer = writer;
	}

	private static final String emptyTagPrefix = "<";
	private static final String emptyTagSuffix = "/>";
	
	public void endElement(QName element, Augmentations augs)
			throws XNIException {
		super.endElement(element, augs);
		String tagName = element.localpart;
		if(!isAllowedEmptyTag(tagName)) {
			StringBuffer sb = writer.getBuffer();
			int len = tagName.length() + emptyTagPrefix.length() + emptyTagSuffix.length();
			String toChop = emptyTagPrefix + tagName + emptyTagSuffix;
			String currentTail = sb.substring(sb.length()-len); 
			if(currentTail.equals(toChop)) {
				sb.delete(sb.length() - len,sb.length());
			}
		}
	}
	
	private boolean isAllowedEmptyTag(String tagName) {
    	boolean allowed = false;
        String[] allowedEmptyTags = policy.getAllowedEmptyTags();
        for (int i = 0; i < allowedEmptyTags.length; i++) {
            if (allowedEmptyTags[i].equalsIgnoreCase(tagName)) {
                allowed = true;
                i = allowedEmptyTags.length;
            }
        }
        return allowed;
	}
}
