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

import org.owasp.validator.html.Policy;
import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Tag;

public class Constants{

	public static final String DEFAULT_ENCODING_ALGORITHM = "UTF-8";

	public static final Tag BASIC_PARAM_TAG_RULE;

	static {
		Attribute paramNameAttr = new Attribute("name");
		Attribute paramValueAttr = new Attribute("value");
		paramNameAttr.addAllowedRegExp(Policy.ANYTHING_REGEXP);
		paramValueAttr.addAllowedRegExp(Policy.ANYTHING_REGEXP);
		BASIC_PARAM_TAG_RULE = new Tag("param");
		BASIC_PARAM_TAG_RULE.addAttribute(paramNameAttr);
		BASIC_PARAM_TAG_RULE.addAttribute(paramValueAttr);
		BASIC_PARAM_TAG_RULE.setAction(Policy.ACTION_VALIDATE);
	}

	public static final String DEFAULT_LOCALE_LANG = "en";
	public static final String DEFAULT_LOCALE_LOC = "US";

	public static String[] defaultAllowedEmptyTags = {
		"br", "hr", "a", "img", "link", "iframe", "script", "object", "applet", 
		"frame", "base", "param", "meta", "input", "textarea", "embed", "basefont",
		"col", "td", "th"
	};
	
}
