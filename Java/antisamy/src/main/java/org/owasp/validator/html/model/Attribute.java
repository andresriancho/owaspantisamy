/*
 * Copyright (c) 2007-2013, Arshan Dabirsiaghi, Jason Li, Kristian Rosenvold
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

package org.owasp.validator.html.model;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A model for HTML attributes and the "rules" they must follow (either literals or regular expressions) in
 * order to be considered valid.
 * 
 * @author Arshan Dabirsiaghi
 * @author Kristian Rosenvold
 *
 */

public class Attribute  {

	private final String name;
	private final String description;
	private final String onInvalid;
	private final List<String> allowedValues;
	private final List<Pattern> allowedRegExp;
	
    public Attribute(String name, List<Pattern> allowedRegexps, List<String> allowedValues, String onInvalidStr, String description) {
        this.name = name;
        this.allowedRegExp = Collections.unmodifiableList(allowedRegexps);
        this.allowedValues = Collections.unmodifiableList( allowedValues);
        this.onInvalid = onInvalidStr;
        this.description = description;
    }

    /**
	 *  
	 * @return A <code>List</code> of regular expressions that an attribute can be validated from.
	 */
	public List getAllowedRegExp() {
		return allowedRegExp;
	}

    /**
	 * 
	 * @return A <code>List</code> of literal values that an attribute could have, according to the Policy.
	 */
	public List getAllowedValues() {
		return allowedValues;
	}

    /**
	 * 
	 * @return The name of an Attribute object.
	 */
	public String getName() {
		return name;
	}

    /**
	 * 
	 * @return The <code>onInvalid</code> value a tag could have, from the list of "filterTag", "removeTag" and "removeAttribute" 
	 */
	public String getOnInvalid() {
		return onInvalid;
	}


    public Attribute mutate(String onInvalid, String description)  {
        return new Attribute(name, allowedRegExp, allowedValues, onInvalid != null && onInvalid.length() != 0 ? onInvalid : this.onInvalid,
                description != null && description.length() != 0 ? description : this.description);
    }
}
