/*
 * Copyright (c) 2007-2011, Arshan Dabirsiaghi, Jason Li
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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A model for HTML attributes and the "rules" they must follow (either literals or regular expressions) in
 * order to be considered valid.
 * 
 * @author Arshan Dabirsiaghi
 *
 */

public class Attribute implements Cloneable {

	private String name;
	private String description;
	private String onInvalid;
	private List allowedValues = new ArrayList();
	private List allowedRegExp = new ArrayList();
	
	public Attribute(String name) {
		this.name = name;
	}
	
	/**
	 * 
	 * @param safeValue A legal literal value that an attribute can have, according to the Policy
	 */
	public void addAllowedValue(String safeValue) {
		this.allowedValues.add(safeValue);
	}
	
	/**
	 * 
	 * @param safeRegExpValue A legal regular expression value that an attribute could have, according to the Policy
	 */
	public void addAllowedRegExp(Pattern safeRegExpValue) {
		this.allowedRegExp.add(safeRegExpValue);
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
	 * @param allowedRegExp A <code>List</code> of regular expressions that an attribute can be validated from.
	 */
	public void setAllowedRegExp(List allowedRegExp) {
		this.allowedRegExp = allowedRegExp;
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
	 * @param allowedValues A <code>List</code> of regular expressions that an attribute can be validated from.
	 */
	public void setAllowedValues(List allowedValues) {
		this.allowedValues = allowedValues;
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
	 * @param name The new name of an Attribute object.
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * 
	 * @return The <code>onInvalid</code> value a tag could have, from the list of "filterTag", "removeTag" and "removeAttribute" 
	 */
	public String getOnInvalid() {
		return onInvalid;
	}

	
	/**
	 * 
	 * @param onInvalid The new <code>onInvalid</code> value of an Attribute object.
	 */
	public void setOnInvalid(String onInvalid) {
		this.onInvalid = onInvalid;
	}

	/**
	 * 
	 * @return The description of what the tag does.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * 
	 * @param description The new description of what the tag does.
	 */
	public void setDescription(String description) {
		this.description = description;
	}
	
	/**
	 * We need to implement <code>clone()</code> to make the Policy file work with common attributes and the ability
	 * to use a common-attribute with an alternative <code>onInvalid</code> action.
	 */
	public Object clone() {
		
		Attribute toReturn = new Attribute(name);
		
		toReturn.setDescription(description);
		toReturn.setOnInvalid(onInvalid);
		toReturn.setAllowedValues(allowedValues);
		toReturn.setAllowedRegExp(allowedRegExp);
		
		return toReturn;
	}
}
