/*
 * Copyright (c) 2007-2011, Arshan Dabirsiaghi, Jason Li
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice, 
 * 	 this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of OWASP nor the names of its contributors may be used to
 *   endorse or promote products derived from this software without specific
 *   prior written permission.
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
 * A model for CSS properties and the "rules" they must follow (either literals
 * or regular expressions) in order to be considered valid.
 * 
 * @author Jason Li
 * 
 */
public class Property {
	private final String name;

	private String onInvalid;

	private String description;

	private List allowedValues = new ArrayList();

	private List allowedRegExp = new ArrayList();

	private List shorthandRefs = new ArrayList();

	public Property(String name) {
		this.name = name;
	}
	
	/**
	 * Add the specified value to the allowed list of valid values.
	 * @param safeValue The new valid value to add to the list.
	 */
	public void addAllowedValue(String safeValue) {
		this.allowedValues.add(safeValue);
	}
	
	/**
	 * Add the specified value to the allowed list of valid regular expressions.
	 * @param safeRegExpValue The new valid regular expression to add to the list.
	 */
	public void addAllowedRegExp(Pattern safeRegExpValue) {
		this.allowedRegExp.add(safeRegExpValue);
	}
	
	/**
	 * Add the specified value to the allowed list of valid shorthand values.
	 * @param shorthandValue The new valid shorthand value to add to the list.
	 */
	public void addShorthandRef(String shorthandValue) {
		this.shorthandRefs.add(shorthandValue);
	}

	/**
	 * Return a <code>List</code> of allowed regular expressions as added
	 * by the <code>addAllowedRegExp()</code> method.
	 * @return A <code>List</code> of allowed regular expressions.
	 */
	public List getAllowedRegExp() {
		return allowedRegExp;
	}
	
	/**
	 * Set a new <code>List</code> of allowed regular expressions.
	 * @param allowedRegExp The new <code>List</code> of allowed regular expressions.
	 */
	public void setAllowedRegExp(List allowedRegExp) {
		this.allowedRegExp = allowedRegExp;
	}

	/**
	 * @return A <code>List</code> of allowed literal values.
	 */
	public List getAllowedValues() {
		return allowedValues;
	}

	/**
	 * Set a new <code>List</code> of allowed literal values.
	 * @param allowedValues The new <code>List</code> of allowed literal values.
	 */
	public void setAllowedValues(List allowedValues) {
		this.allowedValues = allowedValues;
	}

	/**
	 * @return A <code>List</code> of allowed shorthand references.
	 */
	public List getShorthandRefs() {
		return shorthandRefs;
	}

	/**
	 * Set a new <code>List</code> of allowed shorthand references.
	 * @param shorthandRefs The new <code>List</code> of allowed shorthand references.
	 */
	public void setShorthandRefs(List shorthandRefs) {
		this.shorthandRefs = shorthandRefs;
	}
	
	/**
	 * 
	 * @return The name of the property.
	 */
	public String getName() {
		return name;
	}

	/**
	 * 
	 * @return The <code>onInvalid</code> action associated with the Property.
	 */
	public String getOnInvalid() {
		return onInvalid;
	}

	/**
	 * 
	 * @param onInvalid The new <code>onInvalid</code> action to define for this property.
	 */
	public void setOnInvalid(String onInvalid) {
		this.onInvalid = onInvalid;
	}

	/**
	 * 
	 * @return The description associated with this Property.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * 
	 * @param description The new description of this Property.
	 */
	public void setDescription(String description) {
		this.description = description;
	}
}
