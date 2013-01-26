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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A model for HTML "tags" and the rules dictating their validation/filtration. Also contains information
 * about their allowed attributes.
 * <p/>
 * There is also some experimental (unused) code in here for generating a valid regular expression according to a policy
 * file on a per-tag basis.
 *
 * @author Arshan Dabirsiaghi
 */
public class Tag {

    /*
      * These are the fields pulled from the policy XML.
      */
    private Map<String, Attribute> allowedAttributes = new HashMap<String, Attribute>();
    private String name;
    private String action;

    /**
     * @return The action for this tag which is one of <code>filter</code>, <code>validate</code> or <code>remove</code>.
     */
    public String getAction() {
        return action;
    }

    /**
     * @param action The new action for this tag which is one of <code>filter</code>, <code>validate</code> or <code>remove</code>.
     */
    public void setAction(String action) {
        this.action = action;
    }

    /**
     * Constructor.
     *
     * @param name The name of the tag, such as "b" for &lt;b&gt; tags.
     */
    public Tag(String name) {
        this.name = name;
    }

    /**
     * Adds a fully-built Attribute to the list of Attributes allowed for this tag.
     *
     * @param attr The Attribute to add to the list of allowed Attributes.
     */
    public void addAttribute(Attribute attr) {
        allowedAttributes.put(attr.getName().toLowerCase(), attr);
    }


    /* --------------------------------------------------------------------------------------------------*/


    /**
     * Returns a regular expression for validating individual tags. Not used by the AntiSamy scanner, but you might find some use for this.
     *
     * @return A regular expression for the tag, i.e., "^<b>$", or "<hr(\s)*(width='((\w){2,3}(\%)*)'>"
     */

    @SuppressWarnings("UnusedDeclaration")
    public String getRegularExpression() {

        StringBuffer regExp;

        /*
           * For such tags as <b>, <i>, <u>
           */
        if (allowedAttributes.size() == 0) {
            return "^<" + name + ">$";
        }

        regExp = new StringBuffer("<" + ANY_NORMAL_WHITESPACES + name + OPEN_TAG_ATTRIBUTES);

        for (Attribute attr : allowedAttributes.values()) {

        }
        Iterator<Attribute> attributes = allowedAttributes.values().iterator();
        while (attributes.hasNext()) {

            Attribute attr = attributes.next();
            // <p (id=#([0-9.*{6})|sdf).*>

            regExp.append(attr.getName()).append(ANY_NORMAL_WHITESPACES).append("=").append(ANY_NORMAL_WHITESPACES).append("\"").append(OPEN_ATTRIBUTE);


            boolean hasRegExps = attr.getAllowedRegExp().size() > 0;

            if (attr.getAllowedRegExp().size() + attr.getAllowedValues().size() > 0) {

                /*
                     * Go through and add static values to the regular expression.
                     */
                Iterator allowedValues = attr.getAllowedValues().iterator();
                while (allowedValues.hasNext()) {
                    String allowedValue = (String) allowedValues.next();

                    regExp.append(escapeRegularExpressionCharacters(allowedValue));

                    if (allowedValues.hasNext() || hasRegExps) {
                        regExp.append(ATTRIBUTE_DIVIDER);
                    }
                }

                /*
                     * Add the regular expressions for this attribute value to the mother regular expression.
                     */
                Iterator allowedRegExps = attr.getAllowedRegExp().iterator();
                while (allowedRegExps.hasNext()) {
                    Pattern allowedRegExp = (Pattern) allowedRegExps.next();
                    regExp.append(allowedRegExp.pattern());

                    if (allowedRegExps.hasNext()) {
                        regExp.append(ATTRIBUTE_DIVIDER);
                    }
                }

                if (attr.getAllowedRegExp().size() + attr.getAllowedValues().size() > 0) {
                    regExp.append(CLOSE_ATTRIBUTE);
                }

                regExp.append("\"" + ANY_NORMAL_WHITESPACES);

                if (attributes.hasNext()) {
                    regExp.append(ATTRIBUTE_DIVIDER);
                }
            }

        }

        regExp.append(CLOSE_TAG_ATTRIBUTES + ANY_NORMAL_WHITESPACES + ">");

        return regExp.toString();
    }

    private String escapeRegularExpressionCharacters(String allowedValue) {

        String toReturn = allowedValue;

        if (toReturn == null) {
            return null;
        }

        for (int i = 0; i < REGEXP_CHARACTERS.length(); i++) {
            toReturn = toReturn.replaceAll("\\" + String.valueOf(REGEXP_CHARACTERS.charAt(i)), "\\" + REGEXP_CHARACTERS.charAt(i));
        }

        return toReturn;
    }

    /**
     * Begin Variables Needed For Generating Regular Expressions *
     */
    private final static String ANY_NORMAL_WHITESPACES = "(\\s)*";
    private final static String OPEN_ATTRIBUTE = "(";
    private final static String ATTRIBUTE_DIVIDER = "|";
    private final static String CLOSE_ATTRIBUTE = ")";
    //private final static String OPEN_VALUES = "(";
    //private final static String VALUE_DIVIDER = "|";
    //private final static String CLOSE_VALUE = ")";
    private final static String OPEN_TAG_ATTRIBUTES = ANY_NORMAL_WHITESPACES + OPEN_ATTRIBUTE;
    private final static String CLOSE_TAG_ATTRIBUTES = ")*";
    private final static String REGEXP_CHARACTERS = "\\(){}.*?$^-+";


    /**
     * @param allowedAttributes The new <code>HashMap</code> of allowed attributes that the tag is allowed to contain.
     */
    public void setAllowedAttributes(Map<String, Attribute> allowedAttributes) {
        this.allowedAttributes = allowedAttributes;
    }

    /**
     * @return The String name of the tag.
     */
    public String getName() {
        return name;
    }


    /**
     * Returns an <code>Attribute</code> associated with a lookup name.
     *
     * @param name The name of the allowed attribute by name.
     * @return The <code>Attribute</code> object associated with the name, or
     */
    public Attribute getAttributeByName(String name) {

        return allowedAttributes.get(name);

    }

}
