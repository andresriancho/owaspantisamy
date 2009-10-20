/*
* Copyright (c) 2008, Jerry Hoff
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
using System;
using System.Collections;
using System.Text.RegularExpressions;

namespace org.owasp.validator.html.model
{

    /// <summary> 
    /// A model for HTML "tags" and the rules dictating their validation/filtration. Also contains information
    /// about their allowed attributes.
    /// There is also some experimental (unused) code in here for generating a valid regular expression according to a policy
    /// file on a per-tag basis.
    /// </summary>
    public class Tag
    {
        private Hashtable allowedAttributes = new Hashtable();
        private string name;
        private string action;

        public string Action
        {
            get { return action; }
            set { this.action = value; }
        }

        public string Name
        {
            get { return name; }
            set { this.name = value; }
        }

        public Hashtable AllowedAttributes
        {
            get { return allowedAttributes; }
            set { this.allowedAttributes = value; }
        }

        /// <summary> Returns a regular expression for validating individual tags. Not used by the AntiSamy scanner, but you might find some use for this.</summary>
        /// <returns> A regular expression for the tag, i.e., "^<b>$", or "<hr(\s)*(width='((\w){2,3}(\%)*)'>"
        /// </returns>
        /// TODO: redo this method, even though apparently it's not being used in AntiSamy
        /*
        public string RegularExpression
        {	
            get
            {
                StringBuilder regExp;		
				
                // For such tags as <b>, <i>, <u>
			
                if (allowedAttributes.Count == 0)
                {
                    return "^<" + name + ">$";
                }
				
                regExp = new System.Text.StringBuilder("<" + ANY_NORMAL_WHITESPACES + name + OPEN_TAG_ATTRIBUTES);
			
                System.Collections.IEnumerator attributes = new SupportClass.HashSetSupport(allowedAttributes.Keys).GetEnumerator();
				
                while (attributes.MoveNext())
                {
					
                    Attribute attr = (Attribute) allowedAttributes[(string) attributes.Current];
                    // <p (id=#([0-9.*{6})|sdf).*>
					
                    regExp.Append(attr.Name + ANY_NORMAL_WHITESPACES + "=" + ANY_NORMAL_WHITESPACES + "\"" + OPEN_ATTRIBUTE);
					
                    System.Collections.IEnumerator allowedValues = attr.AllowedValues.GetEnumerator();
                    System.Collections.IEnumerator allowedRegExps = attr.AllowedRegExp.GetEnumerator();
					
                    if (attr.AllowedRegExp.Count + attr.AllowedValues.Count > 0)
                    {
						
						
                        // Go through and add static values to the regular expression.
						
                        while (allowedValues.MoveNext())
                        {
                            string allowedValue = (string) allowedValues.Current;
							
                            regExp.Append(escapeRegularExpressionCharacters(allowedValue));
							
                            if (allowedValues.MoveNext() || allowedRegExps.MoveNext())
                            {
                                regExp.Append(ATTRIBUTE_DIVIDER);
                            }
                        }
						
						
                        // Add the regular expressions for this attribute value to the mother regular expression.
						
                        while (allowedRegExps.MoveNext())
                        {
                            Pattern allowedRegExp = (Pattern) allowedRegExps.Current;
                            regExp.Append(allowedRegExp.pattern());
							
                            if (allowedRegExps.MoveNext())
                            {
                                regExp.Append(ATTRIBUTE_DIVIDER);
                            }
                        }
						
                        if (attr.AllowedRegExp.Count + attr.AllowedValues.Count > 0)
                        {
                            regExp.Append(CLOSE_ATTRIBUTE);
                        }
						
                        regExp.Append("\"" + ANY_NORMAL_WHITESPACES);
						
                        if (attributes.MoveNext())
                        {
                            regExp.Append(ATTRIBUTE_DIVIDER);
                        }
                    }
                }
				
                regExp.Append(CLOSE_TAG_ATTRIBUTES + ANY_NORMAL_WHITESPACES + ">");
				
                return regExp.ToString();
            }
			
        }*/


        /// <summary> Constructor.</summary>
        /// <param name="name">The name of the tag, such as "b" for &lt;b&gt; tags.
        /// </param>
        public Tag(string name)
        {
            this.name = name;
        }

        /// <summary> Adds a fully-built Attribute to the list of Attributes allowed for this tag.</summary>
        /// <param name="attr">The Attribute to add to the list of allowed Attributes.
        /// </param>
        public void addAttribute(Attribute attr)
        {
            allowedAttributes[attr.Name] = attr;
        }

        private string escapeRegularExpressionCharacters(string allowedValue)
        {
            string toReturn = allowedValue;
            if (toReturn == null)
            {
                return null;
            }
            for (int i = 0; i < REGEXP_CHARACTERS.Length; i++)
            {
                toReturn.Replace("\\" + System.Convert.ToString(REGEXP_CHARACTERS[i]), "\\" + REGEXP_CHARACTERS[i]);
            }
            return toReturn;
        }

        /// <summary>Begin Variables Needed For Generating Regular Expressions *</summary>
        private const string ANY_NORMAL_WHITESPACES = "(\\s)*";
        private const string OPEN_ATTRIBUTE = "(";
        private const string ATTRIBUTE_DIVIDER = "|";
        private const string CLOSE_ATTRIBUTE = ")";
        //private final static String OPEN_VALUES = "(";
        //private final static String VALUE_DIVIDER = "|";
        //private final static String CLOSE_VALUE = ")";
        //UPGRADE_NOTE: Final was removed from the declaration of 'OPEN_TAG_ATTRIBUTES '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
        //private static readonly string OPEN_TAG_ATTRIBUTES = ANY_NORMAL_WHITESPACES + OPEN_ATTRIBUTE;
        private const string CLOSE_TAG_ATTRIBUTES = ")*";
        private const string REGEXP_CHARACTERS = "\\(){}.*?$^-+";

        /// <summary> Returns an <code>Attribute</code> associated with a lookup name.</summary>
        /// <param name="name">The name of the allowed attribute by name.
        /// </param>
        /// <returns> The <code>Attribute</code> object associated with the name, or 
        /// </returns>
        public virtual Attribute getAttributeByName(string name)
        {
            return (Attribute)allowedAttributes[name];
        }
    }
}