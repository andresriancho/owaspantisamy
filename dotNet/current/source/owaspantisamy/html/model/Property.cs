/*
* Copyright (c) 2008, Jerry Hoff
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
using System;
using System.Text.RegularExpressions;
using System.Collections;

namespace org.owasp.validator.html.model
{

    /// <summary> A model for CSS properties and the "rules" they must follow (either literals
    /// or regular expressions) in order to be considered valid.
    /// 
    /// </summary>
    /// <author>  Jason Li
    /// 
    /// </author>
    public class Property
    {
        private string name;
        private string onInvalid;
        private string description;
        private ArrayList allowedValues = new ArrayList();
        private ArrayList allowedRegExp = new ArrayList();
        private ArrayList shorthandRefs = new ArrayList();

        public Property(string name)
        {
            this.name = name;
        }

        /// <summary> Add the specified value to the allowed list of valid values.</summary>
        /// <param name="safeValue">The new valid value to add to the list.
        /// </param>
        public void addAllowedValue(string safeValue)
        {
            this.allowedValues.Add(safeValue);
        }

        /// <summary> Add the specified value to the allowed list of valid regular expressions.</summary>
        /// <param name="safeRegExpValue">The new valid regular expression to add to the list.
        /// </param>
        public virtual void addAllowedRegExp(string safeRegExpValue)
        {
            this.allowedRegExp.Add(safeRegExpValue);
        }

        /// <summary> Add the specified value to the allowed list of valid shorthand values.</summary>
        /// <param name="shorthandValue">The new valid shorthand value to add to the list.
        /// </param>
        public void addShorthandRef(string shorthandValue)
        {
            this.shorthandRefs.Add(shorthandValue);
        }
        public ArrayList AllowedRegExp
        {
            get { return allowedRegExp; }
            set { allowedRegExp = value; }
        }
        public ArrayList AllowedValues
        {
            get { return allowedValues; }
            set { allowedValues = value; }
        }
        public ArrayList ShorthandRefs
        {
            get { return shorthandRefs; }
            set { shorthandRefs = value; }
        }
        public string Name
        {
            get { return name; }
            set { name = value; }
        }
        public string OnInvalid
        {
            get { return onInvalid; }
            set { onInvalid = value; }
        }
        public string Description
        {
            get { return description; }
            set { description = value; }
        }
    }
}