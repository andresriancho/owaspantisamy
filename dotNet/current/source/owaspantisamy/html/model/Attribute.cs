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
    /// <summary> A model for HTML attributes and the "rules" they must follow (either literals or regular expressions) in
    /// order to be considered valid.
    /// </summary>

    public class Attribute : ICloneable
    {
        private string name;
        private string description;
        private string onInvalid;
        private IList allowedValues = new ArrayList();
        private IList allowedRegExp = new ArrayList();

        public IList AllowedRegExp
        {
            get { return allowedRegExp; }
            set { allowedRegExp = value; }
        }

        public IList AllowedValues
        {
            get { return allowedValues; }
            set { this.allowedValues = value; }
        }

        public string Name
        {
            get { return name; }
            set { this.name = value; }
        }
        public string OnInvalid
        {
            get { return onInvalid; }
            set { this.onInvalid = value; }
        }
        public string Description
        {
            get { return description; }
            set { this.description = value; }
        }
        public Attribute(string name)
        {
            this.name = name;
        }
        /// <summary> </summary>
        /// <param name="safeValue">A legal literal value that an attribute can have, according to the Policy
        /// </param>
        public virtual void addAllowedValue(string safeValue)
        {
            this.allowedValues.Add(safeValue);
        }

        /// <summary> </summary>
        /// <param name="safeRegExpValue">A legal regular expression value that an attribute could have, according to the Policy
        /// </param>
        public virtual void addAllowedRegExp(string safeRegExpValue)
        {
            this.allowedRegExp.Add(safeRegExpValue);
        }

        /// <summary> We need to implement <code>clone()</code> to make the Policy file work with common attributes and the ability
        /// to use a common-attribute with an alternative <code>onInvalid</code> action.
        /// </summary>

        public object Clone()
        {
            Attribute toReturn = new Attribute(name);
            toReturn.Description = description;
            toReturn.OnInvalid = onInvalid;
            toReturn.AllowedValues = allowedValues;
            toReturn.AllowedRegExp = allowedRegExp;
            return toReturn;
        }
    }
}