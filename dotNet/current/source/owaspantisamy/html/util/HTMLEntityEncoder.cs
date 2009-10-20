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
using System.Text;

namespace org.owasp.validator.html.util
{
    public class HTMLEntityEncoder
    {

        /// <summary> A helper method for HTML entity-encoding a String value.</summary>
        /// <param name="value">A String containing HTML control characters.
        /// </param>
        /// <returns> An HTML-encoded String.
        /// </returns>
        public static String htmlEntityEncode(String _value)
        {

            StringBuilder buff = new StringBuilder();

            if (_value == null)
            {
                return null;
            }

            for (int i = 0; i < _value.Length; i++)
            {
                char ch = _value[i];

                if (ch == '&')
                {
                    buff.Append("&amp;");
                }
                else if (ch == '<')
                {
                    buff.Append("&lt;");
                }
                else if (ch == '>')
                {
                    buff.Append("&gt;");
                }
                else if (System.Char.IsWhiteSpace(ch))
                {
                    buff.Append(ch);
                }
                else if (System.Char.IsLetterOrDigit(ch))
                {
                    buff.Append(ch);
                }
                else if ((int)ch >= 20 && (int)ch <= 126)
                {
                    buff.Append("&#" + (int)ch + ";");
                }
            }
            return buff.ToString();
        }
    }
}