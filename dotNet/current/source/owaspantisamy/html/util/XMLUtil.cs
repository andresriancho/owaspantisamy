/*
* Copyright (c) 2008, Jerry Hoff
* 
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* 
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of OWASP nor the names of its contributors  may be used to endorse or promote products derived from this software without specific prior written permission.
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
using System.Xml;
namespace org.owasp.validator.html.util
{

    public class XMLUtil
    {

        /// <summary> Helper function for quickly retrieving an attribute from a given
        /// element. 
        /// </summary>
        /// <param name="ele">The document element from which to pull the attribute value.
        /// </param>
        /// <param name="attrName">The name of the attribute.
        /// </param>
        /// <returns> The value of the attribute contained within the element
        /// </returns>
        public static string getAttributeValue(XmlElement ele, string attrName)
        {
            return decode(ele.GetAttribute(attrName));
        }

        /// <summary> Helper function for quickly retrieving an integer value of a given
        /// XML element.
        /// </summary>
        /// <param name="ele">The document element from which to pull the integer value.
        /// </param>
        /// <param name="tagName">The name of the node.
        /// </param>
        /// <returns> The integer value of the given node in the element passed in.
        /// </returns>
        /*
        public static int getIntValue(XmlElement ele, string tagName, int defaultValue)
        {
			
            int toReturn = defaultValue;
			
            try
            {
                toReturn = int.Parse(getTextValue(ele, tagName));
            }
            catch (Exception e)
            {
            }
            return toReturn;
        }
        */

        /// <summary> Helper function for quickly retrieving a String value of a given
        /// XML element.
        /// </summary>
        /// <param name="ele">The document element from which to pull the String value.
        /// </param>
        /// <param name="tagName">The name of the node.
        /// </param>
        /// <returns> The String value of the given node in the element passed in.
        /// </returns>
        public static string getTextValue(XmlElement ele, string tagName)
        {
            string textVal = null;
            XmlNodeList nl = ele.GetElementsByTagName(tagName);
            if (nl != null && nl.Count > 0)
            {
                XmlElement el = (XmlElement)nl.Item(0);
                if (el.FirstChild != null)
                {
                    textVal = el.FirstChild.Value;
                }
                else
                {
                    textVal = "";
                }
            }
            return decode(textVal);
        }


        /// <summary> Helper function for quickly retrieving an boolean value of a given
        /// XML element.
        /// </summary>
        /// <param name="ele">The document element from which to pull the boolean value.
        /// </param>
        /// <param name="tagName">The name of the node.
        /// </param>
        /// <returns> The boolean value of the given node in the element passed in.
        /// </returns>
        public static bool getBooleanValue(XmlElement ele, string tagName)
        {

            bool boolVal = false;
            XmlNodeList nl = ele.GetElementsByTagName(tagName);

            if (nl != null && nl.Count > 0)
            {
                XmlElement el = (XmlElement)nl.Item(0);
                boolVal = el.FirstChild.Value.Equals("true");
            }

            return boolVal;
        }

        /// <summary> Helper function for quickly retrieving an boolean value of a given
        /// XML element, with a default initialization value passed in a parameter.
        /// </summary>
        /// <param name="ele">The document element from which to pull the boolean value.
        /// </param>
        /// <param name="tagName">The name of the node.
        /// </param>
        /// <param name="defaultValue">The default value of the node if it's value can't be processed.
        /// </param>
        /// <returns> The boolean value of the given node in the element passed in.
        /// </returns>
        public static bool getBooleanValue(XmlElement ele, string tagName, bool defaultValue)
        {
            bool boolVal = defaultValue;
            XmlNodeList nl = ele.GetElementsByTagName(tagName);

            if (nl != null && nl.Count > 0)
            {
                XmlElement el = (XmlElement)nl.Item(0);
                if (el.FirstChild.Value != null)
                {
                    boolVal = "true".Equals(el.FirstChild.Value);
                }
                else
                {
                    boolVal = defaultValue;
                }
            }
            return boolVal;
        }


        /// <summary> Helper function for decode XML entities.</summary>
        /// <param name="str">The XML-encoded String to decode.
        /// </param>
        /// <returns> An XML-decoded String.
        /// </returns>
        public static string decode(string str)
        {
            if (str == null)
            {
                return null;
            }
            str = str.Replace("&gt;", ">");
            str = str.Replace("&lt;", "<");
            str = str.Replace("&quot;", "\"");
            str = str.Replace("&amp;", "&");
            return str;
        }

        public static string encode(string str)
        {
            if (str == null)
            {
                return null;
            }
            str = str.Replace(">", "&gt;");
            str = str.Replace("<", "&lt;");
            str = str.Replace("\"", "&quot;");
            str = str.Replace("&", "&amp;");
            return str;
        }
    }
}