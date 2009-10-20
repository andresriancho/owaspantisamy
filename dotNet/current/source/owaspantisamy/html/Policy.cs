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
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using System.Collections;
using System.IO;
using org.owasp.validator.html.model;
using Attribute = org.owasp.validator.html.model.Attribute;
using Tag = org.owasp.validator.html.model.Tag;

namespace org.owasp.validator.html
{

    /// <summary> Policy.java
    /// This file holds the model for our policy engine.
    /// </summary>

    public class Policy
    {

        private static Policy _instance = null;
        private const string DEFAULT_POLICY_URI = @"../../resources/antisamy.xml";
        private const string DEFAULT_ONINVALID = "removeAttribute";

        public const int DEFAULT_MAX_INPUT_SIZE = 100000;

        private static char REGEXP_BEGIN = '^';
        private static char REGEXP_END = '$';

        private Hashtable commonRegularExpressions;
        private Hashtable commonAttributes;
        private Hashtable tagRules;
        private Hashtable cssRules;
        private Hashtable directives;
        private Hashtable globalAttributes;

        private ArrayList tagNames;

        /// <summary> Retrieves a Tag from the Policy.</summary>
        /// <param name="tagName">The name of the Tag to look up.
        /// </param>
        /// <returns> The Tag associated with the name specified, or null if none is found.
        /// </returns>
        public Tag getTagByName(string tagName)
        {
            return (Tag)tagRules[tagName];
        }

        /// <summary> Retrieves a CSS Property from the Policy.</summary>
        /// <param name="propertyName">The name of the CSS Property to look up.
        /// </param>
        /// <returns> The CSS Property associated with the name specified, or null if none is found.
        /// </returns>
        public Property getPropertyByName(string propertyName)
        {
            return (Property)cssRules[propertyName];
        }

        /// <summary> This retrieves a Policy based on a default location ("resources/antisamy.xml")</summary>
        /// <returns> A populated Policy object based on the XML policy file located in the default location.
        /// </returns>
        /// <throws>  PolicyException If the file is not found or there is a problem parsing the file. </throws>
        public static Policy getInstance()
        {
            _instance = new Policy(DEFAULT_POLICY_URI);
            return _instance;
        }

        /// <summary> This retrieves a Policy based on the file name passed in</summary>
        /// <param name="filename">The path to the XML policy file.
        /// </param>
        /// <returns> A populated Policy object based on the XML policy file located in the location passed in.
        /// </returns>
        /// <throws>  PolicyException If the file is not found or there is a problem parsing the file. </throws>
        public static Policy getInstance(string filename)
        {
            _instance = new Policy(filename);
            return _instance;
        }

        /// <summary> This retrieves a Policy based on the File object passed in</summary>
        /// <param name="file">A File object which contains the XML policy information.
        /// </param>
        /// <returns> A populated Policy object based on the XML policy file pointed to by the File parameter.
        /// </returns>
        /// <throws>  PolicyException If the file is not found or there is a problem parsing the file. </throws>
        public static Policy getInstance(FileInfo file)
        {
            _instance = new Policy(new FileInfo(file.FullName));
            return _instance;
        }

        /// <summary> Load the policy from an XML file.</summary>
        /// <param name="file">Load a policy from the File object.
        /// </param>
        /// <throws>  PolicyException </throws>
        private Policy(FileInfo file)
            : this(file.FullName)
        {
        }

        /// <summary> Load the policy from an XML file.</summary>
        /// <param name="filename">Load a policy from the filename specified.
        /// </param>
        /// <throws>  PolicyException </throws>
        private Policy(string filename)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(filename);

                XmlNode commonRegularExpressionListNode = doc.GetElementsByTagName("common-regexps")[0];
                this.commonRegularExpressions = parseCommonRegExps(commonRegularExpressionListNode);

                XmlNode directiveListNode = doc.GetElementsByTagName("directives")[0];
                this.directives = parseDirectives(directiveListNode);

                XmlNode commonAttributeListNode = doc.GetElementsByTagName("common-attributes")[0];
                this.commonAttributes = parseCommonAttributes(commonAttributeListNode);

                XmlNode globalAttributesListNode = doc.GetElementsByTagName("global-tag-attributes")[0];
                this.globalAttributes = parseGlobalAttributes(globalAttributesListNode);

                XmlNode tagListNode = doc.GetElementsByTagName("tag-rules")[0];
                this.tagRules = parseTagRules(tagListNode);

                XmlNode cssListNode = doc.GetElementsByTagName("css-rules")[0];
                this.cssRules = parseCSSRules(cssListNode);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Problem Parsing Policy File: ");
                Console.WriteLine(ex.Message);
            }
        }



        /// <summary> Go through <directives> section of the policy file.</summary>
        /// <param name="directiveListNode">Top level of <directives>
        /// </param>
        /// <returns> A HashMap of directives for validation behavior.
        /// </returns>
        private Hashtable parseDirectives(XmlNode directiveListNode)
        {
            XmlNodeList directiveNodes = directiveListNode.SelectNodes("directive");
            Hashtable directives = new Hashtable();
            string _name = "", _value = "";
            foreach (XmlNode node in directiveNodes)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    _name = node.Attributes[0].Value;
                    _value = node.Attributes[1].Value;
                    if (!directives.ContainsKey(_name))
                        directives.Add(_name, _value);
                }
            }
            return directives;
        }


        /// <summary> Go through <global-tag-attributes> section of the policy file.</summary>
        /// <param name="globalAttributeListNode">Top level of <global-tag-attributes>
        /// </param>
        /// <returns> A HashMap of global Attributes that need validation for every tag.
        /// </returns>
        /// <throws>  PolicyException  </throws>
        private Hashtable parseGlobalAttributes(XmlNode globalAttributeListNode)
        {
            XmlNodeList globalAttributeNodes = globalAttributeListNode.SelectNodes("attribute");
            Hashtable globalAttributes = new Hashtable();
            string _name = "";
            //string _value = "";
            foreach (XmlNode node in globalAttributeNodes)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    _name = node.Attributes[0].Value;
                    //_value = node.Attributes[1].Value;
                    Attribute toAdd = getCommonAttributeByName(_name);
                    if (toAdd != null)
                    {
                        globalAttributes.Add(_name, toAdd);
                    }
                    else
                    {
                        throw new PolicyException("Global attribute '" + _name + "' was not defined in <common-attributes>");
                    }
                    //if (!globalAttributes.ContainsKey(_name))
                    //    globalAttributes.Add(_name, new AntiSamyPattern(_name, _value));
                }
            }
            return globalAttributes;
        }


        /// <summary> Go through the <common-regexps> section of the policy file.</summary>
        /// <param name="root">Top level of <common-regexps>
        /// </param>
        /// <returns> An ArrayList of AntiSamyPattern objects.
        /// </returns>
        private Hashtable parseCommonRegExps(XmlNode commonRegularExpressionListNode)
        {
            XmlNodeList list = commonRegularExpressionListNode.SelectNodes("regexp");
            Hashtable commonRegularExpressions = new Hashtable();
            string _name = "", _value = "";
            foreach (XmlNode node in list)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    _name = node.Attributes[0].Value;
                    _value = node.Attributes[1].Value;
                    if (!commonRegularExpressions.ContainsKey(_name))
                        commonRegularExpressions.Add(_name, _value);
                    //commonRegularExpressions.Add(_name, new AntiSamyPattern(_name, _value));
                }
            }
            return commonRegularExpressions;
        }


        /// <summary> Go through the <common-attributes> section of the policy file.</summary>
        /// <param name="root">Top level of <common-attributes>
        /// </param>
        /// <returns> An ArrayList of Attribute objects.
        /// </returns>
        private Hashtable parseCommonAttributes(XmlNode commonAttributeListNode)
        {
            XmlNodeList commonAttributeNodes = commonAttributeListNode.SelectNodes("attribute");
            Hashtable commonAttributes = new Hashtable();

            foreach (XmlNode node in commonAttributeNodes)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    /*DEFAULT_ONINVALID seems to have been removed from common attributes.  Do we need this code?*/
                    String onInvalid = (node.Attributes["onInvalid"] == null ? null : node.Attributes["onInvalid"].Value);
                    String name = (node.Attributes["name"] == null ? null : node.Attributes["name"].Value);
                    org.owasp.validator.html.model.Attribute attribute = new org.owasp.validator.html.model.Attribute(name);
                    attribute.Description = (node.Attributes["description"] == null ? null : node.Attributes["description"].Value);
                    if (onInvalid != null && onInvalid.Length > 0)
                    {
                        attribute.OnInvalid = onInvalid;
                    }
                    else
                    {
                        attribute.OnInvalid = DEFAULT_ONINVALID;
                    }

                    XmlNodeList regExpListNode = node.SelectNodes("regexp-list");
                    if (regExpListNode != null && regExpListNode.Count > 0)
                    {
                        XmlNodeList regExpList = regExpListNode[0].SelectNodes("regexp");
                        foreach (XmlNode regExpNode in regExpList)
                        {
                            string regExpName = (regExpNode.Attributes["name"] == null ? null : regExpNode.Attributes["name"].Value);
                            string value = (regExpNode.Attributes["value"] == null ? null : regExpNode.Attributes["value"].Value);
                            //TODO: java version uses "Pattern" class to hold regular expressions.  I'm storing them as strings below
                            //find out if I need an equiv to pattern 
                            if (regExpName != null && regExpName.Length > 0)
                            {
                                attribute.addAllowedRegExp(getRegularExpression(regExpName).ToString());
                            }
                            else
                            {
                                attribute.addAllowedRegExp(REGEXP_BEGIN + value + REGEXP_END);
                            }
                        }
                    }
                    XmlNode literalListNode = node.SelectNodes("literal-list")[0];
                    if (literalListNode != null)
                    {
                        XmlNodeList literalNodes = literalListNode.SelectNodes("literal");
                        foreach (XmlNode literalNode in literalNodes)
                        {
                            string value = (literalNode.Attributes["value"] == null ? null : literalNode.Attributes["value"].Value);
                            if (value != null && value.Length > 0)
                            {
                                attribute.addAllowedValue(value);
                            }
                            else if (literalNode.Value != null)
                            {
                                attribute.addAllowedValue(literalNode.Value);
                            }
                        }
                    }
                    commonAttributes.Add(name, attribute);
                }
            }
            return commonAttributes;
        }


        /// <summary> Private method for parsing the <tag-rules> from the XML file.</summary>
        /// <param name="root">The root element for <tag-rules>
        /// </param>
        /// <returns> A List<Tag> containing the rules.
        /// </returns>
        /// <throws>  PolicyException  </throws>
        private Hashtable parseTagRules(XmlNode tagAttributeListNode)
        {
            Hashtable tags = new Hashtable();
            XmlNodeList tagList = tagAttributeListNode.SelectNodes("tag");
            foreach (XmlNode tagNode in tagList)
            {
                if (tagNode.NodeType == XmlNodeType.Element)
                {
                    String name = (tagNode.Attributes["name"] == null ? null : tagNode.Attributes["name"].Value);
                    String action = (tagNode.Attributes["action"] == null ? null : tagNode.Attributes["action"].Value);

                    Tag tag = new Tag(name);
                    if (tagNames == null)
                        tagNames = new ArrayList();

                    tagNames.Add(name);
                    tag.Action = action;
                    //XmlNodeList attributeList = tagNode.SelectNodes("attribute");
                    XmlNodeList attributeList = tagNode.SelectNodes("attribute");
                    foreach (XmlNode attributeNode in attributeList)
                    {
                        if (!attributeNode.HasChildNodes)
                        {
                            Attribute attribute = getCommonAttributeByName(attributeNode.Attributes["name"].Value);

                            if (attribute != null)
                            {
                                String onInvalid = (attributeNode.Attributes["onInvalid"] == null ? null : attributeNode.Attributes["onInvalid"].Value);
                                String description = (attributeNode.Attributes["description"] == null ? null : attributeNode.Attributes["description"].Value);
                                if (onInvalid != null && onInvalid.Length > 0)
                                    attribute.OnInvalid = onInvalid;
                                if (description != null && description.Length > 0)
                                    attribute.Description = description;

                                tag.addAttribute((org.owasp.validator.html.model.Attribute)attribute.Clone());
                            }
                            else
                            {
                                //TODO: make this work with .NET
                                //throw new PolicyException("Attribute '"+XMLUtil.getAttributeValue(attributeNode,"name")+"' was referenced as a common attribute in definition of '"+tag.getName()+"', but does not exist in <common-attributes>");

                            }
                        }
                        else
                        {
                            /* Custom attribute for this tag */
                            Attribute attribute = new Attribute(attributeNode.Attributes["name"].Value);
                            attribute.OnInvalid = (attributeNode.Attributes["onInvalid"] != null ? attributeNode.Attributes["onInvalid"].Value : null);
                            attribute.Description = (attributeNode.Attributes["description"] != null ? attributeNode.Attributes["description"].Value : null);
                            XmlNode regExpListNode = attributeNode.SelectNodes("regexp-list")[0];
                            if (regExpListNode != null)
                            {
                                XmlNodeList regExpList = regExpListNode.SelectNodes("regexp");
                                foreach (XmlNode regExpNode in regExpList)
                                {
                                    string regExpName = (regExpNode.Attributes["name"] == null ? null : regExpNode.Attributes["name"].Value);
                                    string value = (regExpNode.Attributes["value"] == null ? null : regExpNode.Attributes["value"].Value);
                                    if (regExpName != null && regExpName.Length > 0)
                                    {
                                        //AntiSamyPattern pattern = getRegularExpression(regExpName);
                                        string pattern = getRegularExpression(regExpName);
                                        if (pattern != null)
                                            attribute.addAllowedRegExp(pattern);
                                        //attribute.addAllowedRegExp(pattern.Pattern);
                                        else
                                        {
                                            throw new PolicyException("Regular expression '" + regExpName + "' was referenced as a common regexp in definition of '" + tag.Name + "', but does not exist in <common-regexp>");
                                        }
                                    }
                                    else if (value != null && value.Length > 0)
                                    {
                                        //TODO: see if I need to reimplement pattern.compile
                                        attribute.addAllowedRegExp(REGEXP_BEGIN + value + REGEXP_END);
                                    }
                                }
                            }
                            XmlNode literalListNode = attributeNode.SelectNodes("literal-list")[0];
                            if (literalListNode != null)
                            {
                                XmlNodeList literalNodes = literalListNode.SelectNodes("literal");
                                foreach (XmlNode literalNode in literalNodes)
                                {
                                    string value = (literalNode.Attributes["value"] == null ? null : literalNode.Attributes["value"].Value);
                                    if (value != null && value.Length > 0)
                                    {
                                        attribute.addAllowedValue(value);
                                    }
                                    else if (literalNode.Value != null)
                                    {
                                        attribute.addAllowedValue(literalNode.Value);
                                    }
                                }
                            }
                            tag.addAttribute(attribute);
                        }
                    }
                    tags.Add(name, tag);
                }
            }
            return tags;
        }

        /// <summary> Go through the <css-rules> section of the policy file.</summary>
        /// <param name="root">Top level of <css-rules>
        /// </param>
        /// <returns> An ArrayList of Property objects.
        /// </returns>
        /// <throws>  PolicyException  </throws>
        private Hashtable parseCSSRules(XmlNode cssNodeList)
        {
            Hashtable properties = new Hashtable();
            XmlNodeList propertyNodes = cssNodeList.SelectNodes("property");

            /*
		    * Loop through the list of attributes and add them to the collection.
		    */
            foreach (XmlNode ele in propertyNodes)
            {
                String name = (ele.Attributes["name"] == null ? null : ele.Attributes["name"].Value);
                String description = (ele.Attributes["description"] == null ? null : ele.Attributes["description"].Value);

                org.owasp.validator.html.model.Property property = new org.owasp.validator.html.model.Property(name);
                property.Description = description;

                String oninvalid = (ele.Attributes["onInvalid"] == null ? null : ele.Attributes["onInvalid"].Value);

                if (oninvalid != null && oninvalid.Length > 0)
                {
                    property.OnInvalid = oninvalid;
                }
                else
                {
                    property.OnInvalid = DEFAULT_ONINVALID;
                }

                XmlNode regExpListNode = ele.SelectNodes("regexp-list")[0];



                if (regExpListNode != null)
                {
                    XmlNodeList regExpList = regExpListNode.SelectNodes("regexp");


                    /*
    				 * First go through the allowed regular expressions.
	    			 */
                    foreach (XmlNode regExpNode in regExpList)
                    {
                        string regExpName = (regExpNode.Attributes["name"] == null ? null : regExpNode.Attributes["name"].Value);
                        string value = (regExpNode.Attributes["value"] == null ? null : regExpNode.Attributes["value"].Value);
                        //AntiSamyPattern pattern = getRegularExpression(regExpName);
                        string pattern = getRegularExpression(regExpName);
                        if (pattern != null)
                        {
                            //property.addAllowedRegExp(pattern.Pattern);
                            property.addAllowedRegExp(pattern);
                        }
                        else if (value != null)
                        {
                            property.addAllowedRegExp(REGEXP_BEGIN + value + REGEXP_END);
                        }
                        else
                        {
                            throw new PolicyException("Regular expression '" + regExpName + "' was referenced as a common regexp in definition of '" + property.Name + "', but does not exist in <common-regexp>");
                        }
                    }
                }
                
                XmlNode literalListNode = ele.SelectNodes("literal-list")[0];
                /*
                 * Then go through the allowed constants.
                 */
                if (literalListNode != null)
                {
                    XmlNodeList literalList = literalListNode.SelectNodes("literal");
                    foreach (XmlNode literalNode in literalList)
                    {
                        property.addAllowedValue(literalNode.Attributes["value"].Value);
                    }
                }
                XmlNode shorthandListNode = ele.SelectNodes("shorthand-list")[0];
                if (shorthandListNode != null)
                {
                    XmlNodeList shorthandList = shorthandListNode.SelectNodes("shorthand");
                    foreach (XmlNode shorthandNode in shorthandList)
                    {
                        property.addShorthandRef(shorthandNode.Attributes["name"].Value);
                    }
                }

                properties.Add(name, property);
            }
            return properties;
        }


        /// <summary> A simple method for returning on of the <common-regexp> entries by
        /// name.
        /// 
        /// </summary>
        /// <param name="name">The name of the common regexp we want to look up.
        /// </param>
        /// <returns> An AntiSamyPattern associated with the lookup name specified.
        /// </returns>
        /*
        public virtual AntiSamyPattern getRegularExpression(string name)
        {
            return (AntiSamyPattern)commonRegularExpressions[name];
        }
        */
        public virtual string getRegularExpression(string name)
        {
            if (name == null || commonRegularExpressions[name] == null) 
                return null;
            else
                return commonRegularExpressions[name].ToString();
            
        }
        /// <summary> A simple method for returning on of the <global-attribute> entries by
        /// name.
        /// </summary>
        /// <param name="name">The name of the global-attribute we want to look up.
        /// </param>
        /// <returns> An Attribute associated with the global-attribute lookup name specified.
        /// </returns>
        public virtual Attribute getGlobalAttributeByName(string name)
        {
            return (Attribute)globalAttributes[name];
        }

        /// <summary> A simple method for returning on of the <common-attribute> entries by
        /// name.
        /// </summary>
        /// <param name="name">The name of the common-attribute we want to look up.
        /// </param>
        /// <returns> An Attribute associated with the common-attribute lookup name specified.
        /// </returns>
        private Attribute getCommonAttributeByName(string attributeName)
        {
            return (Attribute)commonAttributes[attributeName];
        }

        /// <summary> Return a directive value based on a lookup name.</summary>
        /// <returns> A String object containing the directive associated with the lookup name, or null if none is found.
        /// </returns>
        public virtual string getDirective(string name)
        {
            return (string)directives[name];
        }
    }
}