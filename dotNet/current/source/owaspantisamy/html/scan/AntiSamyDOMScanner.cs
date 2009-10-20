/*
* Copyright (c) 2009, Jerry Hoff
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
using System.IO;
using System.Xml;
using System.Text;
using System.Web;
using System.Collections;

using HtmlAgilityPack;

using org.owasp.validator.html.model;
using org.owasp.validator.css;
using org.owasp.validator.html.util;

using Attribute = org.owasp.validator.html.model.Attribute;



namespace org.owasp.validator.html.scan
{
    /// <summary> This is where the magic lives. All the scanning/filtration logic resides here, but it should not be called
    /// directly. All scanning should be done through a <code>AntiSamy.scan()</code> method.
    /// </summary>

    public class AntiSamyDOMScanner
    {
        private void InitBlock()
        {
            dom = document.CreateDocumentFragment();
        }

        virtual public CleanResults Results
        {
            get { return results; }
            set { this.results = value; }
        }

        //policy holds the parsed attributes from the XML config file
        private Policy policy;

        //will hold the results of the scan
        private CleanResults results = null;

        //all error messages live in here
        private ArrayList errorMessages = new ArrayList();

        //needed to parse input
        private XmlDocument document = new XmlDocument();

        //needed to represent the parsed version of the input
        private XmlDocumentFragment dom;

        public const string DEFAULT_ENCODING_ALGORITHM = "UTF-8";

        /// <summary> Main parsing engine </summary>
        /// <param name="html">A String whose contents we want to scan.</param>
        /// <returns> A <code>CleanResults</code> object with an <code>XMLDocumentFragment</code>
        ///  object and its String representation, as well as some scan statistics.
        /// </returns>
        /// <throws>  ScanException </throws>
        public virtual CleanResults scan(string html, string inputEncoding, string outputEncoding)
        {
            if (html == null)
            {
                throw new ScanException("No input (null)");
            }

            //had problems with the &nbsp; getting double encoded, so this converts it to a literal space.  
            //this may need to be changed.
            html = html.Replace("&nbsp;", char.Parse("\u00a0").ToString());


            //We have to replace any invalid XML characters
            
            html = stripNonValidXMLCharacters(html);


            //holds the maximum input size for the incoming fragment
            int maxInputSize = Policy.DEFAULT_MAX_INPUT_SIZE;

            //grab the size specified in the config file
            try
            {
                maxInputSize = int.Parse(policy.getDirective("maxInputSize"));
            }
            catch (FormatException fe)
            {
                Console.WriteLine("Format Exception: " + fe.ToString());
            }

            //ensure our input is less than the max
            if (maxInputSize < html.Length)
            {
                throw new ScanException("File size [" + html.Length + "] is larger than maximum [" + maxInputSize + "]");
            }

            //grab start time (to be put in the result set along with end time)
            DateTime start = DateTime.Now;

            //fixes some weirdness in HTML agility
            if (!HtmlNode.ElementsFlags.Contains("iframe"))
                HtmlNode.ElementsFlags.Add("iframe", HtmlElementFlag.Empty);
            HtmlNode.ElementsFlags.Remove("form");

            //Let's parse the incoming HTML
            HtmlDocument doc = new HtmlDocument();
            doc.LoadHtml(html);

            //add closing tags
            doc.OptionAutoCloseOnEnd = true;

            //enforces XML rules, encodes big 5
            doc.OptionOutputAsXml = true;

            //loop through every node now, and enforce the rules held in the policy object
            for (int i = 0; i < doc.DocumentNode.ChildNodes.Count; i++)
            {
                //grab current node
                HtmlNode tmp = doc.DocumentNode.ChildNodes[i];

                //this node can hold other nodes, so recursively validate
                recursiveValidateTag(tmp);

                if (tmp.ParentNode == null)
                {
                    i--;
                }
            }

            //all the cleaned HTML
            string finalCleanHTML = doc.DocumentNode.InnerHtml;

            //grab end time (to be put in the result set along with start time)
            DateTime end = DateTime.Now;

            results = new CleanResults(start, end, finalCleanHTML, dom, errorMessages);

            return results;
        }



        int num = 0;


        private void recursiveValidateTag(HtmlNode node)
        {
            int maxinputsize = int.Parse(policy.getDirective("maxInputSize"));

            num++;

            HtmlNode parentNode = node.ParentNode;
            HtmlNode tmp = null;
            string tagName = node.Name;

            //check this out
            //might not be robust enough
            if (tagName.ToLower().Equals("#text"))  // || tagName.ToLower().Equals("#comment"))
            {
                return;
            }

            Tag tag = policy.getTagByName(tagName.ToLower());

            if (tag == null || "filter".Equals(tag.Action))
            {
                StringBuilder errBuff = new StringBuilder();
                if (tagName == null || tagName.Trim().Equals(""))
                    errBuff.Append("An unprocessable ");
                else
                    errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName.ToLower()) + "</b> ");

                errBuff.Append("tag has been filtered for security reasons. The contents of the tag will ");
                errBuff.Append("remain in place.");

                errorMessages.Add(errBuff.ToString());

                for (int i = 0; i < node.ChildNodes.Count; i++)
                {
                    tmp = node.ChildNodes[i];
                    recursiveValidateTag(tmp);

                    if (tmp.ParentNode == null)
                    {
                        i--;
                    }
                }
                promoteChildren(node);
                return;
            }
            else if ("validate".Equals(tag.Action))
            {
                if ("style".Equals(tagName.ToLower()) && policy.getTagByName("style") != null)
                {
                    CssScanner styleScanner = new CssScanner(policy);
                    try
                    {

                        CleanResults cr = styleScanner.scanStyleSheet(node.FirstChild.InnerHtml, maxinputsize);

                        foreach (string msg in cr.getErrorMessages())
                            errorMessages.Add(msg.ToString());

                        /*
                         * If IE gets an empty style tag, i.e. <style/>
                         * it will break all CSS on the page. I wish I
                         * was kidding. So, if after validation no CSS
                         * properties are left, we would normally be left
                         * with an empty style tag and break all CSS. To
                         * prevent that, we have this check.
                         */

                        if (cr.getCleanHTML() == null || cr.getCleanHTML().Equals(""))
                        {

                            //node.getFirstChild().setNodeValue("/* */");
                            node.FirstChild.InnerHtml = "/* */";


                        }
                        else
                        {

                            //node.getFirstChild().setNodeValue(cr.getCleanHTML());
                            node.FirstChild.InnerHtml = cr.getCleanHTML();
                        }

                    }
                    //    catch (DomException e)
                    //    {
                    //        addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[] { HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue()) });
                    //        parentNode.removeChild(node);
                    //    }
                    catch (ScanException e)
                    {
                        Console.WriteLine("Scan Exception: " + e.Message);
                        
                        //addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[] { HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue()) });
                        parentNode.RemoveChild(node);
                    }
                }

                HtmlAttribute attribute = null;
                for (int currentAttributeIndex = 0; currentAttributeIndex < node.Attributes.Count; currentAttributeIndex++)
                {
                    attribute = node.Attributes[currentAttributeIndex];

                    string name = attribute.Name;
                    string _value = attribute.Value;

                    Attribute attr = tag.getAttributeByName(name);

                    if (attr == null)
                    {
                        attr = policy.getGlobalAttributeByName(name);
                    }

                    bool isAttributeValid = false;

                    if ("style".Equals(name.ToLower()) && attr != null)
                    {

                        CssScanner styleScanner = new CssScanner(policy);

                        try
                        {

                            CleanResults cr = styleScanner.scanInlineStyle(_value, tagName, maxinputsize);

                            //attribute.setNodeValue(cr.getCleanHTML());
                            attribute.Value = cr.getCleanHTML();

                            ArrayList cssScanErrorMessages = cr.getErrorMessages();

                            foreach (string msg in cr.getErrorMessages())
                                errorMessages.Add(msg.ToString());

                        }
                        /*
                        catch (DOMException e)
                        {

                            addError(ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED, new Object[] { tagName, HTMLEntityEncoder.htmlEntityEncode(node.getNodeValue()) });

                            ele.removeAttribute(name);
                            currentAttributeIndex--;

                        }
                        */
                        catch (ScanException ex)
                        {
                            Console.WriteLine(ex.Message);
                            //addError(ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED, new Object[] { tagName, HTMLEntityEncoder.htmlEntityEncode(node.getNodeValue()) });
                            //ele.removeAttribute(name);
                            currentAttributeIndex--;
                        }

                    }
                    else
                    {
                        if (attr != null)
                        {
                            //try to find out how robust this is - do I need to do this in a loop?
                            _value = HtmlEntity.DeEntitize(_value);

                            foreach (string allowedValue in attr.AllowedValues)
                            {
                                if (isAttributeValid) break;

                                if (allowedValue != null && allowedValue.ToLower().Equals(_value.ToLower()))
                                {
                                    isAttributeValid = true;
                                }
                            }

                            foreach (string ptn in attr.AllowedRegExp)
                            {
                                if (isAttributeValid) break;
                                string pattern = "^" + ptn + "$";
                                Match m = Regex.Match(_value, pattern);
                                if (m.Success)
                                {
                                    isAttributeValid = true;
                                }
                            }

                            if (!isAttributeValid)
                            {
                                string onInvalidAction = attr.OnInvalid;
                                StringBuilder errBuff = new StringBuilder();

                                errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag contained an attribute that we couldn't process. ");
                                errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(name) + "</b> attribute had a value of <u>" + HTMLEntityEncoder.htmlEntityEncode(_value) + "</u>. ");
                                errBuff.Append("This value could not be accepted for security reasons. We have chosen to ");

                                //Console.WriteLine(policy);

                                if ("removeTag".Equals(onInvalidAction))
                                {
                                    parentNode.RemoveChild(node);
                                    errBuff.Append("remove the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag and its contents in order to process this input. ");
                                }
                                else if ("filterTag".Equals(onInvalidAction))
                                {
                                    for (int i = 0; i < node.ChildNodes.Count; i++)
                                    {
                                        tmp = node.ChildNodes[i];
                                        recursiveValidateTag(tmp);
                                        if (tmp.ParentNode == null)
                                        {
                                            i--;
                                        }
                                    }

                                    promoteChildren(node);

                                    errBuff.Append("filter the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag and leave its contents in place so that we could process this input.");
                                }
                                else
                                {
                                    node.Attributes.Remove(attr.Name);
                                    currentAttributeIndex--;
                                    errBuff.Append("remove the <b>" + HTMLEntityEncoder.htmlEntityEncode(name) + "</b> attribute from the tag and leave everything else in place so that we could process this input.");

                                }

                                errorMessages.Add(errBuff.ToString());

                                if ("removeTag".Equals(onInvalidAction) || "filterTag".Equals(onInvalidAction))
                                {
                                    return; // can't process any more if we remove/filter the tag	
                                }
                            }
                        }
                        else
                        {
                            StringBuilder errBuff = new StringBuilder();

                            errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(name));
                            errBuff.Append("</b> attribute of the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag has been removed for security reasons. ");
                            errBuff.Append("This removal should not affect the display of the HTML submitted.");

                            errorMessages.Add(errBuff.ToString());
                            node.Attributes.Remove(name);
                            currentAttributeIndex--;

                        } // end if attribute is or is not found in policy file
                    } // end if style.equals("name") 
                } // end while loop through attributes 


                for (int i = 0; i < node.ChildNodes.Count; i++)
                {
                    tmp = node.ChildNodes[i];
                    recursiveValidateTag(tmp);
                    if (tmp.ParentNode == null)
                    {
                        i--;
                    }
                }

            }
            else if ("truncate".Equals(tag.Action))
            {
                Console.WriteLine("truncate");
                HtmlAttributeCollection nnmap = node.Attributes;

                while (nnmap.Count > 0)
                {

                    StringBuilder errBuff = new StringBuilder();

                    errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(nnmap[0].Name));
                    errBuff.Append("</b> attribute of the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag has been removed for security reasons. ");
                    errBuff.Append("This removal should not affect the display of the HTML submitted.");
                    node.Attributes.Remove(nnmap[0].Name);
                    errorMessages.Add(errBuff.ToString());
                }

                HtmlNodeCollection cList = node.ChildNodes;

                int i = 0;
                int j = 0;
                int length = cList.Count;

                while (i < length)
                {

                    HtmlNode nodeToRemove = cList[j];
                    if (nodeToRemove.NodeType != HtmlNodeType.Text && nodeToRemove.NodeType != HtmlNodeType.Comment)
                    {
                        node.RemoveChild(nodeToRemove);
                    }
                    else
                    {
                        j++;
                    }
                    i++;
                }

            }
            else
            {
                errorMessages.Add("The <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag has been removed for security reasons.");
                parentNode.RemoveChild(node);
            }
        }

        public AntiSamyDOMScanner(Policy policy)
        {
            InitBlock();
            this.policy = policy;
        }

        public AntiSamyDOMScanner()
        {
            InitBlock();
            this.policy = Policy.getInstance();
        }

        private void addError(string errorKey, object[] objs)
        {

            errorMessages.Add(errorKey);
            //errorMessages.add(ErrorMessageUtil.getMessage(errorKey, objs));

        }


        private void promoteChildren(HtmlNode node)
        {

            HtmlNodeCollection nodeList = node.ChildNodes;
            HtmlNode parent = node.ParentNode;

            while (nodeList.Count > 0)
            {
                HtmlNode removeNode = node.RemoveChild(nodeList[0]);
                parent.InsertBefore(removeNode, node);
            }

            parent.RemoveChild(node);
        }
        
        private string stripNonValidXMLCharacters(string in_Renamed)
        {

            StringBuilder out_Renamed = new StringBuilder(); // Used to hold the output.

            char current; // Used to reference the current character.

            if (in_Renamed == null || ("".Equals(in_Renamed)))
                return ""; // vacancy test.
            for (int i = 0; i < in_Renamed.Length; i++)
            {
                current = in_Renamed[i]; // NOTE: No IndexOutOfBoundsException caught here; it should not happen.
                if ((current == 0x9) || (current == 0xA) || (current == 0xD) || ((current >= 0x20) && (current <= 0xD7FF)) || ((current >= 0xE000) && (current <= 0xFFFD)) || ((current >= 0x10000) && (current <= 0x10FFFF)))
                    out_Renamed.Append(current);
            }

            return out_Renamed.ToString();
        }
        
    }
}