/*
* Copyright (c) 2007-2008, Arshan Dabirsiaghi, Jason Li
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
using System.Collections;
using TidyCOM;
using org.owasp.validator.html.model;
using System.Web;


namespace org.owasp.validator.html.scan
{
	/// <summary> This is where the magic lives. All the scanning/filtration logic resides here, but it should not be called
	/// directly. All scanning should be done through a <code>AntiSamy.scan()</code> method.
	/// 
	/// </summary>
	/// <author>  Arshan Dabirsiaghi
	/// 
	/// </author>
	
	public class AntiSamyDOMScanner
	{
		private void  InitBlock()
		{
			dom = document.CreateDocumentFragment();
		}
        
		virtual public CleanResults Results
		{
			get { return results; }
			set { this.results = value; }
		}
		
		private Policy policy;
		private CleanResults results = null;
		private ArrayList errorMessages = new ArrayList();
		private XmlDocument document = new XmlDocument();
		private XmlDocumentFragment dom;
		public const System.String DEFAULT_ENCODING_ALGORITHM = "UTF-8";

		/// <summary> This is where the magic lives.</summary>
		/// <param name="html">A String whose contents we want to scan.
		/// </param>
		/// <returns> A <code>CleanResults</code> object with an <code>XMLDocumentFragment</code> object and its String representation, as well as some scan statistics.
		/// </returns>
		/// <throws>  ScanException </throws>
		public virtual CleanResults scan(string html, string inputEncoding, string outputEncoding)
		{	
			if (html == null)
			{
				throw new ScanException("No input (null)");
			}
			
			int maxInputSize = Policy.DEFAULT_MAX_INPUT_SIZE;
			
			try
			{
				maxInputSize = int.Parse(policy.getDirective("maxInputSize"));
			}
			catch (System.FormatException nfe)
			{
			}
			
			if (maxInputSize < html.Length)
			{
				throw new ScanException("File size [" + html.Length + "] is larger than maximum [" + maxInputSize + "]");
			}
			
			DateTime start =DateTime.Now;
			/*
			try
			{
				*/
				html = stripNonValidXMLCharacters(html);
                TidyObject o = new TidyObject();
                o.Options.AddXmlDecl = false;
                o.Options.OutputXhtml = true;
                o.Options.UppercaseTags = false;
                o.Options.UppercaseAttributes = false;
                o.Options.Clean = false;
                o.Options.EncloseBlockText = false;
                o.Options.Doctype = "omit";
                //o.Options.OutputXhtml = false;
                o.Options.EncloseText = false;
                o.Options.DropFontTags = true;
                o.Options.Indent = TidyCOM.IndentScheme.AutoIndent;
                o.Options.TabSize = 2;
                string output = o.TidyMemToMem(html);
                Console.Write(output);

                XmlDocument doc = new XmlDocument();
                doc.LoadXml(output);

                try
                {
                    doc.LoadXml(output);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }

                foreach (XmlNode node in doc.ChildNodes)
                {
                    recursiveValidateTag(node);
                }

                //parse this into a dom and then do a recusive tag search
        
                /*
				DOMFragmentParser parser = new DOMFragmentParser();
				parser.setProperty("http://cyberneko.org/html/properties/names/elems", "lower");
				parser.setProperty("http://cyberneko.org/html/properties/default-encoding", inputEncoding);
				
				parser.parse(new XmlSourceSupport(new System.IO.StringReader(html)), dom);

				for (int i = 0; i < dom.ChildNodes.Count; i++)
				{	
					System.Xml.XmlNode tmp = dom.ChildNodes.Item(i);
					
					recursiveValidateTag(tmp);
					
					if (tmp.ParentNode == null)
					{
						i--;
					}
				}
				
				OutputFormat format = new OutputFormat();
				
				format.setLineWidth(80);
				format.setIndenting(true);
				format.setIndent(2);
				
				format.setEncoding(outputEncoding);
				format.setOmitXMLDeclaration("true".Equals(policy.getDirective("omitXmlDeclaration")));
				format.setOmitDocumentType("true".Equals(policy.getDirective("omitDoctypeDeclaration")));
				format.setPreserveEmptyAttributes(true);
				
				
				System.IO.StringWriter sw = new System.IO.StringWriter();
				
				if ("true".Equals(policy.getDirective("useXHTML")))
				{
					XHTMLSerializer serializer = new XHTMLSerializer(sw, format);
					serializer.serialize(dom);
				}
				else
				{
					HTMLSerializer serializer = new HTMLSerializer(sw, format);
					serializer.serialize(dom);
				}
				
				System.String finalCleanHTML = sw.GetStringBuilder().ToString();
				
				if ("true".Equals(policy.getDirective("omitXmlDeclaration")))
				{
					int bpos = finalCleanHTML.IndexOf("<?xml");
					int epos = finalCleanHTML.IndexOf("?>");
                 * 
					if (bpos != - 1 && bpos != - 1 && bpos < epos)
					{
						finalCleanHTML = finalCleanHTML.Substring(epos + 1);
					}
				}
				
				System.DateTime tempAux = System.DateTime.Now;
				results = new CleanResults(ref start, ref tempAux, finalCleanHTML, dom, errorMessages);
				
				return results;
			}			
			catch (XmlException e)
			{
				throw new ScanException(e);
			}
			catch (System.IO.IOException e)
			{
				throw new ScanException(e);
			}
             */
            return null; //remove this - just for testing purposes
		}
		/*
		
		/// <summary> The workhorse of the scanner. Recursively scans document elements
		/// according to the policy. This should be called implicitly through
		/// the AntiSamy.scan() method.
		/// </summary>
		/// <param name="node">The node to validate.
		/// </param>
		*/
		private void  recursiveValidateTag(XmlNode node)
		{
			Console.WriteLine(node.Name);

			if (!(node is System.Xml.XmlElement))
			{
				return ;
			}
			
			XmlElement ele = (XmlElement) node;
			XmlNode parentNode = ele.ParentNode;
			XmlNode tmp = null;
			string tagName = ele.Name;

            
            Tag tag = policy.getTagByName(tagName.ToLower());
            
            if (tag == null || "filter".Equals(tag.Action))
            {
				
                System.Text.StringBuilder errBuff = new System.Text.StringBuilder();

                //errBuff.Append("The <b>" + HttpServerUtility.HtmlEncode(tagName.ToLower()));
                errBuff.Append("</b> tag has been filtered for security reasons. The contents of the tag will ");
                errBuff.Append("remain in place.");
				
                errorMessages.Add(errBuff.ToString());
				
                for (int i = 0; i < node.ChildNodes.Count; i++)
                {
                    tmp = node.ChildNodes.Item(i);
					
                    recursiveValidateTag(tmp);
					
                    if (tmp.ParentNode == null)
                    {
                        i--;
                    }
                }
				
				
                //promoteChildren(ele);
				
                return ;
            }
            /*
            else if ("validate".Equals(tag.Action))
            {
				
				
                if ("style".Equals(tagName.ToLower()) && policy.getTagByName("style") != null)
                {
                    CssScanner styleScanner = new CssScanner(policy);
					
                    try
                    {
						
                        CleanResults cr = styleScanner.scanStyleSheet(node.FirstChild.Value);
						
                        errorMessages.AddRange(cr.ErrorMessages);
						
                        if (cr.CleanHTML == null || cr.CleanHTML.Equals(""))
                        {
							
                            //This was preventing me from commenting out this whole block
                            //so change it back to the comment chars
                            //change the | to /
                            //node.FirstChild.Value = "|* *|";
                        }
                        else
                        {
							
                            node.FirstChild.Value = cr.CleanHTML;
                        }
                    }
                    catch (System.Exception e)
                    {
						
                        errorMessages.Add("The <b>style</b> tag with a value of <u>" + HTMLEntityEncoder.htmlEntityEncode(node.FirstChild.Value) + "</u> because it was malformed. This may affect the look of the page.");
                        parentNode.RemoveChild(node);
						
                        return ;
                    }
                    catch (ScanException e)
                    {
						
                        errorMessages.Add("The <b>style</b> tag with a value of <u>" + HTMLEntityEncoder.htmlEntityEncode(node.FirstChild.Value) + "</u> because it was malformed. This may affect the look of the page.");
                        parentNode.RemoveChild(node);
						
                        return ;
                    }
                }
				
                XmlNode attribute = null;
				
                for (int currentAttributeIndex = 0; currentAttributeIndex < ((System.Xml.XmlAttributeCollection) ele.Attributes).Count; currentAttributeIndex++)
                {
					
                    attribute = ((System.Xml.XmlAttributeCollection) ele.Attributes).Item(currentAttributeIndex);
					
                    System.String name = attribute.Name;
                    System.String value_Renamed = attribute.Value;
					
                    Attribute attr = tag.getAttributeByName(name);
					
					
                    if (attr == null)
                    {
                        attr = policy.getGlobalAttributeByName(name);
                    }
					
                    bool isAttributeValid = false;
					
                    if ("style".Equals(name.ToLower()) && attr != null)
                    {
						
                        // invoke the CSS parser on this element
                        CssScanner styleScanner = new CssScanner(policy);
						
                        try
                        {
							
                            CleanResults cr = styleScanner.scanInlineStyle(value_Renamed, tagName);
							
                            attribute.Value = cr.CleanHTML;
							
                            System.Collections.ArrayList cssScanErrorMessages = cr.ErrorMessages;
                            errorMessages.AddRange(cssScanErrorMessages);
                        }
                        catch (System.Exception e)
                        {
							
                            errorMessages.Add("The <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag had a <b>style</b> attribute with a value of <u>" + HTMLEntityEncoder.htmlEntityEncode(node.Value) + "</u> that could not be accepted for security reasons. This may affect the look of the page.");
                            ele.RemoveAttribute(name);
                            currentAttributeIndex--;
                        }
                        catch (ScanException e)
                        {
							
                            errorMessages.Add("The <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag had a <b>style</b> attribute with a value of <u>" + HTMLEntityEncoder.htmlEntityEncode(node.Value) + "</u> that could not be accepted for security reasons. This may affect the look of the page.");
                            ele.RemoveAttribute(name);
                            currentAttributeIndex--;
                        }
                    }
                    else
                    {
						
                        if (attr != null)
                        {
							
                            System.Collections.IEnumerator allowedValues = attr.AllowedValues.GetEnumerator();
							
                            while (allowedValues.MoveNext() && !isAttributeValid)
                            {
								
                                System.String allowedValue = (System.String) allowedValues.Current;
								
                                if (allowedValue != null && allowedValue.ToLower().Equals(value_Renamed.ToLower()))
                                {
                                    isAttributeValid = true;
                                }
                            }
							
                            System.Collections.IEnumerator allowedRegexps = attr.AllowedRegExp.GetEnumerator();
							
                            while (allowedRegexps.MoveNext() && !isAttributeValid)
                            {
								
                                Pattern pattern = (Pattern) allowedRegexps.Current;
								
                                if (pattern != null && pattern.matcher(value_Renamed.ToLower()).matches())
                                {
                                    isAttributeValid = true;
                                }
                            }
							
                            if (!isAttributeValid)
                            {
								
								
                                System.String onInvalidAction = attr.OnInvalid;
                                System.Text.StringBuilder errBuff = new System.Text.StringBuilder();
								
                                errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag contained an attribute that we couldn't process. ");
                                errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(name) + "</b> attribute had a value of <u>" + HTMLEntityEncoder.htmlEntityEncode(value_Renamed) + "</u>. ");
                                errBuff.Append("This value could not be accepted for security reasons. We have chosen to ");
								
                                if ("removeTag".Equals(onInvalidAction))
                                {
									
                                    parentNode.RemoveChild(ele);
									
                                    errBuff.Append("remove the <b>" + tagName + "</b> tag and its contents in order to process this input. ");
                                }
                                else if ("filterTag".Equals(onInvalidAction))
                                {
									
                                    for (int i = 0; i < node.ChildNodes.Count; i++)
                                    {
                                        tmp = node.ChildNodes.Item(i);
										
                                        recursiveValidateTag(tmp);
										
                                        if (tmp.ParentNode == null)
                                        {
                                            i--;
                                        }
                                    }
									
                                    promoteChildren(ele);
									
                                    errBuff.Append("filter the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag and leave its contents in place so that we could process this input.");
                                }
                                else
                                {
									
									
                                    ele.RemoveAttribute(attr.Name);
									
                                    currentAttributeIndex--;
									
                                    errBuff.Append("remove the <b>" + HTMLEntityEncoder.htmlEntityEncode(name) + "</b> attribute from the tag and leave everything else in place so that we could process this input.");
                                }
								
                                errorMessages.Add(errBuff.ToString());
								
                                if ("removeTag".Equals(onInvalidAction) || "filterTag".Equals(onInvalidAction))
                                {
                                    return ; // can't process any more if we remove/filter the tag	
                                }
                            }
                        }
                        else
                        {
							
							
                            System.Text.StringBuilder errBuff = new System.Text.StringBuilder();
							
                            errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(name));
                            errBuff.Append("</b> attribute of the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag has been removed for security reasons. ");
                            errBuff.Append("This removal should not affect the display of the HTML submitted.");
							
                            errorMessages.Add(errBuff.ToString());
							
                            ele.RemoveAttribute(name);
							
                            currentAttributeIndex--;
                        } // end if attribute is or is not found in policy file
                    } // end if style.equals("name") 
                } // end while loop through attributes 
				
				
                for (int i = 0; i < node.ChildNodes.Count; i++)
                {
				    tmp = node.ChildNodes.Item(i);
					
                    recursiveValidateTag(tmp);
			
                    if (tmp.ParentNode == null)
                    {
                        i--;
                    }
                }
            }
            else if ("truncate".Equals(tag.Action))
            {
				
				
                System.Xml.XmlNamedNodeMap nnmap = (System.Xml.XmlAttributeCollection) ele.Attributes;
				
                while (nnmap.Count > 0)
                {
					
                    System.Text.StringBuilder errBuff = new System.Text.StringBuilder();
					
                    errBuff.Append("The <b>" + HTMLEntityEncoder.htmlEntityEncode(nnmap.Item(0).Name));
                    errBuff.Append("</b> attribute of the <b>" + HTMLEntityEncoder.htmlEntityEncode(tagName) + "</b> tag has been removed for security reasons. ");
                    errBuff.Append("This removal should not affect the display of the HTML submitted.");
					
                    ele.RemoveAttribute(nnmap.Item(0).Name);
					
                    errorMessages.Add(errBuff.ToString());
                }
				
                System.Xml.XmlNodeList cList = ele.ChildNodes;
				
                int i = 0;
                int j = 0;
                int length = cList.Count;
				
                while (i < length)
                {
					
                    System.Xml.XmlNode nodeToRemove = cList.Item(j);
					
                    if (System.Convert.ToInt16(nodeToRemove.NodeType) != (short) System.Xml.XmlNodeType.Text && System.Convert.ToInt16(nodeToRemove.NodeType) != (short) System.Xml.XmlNodeType.Comment)
                    {
                        ele.RemoveChild(nodeToRemove);
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
                parentNode.RemoveChild(ele);
            }
            */
		}
		
		
		
		/// <summary> This method replaces all entity codes with a normalized version of all entity references contained in order to reduce our encoding/parsing
		/// attack surface.
		/// </summary>
		/// <param name="txt">The string to be normalized.
		/// </param>
		/// <returns> The normalized version of the string.
		/// </returns>
		/*
		[STAThread]
		public static void  Main(System.String[] args)
		{
			
			System.DateTime start = System.DateTime.Now;
			
			//System.out.println( new AntiSamyDOMScanner().replaceEntityCodes ("This is &nbsp;&nbsp;, so &iexcl; omfg sdf &infg;") );
			
			System.DateTime end = System.DateTime.Now;
			
			System.Console.Out.WriteLine((end.Ticks - start.Ticks) / 1000D);
		}
		*/
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

		/*
		/// <summary> Used to promote the children of a parent to accomplish the "filterTag" action.</summary>
		/// <param name="ele">The Element we want to filter.
		/// </param>
		private void  promoteChildren(System.Xml.XmlElement ele)
		{
			System.Xml.XmlNodeList nodeList = ele.ChildNodes;
			System.Xml.XmlNode parent = ele.ParentNode;
			
			while (nodeList.Count > 0)
			{
				System.Xml.XmlNode node = ele.RemoveChild(nodeList.Item(0));
				parent.InsertBefore(node, ele);
			}
			
			parent.RemoveChild(ele);
		}
		*/

		/// <summary> 
		/// This method was borrowed from Mark McLaren, to whom I owe much beer.
		/// 
		/// This method ensures that the output String has only
		/// valid XML unicode characters as specified by the
		/// XML 1.0 standard. For reference, please see
		/// <a href="http://www.w3.org/TR/2000/REC-xml-20001006#NT-Char">the
		/// standard</a>. This method will return an empty
		/// String if the input is null or empty.
		/// 
		/// </summary>
		/// <param name="in">The String whose non-valid characters we want to remove.
		/// </param>
		/// <returns> The in String, stripped of non-valid characters.
		/// </returns>
		private string stripNonValidXMLCharacters(string in_Renamed)
		{
			
			System.Text.StringBuilder out_Renamed = new System.Text.StringBuilder(); // Used to hold the output.
			
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