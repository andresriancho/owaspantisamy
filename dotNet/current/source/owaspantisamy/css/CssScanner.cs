/*
* Copyright (c) 2009, Jerry Hoff
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
using System.IO;
using System.Collections;
using Parser = org.w3c.flute.parser.Parser;
using CleanResults = org.owasp.validator.html.CleanResults;
using Policy = org.owasp.validator.html.Policy;
using ScanException = org.owasp.validator.html.ScanException;
using InputSource = org.w3c.css.sac.InputSource;


namespace org.owasp.validator.css
{

    /// <summary> Encapsulates the parsing and validation of a CSS stylesheet or inline
    /// declaration. To make use of this class, instantiate the scanner with the
    /// desired policy and call either <code>scanInlineSheet()</code> or
    /// <code>scanStyleSheet</code> as appropriate.
    /// 
    /// </summary>
    /// <seealso cref="scanInlineStyle(String, String)">
    /// </seealso>
    /// <seealso cref="scanStyleSheet(String)">
    /// 
    /// </seealso>
    
    public class CssScanner
    {
        private static int DEFAULT_TIMEOUT = 1000;

        /// <summary> The parser to be used in any scanning</summary>
        private Parser parser = new Parser();

        /// <summary> The policy file to be used in any scanning</summary>
        private Policy policy;

        /// <summary> Constructs a scanner based on the given policy.
        /// 
        /// </summary>
        /// <param name="policy">the policy to follow when scanning
        /// </param>
        public CssScanner(Policy policy)
        {
            this.policy = policy;
        }

        /// <summary> Scans the contents of a full stylesheet (ex. a file based stylesheet or
        /// the complete stylesheet contents as declared within &lt;style&gt; tags)
        /// 
        /// </summary>
        /// <param name="taintedCss">a <code>String</code> containing the contents of the CSS
        /// stylesheet to validate
        /// </param>
        /// <returns> a <code>CleanResuts</code> object containing the results of the
        /// scan
        /// </returns>
        /// <throws>  ScanException </throws>
        /// <summary>             if an error occurs during scanning
        /// </summary>
        public virtual CleanResults scanStyleSheet(string taintedCss, int sizeLimit)
        {
            DateTime startOfScan = new DateTime();
            ArrayList errorMessages = new ArrayList();
            ArrayList stylesheets = new ArrayList();
            CssHandler handler = new CssHandler(policy, stylesheets, errorMessages);


            parser.setDocumentHandler(handler);
            try
            {
                // parse the style declaration
                // note this does not count against the size limit because it
                // should already have been counted by the caller since it was
                // embedded in the HTML

                InputSource source = new InputSource();
                source.setCharacterStream(new java.io.CharArrayReader(taintedCss.ToCharArray()));
                parser.parseStyleSheet(source);

                //not sure if this is correct, the java version puts in a string reader, i just pass in a string

            }
            catch (IOException ioe)
            {
                throw new ScanException(ioe);
            }

            //parseImportedStylesheets(stylesheets, handler, errorMessages, sizeLimit);

            return new CleanResults(startOfScan, new DateTime(), handler.getCleanStylesheet(), null, errorMessages);
            //return null;
        }

        /// <summary> Scans the contents of an inline style declaration (ex. in the style
        /// attribute of an HTML tag) and validates the style sheet according to this
        /// <code>CssScanner</code>'s policy file.
        /// 
        /// </summary>
        /// <param name="taintedCss">a <code>String</code> containing the contents of the CSS
        /// stylesheet to validate
        /// </param>
        /// <param name="tagName">the name of the tag for which this inline style was declared
        /// </param>
        /// <returns> a <code>CleanResuts</code> object containing the results of the
        /// scan
        /// </returns>
        /// <throws>  ScanException </throws>
        /// <summary>             if an error occurs during scanning
        /// </summary>

        public virtual CleanResults scanInlineStyle(string taintedCss, string tagName, int sizeLimit)
        {

            DateTime startOfScan = new DateTime();

            ArrayList errorMessages = new ArrayList();

            // Create a queue of all style sheets that need to be validated to
            // account for any sheets that may be imported by the current CSS

            ArrayList stylesheets = new ArrayList();

            CssHandler handler = new CssHandler(policy, stylesheets, errorMessages, tagName);

            parser.setDocumentHandler(handler);

            try
            {
                // parse the inline style declaration
                // note this does not count against the size limit because it
                // should already have been counted by the caller since it was
                // embedded in the HTML
                InputSource source = new InputSource();
                source.setCharacterStream(new java.io.CharArrayReader(taintedCss.ToCharArray()));
                parser.parseStyleSheet(source);
                //parser.parseStyleDeclaration(taintedCss);
            }
            catch (IOException ioe)
            {
                throw new ScanException(ioe);
            }

            //parseImportedStylesheets(stylesheets, handler, errorMessages, sizeLimit);

            return new CleanResults(startOfScan, new DateTime(), handler
                .getCleanStylesheet(), null, errorMessages);

        }

        //        /// <summary> Test method to demonstrate CSS scanning.
        //        /// 
        //        /// </summary>
        //        /// <deprecated>
        //        /// </deprecated>
        //        /// <param name="args">unused
        //        /// </param>
        //        /// <throws>  Exception </throws>
        //        /// <summary>             if any error occurs
        //        /// </summary>
        //        [STAThread]
        //        public static void  Main(System.String[] args)
        //        {
        //            Policy policy = Policy.getInstance();
        //            CssScanner scanner = new CssScanner(policy);

        //            CleanResults results = null;

        //            results = scanner.scanStyleSheet(".test, demo, #id {position:absolute;border: thick solid red;} ");

        //            // Test case for live CSS docs. Just change URL to a live CSS on the
        //            // internet. Note this is test code and does not handle IO errors
        //            //		StringBuilder sb = new StringBuilder();
        //            //		BufferedReader reader = new BufferedReader(new InputStreamReader(
        //            //				new URL("http://www.owasp.org/skins/monobook/main.css")
        //            //						.openStream()));
        //            //		String line = null;
        //            //		while ((line = reader.readLine()) != null) {
        //            //			sb.append(line);
        //            //			sb.append("\n");
        //            //		}
        //            //		results = scanner.scanStyleSheet(sb.toString());

        //            System.Console.Out.WriteLine("Cleaned result:");
        //            System.Console.Out.WriteLine(results.CleanHTML);
        //            System.Console.Out.WriteLine("--");
        //            System.Console.Out.WriteLine("Error messages");
        //            //UPGRADE_TODO: Method 'java.io.PrintStream.println' was converted to 'System.Console.Out.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintStreamprintln_javalangObject'"
        //            System.Console.Out.WriteLine(SupportClass.CollectionToString(results.ErrorMessages));
        //        }
    }
}