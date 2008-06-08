/*
 * Copyright (c) 2007-2008, Arshan Dabirsiaghi, Jason Li
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
package org.owasp.validator.css;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;

import org.apache.batik.css.parser.Parser;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpContentTooLargeException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.ScanException;
import org.owasp.validator.html.util.ErrorMessageUtil;
import org.owasp.validator.html.util.HTMLEntityEncoder;
import org.w3c.css.sac.InputSource;

/**
 * Encapsulates the parsing and validation of a CSS stylesheet or inline
 * declaration. To make use of this class, instantiate the scanner with the
 * desired policy and call either <code>scanInlineSheet()</code> or
 * <code>scanStyleSheet</code> as appropriate.
 * 
 * @see #scanInlineStyle(String, String)
 * @see #scanStyleSheet(String)
 * 
 * @author Jason Li
 */
public class CssScanner {

    private static final int DEFAULT_TIMEOUT = 1000;

    /**
     * The parser to be used in any scanning
     */
    private final Parser parser = new Parser();

    /**
     * The policy file to be used in any scanning
     */
    private final Policy policy;

    /**
     * Constructs a scanner based on the given policy.
     * 
     * @param policy
     *                the policy to follow when scanning
     */
    public CssScanner(Policy policy) {
	this.policy = policy;
    }

    /**
     * Scans the contents of a full stylesheet (ex. a file based stylesheet
     * or the complete stylesheet contents as declared within &lt;style&gt;
     * tags)
     * 
     * @param taintedCss
     *                a <code>String</code> containing the contents of the
     *                CSS stylesheet to validate
     * @param sizeLimit
     *                the limit on the total size in bytes of any imported
     *                stylesheets
     * @return a <code>CleanResuts</code> object containing the results of
     *         the scan
     * @throws ScanException
     *                 if an error occurs during scanning
     */
    public CleanResults scanStyleSheet(String taintedCss, int sizeLimit)
	    throws ScanException {

	Date startOfScan = new Date();
	ArrayList errorMessages = new ArrayList();

	// Create a queue of all style sheets that need to be validated to
	// account for any sheets that may be imported by the current CSS
	LinkedList stylesheets = new LinkedList();

	CssHandler handler = new CssHandler(policy, stylesheets, errorMessages);

	// parse the stylesheet
	parser.setDocumentHandler(handler);

	try {
	    // parse the style declaration
	    // note this does not count against the size limit because it
	    // should already have been counted by the caller since it was
	    // embedded in the HTML
	    parser
		    .parseStyleSheet(new InputSource(new StringReader(
			    taintedCss)));
	} catch (IOException ioe) {
	    throw new ScanException(ioe);
	}

	parseImportedStylesheets(stylesheets, handler, errorMessages, sizeLimit);

	return new CleanResults(startOfScan, new Date(), handler
		.getCleanStylesheet(), null, errorMessages);
    }

    /**
     * Scans the contents of an inline style declaration (ex. in the style
     * attribute of an HTML tag) and validates the style sheet according to
     * this <code>CssScanner</code>'s policy file.
     * 
     * @param taintedCss
     *                a <code>String</code> containing the contents of the
     *                CSS stylesheet to validate
     * @param tagName
     *                the name of the tag for which this inline style was
     *                declared
     * 
     * @param sizeLimit
     *                the limit on the total size in bites of any imported
     *                stylesheets
     * @return a <code>CleanResuts</code> object containing the results of
     *         the scan
     * @throws ScanException
     *                 if an error occurs during scanning
     */
    public CleanResults scanInlineStyle(String taintedCss, String tagName,
	    int sizeLimit) throws ScanException {

	Date startOfScan = new Date();

	ArrayList errorMessages = new ArrayList();

	// Create a queue of all style sheets that need to be validated to
	// account for any sheets that may be imported by the current CSS
	LinkedList stylesheets = new LinkedList();

	CssHandler handler = new CssHandler(policy, stylesheets, errorMessages,
		tagName);

	parser.setDocumentHandler(handler);

	try {
	    // parse the inline style declaration
	    // note this does not count against the size limit because it
	    // should already have been counted by the caller since it was
	    // embedded in the HTML
	    parser.parseStyleDeclaration(taintedCss);
	} catch (IOException ioe) {
	    throw new ScanException(ioe);
	}

	parseImportedStylesheets(stylesheets, handler, errorMessages, sizeLimit);

	return new CleanResults(startOfScan, new Date(), handler
		.getCleanStylesheet(), null, errorMessages);
    }

    /**
     * Parses through a <code>LinkedList</code> of imported stylesheet
     * URIs, this method parses through those stylesheets and validates them
     * 
     * @param stylesheets
     *                the <code>LinkedList</code> of stylesheet URIs to
     *                parse
     * @param handler
     *                the <code>CssHandler</code> to use for parsing
     * @param errorMessages
     *                the list of error messages to append to
     * @param sizeLimit
     *                the limit on the total size in bites of any imported
     *                stylesheets
     * @throws ScanException
     *                 if an error occurs during scanning
     */
    private void parseImportedStylesheets(LinkedList stylesheets,
	    CssHandler handler, ArrayList errorMessages, int sizeLimit)
	    throws ScanException {

	int importedStylesheets = 0;

	// if stylesheets were imported by the inline style declaration,
	// continue parsing the nested styles. Note this only happens
	// if CSS importing was enabled in the policy file
	if (!stylesheets.isEmpty()) {
	    HttpClient httpClient = new HttpClient();

	    // Ensure that we have appropriate timeout values so we don't
	    // get DoSed waiting for returns
	    HttpConnectionManagerParams params = httpClient
		    .getHttpConnectionManager().getParams();

	    int timeout = DEFAULT_TIMEOUT;

	    try {
		timeout = Integer.parseInt(policy
			.getDirective(Policy.CONNECTION_TIMEOUT));
	    } catch (NumberFormatException nfe) {
	    }

	    params.setConnectionTimeout(timeout);
	    params.setSoTimeout(timeout);
	    httpClient.getHttpConnectionManager().setParams(params);

	    int allowedImports = Policy.DEFAULT_MAX_STYLESHEET_IMPORTS;
	    try {
		allowedImports = Integer.parseInt(policy
			.getDirective("maxStyleSheetImports"));
	    } catch (NumberFormatException nfe) {
	    }

	    while (!stylesheets.isEmpty()) {

		URI stylesheetUri = (URI) stylesheets.removeFirst();

		if (++importedStylesheets > allowedImports) {
		    errorMessages.add(ErrorMessageUtil.getMessage(
			    ErrorMessageUtil.ERROR_CSS_IMPORT_EXCEEDED,
			    new Object[] {
				    HTMLEntityEncoder
					    .htmlEntityEncode(stylesheetUri
						    .toString()),
				    String.valueOf(allowedImports) }));
		    continue;
		}

		GetMethod stylesheetRequest = new GetMethod(stylesheetUri
			.toString());

		byte[] stylesheet = null;
		try {
		    // pull down stylesheet, observing size limit
		    httpClient.executeMethod(stylesheetRequest);
		    stylesheet = stylesheetRequest.getResponseBody(sizeLimit);
		} catch (HttpContentTooLargeException hctle) {
		    errorMessages
			    .add(ErrorMessageUtil
				    .getMessage(
					    ErrorMessageUtil.ERROR_CSS_IMPORT_INPUT_SIZE,
					    new Object[] {
						    HTMLEntityEncoder
							    .htmlEntityEncode(stylesheetUri
								    .toString()),
						    String.valueOf(policy
							    .getMaxInputSize()) }));
		} catch (IOException ioe) {
		    errorMessages.add(ErrorMessageUtil
			    .getMessage(
				    ErrorMessageUtil.ERROR_CSS_IMPORT_FAILURE,
				    new Object[] { HTMLEntityEncoder
					    .htmlEntityEncode(stylesheetUri
						    .toString()) }));
		} finally {
		    stylesheetRequest.releaseConnection();
		}

		if (stylesheet != null) {
		    // decrease the size limit based on the
		    sizeLimit -= stylesheet.length;

		    try {
			InputSource nextStyleSheet = new InputSource(
				new InputStreamReader(new ByteArrayInputStream(
					stylesheet)));
			parser.parseStyleSheet(nextStyleSheet);

		    } catch (IOException ioe) {
			throw new ScanException(ioe);
		    }

		}
	    }
	}
    }

    /**
     * Test method to demonstrate CSS scanning.
     * 
     * @deprecated
     * @param args
     *                unused
     * @throws Exception
     *                 if any error occurs
     */
    public static void main(String[] args) throws Exception {
	Policy policy = Policy.getInstance("resources/antisamy-1.2.xml");
	CssScanner scanner = new CssScanner(policy);

	CleanResults results = null;

	results = scanner
		.scanStyleSheet(
			"@import url(http://www.owasp.org/skins/monobook/main.css);"
				+ "@import url(http://www.w3schools.com/stdtheme.css);"
				+ "@import url(http://www.google.com/ig/f/t1wcX5O39cc/ig.css); ",
			Integer.MAX_VALUE);

	// Test case for live CSS docs. Just change URL to a live CSS on
	// the internet. Note this is test code and does not handle IO
	// errors
	// StringBuffer sb = new StringBuffer();
	// BufferedReader reader = new BufferedReader(new InputStreamReader(
	// new URL("http://www.owasp.org/skins/monobook/main.css")
	// .openStream()));
	// String line = null;
	// while ((line = reader.readLine()) != null) {
	// sb.append(line);
	// sb.append("\n");
	// }
	// results = scanner.scanStyleSheet(sb.toString(),
	// Policy.DEFAULT_MAX_INPUT_SIZE);

	System.out.println("Cleaned result:");
	System.out.println(results.getCleanHTML());
	System.out.println("--");
	System.out.println("Error messages");
	System.out.println(results.getErrorMessages());
    }
}
