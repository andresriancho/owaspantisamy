/*
 * Copyright (c) 2007, Arshan Dabirsiaghi, Jason Li
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

import java.io.IOException;
import java.io.StringReader;
import java.util.LinkedList;

import org.apache.batik.css.parser.Parser;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.ScanException;
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
	 *            the policy to follow when scanning
	 */
	public CssScanner(Policy policy) {
		this.policy = policy;
	}

	/**
	 * Scans the contents of a full stylesheet (ex. a file based stylesheet or
	 * the complete stylesheet contents as declared within &lt;style&gt; tags)
	 * 
	 * @param taintedCss
	 *            a <code>String</code> containing the contents of the CSS
	 *            stylesheet to validate
	 * @return a <code>CleanResuts</code> object containing the results of the
	 *         scan
	 * @throws ScanException
	 *             if an error occurs during scanning
	 */
	public CleanResults scanStyleSheet(String taintedCss) throws ScanException {

		// Create a queue of all style sheets that need to be validated to
		// account for any sheets that may be imported by the current CSS
		LinkedList stylesheets = new LinkedList();
		stylesheets.add(new InputSource(new StringReader(taintedCss)));

		CssHandler handler = new CssHandler(policy, stylesheets);

		// parse the stylesheet
		parser.setDocumentHandler(handler);

		// if any stylesheets are left to be parsed, continue parsing
		while (!stylesheets.isEmpty()) {
			try {
				parser.parseStyleSheet((InputSource) stylesheets.getFirst());
				stylesheets.removeFirst();
			} catch (IOException ioe) {
				throw new ScanException(ioe);
			}
		}

		return handler.getResults();
	}

	/**
	 * Scans the contents of an inline style declaration (ex. in the style
	 * attribute of an HTML tag) and validates the style sheet according to this
	 * <code>CssScanner</code>'s policy file.
	 * 
	 * @param taintedCss
	 *            a <code>String</code> containing the contents of the CSS
	 *            stylesheet to validate
	 * @param tagName
	 *            the name of the tag for which this inline style was declared
	 * @return a <code>CleanResuts</code> object containing the results of the
	 *         scan
	 * @throws ScanException
	 *             if an error occurs during scanning
	 */
	public CleanResults scanInlineStyle(String taintedCss, String tagName)
			throws ScanException {

		// Create a queue of all style sheets that need to be validated to
		// account for any sheets that may be imported by the current CSS
		LinkedList stylesheets = new LinkedList();

		CssHandler handler = new CssHandler(policy, stylesheets, tagName);

		parser.setDocumentHandler(handler);

		try {
			// parse the inline style declaration
			parser.parseStyleDeclaration(taintedCss);

			// if stylesheets were imported by the inline style declaration,
			// continue parsing the nested styles
			while (!stylesheets.isEmpty()) {
				try {
					parser.parseStyleSheet((InputSource) stylesheets.getFirst());

				} catch (IOException ioe) {
					throw new ScanException(ioe);
				}
			}
		} catch (IOException ioe) {
			throw new ScanException(ioe);
		}

		return handler.getResults();
	}

	/**
	 * Test method to demonstrate CSS scanning.
	 * 
	 * @deprecated
	 * @param args
	 *            unused
	 * @throws Exception
	 *             if any error occurs
	 */
	public static void main(String[] args) throws Exception {
		Policy policy = Policy.getInstance();
		CssScanner scanner = new CssScanner(policy);

		CleanResults results = null;

		results = scanner.scanStyleSheet(".test, demo, #id {border: thick solid red;} ");
		
		// Test case for live CSS docs. Just change URL to a live CSS on the
		// internet. Note this is test code and does not handle IO errors
//		StringBuilder sb = new StringBuilder();
//		BufferedReader reader = new BufferedReader(new InputStreamReader(
//				new URL("http://www.owasp.org/skins/monobook/main.css")
//						.openStream()));
//		String line = null;
//		while ((line = reader.readLine()) != null) {
//			sb.append(line);
//			sb.append("\n");
//		}
//		results = scanner.scanStyleSheet(sb.toString());

		System.out.println("Cleaned result:");
		System.out.println(results.getCleanHTML());
		System.out.println("--");
		System.out.println("Error messages");
		System.out.println(results.getErrorMessages());
	}
}
