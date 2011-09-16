/*
 * Copyright (c) 2007-2010, Arshan Dabirsiaghi, Jason Li
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

package org.owasp.validator.html.scan;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Date;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xerces.xni.parser.XMLDocumentFilter;
import org.apache.xml.serialize.HTMLSerializer;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XHTMLSerializer;
import org.cyberneko.html.parsers.SAXParser;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.ScanException;
import org.owasp.validator.html.util.ErrorMessageUtil;
import org.xml.sax.AttributeList;
import org.xml.sax.DocumentHandler;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;

public class AntiSamySAXScanner extends AbstractAntiSamyScanner {

	public AntiSamySAXScanner(Policy policy) {
		super(policy);
	}

	public CleanResults getResults() {
		return null;
	}

	public CleanResults scan(String html, String inputEncoding, String outputEncoding) throws ScanException {

		if (html == null) {
			throw new ScanException(new NullPointerException("Null input"));
		}

		int maxInputSize = policy.getMaxInputSize();

		if (html.length() > maxInputSize) {
			addError(ErrorMessageUtil.ERROR_INPUT_SIZE, new Object[] { new Integer(html.length()), new Integer(maxInputSize) });
			throw new ScanException(errorMessages.get(0).toString());
		}
		
		try {
			
			boolean formatOutput = "true".equals(policy.getDirective(Policy.FORMAT_OUTPUT));
            boolean useXhtml = "true".equals(policy.getDirective(Policy.USE_XHTML));
            boolean omitXml = "true".equals(policy.getDirective(Policy.OMIT_XML_DECLARATION));
           
			SAXParser parser = new SAXParser();
			parser.setFeature("http://xml.org/sax/features/namespaces", false);
			parser.setFeature("http://cyberneko.org/html/features/balance-tags/document-fragment", true);
			parser.setFeature("http://cyberneko.org/html/features/scanner/cdata-sections", true);
			parser.setFeature("http://apache.org/xml/features/scanner/notify-char-refs", true);
			parser.setFeature("http://apache.org/xml/features/scanner/notify-builtin-refs", true);
			
			StringWriter out = new StringWriter();
			
			MagicSAXFilter sanitizingFilter = new MagicSAXFilter(policy, messages);
			XMLDocumentFilter[] filters = { sanitizingFilter };

			parser.setProperty("http://cyberneko.org/html/properties/filters", filters);
			parser.setProperty("http://cyberneko.org/html/properties/names/elems", "lower");
			
			Date start = new Date();

			SAXSource source = new SAXSource(parser, new InputSource(new StringReader(html)));
			
			TransformerFactory transformerFactory = TransformerFactory.newInstance();

			Transformer transformer = transformerFactory.newTransformer();
			transformer.setParameter("encoding", outputEncoding);
			transformer.setOutputProperty(OutputKeys.INDENT, formatOutput ? "yes" : "no");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, omitXml ? "yes" : "no");
			transformer.setOutputProperty(OutputKeys.ENCODING, outputEncoding);
			transformer.setOutputProperty(OutputKeys.METHOD, useXhtml ? "xml" : "html");
			
			OutputFormat format = getOutputFormat(outputEncoding);
			HTMLSerializer serializer = getHTMLSerializer(out, format);
			transformer.transform(source, new SAXResult(serializer));			
			Date end = new Date();

			String cleanHtml = trim(html, out.getBuffer().toString());

			errorMessages = sanitizingFilter.getErrorMessages();
			return new CleanResults(start, end, cleanHtml, null, errorMessages);

		} catch (Exception e) {
			throw new ScanException(e);
		}

	}
	

}
