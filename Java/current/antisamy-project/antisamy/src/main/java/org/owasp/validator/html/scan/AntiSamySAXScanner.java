package org.owasp.validator.html.scan;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Date;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xerces.xni.parser.XMLDocumentFilter;
import org.cyberneko.html.parsers.SAXParser;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.ScanException;
import org.owasp.validator.html.util.ErrorMessageUtil;
import org.xml.sax.InputSource;

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

		if (maxInputSize < html.length()) {
			addError(ErrorMessageUtil.ERROR_INPUT_SIZE, new Object[] { new Integer(html.length()), new Integer(maxInputSize) });
			throw new ScanException(errorMessages.get(0).toString());
		}

		MagicSAXFilter filter = new MagicSAXFilter(policy, messages);
		XMLDocumentFilter[] filters = { filter };

		try {
			SAXParser parser = new SAXParser();
			parser.setFeature("http://xml.org/sax/features/namespaces", false);
			parser.setFeature("http://cyberneko.org/html/features/balance-tags/document-fragment", true);

			parser.setProperty("http://cyberneko.org/html/properties/filters", filters);
			parser.setProperty("http://cyberneko.org/html/properties/names/elems", "lower");

			Date start = new Date();

			SAXSource source = new SAXSource(parser, new InputSource(new StringReader(html)));
			StringWriter out = new StringWriter();
			StreamResult result = new StreamResult(out);

			TransformerFactory transformerFactory = TransformerFactory.newInstance();

			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "no");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.METHOD, "html");

			transformer.transform(source, result);

			Date end = new Date();

			// System.out.println(out.getBuffer().toString());
			errorMessages = filter.getErrorMessages();
			return new CleanResults(start, end, out.getBuffer().toString(), null, errorMessages);

		} catch (Exception e) {
			throw new ScanException(e);
		}

	}

}
