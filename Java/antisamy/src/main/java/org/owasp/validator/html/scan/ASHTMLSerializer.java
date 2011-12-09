package org.owasp.validator.html.scan;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Locale;

import org.apache.xml.serialize.ElementState;
import org.apache.xml.serialize.HTMLSerializer;
import org.apache.xml.serialize.HTMLdtd;
import org.apache.xml.serialize.OutputFormat;
import org.owasp.validator.html.Policy;

public class ASHTMLSerializer extends HTMLSerializer {

	private boolean encodeAllPossibleEntities;
	private String[] allowedEmptyTags;
	private String[] requireClosingTags;
	
	public ASHTMLSerializer(Writer w, OutputFormat format, Policy policy) {
		super(w, format);
		this.allowedEmptyTags = policy.getAllowedEmptyTags();
		this.requireClosingTags = policy.getRequiresClosingTags();
		this.encodeAllPossibleEntities = "true".equals(policy.getDirective(Policy.ENTITY_ENCODE_INTL_CHARS));
	}
	
	protected String getEntityRef(int charToPrint) {
		if(encodeAllPossibleEntities || Constants.big5CharsToEncode.indexOf(charToPrint) != -1)
			return super.getEntityRef(charToPrint);
		return null;
	}

	public void endElementIO(String namespaceURI, String localName,
			String rawName) throws IOException {
		
		ElementState state;

		// Works much like content() with additions for closing
		// an element. Note the different checks for the closed
		// element's state and the parent element's state.
		_printer.unindent();
		state = getElementState();
		String htmlName = rawName;
		
		if (state.empty)
			_printer.printText('>');
		// This element is not empty and that last content was
		// another element, so print a line break before that
		// last element and this element's closing tag.
		// [keith] Provided this is not an anchor.
		// HTML: some elements do not print closing tag (e.g. LI)
		if (htmlName == null || !HTMLdtd.isOnlyOpening(htmlName)) {
			if (_indenting && !state.preserveSpace && state.afterElement)
				_printer.breakLine();
			// Must leave CData section first (Illegal in HTML, but still)
			if (state.inCData)
				_printer.printText("]]>");
			_printer.printText("</");
			_printer.printText(state.rawName);
			_printer.printText('>');
		}
		
		// Leave the element state and update that of the parent
		// (if we're not root) to not empty and after element.
		state = leaveElementState();
		// Temporary hack to prevent line breaks inside A/TD
		if (rawName == null
				|| (!rawName.equalsIgnoreCase("A") && !rawName
						.equalsIgnoreCase("TD")))

			state.afterElement = true;
		state.empty = false;
		if (isDocumentState())
			_printer.flush();
	}
	
	private boolean requiresClosingTag(String tagName) {
		for(int i=0;i<requireClosingTags.length;i++) {
			String requiresClosingTag  = requireClosingTags[i];
			if (tagName.equalsIgnoreCase(requiresClosingTag))
				return true;
		}
		return false;
	}
	
	private boolean isAllowedEmptyTag(String tagName) {
    	boolean allowed = false;
        for (int i = 0; i < allowedEmptyTags.length; i++) {
            if (allowedEmptyTags[i].equalsIgnoreCase(tagName)) {
                allowed = true;
                i = allowedEmptyTags.length;
            }
        }
        return allowed;
	}
}
