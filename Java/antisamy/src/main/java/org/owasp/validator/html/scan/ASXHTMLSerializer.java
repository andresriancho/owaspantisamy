package org.owasp.validator.html.scan;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Locale;

import org.apache.xml.serialize.ElementState;
import org.apache.xml.serialize.HTMLdtd;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XHTMLSerializer;
import org.owasp.validator.html.Policy;

/**
 * This is an extension of the default XHTMLSerializer class that's had it's endElementIO()
 * method tweaked to serialize closing tags and self-closing tags the way we require.
 */
public class ASXHTMLSerializer extends XHTMLSerializer {

	private boolean encodeAllPossibleEntities;
	private String[] allowedEmptyTags;
	private String[] requireClosingTags;
	
	public ASXHTMLSerializer(Writer w, OutputFormat format, Policy policy) {
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
		String htmlName;

		// Works much like content() with additions for closing
		// an element. Note the different checks for the closed
		// element's state and the parent element's state.
		_printer.unindent();
		state = getElementState();

		if (state.empty && isAllowedEmptyTag(rawName) && !requiresClosingTag(rawName)) { //
			_printer.printText(" />");
		} else {
			if(state.empty)
				_printer.printText('>');
			// Must leave CData section first
			if (state.inCData)
				_printer.printText("]]>");
			// XHTML: element names are lower case, DOM will be different
			_printer.printText("</");
			_printer.printText(state.rawName.toLowerCase(Locale.ENGLISH));
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
