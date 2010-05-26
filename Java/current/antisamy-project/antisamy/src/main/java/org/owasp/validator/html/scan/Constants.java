package org.owasp.validator.html.scan;

import org.owasp.validator.html.Policy;
import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Tag;

public class Constants {
	public static String[] allowedEmptyTags = {
			"br", "hr", "a", "img", "link", "iframe", "script", "object", "applet", "frame", "base", "param", "meta", "input", "textarea", "embed", "basefont", "col"
	};

	public static final String DEFAULT_ENCODING_ALGORITHM = "UTF-8";

	public static final Tag BASIC_PARAM_TAG_RULE;

	static {
		Attribute paramNameAttr = new Attribute("name");
		Attribute paramValueAttr = new Attribute("value");
		paramNameAttr.addAllowedRegExp(Policy.ANYTHING_REGEXP);
		paramValueAttr.addAllowedRegExp(Policy.ANYTHING_REGEXP);
		BASIC_PARAM_TAG_RULE = new Tag("param");
		BASIC_PARAM_TAG_RULE.addAttribute(paramNameAttr);
		BASIC_PARAM_TAG_RULE.addAttribute(paramValueAttr);
		BASIC_PARAM_TAG_RULE.setAction(Policy.ACTION_VALIDATE);
	}

	public static final String DEFAULT_LOCALE_LANG = "en";
	public static final String DEFAULT_LOCALE_LOC = "US";

}
