package org.owasp.validator.html.scan;

import java.util.ArrayList;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;
import org.owasp.validator.html.util.ErrorMessageUtil;

public abstract class AbstractAntiSamyScanner {

	protected Policy policy;
	protected ArrayList errorMessages = new ArrayList();

	protected ResourceBundle messages;
	protected Locale locale = Locale.getDefault();

	protected boolean isNofollowAnchors = false;
	protected boolean isValidateParamAsEmbed = false;

	public abstract CleanResults scan(String html, String inputEncoding, String outputEncoding) throws ScanException;

	public abstract CleanResults getResults();

	public AbstractAntiSamyScanner(Policy policy) {
		this.policy = policy;
		initializeErrors();
	}

	public AbstractAntiSamyScanner() throws PolicyException {
		policy = Policy.getInstance();
		initializeErrors();
	}

	protected void initializeErrors() {
		try {
			messages = ResourceBundle.getBundle("AntiSamy", locale);
		} catch (MissingResourceException mre) {
			messages = ResourceBundle.getBundle("AntiSamy", new Locale(Constants.DEFAULT_LOCALE_LANG, Constants.DEFAULT_LOCALE_LOC));
		}
	}

	protected void addError(String errorKey, Object[] objs) {
		errorMessages.add(ErrorMessageUtil.getMessage(messages, errorKey, objs));
	}
}
