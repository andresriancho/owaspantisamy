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
