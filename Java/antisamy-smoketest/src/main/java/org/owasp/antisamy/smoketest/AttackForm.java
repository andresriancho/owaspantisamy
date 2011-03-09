package org.owasp.antisamy.smoketest;

import java.util.HashMap;
import java.util.Map;

import org.apache.struts.action.ActionForm;

public class AttackForm extends ActionForm {

	public static final int engineBoth = 0;
	public static final int engineSax = 1;
	public static final int engineDom = 2;

	private static final int policySlashdot = 0;
	private static final int policyEbay = 1;
	private static final int policyMyspace = 2;
	private static final int policyTinymce = 3;
	private static final int policyPsychotic = 4;
	
	public static Map<Integer,String> policyLookup = new HashMap<Integer,String>();
	
	static {
		policyLookup.put(policySlashdot, "antisamy-slashdot.xml");
		policyLookup.put(policyEbay, "antisamy-slashdot.xml");
		policyLookup.put(policyMyspace, "antisamy-slashdot.xml");
		policyLookup.put(policyTinymce, "antisamy-slashdot.xml");
		policyLookup.put(policyPsychotic, "antisamy-anythinggoes.xml");
	}

	String input;
	
	String domOutput;
	String domErrors;
	double domTime;
	
	String saxOutput;
	String saxErrors;
	double saxTime;

	String noFollowAnchors;
	String validateParamAsEmbed;
	
	String pageEncoding;
	
	int policy;
	
	int engine;

	public double getDomTime() {
		return domTime;
	}

	public void setDomTime(double domTime) {
		this.domTime = domTime;
	}

	public double getSaxTime() {
		return saxTime;
	}

	public void setSaxTime(double saxTime) {
		this.saxTime = saxTime;
	}

	public String getInput() {
		return input;
	}

	public void setInput(String input) {
		this.input = input;
	}

	public String getDomOutput() {
		return domOutput;
	}

	public void setDomOutput(String domOutput) {
		this.domOutput = domOutput;
	}

	public String getDomErrors() {
		return domErrors;
	}

	public void setDomErrors(String domErrors) {
		this.domErrors = domErrors;
	}

	public String getSaxOutput() {
		return saxOutput;
	}

	public void setSaxOutput(String saxOutput) {
		this.saxOutput = saxOutput;
	}

	public String getSaxErrors() {
		return saxErrors;
	}

	public void setSaxErrors(String saxErrors) {
		this.saxErrors = saxErrors;
	}

	public String getNoFollowAnchors() {
		return noFollowAnchors;
	}

	public void setNoFollowAnchors(String noFollowAnchors) {
		this.noFollowAnchors = noFollowAnchors;
	}

	public String getValidateParamAsEmbed() {
		return validateParamAsEmbed;
	}

	public void setValidateParamAsEmbed(String validateParamAsEmbed) {
		this.validateParamAsEmbed = validateParamAsEmbed;
	}

	public String getPageEncoding() {
		return pageEncoding;
	}

	public void setPageEncoding(String pageEncoding) {
		this.pageEncoding = pageEncoding;
	}

	public int getPolicy() {
		return policy;
	}

	public void setPolicy(int policy) {
		this.policy = policy;
	}

	public int getEngine() {
		return engine;
	}

	public void setEngine(int engine) {
		this.engine = engine;
	}
	
}
