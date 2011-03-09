package org.owasp.antisamy.smoketest;

import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionErrors;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.ActionMessage;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;

public class ProcessAttackAction extends Action {

	private static final String inputPage = "inputPage";
	
	public ActionForward execute(ActionMapping mapping, ActionForm actionForm,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		
		ActionForward page = mapping.findForward(inputPage);
		ActionErrors errors = new ActionErrors();
		
		AttackForm form = (AttackForm)actionForm;
		
		AntiSamy as = new AntiSamy();
		
		String policyFile = AttackForm.policyLookup.get(form.getPolicy());
		
		if ( policyFile == null ) {
			errors.add(ActionErrors.GLOBAL_MESSAGE, new ActionMessage("error.invalid.policy"));
			saveErrors(request, errors);
			return page;
		}
		
		policyFile = "/WEB-INF/policies/" + policyFile;
		
		InputStream is = request.getSession().getServletContext().getResourceAsStream(policyFile); 
		
		Policy p = Policy.getInstance(is);
		
		String attack = form.getInput() != null ? form.getInput() : "";
		
		try {
			if ( form.getEngine() == AttackForm.engineBoth || form.getEngine() == AttackForm.engineDom ) {
				CleanResults domCr = as.scan(attack,p,AntiSamy.DOM);
				form.setDomOutput(domCr.getCleanHTML());
				form.setDomErrors(convertErrors(domCr.getErrorMessages()));
				form.setDomTime(domCr.getScanTime());
			}
		} catch (Exception e) {
			form.setDomOutput(exception2string(e));
			form.setDomErrors("");
			form.setDomTime(0);
		}
		
		try {
			if ( form.getEngine() == AttackForm.engineBoth || form.getEngine() == AttackForm.engineSax ) {
				CleanResults saxCr = as.scan(attack,p,AntiSamy.SAX);
				form.setSaxOutput(saxCr.getCleanHTML());
				form.setSaxErrors(convertErrors(saxCr.getErrorMessages()));
				form.setSaxTime(saxCr.getScanTime());
			}
		} catch (Exception e) {
			form.setSaxOutput(exception2string(e));
			form.setSaxErrors("");
			form.setSaxTime(0);
		}
		
		return page;
	}

	private String exception2string(Exception e) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		return sw.toString().replaceAll(System.getProperty("line.separator"),"<br/>");
	}

	private String convertErrors(ArrayList errorMessages) {
		StringBuilder sb = new StringBuilder();
		
		for(Object o : errorMessages) {
			sb.append((String)o);
			sb.append("<br/>");
			sb.append(System.getProperty("line.separator"));
		}
		
		return sb.toString();
	}
		
}
