/*
 * Copyright (c) 2007-2008, Arshan Dabirsiaghi, Jason Li
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

package org.owasp.validator.html;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.owasp.validator.html.scan.AntiSamyDOMScanner;
import org.w3c.dom.DocumentFragment;


/**
 * 
 * This is the only class from which the outside world should be calling. The <code>scan()</code> method holds
 * the meat and potatoes of AntiSamy. The file contains a number of ways for <code>scan()</code>'ing depending
 * on the accessibility of the policy file.
 * 
 * @author Arshan Dabirsiaghi
 *
 */

public class AntiSamy {
		
	private String inputEncoding = AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM;
	private String outputEncoding = AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM;
	
	/**
	 * The meat and potatoes. The <code>scan()</code> family of methods are the only methods the outside world should
	 * be calling to invoke AntiSamy.
	 * 
	 * @param taintedHTML Untrusted HTML which may contain malicious code.
	 * @param inputEncoding The encoding of the input.
	 * @param outputEncoding The encoding that the output should be in.
	 * @return A <code>CleanResults</code> object which contains information about the scan (including the results).
	 * @throws <code>ScanException</code> When there is a problem encountered while scanning the HTML.
	 * @throws <code>PolicyException</code> When there is a problem reading the policy file.
	 */
	
	public CleanResults scan(String taintedHTML) throws ScanException, PolicyException {
		
		Policy policy = null;
	
		/*
		 * Get or reload the policy document (antisamy.xml). We'll need to pass that to the
		 * scanner so it knows what to look for.
		 */
		policy = Policy.getInstance();

		/*
		 * We use HTMLCleaner's HTML HTML-XHTML parser combined with our
		 * own Anti-Samy 3000 Fireball of Superior Fury Scanner.
		 */
		AntiSamyDOMScanner antiSamy = new AntiSamyDOMScanner(policy);
		
		/*
		 * Go get 'em!
		 */

		return antiSamy.scan(taintedHTML, inputEncoding, outputEncoding);

	}
	
	
	/**
	 * This method wraps <code>scan()</code> using the Policy object passed in.
	 */
	public CleanResults scan(String taintedHTML, Policy policy) throws ScanException, PolicyException {
		return new AntiSamyDOMScanner(policy).scan(taintedHTML, inputEncoding, outputEncoding);
	}
	
	/**
	 * This method wraps <code>scan()</code> using the Policy object passed in.
	 */
	public CleanResults scan(String taintedHTML, String filename) throws ScanException, PolicyException {
		
		Policy policy = null;
		
		/*
		 * Get or reload the policy document (antisamy.xml). We'll need to pass that to the
		 * scanner so it knows what to look for.
		 */
		policy = Policy.getInstance(filename);

		/*
		 * We use HTMLCleaner's HTML HTML-XHTML parser combined with our
		 * own Anti-Samy 3000 Fireball of Superior Fury Scanner.
		 */
		AntiSamyDOMScanner antiSamy = new AntiSamyDOMScanner(policy);
		
		/*
		 * Go get 'em!
		 */

		return antiSamy.scan(taintedHTML,inputEncoding,outputEncoding);

	}
	
	/**
	 * This method wraps <code>scan()</code> using the policy File object passed in.
	 */
	public CleanResults scan(String taintedHTML, File policyFile) throws ScanException, PolicyException {
		
		Policy policy = null;
	
		/*
		 * Get or reload the policy document (antisamy.xml). We'll need to pass that to the
		 * scanner so it knows what to look for.
		 */
		policy = Policy.getInstance(policyFile);

		/*
		 * We use NekoHTML's HTML HTML-XHTML parser combined with our
		 * own Anti-Samy 3000 Fireball of Superior Fury Scanner.
		 */
		AntiSamyDOMScanner antiSamy = new AntiSamyDOMScanner(policy);
		
		/*
		 * Go get 'em!
		 */

		return antiSamy.scan(taintedHTML,inputEncoding,outputEncoding);

	}
	
	
	
	/**
	 * Main method for testing AntiSamy.
	 * @param args Command line arguments. Only 1 argument is processed, and it should be a URL or filename to run through AntiSamy using the default policy location.
	 */	
	public static void main(String[] args) {

		if ( args.length == 0 ) {
			System.err.println("Please specify a URL or file name to filter - thanks!");	
			return;
		}
		
		try {
			
			StringBuffer buff = new StringBuffer();

			URL httpUrl = null;
			FileReader fileUrl = null;
			BufferedReader in = null;			
			
			try {
			
				httpUrl = new URL(args[0]);
				in = new BufferedReader( new InputStreamReader(httpUrl.openStream()));
				
			} catch (MalformedURLException e) {
				
				try {
					fileUrl = new FileReader(new File(args[0]));
				} catch (FileNotFoundException e1) {
					System.err.println("Please specify a URL or file name to filter - thanks!");
					return;
				}
				
				in = new BufferedReader(fileUrl);
				
			} catch (IOException e) {

				System.err.println("Encountered an IOException while reading URL: ");
				e.printStackTrace();
			}
			
			String inputLine;

			while ((inputLine = in.readLine()) != null)
				buff.append(inputLine);

			in.close();

			AntiSamy as = new AntiSamy();
			
			CleanResults test = as.scan(buff.toString());
			
			System.out.println("[1] Finished scan [" + test.getCleanHTML().length() + " bytes] in " + test.getScanTime() + " seconds");
			
	        System.out.println("\n[2] Clean HTML fragment:\n" +  test.getCleanHTML());
	        System.out.println("[3] Error Messages ("+test.getNumberOfErrors() +"):");
	        
	        
			for(int i=0;i<test.getErrorMessages().size();i++) {
				String s = (String) test.getErrorMessages().get(i);
				System.out.println(s);
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	public String getInputEncoding() {
		return inputEncoding;
	}


	public void setInputEncoding(String inputEncoding) {
		this.inputEncoding = inputEncoding;
	}


	public String getOutputEncoding() {
		return outputEncoding;
	}


	public void setOutputEncoding(String outputEncoding) {
		this.outputEncoding = outputEncoding;
	}
}
