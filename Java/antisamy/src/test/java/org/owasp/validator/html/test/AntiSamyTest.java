/*
 * Copyright (c) 2007-2011, Arshan Dabirsiaghi, Jason Li
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

package org.owasp.validator.html.test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.regex.Pattern;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.codec.binary.Base64;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;
import org.owasp.validator.html.model.Tag;

/**
 * This class tests AntiSamy functionality and the basic policy file which
 * should be immune to XSS and CSS phishing attacks.
 * 
 * @author Arshan Dabirsiaghi
 * 
 */

public class AntiSamyTest extends TestCase {

	private static final String[] BASE64_BAD_XML_STRINGS = new String[] {
			// first string is
			// "<a - href=\"http://www.owasp.org\">click here</a>"
			"PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=",
			// the rest are randomly generated 300 byte sequences which generate
			// parser errors, turned into Strings
			"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",
	};

	private AntiSamy as = new AntiSamy();
	private Policy policy = null;

	public AntiSamyTest(String s) {
		super(s);
	}

	protected void setUp() throws Exception {

		/*
		 * Load the policy. You may have to change the path to find the Policy
		 * file for your environment.
		 */

		//get Policy instance from a stream to make sure includes fail nicely
        InputStream is = getClass().getResourceAsStream("/antisamy.xml");
		policy = Policy.getInstance(is);

		//get Policy instance from a URL.
        URL url = getClass().getResource("/antisamy.xml");
		policy = Policy.getInstance(url);
	}

	protected void tearDown() throws Exception {
	}

	public static Test suite() {

		TestSuite suite = new TestSuite(AntiSamyTest.class);
		return suite;

	}


	public void testSAX() {
		try {
			CleanResults cr = as.scan("<b>test</i></b>test thsidfshidf<script>sdfsdf", policy, AntiSamy.SAX);
			assertTrue(cr != null && cr.getCleanXMLDocumentFragment() == null && cr.getCleanHTML().length() > 0);
		} catch (ScanException e) {
			e.printStackTrace();
		} catch (PolicyException e) {
			e.printStackTrace();
		}
	}

	/*
	 * Test basic XSS cases.
	 */

	public void testScriptAttacks() {

		try {

			assertTrue(as.scan("test<script>alert(document.cookie)</script>", policy, AntiSamy.DOM).getCleanHTML().indexOf("script") == -1);
			assertTrue(as.scan("test<script>alert(document.cookie)</script>", policy, AntiSamy.SAX).getCleanHTML().indexOf("script") == -1);

			assertTrue(as.scan("<<<><<script src=http://fake-evil.ru/test.js>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<<<><<script src=http://fake-evil.ru/test.js>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<script<script src=http://fake-evil.ru/test.js>>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<script<script src=http://fake-evil.ru/test.js>>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", policy, AntiSamy.DOM).getCleanHTML().indexOf("onload") == -1);
			assertTrue(as.scan("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", policy, AntiSamy.SAX).getCleanHTML().indexOf("onload") == -1);

			assertTrue(as.scan("<BODY ONLOAD=alert('XSS')>", policy, AntiSamy.DOM).getCleanHTML().indexOf("alert") == -1);
			assertTrue(as.scan("<BODY ONLOAD=alert('XSS')>", policy, AntiSamy.SAX).getCleanHTML().indexOf("alert") == -1);

			assertTrue(as.scan("<iframe src=http://ha.ckers.org/scriptlet.html <", policy, AntiSamy.DOM).getCleanHTML().indexOf("<iframe") == -1);
			assertTrue(as.scan("<iframe src=http://ha.ckers.org/scriptlet.html <", policy, AntiSamy.SAX).getCleanHTML().indexOf("<iframe") == -1);

			assertTrue(as.scan("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("src") == -1);
			assertTrue(as.scan("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("src") == -1);

			as.scan("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", policy, AntiSamy.DOM);
			as.scan("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", policy, AntiSamy.SAX);

		} catch (Exception e) {
			fail("Caught exception in testScriptAttack(): " + e.getMessage());
		}

	}

	public void testImgAttacks() {

		try {

			assertTrue(as.scan("<img src=\"http://www.myspace.com/img.gif\"/>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<img") != -1);
			assertTrue(as.scan("<img src=\"http://www.myspace.com/img.gif\"/>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<img") != -1);

			assertTrue(as.scan("<img src=javascript:alert(document.cookie)>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<img") == -1);
			assertTrue(as.scan("<img src=javascript:alert(document.cookie)>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<img") == -1);

			assertTrue(as.scan("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", policy, AntiSamy.DOM).getCleanHTML()
					.indexOf("<img") == -1);
			assertTrue(as.scan("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", policy, AntiSamy.SAX)
					.getCleanHTML().indexOf("<img") == -1);

			assertTrue(as
					.scan(
							"<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>",
							policy, AntiSamy.DOM).getCleanHTML().indexOf("<img") == -1);
			assertTrue(as
					.scan(
							"<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>",
							policy, AntiSamy.SAX).getCleanHTML().indexOf("<img") == -1);

			assertTrue(as.scan("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("alert") == -1);
			assertTrue(as.scan("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("alert") == -1);

			String s = as
					.scan(
							"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
							policy, AntiSamy.DOM).getCleanHTML();
			assertTrue(s.length() == 0 || s.indexOf("&amp;") != -1);
			s = as
					.scan(
							"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
							policy, AntiSamy.SAX).getCleanHTML();
			assertTrue(s.length() == 0 || s.indexOf("&amp;") != -1);

			as.scan("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", policy, AntiSamy.DOM);
			as.scan("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", policy, AntiSamy.SAX);

			assertTrue(as.scan("<IMG SRC=\"javascript:alert('XSS')\"", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<IMG SRC=\"javascript:alert('XSS')\"", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<IMG LOWSRC=\"javascript:alert('XSS')\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<IMG LOWSRC=\"javascript:alert('XSS')\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<BGSOUND SRC=\"javascript:alert('XSS');\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<BGSOUND SRC=\"javascript:alert('XSS');\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Caught exception in testImgSrcAttacks(): " + e.getMessage());
		}
	}

	public void testHrefAttacks() {

		try {

			assertTrue(as.scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("href") == -1);
			assertTrue(as.scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("href") == -1);

			assertTrue(as.scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("href") == -1);
			assertTrue(as.scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("href") == -1);

			assertTrue(as.scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", policy, AntiSamy.DOM).getCleanHTML().indexOf("ha.ckers.org") == -1);
			assertTrue(as.scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", policy, AntiSamy.SAX).getCleanHTML().indexOf("ha.ckers.org") == -1);

			assertTrue(as.scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy, AntiSamy.DOM).getCleanHTML().indexOf("ha.ckers.org") == -1);
			assertTrue(as.scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy, AntiSamy.SAX).getCleanHTML().indexOf("ha.ckers.org") == -1);

			assertTrue(as.scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>", policy, AntiSamy.DOM).getCleanHTML().indexOf("vbscript") == -1);
			assertTrue(as.scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>", policy, AntiSamy.SAX).getCleanHTML().indexOf("vbscript") == -1);

			assertTrue(as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("<meta") == -1);
			assertTrue(as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("<meta") == -1);

			assertTrue(as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("<meta") == -1);
			assertTrue(as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("<meta") == -1);

			assertTrue(as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("<meta") == -1);
			assertTrue(as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("<meta") == -1);

			assertTrue(as.scan("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", policy, AntiSamy.DOM).getCleanHTML().indexOf("iframe") == -1);
			assertTrue(as.scan("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", policy, AntiSamy.SAX).getCleanHTML().indexOf("iframe") == -1);

			assertTrue(as.scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("background") == -1);
			assertTrue(as.scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("background") == -1);

			assertTrue(as.scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("background") == -1);
			assertTrue(as.scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("background") == -1);

			assertTrue(as.scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<DIV STYLE=\"width: expression(alert('XSS'));\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("alert") == -1);
			assertTrue(as.scan("<DIV STYLE=\"width: expression(alert('XSS'));\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("alert") == -1);

			assertTrue(as.scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("alert") == -1);
			assertTrue(as.scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("alert") == -1);

			assertTrue(as.scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy, AntiSamy.DOM).getCleanHTML().indexOf("ript:alert") == -1);
			assertTrue(as.scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy, AntiSamy.SAX).getCleanHTML().indexOf("ript:alert") == -1);

			assertTrue(as.scan("<BASE HREF=\"javascript:alert('XSS');//\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<BASE HREF=\"javascript:alert('XSS');//\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<BaSe hReF=\"http://arbitrary.com/\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("<base") == -1);
			assertTrue(as.scan("<BaSe hReF=\"http://arbitrary.com/\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("<base") == -1);

			assertTrue(as.scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<object") == -1);
			assertTrue(as.scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<object") == -1);

			assertTrue(as.scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);

			CleanResults cr = as.scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy, AntiSamy.SAX);
			// System.out.println(cr.getErrorMessages().get(0));
			assertTrue(cr.getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<embed") == -1);
			assertTrue(as.scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<embed") == -1);

			assertTrue(as
					.scan(
							"<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>",
							policy, AntiSamy.DOM).getCleanHTML().indexOf("<embed") == -1);
			assertTrue(as
					.scan(
							"<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>",
							policy, AntiSamy.SAX).getCleanHTML().indexOf("<embed") == -1);

			assertTrue(as.scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as.scan("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.DOM).getCleanHTML().indexOf("script") == -1);
			assertTrue(as.scan("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy, AntiSamy.SAX).getCleanHTML().indexOf("script") == -1);

			assertTrue(as.scan("<SCRIPT SRC=http://ha.ckers.org/xss.js", policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan("<SCRIPT SRC=http://ha.ckers.org/xss.js", policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			assertTrue(as
					.scan(
							"<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>",
							policy, AntiSamy.DOM).getCleanHTML().indexOf("style") == -1);
			assertTrue(as
					.scan(
							"<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>",
							policy, AntiSamy.SAX).getCleanHTML().indexOf("style") == -1);

			assertTrue(as.scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", policy, AntiSamy.DOM).getCleanHTML().indexOf(
					"aim.exe") == -1);
			assertTrue(as.scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", policy, AntiSamy.SAX)
					.getCleanHTML().indexOf("aim.exe") == -1);

			assertTrue(as.scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", policy, AntiSamy.DOM).getCleanHTML().indexOf("javascript") == -1);
			assertTrue(as.scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", policy, AntiSamy.SAX).getCleanHTML().indexOf("javascript") == -1);

			assertTrue(as.scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("document") == -1);
			assertTrue(as.scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", policy, AntiSamy.SAX).getCleanHTML().indexOf(
					"document") == -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Caught exception in testHrefSrcAttacks(): " + e.getMessage());
		}
	}

	/*
	 * Test CSS protections.
	 */

	public void testCssAttacks() {

		try {

			assertTrue(as.scan("<div style=\"position:absolute\">", policy, AntiSamy.DOM).getCleanHTML().indexOf("position") == -1);
			assertTrue(as.scan("<div style=\"position:absolute\">", policy, AntiSamy.SAX).getCleanHTML().indexOf("position") == -1);

			assertTrue(as.scan("<style>b { position:absolute }</style>", policy, AntiSamy.DOM).getCleanHTML().indexOf("position") == -1);
			assertTrue(as.scan("<style>b { position:absolute }</style>", policy, AntiSamy.SAX).getCleanHTML().indexOf("position") == -1);

			assertTrue(as.scan("<div style=\"z-index:25\">test</div>", policy, AntiSamy.DOM).getCleanHTML().indexOf("z-index") == -1);
			assertTrue(as.scan("<div style=\"z-index:25\">test</div>", policy, AntiSamy.SAX).getCleanHTML().indexOf("z-index") == -1);

			assertTrue(as.scan("<style>z-index:25</style>", policy, AntiSamy.DOM).getCleanHTML().indexOf("z-index") == -1);
			assertTrue(as.scan("<style>z-index:25</style>", policy, AntiSamy.SAX).getCleanHTML().indexOf("z-index") == -1);

		} catch (Exception e) {
			fail("Caught exception in testCssAttacks(): " + e.getMessage());
		}
	}

	/*
	 * Test a bunch of strings that have tweaked the XML parsing capabilities of
	 * NekoHTML.
	 */
	public void testIllegalXML() {

		for (int i = 0; i < BASE64_BAD_XML_STRINGS.length; i++) {

			try {

				String testStr = new String(Base64.decodeBase64(BASE64_BAD_XML_STRINGS[i].getBytes()));
				as.scan(testStr, policy, AntiSamy.DOM);
				as.scan(testStr, policy, AntiSamy.SAX);

			} catch (ScanException ex) {
				// still success!

			} catch (Throwable ex) {
				ex.printStackTrace();
				fail("Caught unexpected exception in testIllegalXML(): " + ex.getMessage());
			}
		}

		// This fails due to a bug in NekoHTML
		// try {
		// assertTrue (
		// as.scan("<a . href=\"http://www.test.com\">",policy, AntiSamy.DOM).getCleanHTML().indexOf("href")
		// != -1 );
		// } catch (Exception e) {
		// e.printStackTrace();
		// fail("Couldn't parse malformed HTML: " + e.getMessage());
		// }

		// This fails due to a bug in NekoHTML
		// try {
		// assertTrue (
		// as.scan("<a - href=\"http://www.test.com\">",policy, AntiSamy.DOM).getCleanHTML().indexOf("href")
		// != -1 );
		// } catch (Exception e) {
		// e.printStackTrace();
		// fail("Couldn't parse malformed HTML: " + e.getMessage());
		// }

		try {
			assertTrue(as.scan("<style>", policy, AntiSamy.DOM) != null);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Couldn't parse malformed HTML: " + e.getMessage());
		}
	}

	public void testPreviousBugs() {

		/*
		 * issues 12 (and 36, which was similar). empty tags cause display
		 * problems/"formjacking"
		 */

		try {

			Pattern p = Pattern.compile(".*<strong(\\s*)/>.*");
			String s1 = as.scan("<br ><strong></strong><a>hello world</a><b /><i/><hr>", policy, AntiSamy.DOM).getCleanHTML();
			String s2 = as.scan("<br ><strong></strong><a>hello world</a><b /><i/><hr>", policy, AntiSamy.SAX).getCleanHTML();

			assertFalse(p.matcher(s1).matches());

			p = Pattern.compile(".*<b(\\s*)/>.*");
			assertFalse(p.matcher(s1).matches());
			assertFalse(p.matcher(s2).matches());

			p = Pattern.compile(".*<i(\\s*)/>.*");
			assertFalse(p.matcher(s1).matches());
			assertFalse(p.matcher(s2).matches());
			
			assertTrue(s1.indexOf("<hr />") != -1 || s1.indexOf("<hr/>") != -1);
			assertTrue(s2.indexOf("<hr />") != -1 || s2.indexOf("<hr/>") != -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #20 */
		try {

			String s = as.scan("<b><i>Some Text</b></i>", policy, AntiSamy.DOM).getCleanHTML();
			assertTrue(s.indexOf("<i />") == -1);

			s = as.scan("<b><i>Some Text</b></i>", policy, AntiSamy.SAX).getCleanHTML();
			assertTrue(s.indexOf("<i />") == -1);

		} catch (Exception e) {
			e.printStackTrace();
		}

		/* issue #25 */
		try {

			String s = "<div style=\"margin: -5em\">Test</div>";
			String expected = "<div style=\"\">Test</div>";
			
			String crDom = as.scan(s, policy, AntiSamy.DOM).getCleanHTML(); 
			assertEquals(crDom, expected);
			String crSax = as.scan(s, policy, AntiSamy.SAX).getCleanHTML(); 
			assertEquals(crSax, expected);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #28 */
		try {

			String s1 = as.scan("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>", policy, AntiSamy.DOM).getCleanHTML();
			String s2 = as.scan("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>", policy, AntiSamy.SAX).getCleanHTML();
			assertTrue(s1.indexOf("font-family") > -1);
			assertTrue(s2.indexOf("font-family") > -1);

		} catch (Exception e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		/* issue #29 - missing quotes around properties with spaces */

		try {

			String s = "<style type=\"text/css\"><![CDATA[P {\n	font-family: \"Arial Unicode MS\";\n}\n]]></style>";
			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);
			assertEquals(s, cr.getCleanHTML());

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #30 */
		try {
			String s = "<style type=\"text/css\"><![CDATA[P { margin-bottom: 0.08in; } ]]></style>";

			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);

			String oldValue = policy.getDirective(Policy.USE_XHTML);

			/* followup - does the patch fix multiline CSS? */
			String s2 = "<style type=\"text/css\"><![CDATA[\r\nP {\r\n margin-bottom: 0.08in;\r\n}\r\n]]></style>";
			cr = as.scan(s2, policy, AntiSamy.DOM);
			assertEquals("<style type=\"text/css\"><![CDATA[P {\n\tmargin-bottom: 0.08in;\n}\n]]></style>", cr.getCleanHTML());

			/* next followup - does non-CDATA parsing still work? */

			policy.setDirective(Policy.USE_XHTML, "false");
			String s3 = "<style>P {\n\tmargin-bottom: 0.08in;\n}\n";
			cr = as.scan(s3, policy, AntiSamy.DOM);
			assertEquals("<style>P {\n\tmargin-bottom: 0.08in;\n}\n</style>\n", cr.getCleanHTML());

			policy.setDirective(Policy.USE_XHTML, oldValue); // reset this value
			// for other
			// tests

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue 31 */

		String toDoOnBoldTags = policy.getTagByName("b").getAction();

		try {
			String test = "<b><u><g>foo";

			policy.setDirective("onUnknownTag", "encode");
			CleanResults cr = as.scan(test, policy, AntiSamy.DOM);
			String s = cr.getCleanHTML();
			assertFalse(s.indexOf("&lt;g&gt;") == -1);
			s = as.scan(test, policy, AntiSamy.SAX).getCleanHTML();
			assertFalse(s.indexOf("&lt;g&gt;") == -1);

			policy.getTagByName("b").setAction("encode");

			cr = as.scan(test, policy, AntiSamy.DOM);
			s = cr.getCleanHTML();

			assertFalse(s.indexOf("&lt;b&gt;") == -1);

			cr = as.scan(test, policy, AntiSamy.SAX);
			s = cr.getCleanHTML();

			assertFalse(s.indexOf("&lt;b&gt;") == -1);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		} finally {
			policy.getTagByName("b").setAction(toDoOnBoldTags);
		}

		/* issue #32 - nekos problem */
		try {
			String s = "<SCRIPT =\">\" SRC=\"\"></SCRIPT>";
			as.scan(s, policy, AntiSamy.DOM);
			as.scan(s, policy, AntiSamy.SAX);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #37 - OOM */

		try {
			String dirty = "<a onblur=\"try {parent.deselectBloggerImageGracefully();}" + "catch(e) {}\""
					+ "href=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\"><img" + "style=\"FLOAT: right; MARGIN: 0px 0px 10px 10px; WIDTH: 150px; CURSOR:"
					+ "hand; HEIGHT: 100px\" alt=\"\"" + "src=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\""
					+ "border=\"0\" /></a><br />Poor Bill, couldn't make it to the Museum's <span" + "class=\"blsp-spelling-corrected\" id=\"SPELLING_ERROR_0\">story time</span>"
					+ "today, he was so busy shoveling! Well, we sure missed you Bill! So since" + "ou were busy moving snow we read books about snow. We found a clue in one"
					+ "book which revealed a snowplow at the end of the story - we wish it had" + "driven to your driveway Bill. We also read a story which shared fourteen"
					+ "<em>Names For Snow. </em>We'll catch up with you next week....wonder which" + "hat Bill will wear?<br />Jane";

			Policy mySpacePolicy = Policy.getInstance(getClass().getResourceAsStream("/antisamy-myspace.xml"));
			CleanResults cr = as.scan(dirty, mySpacePolicy, AntiSamy.DOM);
			assertNotNull(cr.getCleanHTML());
			cr = as.scan(dirty, mySpacePolicy, AntiSamy.SAX);
			assertNotNull(cr.getCleanHTML());

			Policy ebayPolicy = Policy.getInstance(getClass().getResourceAsStream("/antisamy-ebay.xml"));
			cr = as.scan(dirty, ebayPolicy, AntiSamy.DOM);
			assertNotNull(cr.getCleanHTML());
			cr = as.scan(dirty, mySpacePolicy, AntiSamy.SAX);
			assertNotNull(cr.getCleanHTML());

			Policy slashdotPolicy = Policy.getInstance(getClass().getResourceAsStream("/antisamy-slashdot.xml"));
			cr = as.scan(dirty, slashdotPolicy, AntiSamy.DOM);
			assertNotNull(cr.getCleanHTML());
			cr = as.scan(dirty, slashdotPolicy, AntiSamy.SAX);
			assertNotNull(cr.getCleanHTML());

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #38 - color problem/color combinations */
		try {

			String s = "<font color=\"#fff\">Test</font>";
			String expected = "<font color=\"#fff\">Test</font>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<div style=\"color: #fff\">Test 3 letter code</div>";
			expected = "<div style=\"color: rgb(255,255,255);\">Test 3 letter code</div>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<font color=\"red\">Test</font>";
			expected = "<font color=\"red\">Test</font>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<font color=\"neonpink\">Test</font>";
			expected = "<font>Test</font>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<font color=\"#0000\">Test</font>";
			expected = "<font>Test</font>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<div style=\"color: #0000\">Test</div>";
			expected = "<div style=\"\">Test</div>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<font color=\"#000000\">Test</font>";
			expected = "<font color=\"#000000\">Test</font>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			s = "<div style=\"color: #000000\">Test</div>";
			expected = "<div style=\"color: rgb(0,0,0);\">Test</div>";
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getCleanHTML(), expected);
			assertEquals(as.scan(s, policy, AntiSamy.SAX).getCleanHTML(), expected);

			/*
			 * This test case was failing because of the following code from the
			 * batik CSS library, which throws an exception if any character
			 * other than a '!' follows a beginning token of '<'. The
			 * ParseException is now caught in the node a CssScanner.java and
			 * the outside AntiSamyDOMScanner.java.
			 * 
			 * 0398 nextChar(); 0399 if (current != '!') { 0400 throw new
			 * ParseException("character", 0401 reader.getLine(), 0402
			 * reader.getColumn());
			 */
			s = "<b><u>foo<style><script>alert(1)</script></style>@import 'x';</u>bar";
			as.scan(s, policy, AntiSamy.DOM);
			as.scan(s, policy, AntiSamy.SAX);

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #40 - handling <style> media attributes right */

		try {

			String s = "<style media=\"print, projection, screen\"> P { margin: 1em; }</style>";
			policy.setDirective(Policy.PRESERVE_SPACE, "true");

			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);
			String oldSpaceValue = policy.getDirective(Policy.PRESERVE_SPACE);
			// System.out.println("here: " + cr.getCleanHTML());
			assertTrue(cr.getCleanHTML().indexOf("print, projection, screen") != -1);
			// System.out.println(cr.getCleanHTML());

			cr = as.scan(s, policy, AntiSamy.SAX);
			// System.out.println(cr.getCleanHTML());
			assertTrue(cr.getCleanHTML().indexOf("print, projection, screen") != -1);

			policy.setDirective(Policy.PRESERVE_SPACE, oldSpaceValue);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

		/* issue #41 - comment handling */

		try {

			String oldCommentsValue = policy.getDirective(Policy.PRESERVE_COMMENTS);
			String oldSpaceValue = policy.getDirective(Policy.PRESERVE_SPACE);

			policy.setDirective(Policy.PRESERVE_COMMENTS, "false");

			assertEquals("text ", as.scan("text <!-- comment -->", policy, AntiSamy.DOM).getCleanHTML());
			assertEquals("text ", as.scan("text <!-- comment -->", policy, AntiSamy.SAX).getCleanHTML());

			policy.setDirective(Policy.PRESERVE_COMMENTS, "true");
			policy.setDirective(Policy.PRESERVE_SPACE, "true");
			policy.setDirective(Policy.FORMAT_OUTPUT, "false");

			/*
			 * These make sure the regular comments are kept alive and that
			 * conditional comments are ripped out.
			 */
			assertEquals("<div>text <!-- comment --></div>", as.scan("<div>text <!-- comment --></div>", policy, AntiSamy.DOM).getCleanHTML());
			assertEquals("<div>text <!-- comment --></div>", as.scan("<div>text <!-- comment --></div>", policy, AntiSamy.SAX).getCleanHTML());

			assertEquals("<div>text <!-- comment --></div>", as.scan("<div>text <!--[if IE]> comment <[endif]--></div>", policy, AntiSamy.DOM).getCleanHTML());
			assertEquals("<div>text <!-- comment --></div>", as.scan("<div>text <!--[if IE]> comment <[endif]--></div>", policy, AntiSamy.SAX).getCleanHTML());

			/*
			 * Check to see how nested conditional comments are handled. This is
			 * not very clean but the main goal is to avoid any tags. Not sure
			 * on encodings allowed in comments.
			 */
			String input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>";
			String expected = "<div>text <!-- <!-- comment -->&lt;[endif]--&gt;</div>";
			String output = as.scan(input, policy, AntiSamy.DOM).getCleanHTML();
			assertEquals(expected, output);

			input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>";
			expected = "<div>text <!-- <!-- comment -->&lt;[endif]--&gt;</div>";
			output = as.scan(input, policy, AntiSamy.SAX).getCleanHTML();

			assertEquals(expected, output);

			/*
			 * Regular comment nested inside conditional comment. Test makes
			 * sure
			 */
			assertEquals("<div>text <!-- <!-- IE specific --> comment &lt;[endif]--&gt;</div>", as.scan("<div>text <!--[if IE]> <!-- IE specific --> comment <[endif]--></div>", policy, AntiSamy.DOM).getCleanHTML());

			/*
			 * These play with whitespace and have invalid comment syntax.
			 */
			assertEquals("<div>text <!-- \ncomment --></div>", as.scan("<div>text <!-- [ if lte 6 ]>\ncomment <[ endif\n]--></div>", policy, AntiSamy.DOM).getCleanHTML());
			assertEquals("<div>text  comment </div>", as.scan("<div>text <![if !IE]> comment <![endif]></div>", policy, AntiSamy.DOM).getCleanHTML());
			assertEquals("<div>text  comment </div>", as.scan("<div>text <![ if !IE]> comment <![endif]></div>", policy, AntiSamy.DOM).getCleanHTML());

			String attack = "[if lte 8]<script>";
			String spacer = "<![if IE]>";

			StringBuffer sb = new StringBuffer();

			sb.append("<div>text<!");

			for (int i = 0; i < attack.length(); i++) {
				sb.append(attack.charAt(i));
				sb.append(spacer);
			}

			sb.append("<![endif]>");

			String s = sb.toString();

			assertTrue(as.scan(s, policy, AntiSamy.DOM).getCleanHTML().indexOf("<script") == -1);
			assertTrue(as.scan(s, policy, AntiSamy.SAX).getCleanHTML().indexOf("<script") == -1);

			policy.setDirective(Policy.PRESERVE_COMMENTS, oldCommentsValue);
			policy.setDirective(Policy.PRESERVE_SPACE, oldSpaceValue);

		} catch (Exception e) {

		}

		/*
		 * issue #44 - childless nodes of non-allowed elements won't cause an
		 * error
		 */

		try {
			String s = "<iframe src='http://foo.com/'></iframe>" + "<script src=''></script>" + "<link href='/foo.css'>";
			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);
			assertEquals(as.scan(s, policy, AntiSamy.DOM).getNumberOfErrors(), 3);

			cr = as.scan(s, policy, AntiSamy.SAX);

			assertEquals(cr.getNumberOfErrors(), 3);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #51 - offsite urls with () are found to be invalid */
		try {
			String s = "<a href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'>test</a>";
			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);

			// System.out.println(cr.getCleanHTML());
			assertEquals(cr.getNumberOfErrors(), 0);

			cr = as.scan(s, policy, AntiSamy.SAX);
			assertEquals(cr.getNumberOfErrors(), 0);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #56 - unnecessary spaces */

		try {
			String s = "<SPAN style='font-weight: bold;'>Hello World!</SPAN>";
			String expected = "<span style=\"font-weight: bold;\">Hello World!</span>";

			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);
			String s2 = cr.getCleanHTML();

			assertEquals(expected, s2);

			cr = as.scan(s, policy, AntiSamy.SAX);
			s2 = cr.getCleanHTML();

			assertEquals(expected, s2);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #58 - input not in list of allowed-to-be-empty tags */
		try {
			String s = "tgdan <input/> g  h";
			CleanResults cr = as.scan(s, policy, AntiSamy.DOM);
			assertTrue(cr.getErrorMessages().size() == 0);

			cr = as.scan(s, policy, AntiSamy.SAX);
			assertTrue(cr.getErrorMessages().size() == 0);

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #61 - input has newline appended if ends with an accepted tag */
		try {
			String dirtyInput = "blah <b>blah</b>.";
			CleanResults cr = as.scan(dirtyInput, policy, AntiSamy.DOM);
			assertEquals(dirtyInput, cr.getCleanHTML());

			cr = as.scan(dirtyInput, policy, AntiSamy.SAX);
			assertEquals(dirtyInput, cr.getCleanHTML());

		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* issue #69 - char attribute should allow single char or entity ref */

		try {
			String s = "<td char='.'>test</td>";
			CleanResults crDom = as.scan(s, policy, AntiSamy.DOM);
			CleanResults crSax = as.scan(s, policy, AntiSamy.SAX);
			String domValue = crDom.getCleanHTML();
			String saxValue = crSax.getCleanHTML();
			assertTrue(domValue.indexOf("char") > -1);
			assertTrue(saxValue.indexOf("char") > -1);

			s = "<td char='..'>test</td>";
			assertTrue(as.scan(s, policy, AntiSamy.DOM).getCleanHTML().indexOf("char") == -1);
			assertTrue(as.scan(s, policy, AntiSamy.SAX).getCleanHTML().indexOf("char") == -1);

			s = "<td char='&quot;'>test</td>";
			assertTrue(as.scan(s, policy, AntiSamy.DOM).getCleanHTML().indexOf("char") > -1);
			assertTrue(as.scan(s, policy, AntiSamy.SAX).getCleanHTML().indexOf("char") > -1);

			s = "<td char='&quot;a'>test</td>";
			assertTrue(as.scan(s, policy, AntiSamy.DOM).getCleanHTML().indexOf("char") == -1);
			assertTrue(as.scan(s, policy, AntiSamy.SAX).getCleanHTML().indexOf("char") == -1);

			s = "<td char='&quot;&amp;'>test</td>";
			assertTrue(as.scan(s, policy, AntiSamy.DOM).getCleanHTML().indexOf("char") == -1);
			assertTrue(as.scan(s, policy, AntiSamy.SAX).getCleanHTML().indexOf("char") == -1);

		} catch (Throwable t) {
			t.printStackTrace();
			fail(t.getMessage());
		}
		
		/* privately disclosed issue - cdata bypass */
		try {
			
			String malInput = "<![CDATA[]><script>alert(1)</script>]]>";
			CleanResults crd = as.scan(malInput, policy, AntiSamy.DOM);
                        CleanResults crs = as.scan(malInput, policy, AntiSamy.SAX);
			String crDom = crd.getCleanHTML();
			String crSax = crs.getCleanHTML();

                        assertTrue(crd.getErrorMessages().size() > 0);
                        assertTrue(crs.getErrorMessages().size() > 0);

			//System.out.println("DOM result: " + crDom);
			//System.out.println("SAX result: " + crSax);

			assertTrue(crSax.indexOf("&lt;script") != -1 && crDom.indexOf("<script") == -1);
			assertTrue(crDom.indexOf("&lt;script") != -1 && crDom.indexOf("<script") == -1);
			
		} catch (Exception e) {
			fail(e.getMessage());
		}

		/* this test is for confirming literal-lists work as
		 * advertised. it turned out to be an invalid / non-
		 * reproducible bug report but the test seemed useful
		 * enough to keep. 
		 */
		try {
			
			String malInput = "hello<p align='invalid'>world</p>";
			
			CleanResults crd = as.scan(malInput, policy, AntiSamy.DOM); 
			String crDom = crd.getCleanHTML();
			CleanResults crs = as.scan(malInput, policy, AntiSamy.SAX); 
			String crSax = crs.getCleanHTML();

			//System.out.println("DOM result: " + crDom);
			//System.out.println("SAX result: " + crSax);

			assertTrue(crSax.indexOf("invalid") == -1);
			assertTrue(crDom.indexOf("invalid") == -1);

			assertTrue(crd.getErrorMessages().size() == 1);
			assertTrue(crs.getErrorMessages().size() == 1);
			
			String goodInput = "hello<p align='left'>world</p>";
			crDom = as.scan(goodInput, policy, AntiSamy.DOM).getCleanHTML();
			crSax = as.scan(goodInput, policy, AntiSamy.SAX).getCleanHTML();

			assertTrue(crSax.indexOf("left") != -1);
			assertTrue(crDom.indexOf("left") != -1);

		} catch (Exception e) {
			fail(e.getMessage());
		}

            /*
             * Test Julian Cohen's stack exhaustion bug.
             */

            StringBuilder sb = new StringBuilder();
            for(int i=0;i<249;i++) {
                sb.append("<div>" );
            }
            try {

                /*
                 * First, make sure this attack is useless against the
                 * SAX parser.
                 */
                CleanResults crs = as.scan(sb.toString(), policy, AntiSamy.SAX);

                /*
                 * Scan this really deep tree (depth=249, 1 less than the
                 * max) and make sure it doesn't blow up.
                 */

                CleanResults crd = as.scan(sb.toString(), policy, AntiSamy.DOM);

                String crDom = crd.getCleanHTML();
                assertTrue(crDom.length() != 0);
                /*
                 * Now push it over the limit to 251 and make sure we blow
                 * up safely.
                 */
                sb.append("<div><div>"); // this makes 251

                try {
                    crd = as.scan(sb.toString(), policy, AntiSamy.DOM);
                    fail("DOM depth exceeded max - should've errored");
                } catch (ScanException e) {
                    
                }
        } catch (Throwable t) {
            fail(t.getMessage());
        }

        /*
         * #107 - erroneous newlines appearing? couldn't reproduce this
         * error but the test seems worthy of keeping.
         */
        String nl = "\n";

        try {
            sb = new StringBuilder();
            String header = "<h1>Header</h1>";
            String para = "<p>Paragraph</p>";
            sb.append(header);
            sb.append(nl);
            sb.append(para);
            
            String html = sb.toString();

            String crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
            String crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();

            /* Make sure only 1 newline appears */
            assertTrue(crDom.lastIndexOf(nl) == crDom.indexOf(nl));
            assertTrue(crSax.lastIndexOf(nl) == crSax.indexOf(nl));

            int expectedLoc = header.length();
            int actualLoc = crSax.indexOf(nl);
            assertTrue(expectedLoc == actualLoc);

            actualLoc = crDom.indexOf(nl);
            // account for line separator length difference across OSes.
            assertTrue(expectedLoc == actualLoc || expectedLoc == actualLoc+1); 

        } catch(Exception e) {
            fail(e.getMessage());
        }	
        
        /*
         * #112 - empty tag becomes self closing
         */
        
        try {
        	String html = "text <strong></strong> text <strong><em></em></strong> text";
        	
        	String crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	String crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
        	
        	assertTrue(crDom.indexOf("<strong />") == -1 && crDom.indexOf("<strong/>") == -1);
        	assertTrue(crSax.indexOf("<strong />") == -1 && crSax.indexOf("<strong/>") == -1);
        	
        } catch (Exception e) {
        	fail(e.getMessage());
        }
        
        /*
         * #116 - unclosed tags appearing during XHTML sanitization in SAX parser.
         */
        try {
        	String useXhtmlBefore = policy.getDirective(Policy.USE_XHTML);
        	sb = new StringBuilder();
        	sb.append("<html><head><title>foobar</title></head><body>");
        	sb.append("<img src=\"http://foobar.com/pic.gif\" /></body></html>");
        	
        	String html = sb.toString();
        	
        	policy.setDirective(Policy.USE_XHTML, "true");
        	String crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	String crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
            
            assertTrue(html.equals(crDom));
            assertTrue(html.equals(crSax));
            
            policy.setDirective(Policy.USE_XHTML, useXhtmlBefore);
            
        } catch (Exception e) {
        	fail(e.getMessage());
        }
        
        /*
         * Testing for nested CDATA attacks against the SAX parser.
         */
        
        try {
        	String html ="<![CDATA[]><script>alert(1)</script><![CDATA[]>]]><script>alert(2)</script>>]]>";
        	String crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	String crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
        	assertTrue(crDom.indexOf("<script>") == -1);
        	assertTrue(crSax.indexOf("<script>") == -1);
        } catch (Exception e) {
        	fail(e.getMessage());
        }
        
        /*
         * #101 - testing international character support
         */
        String entityEncodeUnicodeChars = policy.getDirective(Policy.ENTITY_ENCODE_INTL_CHARS);
        String useXhtml = policy.getDirective(Policy.USE_XHTML);
        
        policy.setDirective(Policy.ENTITY_ENCODE_INTL_CHARS, "false");
        
        try {
        	String html = "<b>letter 'a' with umlaut: ä";
        	String crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	String crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
        	assertTrue(crDom.indexOf("ä") != -1);
        	assertTrue(crSax.indexOf("ä") != -1);
        	
        	policy.setDirective(Policy.USE_XHTML, "false");
        	policy.setDirective(Policy.ENTITY_ENCODE_INTL_CHARS, "true");
        	crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
        	assertTrue(crDom.indexOf("ä") == -1);
        	assertTrue(crDom.indexOf("&auml;") != -1);
        	assertTrue(crSax.indexOf("ä") == -1);
        	assertTrue(crSax.indexOf("&auml;") != -1);
        	
        	policy.setDirective(Policy.USE_XHTML, "true");
        	policy.setDirective(Policy.ENTITY_ENCODE_INTL_CHARS, "true");
        	crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
        	assertTrue(crDom.indexOf("ä") == -1);
        	assertTrue(crDom.indexOf("&auml;") != -1);
        	assertTrue(crSax.indexOf("ä") == -1);
        	assertTrue(crSax.indexOf("&auml;") != -1);
        	
        } catch (Exception e) {
        	fail(e.getMessage());
        } finally {
        	policy.setDirective(Policy.ENTITY_ENCODE_INTL_CHARS, entityEncodeUnicodeChars);
        	policy.setDirective(Policy.USE_XHTML, useXhtml);
        }
        
        /*
         * Testing iframe as reported by Ondrej.
         */
        try {
        	String useXhtmlBefore = policy.getDirective(Policy.USE_XHTML);
        	String html = "<iframe></iframe>";
        	
        	policy.setDirective(Policy.USE_XHTML, "true");
        	
        	Tag tag = new Tag("iframe");
        	tag.setAction(Policy.ACTION_VALIDATE);
        	tag.setAllowedAttributes(new HashMap());
        	policy.addTagRule(tag);
        	
        	String crDom = as.scan(html, policy, AntiSamy.DOM).getCleanHTML();
        	String crSax = as.scan(html, policy, AntiSamy.SAX).getCleanHTML();
            
            assertTrue(html.equals(crDom));
            assertTrue(html.equals(crSax));
            
            policy.setDirective(Policy.USE_XHTML, useXhtmlBefore);
        } catch (Exception e) {
        	fail(e.getMessage());
        } finally {

        }
	}

	/*
	 * Tests cases dealing with nofollowAnchors directive. Assumes anchor tags
	 * have an action set to "validate" (may be implicit) in the policy file.
	 */
	public void testNofollowAnchors() {

		try {

			// if we have activated nofollowAnchors
			String val = policy.getDirective(Policy.ANCHORS_NOFOLLOW);

			policy.setDirective(Policy.ANCHORS_NOFOLLOW, "true");

			// adds when not present

			assertTrue(as.scan("<a href=\"blah\">link</a>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(as.scan("<a href=\"blah\">link</a>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// adds properly even with bad attr
			assertTrue(as.scan("<a href=\"blah\" bad=\"true\">link</a>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(as.scan("<a href=\"blah\" bad=\"true\">link</a>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// rel with bad value gets corrected
			assertTrue(as.scan("<a href=\"blah\" rel=\"blh\">link</a>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(as.scan("<a href=\"blah\" rel=\"blh\">link</a>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// correct attribute doesnt get messed with
			assertTrue(as.scan("<a href=\"blah\" rel=\"nofollow\">link</a>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(as.scan("<a href=\"blah\" rel=\"nofollow\">link</a>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// if two correct attributes, only one remaining after scan
			assertTrue(as.scan("<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>", policy, AntiSamy.DOM).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);
			assertTrue(as.scan("<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>", policy, AntiSamy.SAX).getCleanHTML().indexOf("<a href=\"blah\" rel=\"nofollow\">link</a>") > -1);

			// test if value is off - does it add?

			assertTrue(as.scan("a href=\"blah\">link</a>", policy, AntiSamy.DOM).getCleanHTML().indexOf("nofollow") == -1);
			assertTrue(as.scan("a href=\"blah\">link</a>", policy, AntiSamy.SAX).getCleanHTML().indexOf("nofollow") == -1);

			policy.setDirective(Policy.ANCHORS_NOFOLLOW, val);

		} catch (Exception e) {
			fail("Caught exception in testNofollowAnchors(): " + e.getMessage());
		}
	}

	public void testValidateParamAsEmbed() {
		try {
			// activate policy setting for this test
			String isValidateParamAsEmbed = policy.getDirective(Policy.VALIDATE_PARAM_AS_EMBED);
			String isFormatOutput = policy.getDirective(Policy.FORMAT_OUTPUT);
			String isXhtml = policy.getDirective(Policy.USE_XHTML);
			
			policy.setDirective(Policy.VALIDATE_PARAM_AS_EMBED, "true");
			policy.setDirective(Policy.FORMAT_OUTPUT, "false");
			policy.setDirective(Policy.USE_XHTML, "true");
			
			// let's start with a YouTube embed
			String input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			String expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>";
			CleanResults cr = as.scan(input, policy, AntiSamy.DOM);
			assertTrue(cr.getCleanHTML().indexOf(expectedOutput) > -1);

			String saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\" /></object>"; 
			cr = as.scan(input, policy, AntiSamy.SAX);
			// System.out.println("Expected: " + saxExpectedOutput);
			// System.out.println("Received: " + cr.getCleanHTML());
			assertTrue(cr.getCleanHTML().equals(saxExpectedOutput));

			// now what if someone sticks malicious URL in the value of the
			// value attribute in the param tag? remove that param tag
			input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://supermaliciouscode.com/badstuff.swf\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>";
			saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\" /></object>";
			cr = as.scan(input, policy, AntiSamy.DOM);
			assertTrue(cr.getCleanHTML().indexOf(expectedOutput) > -1);

			cr = as.scan(input, policy, AntiSamy.SAX);
			// System.out.println("Expected: " + saxExpectedOutput);
			// System.out.println("Received: " + cr.getCleanHTML());
			assertTrue(cr.getCleanHTML().equals(saxExpectedOutput));

			// now what if someone sticks malicious URL in the value of the src
			// attribute in the embed tag? remove that embed tag
			input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://hereswhereikeepbadcode.com/ohnoscary.swf\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
			expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /></object>";
			saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /></object>";

			cr = as.scan(input, policy, AntiSamy.DOM);
			assertTrue(cr.getCleanHTML().indexOf(expectedOutput) > -1);
			cr = as.scan(input, policy, AntiSamy.SAX);

			// System.out.println("Expected: " + saxExpectedOutput);
			// System.out.println("Received: " + cr.getCleanHTML());
			assertTrue(cr.getCleanHTML().indexOf(saxExpectedOutput) > -1);

			// revert policy settings
			policy.setDirective(Policy.VALIDATE_PARAM_AS_EMBED, isValidateParamAsEmbed);
			policy.setDirective(Policy.FORMAT_OUTPUT, isFormatOutput);
			policy.setDirective(Policy.USE_XHTML, isXhtml);
			
		} catch (Exception e) {
			fail("Caught exception in testValidateParamAsEmbed(): " + e.getMessage());
		}
	}

	public void testCompareSpeeds() throws IOException, ScanException, PolicyException {

		String urls[] = {
				"http://slashdot.org/", "http://www.fark.com/", "http://www.cnn.com/", "http://google.com/", "http://www.microsoft.com/en/us/default.aspx", "http://deadspin.com/"
		};

		double totalDomTime = 0;
		double totalSaxTime = 0;

		int testReps = 15;

		for (int i = 0; i < urls.length; i++) {
			URL url = new URL(urls[i]);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			InputStreamReader in = new InputStreamReader(conn.getInputStream());
			StringBuilder out = new StringBuilder();
			char[] buffer = new char[5000];
			int read = 0;
			do {
				read = in.read(buffer, 0, buffer.length);
				if (read > 0) {
					out.append(buffer, 0, read);
				}
			} while (read >= 0);

			in.close();

			String html = out.toString();

			System.out.println("About to scan: " + url + " size: " + html.length());
			if (html.length() > policy.getMaxInputSize()) {
				System.out.println("   -Maximum input size exceeded. SKIPPING.");
				continue;
			}

			double domTime = 0;
			double saxTime = 0;

			for (int j = 0; j < testReps; j++) {
				domTime += as.scan(html, policy, AntiSamy.DOM).getScanTime();
				saxTime += as.scan(html, policy, AntiSamy.SAX).getScanTime();
			}

			domTime = domTime / testReps;
			saxTime = saxTime / testReps;

			totalDomTime += domTime;
			totalSaxTime += saxTime;
		}

		System.out.println("Total DOM time: " + totalDomTime);
		System.out.println("Total SAX time: " + totalSaxTime);
	}

    public void testCompareSpeedsShortStrings() throws IOException, ScanException, PolicyException {

        double totalDomTime = 0;
        double totalSaxTime = 0;

        int testReps = 1000;

        String html = "<body> hey you <img/> out there on your own </body>";

        for (int j = 0; j < testReps; j++) {
            totalDomTime += as.scan(html, policy, AntiSamy.DOM).getScanTime();;
            totalSaxTime += as.scan(html, policy, AntiSamy.SAX).getScanTime();
        }

        System.out.println("Total DOM time short string: " + totalDomTime);
        System.out.println("Total SAX time short string: " + totalSaxTime);
    }

}