<%@ page language="java"%>
<%@ page import="java.util.*"%>
<%@ page import="org.owasp.validator.html.*"%>
<%
	final Locale LOCALE_CHINESE = new Locale("zh", "CN");
	final Locale LOCALE_ENGLISH = new Locale("en", "US");
	final Locale LOCALE_ITALIAN = new Locale("it", "IT");
	final Locale LOCALE_GERMAN = new Locale("de", "DE");
	final Locale LOCALE_NORWEGIAN = new Locale("no", "NB");
	final Locale LOCALE_PORTUGUESE = new Locale("pt", "PT");
	final Locale LOCALE_RUSSIAN = new Locale("ru", "RU");
	final Locale LOCALE_SPANISH = new Locale("es", "MX");
	
	AntiSamy as = new AntiSamy();
	String policy = "NO POLICY";
	Locale locale = LOCALE_ENGLISH;
		
	StringBuffer policyFile = new StringBuffer();
	
	boolean validate = false;
	
	if ( request.getParameter("policy") != null ) {
		String unvalidatedPolicy = request.getParameter("policy");
		
		if ("NO POLICY".equals(unvalidatedPolicy)) {
			validate = false;
		} else if ("antisamy-demo0.xml".equals(unvalidatedPolicy)
				|| "antisamy-demo1.xml".equals(unvalidatedPolicy)
				|| "antisamy-demo2.xml".equals(unvalidatedPolicy)
				|| "antisamy-demo3.xml".equals(unvalidatedPolicy)
				|| "antisamy.xml".equals(unvalidatedPolicy)) {
			policy = unvalidatedPolicy;
			validate = true;
		} else {
			policy = "antisamy.xml";
			validate = true;
		}
	}
	
	String lang = request.getParameter("language");
	
	if ("zh".equals(lang)) {
		locale = LOCALE_CHINESE;
	} else if ("en".equals(lang)) {
		locale =  LOCALE_ENGLISH;
	} else if ("it".equals(lang)) {
		locale = LOCALE_ITALIAN;
	} else if ("de".equals(lang)) {
		locale = LOCALE_GERMAN;
	} else if ("no".equals(lang)) {
		locale = LOCALE_NORWEGIAN;
	} else if ("pt".equals(lang)) {
		locale = LOCALE_PORTUGUESE;
	} else if ("ru".equals(lang)) {
		locale = LOCALE_RUSSIAN;
	} else if ("es".equals(lang)) {
		locale = LOCALE_SPANISH;
	} else {
		locale = LOCALE_ENGLISH;
	}
	
	String profile = request.getParameter("profile");
	String cleanedProfile = profile != null ? profile : "(not set yet)";
	CleanResults cr = null;
	
	if (validate)
	{
		Locale.setDefault(locale);
		
		if ( policyFile.toString().length() == policy.length() ) {
			policy = policyFile.toString();
		}
		
		ServletContext sc = session.getServletContext();
		String realPath = sc.getRealPath("/WEB-INF/resources/" + policy);
		
		cr = as.scan(profile,realPath);
		
		if (profile == null) {
			profile = "(profile not set yet)";
		} else {
			cleanedProfile = cr.getCleanHTML();
		}
	}
%>
<html>

<head>
	<meta http-equiv="Content-Type" content="text/html;charset=UTF-8"> 
	<title>AntiSamy Validation - using <%=policy%></title>

	<style>
	
	body {
		font-family: arial, "lucida console", sans-serif;
	}
	
	li {
		padding: 5px;
	}
	
	div#header {

	}

	div#menu {
		/*height: 500px;*/
		width: 200px;
		float:left;
		border: 1px solid black; 
	}
	
	div#profile {
		width: 540px;
		padding-top: 10px;
		padding-left: 30px;
		padding-right: 30px;
		margin-left: 201px;
		border-top: 1px solid black;
		border-right: 1px solid black;
		border-bottom: 1px solid black;
	}
	
	div#footer {
		float:left;
		clear:both;
	}
	</style>
	
</head>

<body>

<div id="header">
<img src="images/header.jpg">
</div>


<div id="menu">

	<div align="center">
		<h2>FaceSpace:</h2>
	</div>

	<ul>
		<li><a href="?">Home</a></li>
		<li><a href="#">Friends</a></li>
		<li><a href="#">Enemies</a></li>
		<li><a href="#">Frenemies</a></li>
		<li><a href="#">Logout</a></li>
	</ul>
	
	<br><br><br>
	
	<ul>
		<li><font size="-1">NO POLICY</font></li>
		<li><a href="antisamy-slashdot.xml"><font size="-1">antisamy-slashdot.xml</font></a></li>
		<li><a href="antisamy-ebay.xml"><font size="-1">antisamy-ebay.xml</font></a></li>
		<li><a href="antisamy-myspace.xml"><font size="-1">antisamy-myspace.xml</font></a></li>		
		<li><a href="antisamy.xml"><font size="-1">antisamy.xml</font></a></li>
		<li><a href="antisamy-demo1.xml"><font size="-1">antisamy-demo1.xml</font></a></li>
		<li><a href="antisamy-demo2.xml"><font size="-1">antisamy-demo2.xml</font></a></li>
		<li><a href="antisamy-demo3.xml"><font size="-1">antisamy-demo3.xml</font></a></li>


	</ul>
		
</div>



<div id="profile">
	
	<h2>OWASP AppSec Blog</h2>
	
	<%= cleanedProfile %>
	
	<br><br><hr><br>
	
	<%
	
		if ( cr != null && cr.getErrorMessages().size() != 0 ) {
			%><font color="red" face="bold" size="+2">We encountered some errors with your profile:</font><br><ul><%
			
			for(int i=0;i<cr.getErrorMessages().size();i++) {
				%><li><%=cr.getErrorMessages().get(i)%></li><%
			}
			
			%></ul><%
		}
	
	%>

	<form id="myForm" method="GET">
	<table>
		<tr><td>	
		<textarea rows="8" cols="40" name="profile"></textarea>
		</td><td valign="top"><strong>Policy:</strong>
		<select name="policy">			
			<option>NO POLICY</option>
			<option<%= policy.equals("antisamy-demo0.xml") ? " SELECTED" : "" %>>antisamy-demo0.xml</option>			
			<option<%= policy.equals("antisamy-demo1.xml") ? " SELECTED" : "" %>>antisamy-demo1.xml</option>
			<option<%= policy.equals("antisamy-demo2.xml") ? " SELECTED" : "" %>>antisamy-demo2.xml</option>
			<option<%= policy.equals("antisamy-demo3.xml") ? " SELECTED" : "" %>>antisamy-demo3.xml</option>
			<option<%= policy.equals("antisamy.xml") ? " SELECTED" : "" %>>antisamy.xml</option>			
		</select>
		<strong>Language:</strong>
		<select name="language">		
			<option<%= locale.equals(LOCALE_CHINESE) ? " selected" : "" %> value="zh">Chinese (zh)</option>
			<option<%= locale.equals(LOCALE_ENGLISH) ? " selected" : "" %> value="en">English (en)</option>
			<option<%= locale.equals(LOCALE_ITALIAN) ? " selected" : "" %> value="it">Italian (it)</option>			
			<option<%= locale.equals(LOCALE_GERMAN) ? " selected" : "" %> value="de">German (de)</option>
			<option<%= locale.equals(LOCALE_NORWEGIAN) ? " selected" : "" %> value="no">Norwegian (no)</option>
			<option<%= locale.equals(LOCALE_PORTUGUESE) ? " selected" : "" %> value="pt">Portuguese (pt)</option>
			<option<%= locale.equals(LOCALE_RUSSIAN) ? " selected" : "" %> value="ru">Russian (ru)</option>			
			<option<%= locale.equals(LOCALE_SPANISH) ? " selected" : "" %> value="es">Spanish (es)</option>
		</select>		
		<input type="submit" value="Update Profile">
		</td>
		</tr>
	</table>
	</form>
</div>

</div>

<div id="footer">
<img src="images/footer.jpg"/>
</div>