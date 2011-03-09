<%@ page language="java" %>
<%@ taglib uri="/WEB-INF/struts-html.tld" prefix="html" %>
<%@ taglib uri="/WEB-INF/struts-bean.tld" prefix="bean" %>
<%@ taglib uri="/WEB-INF/struts-logic.tld" prefix="logic" %>

<html:html>

<head>
<title>AntiSamy Smoketest</title>
<link rel="stylesheet" href="/template.css" type="text/css" media="screen" />
<link rel="stylesheet" href="/jquery-ui-1.8.10.custom.css" type="text/css" media="screen" /> 
<script src="/jquery.min.js"></script>
<script src="/jquery-ui.js"></script>

<script>

function showDomErrors() {
	$( "#dom-error-container" ).dialog({
		modal: true,
		width:400,
		height: 300
	});
}
function showSaxErrors() {
	$( "#sax-error-container" ).dialog({
		modal: true
		width:400,
		height: 300
	});
}
</script>

</head>

<body>

<html:form action="attack" focus="input">

<div id="our-container">
  <div id="sample04">
    <div id="banner">
       <div style="float: left"><strong>AntiSamy Smoketest</strong></div>
       <div style="float: right"><a href="http://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project">project home</a> - <a href="http://i8jesus.com">blog</a> - <a href="http://twitter.com/nahsra">twitter</a></div>
       <div style="clear: both"></div>
    </div>
  
<div id="nav">
<p><html:textarea property="input" style="width: 100%; height: 200px"></html:textarea></p>

<div style="float: left">

<table cellspacing='3' cellpadding='3'>
<tr class="category"><td colspan="2">Setup</td></tr>
<tr>
   <td>Policy</td>
   <td><html:select property="policy">
      <html:option value="0">antisamy-slashdot.xml</html:option >
      <html:option  value="1">antisamy-ebay.xml</html:option >
      <html:option  value="2">antisamy-myspace.xml</html:option >
      <html:option  value="3">antisamy-tinymce.xml</html:option >
      <html:option  value="4">antisamy-psychotic.xml</html:option >
   </html:select></td>
</tr>
<tr>
   <td>Page encoding</td>
   <td><html:select property="pageEncoding">
      <html:option value="0">UTF-8</html:option>
      <html:option value="1">ISO-8859-1</html:option>
      <html:option value="2">US-ASCII</html:option>
      <html:option value="3">UTF-7</html:option>
      <html:option value="4">EUC-JP</html:option>
   </html:select></td>
</tr>
<tr>
   <td>Engine</td>
   <td><html:select property="engine">
        <html:option value="0">Both SAX and DOM</html:option >
        <html:option value="1">Just SAX</html:option >
        <html:option value="2">Just DOM</html:option >
     </html:select></td>
</tr>
<tr class="category"><td colspan="2">Directives</td></tr>
  <tr>
    <td>nofollowAnchors</td>
    <td><html:select property='noFollowAnchors'>
        <html:option value="(default)">(default)</html:option>
        <html:option value="true">true</html:option>
        <html:option value="false">false</html:option>
    </html:select></td>
  </tr>
  <tr>
    <td>validateParamAsEmbed</td>
    <td><html:select property='validateParamAsEmbed'>
        <html:option value="(default)">(default)</html:option>
        <html:option value="true">true</html:option>
        <html:option value="false">false</html:option>
    </html:select></td>
  </tr>  
</table>

</div>
<div style="float:right"><html:submit value="Run AntiSamy!"></html:submit></div>
<div style="clear:both"></div>
</div>

<div id="content">

<logic:lessEqual value="1" parameter="engine">
<div class="result" id="sax-result">
	<p>SAX engine result (<bean:write name="attackForm" property="saxTime"/>) - <a href="javascript:showSaxErrors()">see errors</a></p>
    <div class="executed-result"><bean:write name="attackForm" property="saxOutput" filter="false"/></div>
	<div class="source-result"><bean:write name="attackForm" property="saxOutput"/></div>
	<div id="sax-error-container"><bean:write name="attackForm" property="saxErrors" filter="false"/></div>
</div>
</logic:lessEqual>

<logic:equal value="0" parameter="engine">
<div><p>&nbsp;</p></div>
</logic:equal>

<logic:notEqual value="1" parameter="engine">
<div class="result" id="dom-result">
	<p>DOM engine result (<bean:write name="attackForm" property="domTime"/>) - <a href="javascript:showDomErrors()">see errors</a></p>
	<div class="executed-result"><bean:write name="attackForm" property="domOutput" filter="false"/></div>
	<div class="source-result"><bean:write name="attackForm" property="domOutput"/></div>
	<div id="dom-error-container"><bean:write name="attackForm" property="domErrors" filter="false"/></div>
</div>
</logic:notEqual>

</div>

<div id="footer">Found an issue? Please report it our <a target="_new" href="https://code.google.com/p/owaspantisamy/issues/list">issue tracker!</a></div>
</div>
</div>

<html:errors/>

</html:form>

</body>

</html:html>