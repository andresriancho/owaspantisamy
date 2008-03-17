==============================================================================
=README.txt (Version 1.0) scraped from http://www.owasp.org/index.php/AntiSamy
==============================================================================

= OWASP AntiSamy =

== What is it? ==

The OWASP AntiSamy project is a few things. Technically, it is an API for ensuring user-supplied HTML/CSS is in compliance within an application's rules. Another way of saying that could be: It's an API that helps you make sure that clients don't supply malicious cargo code in the HTML they supply for their profile, comments, etc. that gets persisted on the server. The term malicious code in terms of web applications is usually regarded only as JavaScript. Cascading Stylesheets are only considered malicious when they invoke the JavaScript engine. However, there are many situations where "normal" HTML and CSS can be used in a malicious manner.

Philosophically, AntiSamy is a departure from all contemporary security mechanisms. Generally, the security mechanism and user have a communication that is virtually one way, for good reason. Letting the potential attacker know details about the validation is considered unwise as it allows the attacker to "learn" and "recon" the mechanism for weaknesses. These types of information leaks can also hurt in ways you don't expect. A login mechanism that tells the user, "Username invalid" leaks the fact that a user by that name does not exist. A user could use a dictionary or phone book or both to remotely come up with a list of valid usernames. Using this information, an attacker could launch a brute force attack or massive account lock denial-of-service.

So, I get that.

Unfortunately, that's just not very usable in this situation. Typical Internet users are largely ineffective when it comes to writing HTML/CSS, so where do they get their HTML from? Usually they copy it from somewhere out on the web. Simply rejecting their input without any clue as to why is jolting and annoying. Annoyed users go somewhere else to do their social networking.

Socioeconomically, AntiSamy is a have-not enabler. Private companies like Google, MySpace, eBay, etc. have come up with proprietary solutions for solving this problem. This introduces two problems. One is that proprietary solutions are not usually all that good, and even if they are, well - naturally they're reluctant to share this hard-earned IP for free. Fortunately, I just don't care. I don't see any reason why all these private companies should have this functionality safely, so I'm releasing this for free under the GPLv3 license.

== Who are you? ==

My name is Arshan Dabirsiaghi (arshan.dabirsiaghi [at the] gmail.com). I'm currently a Senior Application Security Engineer at Aspect Security. I've often heard of the problem AntiSamy solves as one that is "impossible" or "impossible to do right". I like punching ideas like that in the face. Maybe if I was smarter I could do it more often. I developed the framework and Java implementation of AntiSamy. I had help on the CSS portion from Jason Li, also of Aspect Security. I plan on releasing versions in .NET and PHP. If the Rails community can meet me halfway, I can help them too.

== How do I get started? ==

There's 3 steps in the process of integrating AntiSamy. Each step is detailed in the next section, but the high level overview follows:

# Choose one of the standard policy files that matches as close to the functionality you need:
#* antisamy-slashdot.xml
#* antisamy-ebay.xml
#* antisamy-myspace.xml
#* antisamy-insanity.xml
# Tailor the policy file according to your site's rules
# Call the API from the code

=== Stage 1 - Choosing a base policy file ===

Chances are that your site's use case for AntiSamy is at least roughly comparable to one of the predefined policy files. They each represent a "typical" scenario for allowing users to provide HTML (and possibly CSS) formatting information. Let's look into the different policy files:

1) antisamy-slashdot.xml

Slashdot (http://www.slashdot.org/) is a techie news site that allows users to respond anonymously to news posts with very limited HTML markup. Now Slashdot is not only one of the coolest sites around, it's also one that's been subject to many different successful attacks. Even more unfortunate is the fact that most of the attacks led users to the infamous goatse.cx picture (please don't go look it up). The rules for Slashdot are fairly strict: users can only submit the following HTML tags and no CSS: &lt;b&gt;, &lt;u&gt;, &lt;i&gt;, &lt;a&gt;, &lt;blockquote&gt;. 

Accordingly, we've built a policy file that allows fairly similar functionality. All text-formatting tags that operate directly on the font, color or emphasis have been allowed. 



2) antisamy-ebay.xml

eBay (http://www.ebay.com/) is the most popular online auction site in the universe, as far as I can tell. It is a public site so anyone is allowed to post listings with rich HTML content. It's not surprising that given the attractiveness of eBay as a target that it has been subject to a few complex XSS attacks. Listings are allowed to contain much more rich content than, say, Slashdot- so it's attack surface is considerably larger. The following tags appear to be accepted by eBay (they don't publish rules): <a>,...



3) antisamy-myspace.xml

MySpace (http://www.myspace.com/) is arguably the most popular social networking site today. Users are allowed to submit pretty much all HTML and CSS they want - as long as it doesn't contain JavaScript. MySpace is currently using a word blacklist to validate users' HTML, which is why they were subject to the infamous Samy worm (http://namb.la/). The Samy worm, which used fragmentation attacks combined with a word that should have been blacklisted (eval) - was the inspiration for the project. 


4) antisamy-insanity.xml

I don't know of a possible use case for this policy file. If you wanted to allow every single valid HTML and CSS element (but without JavaScript or blatant CSS-related phishing attacks), you can use this policy file. Not even MySpace is _this_ crazy. However, it does serve as a good reference because it contains base rules for every element, so you can use it as a knowledge base when using tailoring the other policy files.



=== Stage 2 - Tailoring the policy file ===

Smaller organizations may want to deploy AntiSamy in a default configuration, but it's equally likely that a site may want to have strict, business-driven rules for what users can allow. The discussion that decides the tailoring should also consider attack surface - which grows in relative proportion to the policy file.



=== Stage 3 - Calling the AntiSamy API ===

Using AntiSamy is abnormally easy. 
Here is an example of invoking AntiSamy with a policy file:

<code><pre>import org.owasp.validator.html.*;

Policy policy = new Policy(POLICY_FILE_LOCATION);

AntiSamy as = new AntiSamy();
CleanResults cr = as.scan(dirtyInput, policy);

MyUserDAO.storeUserProfile(cr.getCleanHTML()); // some custom function
</pre></code>

Policy files can also be referenced by filename by passing a second argument to the <code>AntiSamy:scan()</code> method as the following examples show.:

<code><pre>AntiSamy as = new AntiSamy();
CleanResults cr = as.scan(dirtyInput, policyFilePath);</pre></code>

Lastly, policy files can be referenced by File objects directly in the second parameter:

<code><pre>AntiSamy as = new AntiSamy();
CleanResults cr = as.scan(dirtyInput, new File(policyFilePath));</pre></code>

=== Stage 4 - Analyzing CleanResults ===

The CleanResults object provides a lot of useful stuff. 

<code>getErrorMessages()</code> - a list of <code>String</code> error messages

<code>getCleanHTML()</code> - the clean, safe HTML output

<code>getCleanXMLDocumentFragment()</code> - the clean, safe <code>XMLDocumentFragment</code> which is reflected in <code>getCleanHTML()</code>

<code>getScanTime()</code> - returns the scan time in seconds

== Project roadmap ==

We have a number of milestones we'd like to accomplish with the help of the community. Hopefully we can allocate some funds for this in the OWASP Spring of Code 2008, but it is far too early to tell. In the meantime, this is a labor of love.

=== .NET version (early Spring 2008, rc1 Fall 2008) ===
We're aiming for a beta of a .NET version of AntiSamy to be available by early Spring 2008. The major hurdles are finding a suitable "HTML cleaner" like nekohtml in .NET. It needs to be capable of producing document fragments, not just entire HTML documents. For example, if I pass in <code>&lt;i&gt;&lt;b&gt;This is a test&lt;/i&gt;&lt;/b&gt;</code> to the HTML cleaner, we can't have it send back <code>&lt;html>&lt;head>&lt;/head>&lt;body>&lt;i&gt;&lt;b&gt;This is a test&lt;/i&gt;&lt;/b&gt;&lt;/body&gt;&lt;/html&gt;</code>.

I personally (Arshan) plan on developing this, but am happy to let someone take over who can focus more time on it.

=== PHP version (beta early Spring 2008, rc1 Fall 2008) ===
We're aiming for a beta of a PHP version of AntiSamy to be available by early Spring 2008. The major hurdles are finding a suitable "HTML cleaner" like nekohtml in PHP. It needs to be capable of producing document fragments, not just entire HTML documents. For example, if I pass in <code>&lt;i&gt;&lt;b&gt;This is a test&lt;/i&gt;&lt;/b&gt;</code> to the HTML cleaner, we can't have it send back <code>&lt;html>&lt;head>&lt;/head>&lt;body>&lt;i&gt;&lt;b&gt;This is a test&lt;/i&gt;&lt;/b&gt;&lt;/body&gt;&lt;/html&gt;</code>.

Several members of the community have been in touch with us about working together, including the smart folks over at Zend.net.

== Contacting us ==
There are two ways of getting information on AntiSamy. The mailing list, and contacting the project lead directly.

=== OWASP AntiSamy mailing list ===
The first is the mailing list which is located at https://lists.owasp.org/mailman/listinfo/owasp-antisamy. The list was previously private and the archives have been cleared with the release of version 1.0. We encourage all prospective and current users and bored attackers to join in the conversation. We're happy to brainstorm attack scenarios, discuss regular expressions and help with integration.

=== Emailing the project lead ===

For content which is not appropriate for the public mailing list, you can alternatively contact the project lead, Arshan Dabirsiaghi, at [arshan.dabirsiaghi] at the [aspectsecurity.com] (s/ at the /@/).
