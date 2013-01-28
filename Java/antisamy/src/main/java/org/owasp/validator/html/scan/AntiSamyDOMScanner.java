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
package org.owasp.validator.html.scan;

import java.io.IOException;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.batik.css.parser.ParseException;
import org.apache.xerces.dom.DocumentImpl;
import org.apache.xml.serialize.OutputFormat;
import org.cyberneko.html.parsers.DOMFragmentParser;
import org.owasp.validator.css.CssScanner;
import org.owasp.validator.css.ExternalCssScanner;
import org.owasp.validator.html.*;
import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Tag;
import org.owasp.validator.html.util.ErrorMessageUtil;
import org.owasp.validator.html.util.HTMLEntityEncoder;
import org.w3c.dom.Comment;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ProcessingInstruction;
import org.w3c.dom.Text;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

/**
 * This is where the magic lives. All the scanning/filtration logic resides
 * here, but it should not be called directly. All scanning should be done
 * through a <code>AntiSamy.scan()</code> method.
 * 
 * @author Arshan Dabirsiaghi
 * 
 */
public class AntiSamyDOMScanner extends AbstractAntiSamyScanner {

    private Document document = new DocumentImpl();
    private DocumentFragment dom = document.createDocumentFragment();
    private CleanResults results = null;
    private static final int maxDepth = 250;
    private static final Pattern invalidXmlCharacters =
            Pattern.compile("[\\u0000-\\u001F\\uD800-\\uDFFF\\uFFFE-\\uFFFF&&[^\\u0009\\u000A\\u000D]]");
    private static final Pattern conditionalDirectives =
            Pattern.compile("<?!?\\[\\s*(?:end)?if[^]]*\\]>?");
    private int currentStackDepth;

    public AntiSamyDOMScanner(Policy policy) {
        super(policy);
    }

    /** @noinspection UnusedDeclaration Todo Investigate */
    public AntiSamyDOMScanner() throws PolicyException {
        super();
    }

    /**
     * This is where the magic lives.
     *
     * @param html
     *            A String whose contents we want to scan.
     * @return A <code>CleanResults</code> object with an
     *         <code>XMLDocumentFragment</code> object and its String
     *         representation, as well as some scan statistics.
     * @throws ScanException
     */
    public CleanResults scan(String html, String inputEncoding, final String outputEncoding) throws ScanException {

        if (html == null) {
            throw new ScanException(new NullPointerException("Null input"));
        }

        int maxInputSize = policy.getMaxInputSize();

        if (maxInputSize < html.length()) {
            addError(ErrorMessageUtil.ERROR_INPUT_SIZE, new Object[]{html.length(), maxInputSize});
            throw new ScanException(errorMessages.get(0));
        }

        isNofollowAnchors = "true".equals(policy.getDirective(Policy.ANCHORS_NOFOLLOW));
        isValidateParamAsEmbed = "true".equals(policy.getDirective(Policy.VALIDATE_PARAM_AS_EMBED));

        Date start = new Date();

        try {

            /*
             * We have to replace any invalid XML characters to prevent NekoHTML
             * from breaking when it gets passed encodings like %21.
             */

            html = stripNonValidXMLCharacters(html);

            /*
             * First thing we do is call the HTML cleaner ("NekoHTML") on it
             * with the appropriate options. We choose not to omit tags due to
             * the fallibility of our own listing in the ever changing world of
             * W3C.
             */

          DOMFragmentParser parser = getThreadLocalDomParser(inputEncoding);

            try {
                parser.parse(new InputSource(new StringReader(html)), dom);
            } catch (Exception e) {
                throw new ScanException(e);
            }

            currentStackDepth = 0;

            /*
             * Call the work horse.
             */

            for (int i = 0; i < dom.getChildNodes().getLength(); i++) {

                Node tmp = dom.getChildNodes().item(i);

                recursiveValidateTag(tmp);

                /*
                 * This check indicates if the node that was just scanned was
                 * removed/failed validation.
                 */
                if (tmp.getParentNode() == null) {
                    i--;
                }

            }

            /*
             * Serialize the output and then return the resulting DOM object and
             * its string representation.
             */


            final String trimmedHtml = html;
            Callable<String> cleanHtml = new Callable<String>() {
                public String call() throws Exception {
                    StringWriter out = new StringWriter();

                    OutputFormat format = getOutputFormat(outputEncoding);

                    //noinspection deprecation
                    org.apache.xml.serialize.HTMLSerializer serializer = getHTMLSerializer(out, format);
                    serializer.serialize(dom);

                    /*
                    * Get the String out of the StringWriter and rip out the XML
                    * declaration if the Policy says we should.
                    */
                    return trim(trimmedHtml, out.getBuffer().toString());
                }
            };

            /**
             * Return the DOM object as well as string HTML.
             */
            results = new CleanResults(start, new Date(), cleanHtml, dom, errorMessages);

            return results;

        } catch (SAXException e) {
            throw new ScanException(e);
        }

    }

    private static final ThreadLocal parsers = new ThreadLocal(){
        protected Object initialValue() {
            return new HashMap();
        }
    };

    DOMFragmentParser getThreadLocalDomParser(String inputEncoding) throws SAXNotSupportedException, SAXNotRecognizedException {
        if (inputEncoding == null) {
            inputEncoding = "DEFAULT-ENC";
        }
        @SuppressWarnings("unchecked")
        Map<String,DOMFragmentParser> byEncoding = (Map<String,DOMFragmentParser>) parsers.get();
        DOMFragmentParser parser = byEncoding.get(inputEncoding);
        if (parser == null){
            parser = getDomParser( inputEncoding);
            byEncoding.put( inputEncoding, parser);
        }
        return parser;
    }


    DOMFragmentParser getDomParser(String inputEncoding)
            throws SAXNotRecognizedException, SAXNotSupportedException {
        DOMFragmentParser parser = new DOMFragmentParser();
        parser.setProperty("http://cyberneko.org/html/properties/names/elems", "lower");
        parser.setProperty("http://cyberneko.org/html/properties/default-encoding", inputEncoding);

        parser.setFeature("http://cyberneko.org/html/features/scanner/style/strip-cdata-delims", false);
        parser.setFeature("http://cyberneko.org/html/features/scanner/cdata-sections", true);

        try {
            parser.setFeature("http://cyberneko.org/html/features/enforce-strict-attribute-names", true);
        } catch (SAXNotRecognizedException se) {
            // this indicates that the patched nekohtml is not on the
            // classpath
        }
        return parser;
    }

    /**
     * The workhorse of the scanner. Recursively scans document elements
     * according to the policy. This should be called implicitly through the
     * AntiSamy.scan() method.
     *
     * @param node
     *            The node to validate.
     */
    private void recursiveValidateTag(Node node) throws ScanException {

        currentStackDepth++;

        if(currentStackDepth > maxDepth) {
            throw new ScanException("Too many nested tags");
        }

        if (node instanceof Comment) {

            String preserveComments = policy.getDirective(Policy.PRESERVE_COMMENTS);

            if (preserveComments == null || !"true".equals(preserveComments)) {
                node.getParentNode().removeChild(node);
            } else {
                String value = ((Comment) node).getData();
                // Strip conditional directives regardless of the
                // PRESERVE_COMMENTS setting.
                if (value != null) {
                    ((Comment) node).setData(conditionalDirectives.matcher(value).replaceAll(""));
                }
            }

            currentStackDepth--;
            return;
        }

        if (node instanceof Element && node.getChildNodes().getLength() == 0) {

        	String tagName = node.getNodeName();

            if (!isAllowedEmptyTag(tagName)) {
                /*
                 * Wasn't in the list of allowed elements, so we'll nuke it.
                 */
                addError(ErrorMessageUtil.ERROR_TAG_EMPTY, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getNodeName())});
                removeNode(node);
                currentStackDepth--;
                return;
            }
        }

        if (node instanceof Text && Node.CDATA_SECTION_NODE == node.getNodeType()) {

            addError(ErrorMessageUtil.ERROR_CDATA_FOUND, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getTextContent())});

            //String encoded = HTMLEntityEncoder.htmlEntityEncode(node.getTextContent());

            Node text = document.createTextNode(node.getTextContent());
            node.getParentNode().insertBefore(text, node);
            node.getParentNode().removeChild(node);
    
            currentStackDepth--;
            return;
        }

        if (node instanceof ProcessingInstruction) {
            addError(ErrorMessageUtil.ERROR_PI_FOUND, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getTextContent())});
            removeNode(node);
            node.getParentNode().removeChild(node);
        }

        if (!(node instanceof Element)) {
            currentStackDepth--;
            return;
        }

        Element ele = (Element) node;
        Node parentNode = ele.getParentNode();
        Node tmp;

        /*
         * See if we have a policy for this tag. If we do, getTagByName() will
         * retrieve its object representation.
         */

        String tagName = ele.getNodeName();
        String tagNameLowerCase = tagName.toLowerCase();
        Tag tag = policy.getTagByName(tagNameLowerCase);

        /*
         * If <param> and no policy and isValidateParamAsEmbed and policy in
         * place for <embed> and <embed> policy is to validate, use custom
         * policy to get the tag through to the validator.
         */
        boolean masqueradingParam = false;
        Tag embedTag = policy.getTagByName("embed");
        if (tag == null && isValidateParamAsEmbed && "param".equals(tagNameLowerCase)) {
            if (embedTag != null && Policy.ACTION_VALIDATE.equals(embedTag.getAction())) {
                tag = Constants.BASIC_PARAM_TAG_RULE;
                masqueradingParam = true;
            }
        }

        if ((tag == null && "encode".equals(policy.getDirective("onUnknownTag"))) || (tag != null && "encode".equals(tag.getAction()))) {

            addError(ErrorMessageUtil.ERROR_TAG_ENCODED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(tagName)});

            /*
             * We have to filter out the tags only. This means the content
             * should remain. First step is to validate before promoting its
             * children.
             */

            for (int i = 0; i < node.getChildNodes().getLength(); i++) {

                tmp = node.getChildNodes().item(i);

                recursiveValidateTag(tmp);

                /*
                 * This indicates the node was removed/failed validation.
                 */
                if (tmp.getParentNode() == null) {
                    i--;
                }
            }

            /*
             * Transform the tag to text, HTML-encode it and promote the
             * children. The tag will be kept in the fragment as one or two text
             * Nodes located before and after the children; representing how the
             * tag used to wrap them.
             */

            encodeAndPromoteChildren(ele);
            currentStackDepth--;
            return;

        } else if (tag == null || Policy.ACTION_FILTER.equals(tag.getAction())) {

            if (tag == null) {
                addError(ErrorMessageUtil.ERROR_TAG_NOT_IN_POLICY, new Object[]{HTMLEntityEncoder.htmlEntityEncode(tagName)});
            } else {
                addError(ErrorMessageUtil.ERROR_TAG_FILTERED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(tagName)});
            }

            /*
             * We have to filter out the tags only. This means the content
             * should remain. First step is to validate before promoting its
             * children.
             */

            for (int i = 0; i < node.getChildNodes().getLength(); i++) {

                tmp = node.getChildNodes().item(i);

                recursiveValidateTag(tmp);

                /*
                 * This indicates the node was removed/failed validation.
                 */
                if (tmp.getParentNode() == null) {
                    i--;
                }
            }

            /*
             * Loop through and add the children node to the parent before
             * removing the current node from the parent.
             *
             * We must get a fresh copy of the children nodes because validating
             * the children may have resulted in us getting less or more
             * children.
             */

            promoteChildren(ele);
            currentStackDepth--;
            return;

        } else if (Policy.ACTION_VALIDATE.equals(tag.getAction())) {

            /*
             * If doing <param> as <embed>, now is the time to convert it.
             */
            String nameValue = null;
            if (masqueradingParam) {
                nameValue = ele.getAttribute("name");
                if (nameValue != null && !"".equals(nameValue)) {
                    String valueValue = ele.getAttribute("value");
                    ele.setAttribute(nameValue, valueValue);
                    ele.removeAttribute("name");
                    ele.removeAttribute("value");
                    tag = embedTag;
                }
            }

            /*
             * Check to see if it's a <style> tag. We have to special case this
             * tag so we can hand it off to the custom style sheet validating
             * parser.
             */

            if ("style".equals(tagNameLowerCase) && policy.getTagByName("style") != null) {

                /*
                 * Invoke the css parser on this element.
                 */
            	CssScanner styleScanner;
            	
            	if("true".equals(policy.getDirective(Policy.EMBED_STYLESHEETS))) {
            		styleScanner = new ExternalCssScanner(policy, messages);
            	}else{
            		styleScanner = new CssScanner(policy, messages);
            	}

                try {

                    if (node.getFirstChild() != null) {

                        String toScan = node.getFirstChild().getNodeValue();

                        CleanResults cr = styleScanner.scanStyleSheet(toScan, policy.getMaxInputSize());

                        errorMessages.addAll(cr.getErrorMessages());

                        /*
                         * If IE gets an empty style tag, i.e. <style/> it will
                         * break all CSS on the page. I wish I was kidding. So,
                         * if after validation no CSS properties are left, we
                         * would normally be left with an empty style tag and
                         * break all CSS. To prevent that, we have this check.
                         */

                        final String cleanHTML = cr.getCleanHTML();

                        if (cleanHTML == null || cleanHTML.equals("")) {

                            node.getFirstChild().setNodeValue("/* */");

                        } else {

                            node.getFirstChild().setNodeValue(cleanHTML);

                        }

                    }

                } catch (DOMException e) {

                    addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue())});
                    parentNode.removeChild(node);
                    currentStackDepth--;
                    return;

                } catch (ScanException e) {

                    addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue())});
                    parentNode.removeChild(node);
                    currentStackDepth--;
                    return;

                    /*
                     * This shouldn't be reachable anymore, but we'll leave it
                     * here because I'm hilariously dumb sometimes.
                     */
                } catch (ParseException e) {

                    addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue())});
                    parentNode.removeChild(node);
                    currentStackDepth--;
                    return;

                    /*
                     * Batik can throw NumberFormatExceptions (see bug #48).
                     */
                } catch (NumberFormatException e) {

                    addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue())});
                    parentNode.removeChild(node);
                    currentStackDepth--;
                    return;
                }
            }

            /*
             * Go through the attributes in the tainted tag and validate them
             * against the values we have for them.
             *
             * If we don't have a rule for the attribute we remove the
             * attribute.
             */

            Node attribute;

            for (int currentAttributeIndex = 0; currentAttributeIndex < ele.getAttributes().getLength(); currentAttributeIndex++) {

                attribute = ele.getAttributes().item(currentAttributeIndex);

                String name = attribute.getNodeName();
                String value = attribute.getNodeValue();

                Attribute attr = tag.getAttributeByName(name.toLowerCase());

                /**
                 * If we there isn't an attribute by that name in our policy
                 * check to see if it's a globally defined attribute. Validate
                 * against that if so.
                 */
                if (attr == null) {
                    attr = policy.getGlobalAttributeByName(name);
                }

                boolean isAttributeValid = false;

                /*
                 * We have to special case the "style" attribute since it's
                 * validated quite differently.
                 */
                if ("style".equals(name.toLowerCase()) && attr != null) {

                    /*
                     * Invoke the CSS parser on this element.
                     */
                    CssScanner styleScanner = new CssScanner(policy, messages);

                    try {

                        CleanResults cr = styleScanner.scanInlineStyle(value, tagName, policy.getMaxInputSize());

                        attribute.setNodeValue(cr.getCleanHTML());

                        List<String> cssScanErrorMessages = cr.getErrorMessages();

                        errorMessages.addAll(cssScanErrorMessages);

                    } catch (DOMException e) {

                        addError(ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(node.getNodeValue())});

                        ele.removeAttribute(attribute.getNodeName());
                        currentAttributeIndex--;

                    } catch (ScanException e) {

                        addError(ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(node.getNodeValue())});

                        ele.removeAttribute(attribute.getNodeName());
                        currentAttributeIndex--;
                    }

                } else {

                    if (attr != null) {

                        Iterator allowedValues = attr.getAllowedValues().iterator();

                        while (allowedValues.hasNext() && !isAttributeValid) {

                            String allowedValue = (String) allowedValues.next();

                            if (allowedValue != null && allowedValue.toLowerCase().equals(value.toLowerCase())) {
                                isAttributeValid = true;
                            }
                        }

                        if (attr.matchesAllowedExpression(value)){
                            isAttributeValid = true;
                        };

                        if (!isAttributeValid) {

                            /*
                             * Document transgression and perform the
                             * "onInvalid" action. The default action is to
                             * strip the attribute and leave the rest intact.
                             */

                            String onInvalidAction = attr.getOnInvalid();

                            if ("removeTag".equals(onInvalidAction)) {

                                /*
                                 * Remove the tag and its contents.
                                 */

                                removeNode(ele);
                            	
                                addError(ErrorMessageUtil.ERROR_ATTRIBUTE_INVALID_REMOVED,
                                        new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(name), HTMLEntityEncoder.htmlEntityEncode(value)});
                                currentStackDepth--;
                                return;

                            } else if ("filterTag".equals(onInvalidAction)) {

                                /*
                                 * Remove the attribute and keep the rest of the
                                 * tag.
                                 */

                                for (int i = 0; i < node.getChildNodes().getLength(); i++) {

                                    tmp = node.getChildNodes().item(i);

                                    recursiveValidateTag(tmp);

                                    /*
                                     * This indicates the node was
                                     * removed/failed validation.
                                     */
                                    if (tmp.getParentNode() == null) {
                                        i--;
                                    }
                                }

                                promoteChildren(ele);

                                addError(ErrorMessageUtil.ERROR_ATTRIBUTE_CAUSE_FILTER, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(name), HTMLEntityEncoder.htmlEntityEncode(value)});

                            } else if ("encodeTag".equals(onInvalidAction)) {

                                /*
                                 * Remove the attribute and keep the rest of the
                                 * tag.
                                 */

                                for (int i = 0; i < node.getChildNodes().getLength(); i++) {

                                    tmp = node.getChildNodes().item(i);

                                    recursiveValidateTag(tmp);

                                    /*
                                     * This indicates the node was
                                     * removed/failed validation.
                                     */
                                    if (tmp.getParentNode() == null) {
                                        i--;
                                    }
                                }

                                encodeAndPromoteChildren(ele);

                                addError(ErrorMessageUtil.ERROR_ATTRIBUTE_CAUSE_ENCODE, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(name), HTMLEntityEncoder.htmlEntityEncode(value)});

                            } else {

                                /*
                                 * onInvalidAction = "removeAttribute"
                                 */

                                ele.removeAttribute(attribute.getNodeName());

                                currentAttributeIndex--;

                                addError(ErrorMessageUtil.ERROR_ATTRIBUTE_INVALID, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(name), HTMLEntityEncoder.htmlEntityEncode(value)});

                                if ("removeTag".equals(onInvalidAction) || "filterTag".equals(onInvalidAction)) {
                                    return; // can't process any more if we
                                    // remove/filter the tag
                                }

                            }

                        }

                    } else { /*
                         * the attribute they specified isn't in our policy
                         * - remove it (whitelisting!)
                         */

                        addError(ErrorMessageUtil.ERROR_ATTRIBUTE_NOT_IN_POLICY, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(name), HTMLEntityEncoder.htmlEntityEncode(value)});

                        ele.removeAttribute(attribute.getNodeName());

                        currentAttributeIndex--;

                    } // end if attribute is or is not found in policy file

                } // end while loop through attributes

            } // loop through each attribute

            if (isNofollowAnchors && "a".equals(tagNameLowerCase)) {
                ele.setAttribute("rel", "nofollow");
            }

            for (int i = 0; i < node.getChildNodes().getLength(); i++) {

                tmp = node.getChildNodes().item(i);

                recursiveValidateTag(tmp);

                /*
                 * This indicates the node was removed/failed validation.
                 */
                if (tmp.getParentNode() == null) {
                    i--;
                }
            }

            /*
             * If we have been dealing with a <param> that has been converted to
             * an <embed>, convert it back
             */
            if (masqueradingParam && nameValue != null && !"".equals(nameValue)) {
                String valueValue = ele.getAttribute(nameValue);
                ele.setAttribute("name", nameValue);
                ele.setAttribute("value", valueValue);
                ele.removeAttribute(nameValue);
            }

            currentStackDepth--;
            return;

        } else if (Policy.ACTION_TRUNCATE.equals(tag.getAction())) {

            /*
             * Remove all attributes. This is for tags like i, b, u, etc. Purely
             * formatting without any need for attributes. It also removes any
             * children.
             */

            NamedNodeMap nnmap = ele.getAttributes();

            while (nnmap.getLength() > 0) {

                addError(ErrorMessageUtil.ERROR_ATTRIBUTE_NOT_IN_POLICY, new Object[]{tagName, HTMLEntityEncoder.htmlEntityEncode(nnmap.item(0).getNodeName())});

                ele.removeAttribute(nnmap.item(0).getNodeName());

            }

            NodeList cList = ele.getChildNodes();

            int i = 0;
            int j = 0;
            int length = cList.getLength();

            while (i < length) {

                Node nodeToRemove = cList.item(j);

                if (nodeToRemove.getNodeType() != Node.TEXT_NODE) {
                    ele.removeChild(nodeToRemove);
                } else {
                    j++;
                }

                i++;
            }

        } else {

            /*
             * If we reached this that means that the tag's action is "remove",
             * which means to remove the tag (including its contents).
             */

            addError(ErrorMessageUtil.ERROR_TAG_DISALLOWED, new Object[]{HTMLEntityEncoder.htmlEntityEncode(tagName)});
            removeNode(ele);

        }

        currentStackDepth--;
    }

    private void removeNode(Node node) {
		Node parent = node.getParentNode();
		parent.removeChild(node);
		String tagName = parent.getNodeName();
		if(	parent instanceof Element && 
			parent.getChildNodes().getLength() == 0 && 
			!isAllowedEmptyTag(tagName)) {
			removeNode(parent);
		}
	}

	private boolean isAllowedEmptyTag(String tagName) {
        return policy.getAllowedEmptyTags().matches(tagName);
	}

    public static void main(String[] args) throws PolicyException {
    }


    /**
     * Used to promote the children of a parent to accomplish the "filterTag"
     * action.
     *
     * @param ele
     *            The Element we want to filter.
     */
    private void promoteChildren(Element ele) {

        NodeList nodeList = ele.getChildNodes();
        Node parent = ele.getParentNode();

        while (nodeList.getLength() > 0) {
            Node node = ele.removeChild(nodeList.item(0));
            parent.insertBefore(node, ele);
        }

        removeNode(ele);
    }

    /**
     *
     * This method was borrowed from Mark McLaren, to whom I owe much beer.
     *
     * This method ensures that the output has only valid XML unicode characters
     * as specified by the XML 1.0 standard. For reference, please see <a
     * href="http://www.w3.org/TR/2000/REC-xml-20001006#NT-Char">the
     * standard</a>. This method will return an empty String if the input is
     * null or empty.
     *
     * @param in
     *            The String whose non-valid characters we want to remove.
     * @return The in String, stripped of non-valid characters.
     */
    private String stripNonValidXMLCharacters(String in) {

        if (in == null || ("".equals(in))) {
            return ""; // vacancy test.
        }
        Matcher matcher = invalidXmlCharacters.matcher(in);
        return matcher.matches() ? matcher.replaceAll("") : in;
    }

    // private void debug(String s) { System.out.println(s); }
    /**
     * Transform the element to text, HTML-encode it and promote the children.
     * The element will be kept in the fragment as one or two text Nodes located
     * before and after the children; representing how the tag used to wrap
     * them. If the element didn't have any children then only one text Node is
     * created representing an empty element. *
     *
     * @param ele
     *            Element to be encoded
     */
    private void encodeAndPromoteChildren(Element ele) {
        Node parent = ele.getParentNode();
        String tagName = ele.getTagName();
        Node openingTag = parent.getOwnerDocument().createTextNode(toString(ele));
        parent.insertBefore(openingTag, ele);
        if (ele.hasChildNodes()) {
            Node closingTag = parent.getOwnerDocument().createTextNode("</" + tagName + ">");
            parent.insertBefore(closingTag, ele.getNextSibling());
        }
        promoteChildren(ele);
    }

    /**
     * Returns a text version of the passed element
     *
     * @param ele
     *            Element to be converted
     * @return String representation of the element
     */
    private String toString(Element ele) {
        StringBuilder eleAsString = new StringBuilder("<" + ele.getNodeName());
        NamedNodeMap attributes = ele.getAttributes();
        Node attribute;
        for (int i = 0; i < attributes.getLength(); i++) {
            attribute = attributes.item(i);

            String name = attribute.getNodeName();
            String value = attribute.getNodeValue();

            eleAsString.append(" ");
            eleAsString.append(HTMLEntityEncoder.htmlEntityEncode(name));
            eleAsString.append("=\"");
            eleAsString.append(HTMLEntityEncoder.htmlEntityEncode(value));
            eleAsString.append("\"");
        }
        if (ele.hasChildNodes()) {
            eleAsString.append(">");
        } else {
            eleAsString.append("/>");
        }
        return eleAsString.toString();
    }

    public CleanResults getResults() {
        return results;
    }
}
