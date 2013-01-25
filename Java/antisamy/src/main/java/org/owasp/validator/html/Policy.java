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

package org.owasp.validator.html;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.owasp.validator.html.model.AntiSamyPattern;
import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Property;
import org.owasp.validator.html.model.Tag;
import org.owasp.validator.html.scan.Constants;
import org.owasp.validator.html.util.URIUtils;
import org.owasp.validator.html.util.XMLUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Policy.java
 * <p/>
 * This file holds the model for our policy engine.
 *
 * @author Arshan Dabirsiaghi
 */

public class Policy {

    public static final Pattern ANYTHING_REGEXP = Pattern.compile(".*");

    private static final String DEFAULT_POLICY_URI = "resources/antisamy.xml";
    private static final String DEFAULT_ONINVALID = "removeAttribute";

    public static final int DEFAULT_MAX_INPUT_SIZE = 100000;
    public static final int DEFAULT_MAX_STYLESHEET_IMPORTS = 1;

    public static final String OMIT_XML_DECLARATION = "omitXmlDeclaration";
    public static final String OMIT_DOCTYPE_DECLARATION = "omitDoctypeDeclaration";
    public static final String USE_XHTML = "useXHTML";
    public static final String FORMAT_OUTPUT = "formatOutput";
    public static final String EMBED_STYLESHEETS = "embedStyleSheets";
    public static final String CONNECTION_TIMEOUT = "connectionTimeout";
    public static final String ANCHORS_NOFOLLOW = "nofollowAnchors";
    public static final String VALIDATE_PARAM_AS_EMBED = "validateParamAsEmbed";
    public static final String PRESERVE_SPACE = "preserveSpace";
    public static final String PRESERVE_COMMENTS = "preserveComments";
    public static final String ENTITY_ENCODE_INTL_CHARS = "entityEncodeIntlChars";

    public static final String ACTION_VALIDATE = "validate";
    public static final String ACTION_FILTER = "filter";
    public static final String ACTION_TRUNCATE = "truncate";

    private static char REGEXP_BEGIN = '^';
    private static char REGEXP_END = '$';

    public final Map<String, AntiSamyPattern> commonRegularExpressions;
    private final Map<String, Tag> tagRules;
    private final Map<String, Property> cssRules;
    private final Map<String, String> directives;
    private final Map<String, Attribute> globalAttributes;
    private final Set<String> encodeTags;

    private final List<String> tagNames;
    private final TagMatcher allowedEmptyTagsMatcher;
    private final TagMatcher requiresClosingTagsMatcher;

    /**
     * The path to the base policy file, used to resolve relative paths when reading included files
     */
    private static URL baseUrl = null;


    private static class ParseContext {
        Map<String, AntiSamyPattern> commonRegularExpressions = new HashMap<String, AntiSamyPattern>();
        Map<String, Attribute> commonAttributes = new HashMap<String, Attribute>();
        Map<String, Tag> tagRules = new HashMap<String, Tag>();
        Map<String, Property> cssRules = new HashMap<String, Property>();
        Map<String, String> directives = new HashMap<String, String>();
        Map<String, Attribute> globalAttributes = new HashMap<String, Attribute>();
        Set<String> encodeTags = new HashSet<String>();
        List<String> tagNames = new ArrayList<String>();

        List<String> allowedEmptyTags = new ArrayList<String>();
        List<String> requireClosingTags = new ArrayList<String>();

        public void resetParamsWhereLastConfigWins() {
            allowedEmptyTags.clear();
            requireClosingTags.clear();
        }
    }

    /**
     * Retrieves a Tag from the Policy.
     *
     * @param tagName The name of the Tag to look up.
     * @return The Tag associated with the name specified, or null if none is found.
     */
    public Tag getTagByName(String tagName) {

        return tagRules.get(tagName.toLowerCase());

    }

    /**
     * Retrieves a CSS Property from the Policy.
     *
     * @param propertyName The name of the CSS Property to look up.
     * @return The CSS Property associated with the name specified, or null if none is found.
     */
    public Property getPropertyByName(String propertyName) {

        return cssRules.get(propertyName.toLowerCase());

    }

    /**
     * This retrieves a Policy based on a default location ("resources/antisamy.xml")
     *
     * @return A populated Policy object based on the XML policy file located in the default location.
     * @throws PolicyException If the file is not found or there is a problem parsing the file.
     */
    public static Policy getInstance() throws PolicyException {
        return getInstance(DEFAULT_POLICY_URI);
    }

    /**
     * This retrieves a Policy based on the file name passed in
     *
     * @param filename The path to the XML policy file.
     * @return A populated Policy object based on the XML policy file located in the location passed in.
     * @throws PolicyException If the file is not found or there is a problem parsing the file.
     */
    public static Policy getInstance(String filename) throws PolicyException {
        File file = new File(filename);
        return getInstance(file);
    }

    /**
     * This retrieves a Policy based on the File object passed in
     *
     * @param file A File object which contains the XML policy information.
     * @return A populated Policy object based on the XML policy file pointed to by the File parameter.
     * @throws PolicyException If the file is not found or there is a problem parsing the file.
     */
    public static Policy getInstance(File file) throws PolicyException {
        try {
            URI uri = file.toURI();
            return getInstance(uri.toURL());
        } catch (IOException e) {
            throw new PolicyException(e);
        }
    }


    /**
     * This retrieves a Policy based on the URL object passed in.
     * <p/>
     * NOTE: This is the only factory method that will work with <include> tags
     * in AntiSamy policy files.
     *
     * @param url A URL object which contains the XML policy information.
     * @return A populated Policy object based on the XML policy file pointed to by the File parameter.
     * @throws PolicyException If the file is not found or there is a problem parsing the file.
     */
    public static Policy getInstance(URL url) throws PolicyException {

        if (baseUrl == null) setBaseURL(url);
        return new Policy(url);
    }

    /**
     * This retrieves a Policy based on the InputStream object passed in
     *
     * @param inputStream An InputStream which contains thhe XML policy information.
     * @return A populated Policy object based on the XML policy file pointed to by the inputStream parameter.
     * @throws PolicyException If there is a problem parsing the input stream.
     * @deprecated This method does not properly load included policy files. Use getInstance(URL) instead.
     */
    public static Policy getInstance(InputStream inputStream) throws PolicyException {

        //noinspection deprecation
        return new Policy(inputStream);

    }

    /**
     * Load the policy from a URL.
     *
     * @param url Load a policy from the url specified.
     * @throws PolicyException
     */
    private Policy(URL url) throws PolicyException {
        this( getParseContext(getTopLevelElement(url)));

    }

    /**
     * Load the policy from an XML file.
     *
     * @param is Load a policy from the inpustream specified.
     * @throws PolicyException
     * @deprecated This constructor does not properly load included policy files. Use Policy(URL) instead.
     */
    private Policy(InputStream is) throws PolicyException {
        this(getSimpleParseContext(getTopLevelElement(is)));
    }


    private Policy(ParseContext parseContext) throws PolicyException {
        this.allowedEmptyTagsMatcher = new TagMatcher(parseContext.allowedEmptyTags);
        this.requiresClosingTagsMatcher = new TagMatcher(parseContext.requireClosingTags);
        this.commonRegularExpressions = Collections.unmodifiableMap(parseContext.commonRegularExpressions);
        this.tagRules = Collections.unmodifiableMap(parseContext.tagRules);
        this.cssRules = Collections.unmodifiableMap(parseContext.cssRules);
        this.directives = Collections.unmodifiableMap(parseContext.directives);
        this.globalAttributes = Collections.unmodifiableMap(parseContext.globalAttributes);
        this.encodeTags = Collections.unmodifiableSet(parseContext.encodeTags);
        this.tagNames = Collections.unmodifiableList( parseContext.tagNames);
    }

    private Policy(Policy old, Map<String, String> directives, Map<String, Tag> tagRules)  {
        this.allowedEmptyTagsMatcher = old.allowedEmptyTagsMatcher;
        this.requiresClosingTagsMatcher = old.requiresClosingTagsMatcher;
        this.commonRegularExpressions = old.commonRegularExpressions;
        this.tagRules = tagRules;
        this.cssRules = old.cssRules;
        this.directives = directives;
        this.globalAttributes = old.globalAttributes;
        this.encodeTags = old.encodeTags;
        this.tagNames = old.tagNames;
    }

    private static ParseContext getSimpleParseContext(Element topLevelElement) throws PolicyException {
        ParseContext parseContext = new ParseContext();
        /**
         * Parse the top level element itself
         */
        parsePolicy(topLevelElement, parseContext);
        return parseContext;
    }

    private static ParseContext getParseContext(Element topLevelElement) throws PolicyException {
        ParseContext parseContext = new ParseContext();

        /**
         * Are there any included policies? These are parsed here first so that
         * rules in _this_ policy file will override included rules.
         *
         * NOTE that by this being here we only support one level of includes.
         * To support recursion, move this into the parsePolicy method.
         */
        NodeList includes = topLevelElement.getElementsByTagName("include");
        for (int i = 0; i < includes.getLength(); i++) {
            Element include = (Element) includes.item(i);

            String href = XMLUtil.getAttributeValue(include, "href");

            Element includedPolicy = getPolicy(href);
            parsePolicy(includedPolicy, parseContext);
        }

        parsePolicy(topLevelElement, parseContext);
        return parseContext;
    }

    private static Element getTopLevelElement(InputStream is) throws PolicyException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom = db.parse(is);
            return dom.getDocumentElement();
        } catch (SAXException e) {
            throw new PolicyException(e);
        } catch (ParserConfigurationException e) {
            throw new PolicyException(e);
        } catch (IOException e) {
            throw new PolicyException(e);
        }
    }

    private static Element getTopLevelElement(URL url) throws PolicyException {


        try {

            InputSource source = resolveEntity(url.toExternalForm());
            if (source == null) {
                source = new InputSource(url.toExternalForm());
                source.setByteStream(url.openStream());
            } else {
                source.setSystemId(url.toExternalForm());
            }

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom = db.parse(source);
            return dom.getDocumentElement();
        } catch (SAXException e) {
            throw new PolicyException(e);
        } catch (ParserConfigurationException e) {
            throw new PolicyException(e);
        } catch (IOException e) {
            throw new PolicyException(e);
        }
    }


    private static void parsePolicy(Element topLevelElement, ParseContext parseContext)
            throws PolicyException {

        if (topLevelElement == null) return;

        parseContext.resetParamsWhereLastConfigWins();

        parseCommonRegExps(getFirstChild(topLevelElement, "common-regexps"), parseContext.commonRegularExpressions);
        parseDirectives(getFirstChild(topLevelElement, "directives"), parseContext.directives);
        parseCommonAttributes(getFirstChild(topLevelElement, "common-attributes"), parseContext.commonAttributes, parseContext.commonRegularExpressions);
        parseGlobalAttributes(getFirstChild(topLevelElement, "global-tag-attributes"), parseContext.globalAttributes, parseContext.commonAttributes);
        parseTagsToEncode(getFirstChild(topLevelElement, "tags-to-encode"), parseContext.encodeTags);
        parseTagRules(getFirstChild(topLevelElement, "tag-rules"), parseContext.tagNames, parseContext.commonAttributes, parseContext.commonRegularExpressions, parseContext.tagRules);
        parseCSSRules(getFirstChild(topLevelElement, "css-rules"), parseContext.cssRules, parseContext.commonRegularExpressions);

        parseAllowedEmptyTags(getFirstChild(topLevelElement, "allowed-empty-tags"), parseContext.allowedEmptyTags);
        parseRequiresClosingTags(getFirstChild(topLevelElement, "require-closing-tags"), parseContext.requireClosingTags);
    }

    private static Element getFirstChild(Element element, String tagName) {
        if (element == null) return null;
        NodeList elementsByTagName = element.getElementsByTagName(tagName);
        if (elementsByTagName != null && elementsByTagName.getLength() > 0)
            return (Element) elementsByTagName.item(0);
        else
            return null;
    }

    /**
     * Returns the top level element of a loaded policy Document
     */
    private static Element getPolicy(String href)
            throws PolicyException {

        try {
            InputSource source = null;

            // Can't resolve public id, but might be able to resolve relative
            // system id, since we have a base URI.
            if (href != null && baseUrl != null) {
                URL url;

                try {
                    url = new URL(baseUrl, href);
                    source = new InputSource(url.openStream());
                    source.setSystemId(href);

                } catch (MalformedURLException except) {
                    try {
                        String absURL = URIUtils.resolveAsString(href, baseUrl.toString());
                        url = new URL(absURL);
                        source = new InputSource(url.openStream());
                        source.setSystemId(href);

                    } catch (MalformedURLException ex2) {
                        // nothing to do
                    }

                } catch (java.io.FileNotFoundException fnfe) {
                    try {
                        String absURL = URIUtils.resolveAsString(href, baseUrl.toString());
                        url = new URL(absURL);
                        source = new InputSource(url.openStream());
                        source.setSystemId(href);

                    } catch (MalformedURLException ex2) {
                        // nothing to do
                    }
                }
            }

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom;

            /**
             * Load and parse the file.
             */
            if (source != null) {
                dom = db.parse(source);


                /**
                 * Get the policy information out of it!
                 */

                return dom.getDocumentElement();
            }

            return null;
        } catch (SAXException e) {
            throw new PolicyException(e);
        } catch (ParserConfigurationException e) {
            throw new PolicyException(e);
        } catch (IOException e) {
            throw new PolicyException(e);
        }
    }


    /**
     * Go through <directives> section of the policy file.
     *
     * @param root       Top level of <directives>
     * @param directives The directives map to update
     */
    private static void parseDirectives(Element root, Map<String, String> directives) {

        if (root == null) return;

        NodeList directiveNodes = root.getElementsByTagName("directive");

        for (int i = 0; i < directiveNodes.getLength(); i++) {

            Element ele = (Element) directiveNodes.item(i);

            String name = XMLUtil.getAttributeValue(ele, "name");
            String value = XMLUtil.getAttributeValue(ele, "value");

            directives.put(name, value);

        }
    }


    /**
     * Go through <allowed-empty-tags> section of the policy file.
     *
     * @param allowedEmptyTagsListNode Top level of <allowed-empty-tags>
     * @param allowedEmptyTags The tags that can be empty
     */
    private static void parseAllowedEmptyTags(Element allowedEmptyTagsListNode, List<String> allowedEmptyTags) throws PolicyException {

        if (allowedEmptyTagsListNode != null) {
            Element literalListNode = (Element) allowedEmptyTagsListNode.getElementsByTagName("literal-list").item(0);

            if (literalListNode != null) {

                NodeList literalList = literalListNode.getElementsByTagName("literal");

                for (int j = 0; j < literalList.getLength(); j++) {
                    Element literalNode = (Element) literalList.item(j);

                    String value = XMLUtil.getAttributeValue(literalNode, "value");

                    if (value != null && value.length() > 0) {
                        allowedEmptyTags.add(value);
                    }
                }

            }
        } else {

            allowedEmptyTags.addAll(Constants.defaultAllowedEmptyTags);
        }
    }

    /**
     * Go through <require-closing-tags> section of the policy file.
     *
     * @param requiresClosingTagsListNode Top level of <require-closing-tags>
     * @param requiresClosingTags The list of tags that require closing
     */
    private static void parseRequiresClosingTags(Element requiresClosingTagsListNode, List<String> requiresClosingTags) throws PolicyException {

        if (requiresClosingTagsListNode != null) {
            Element literalListNode = (Element) requiresClosingTagsListNode.getElementsByTagName("literal-list").item(0);

            if (literalListNode != null) {

                NodeList literalList = literalListNode.getElementsByTagName("literal");

                for (int j = 0; j < literalList.getLength(); j++) {
                    Element literalNode = (Element) literalList.item(j);

                    String value = XMLUtil.getAttributeValue(literalNode, "value");

                    if (value != null && value.length() > 0) {
                        requiresClosingTags.add(value);
                    }
                }

            }
        } else {
            requiresClosingTags.addAll(Constants.defaultRequiresClosingTags);
        }
    }

    /**
     * Go through <tags-to-encode> section of the policy file.
     *
     * @param root        Top level of <tags-to-encode>
     * @param encodeTags1 The set of tags to be encoded when encountered
     * @throws PolicyException
     */
    private static void parseTagsToEncode(Element root, Set<String> encodeTags1) throws PolicyException {

        if (root == null) return;

        NodeList tagsToEncodeNodes = root.getElementsByTagName("tag");

        if (tagsToEncodeNodes != null) {

            for (int i = 0; i < tagsToEncodeNodes.getLength(); i++) {

                Element ele = (Element) tagsToEncodeNodes.item(i);
                if (ele.getFirstChild() != null && ele.getFirstChild().getNodeType() == Node.TEXT_NODE) {
                    encodeTags1.add(ele.getFirstChild().getNodeValue());
                }

            }
        }
    }

    /**
     * Go through <global-tag-attributes> section of the policy file.
     *
     * @param root              Top level of <global-tag-attributes>
     * @param globalAttributes1 A HashMap of global Attributes that need validation for every tag.
     * @param commonAttributes The common attributes
     * @throws PolicyException
     */
    private static void parseGlobalAttributes(Element root, Map<String, Attribute> globalAttributes1, Map<String, Attribute> commonAttributes) throws PolicyException {

        if (root == null) return;

        NodeList globalAttributeNodes = root.getElementsByTagName("attribute");

        /*
           * Loop through the list of regular expressions and add them to the collection.
           */
        for (int i = 0; i < globalAttributeNodes.getLength(); i++) {
            Element ele = (Element) globalAttributeNodes.item(i);

            String name = XMLUtil.getAttributeValue(ele, "name");

            Attribute toAdd = commonAttributes.get(name.toLowerCase());

            if (toAdd != null) {
                globalAttributes1.put(name.toLowerCase(), toAdd);
            } else {
                throw new PolicyException("Global attribute '" + name + "' was not defined in <common-attributes>");
            }
        }
    }

    /**
     * Go through the <common-regexps> section of the policy file.
     *
     * @param root                      Top level of <common-regexps>
     * @param commonRegularExpressions1 the antisamy pattern objects
     */
    private static void parseCommonRegExps(Element root, Map<String, AntiSamyPattern> commonRegularExpressions1) {

        if (root == null) return;

        NodeList commonRegExpPatternNodes = root.getElementsByTagName("regexp");

        /*
           * Loop through the list of regular expressions and add them to the collection.
           */
        for (int i = 0; i < commonRegExpPatternNodes.getLength(); i++) {
            Element ele = (Element) commonRegExpPatternNodes.item(i);

            String name = XMLUtil.getAttributeValue(ele, "name");
            Pattern pattern = Pattern.compile(XMLUtil.getAttributeValue(ele, "value"));

            commonRegularExpressions1.put(name, new AntiSamyPattern(name, pattern));

        }
    }


    private static void parseCommonAttributes(Element root, Map<String, Attribute> commonAttributes1, Map<String, AntiSamyPattern> commonRegularExpressions1) {

        if (root == null) return;

        NodeList commonAttributesNodes = root.getElementsByTagName("attribute");

        /*
           * Loop through the list of attributes and add them to the collection.
           */
        for (int i = 0; i < commonAttributesNodes.getLength(); i++) {

            Element ele = (Element) commonAttributesNodes.item(i);

            String onInvalid = XMLUtil.getAttributeValue(ele, "onInvalid");
            String name = XMLUtil.getAttributeValue(ele, "name");

            Attribute attribute = new Attribute(XMLUtil.getAttributeValue(ele, "name"));
            attribute.setDescription(XMLUtil.getAttributeValue(ele, "description"));

            if (onInvalid != null && onInvalid.length() > 0) {
                attribute.setOnInvalid(onInvalid);
            } else {
                attribute.setOnInvalid(DEFAULT_ONINVALID);
            }

            Element regExpListNode = (Element) ele.getElementsByTagName("regexp-list").item(0);


            if (regExpListNode != null) {
                NodeList regExpList = regExpListNode.getElementsByTagName("regexp");

                /*
                     * First go through the allowed regular expressions.
                     */
                for (int j = 0; j < regExpList.getLength(); j++) {
                    Element regExpNode = (Element) regExpList.item(j);

                    String regExpName = XMLUtil.getAttributeValue(regExpNode, "name");
                    String value = XMLUtil.getAttributeValue(regExpNode, "value");

                    if (regExpName != null && regExpName.length() > 0) {
                        /*
                               * Get the common regular expression.
                               */
                        attribute.addAllowedRegExp(commonRegularExpressions1.get(regExpName).getPattern());
                    } else {
                        attribute.addAllowedRegExp(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));
                    }
                }
            }

            Element literalListNode = (Element) ele.getElementsByTagName("literal-list").item(0);

            if (literalListNode != null) {

                NodeList literalList = literalListNode.getElementsByTagName("literal");
                /*
                     * Then go through the allowed constants.
                     */
                for (int j = 0; j < literalList.getLength(); j++) {
                    Element literalNode = (Element) literalList.item(j);

                    String value = XMLUtil.getAttributeValue(literalNode, "value");

                    if (value != null && value.length() > 0) {
                        attribute.addAllowedValue(value);
                    } else if (literalNode.getNodeValue() != null) {
                        attribute.addAllowedValue(literalNode.getNodeValue());
                    }

                }

            }

            commonAttributes1.put(name.toLowerCase(), attribute);

        }
    }


    private static void parseTagRules(Element root, List<String> tagNames1, Map<String, Attribute> commonAttributes1, Map<String, AntiSamyPattern> commonRegularExpressions1, Map<String, Tag> tagRules1) throws PolicyException {

        if (root == null) return;

        NodeList tagList = root.getElementsByTagName("tag");

        for (int i = 0; i < tagList.getLength(); i++) {

            Element tagNode = (Element) tagList.item(i);

            String name = XMLUtil.getAttributeValue(tagNode, "name");
            String action = XMLUtil.getAttributeValue(tagNode, "action");

            Tag tag = new Tag(name);

            tagNames1.add(name);

            tag.setAction(action);

            NodeList attributeList = tagNode.getElementsByTagName("attribute");

            /*
                * Add its attribute rules.
                */
            for (int j = 0; j < attributeList.getLength(); j++) {

                Element attributeNode = (Element) attributeList.item(j);

                if (!attributeNode.hasChildNodes()) {

                    Attribute attribute = commonAttributes1.get(XMLUtil.getAttributeValue(attributeNode, "name").toLowerCase());

                    /*
                          * All they provided was the name, so they must want a common
                          * attribute.
                          */
                    if (attribute != null) {

                        /*
                               * If they provide onInvalid/description values here they will
                               * override the common values.
                               */

                        String onInvalid = XMLUtil.getAttributeValue(attributeNode, "onInvalid");
                        String description = XMLUtil.getAttributeValue(attributeNode, "description");

                        if (onInvalid != null && onInvalid.length() != 0) {
                            attribute.setOnInvalid(onInvalid);
                        }
                        if (description != null && description.length() != 0) {
                            attribute.setDescription(description);
                        }

                        tag.addAttribute((Attribute) attribute.clone());

                    } else {

                        throw new PolicyException("Attribute '" + XMLUtil.getAttributeValue(attributeNode, "name") + "' was referenced as a common attribute in definition of '" + tag.getName() + "', but does not exist in <common-attributes>");

                    }

                } else {
                    /*
                          * Custom attribute for this tag.
                          */
                    Attribute attribute = new Attribute(XMLUtil.getAttributeValue(attributeNode, "name"));
                    attribute.setOnInvalid(XMLUtil.getAttributeValue(attributeNode, "onInvalid"));
                    attribute.setDescription(XMLUtil.getAttributeValue(attributeNode, "description"));

                    /*
                          * Get the list of regexps for the attribute.
                          */
                    Element regExpListNode = (Element) attributeNode.getElementsByTagName("regexp-list").item(0);

                    if (regExpListNode != null) {
                        NodeList regExpList = regExpListNode.getElementsByTagName("regexp");

                        for (int k = 0; k < regExpList.getLength(); k++) {

                            Element regExpNode = (Element) regExpList.item(k);

                            String regExpName = XMLUtil.getAttributeValue(regExpNode, "name");
                            String value = XMLUtil.getAttributeValue(regExpNode, "value");

                            /*
                                    * Look up common regular expression specified
                                    * by the "name" field. They can put a common
                                    * name in the "name" field or provide a custom
                                    * value in the "value" field. They must choose
                                    * one or the other, not both.
                                    */
                            if (regExpName != null && regExpName.length() > 0) {

                                AntiSamyPattern pattern = commonRegularExpressions1.get(regExpName);

                                if (pattern != null) {

                                    attribute.addAllowedRegExp(pattern.getPattern());
                                } else {

                                    throw new PolicyException("Regular expression '" + regExpName + "' was referenced as a common regexp in definition of '" + tag.getName() + "', but does not exist in <common-regexp>");
                                }

                            } else if (value != null && value.length() > 0) {
                                attribute.addAllowedRegExp(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));
                            }
                        }
                    }

                    /*
                          * Get the list of constant values for the attribute.
                          */
                    Element literalListNode = (Element) attributeNode.getElementsByTagName("literal-list").item(0);

                    if (literalListNode != null) {
                        NodeList literalList = literalListNode.getElementsByTagName("literal");

                        for (int k = 0; k < literalList.getLength(); k++) {
                            Element literalNode = (Element) literalList.item(k);
                            String value = XMLUtil.getAttributeValue(literalNode, "value");

                            /*
                                    * Any constant value will do.
                                    */

                            if (value != null && value.length() > 0) {
                                attribute.addAllowedValue(value);
                            } else if (literalNode.getNodeValue() != null) {
                                attribute.addAllowedValue(literalNode.getNodeValue());
                            }

                        }
                    }
                    /*
                          * Add fully built attribute.
                          */
                    tag.addAttribute(attribute);
                }

            }

            tagRules1.put(name.toLowerCase(), tag);
        }
    }

    private static void parseCSSRules(Element root, Map<String, Property> cssRules1, Map<String, AntiSamyPattern> commonRegularExpressions1) throws PolicyException {

        if (root == null) return;

        NodeList propertyNodes = root.getElementsByTagName("property");

        /*
           * Loop through the list of attributes and add them to the collection.
           */
        for (int i = 0; i < propertyNodes.getLength(); i++) {
            Element ele = (Element) propertyNodes.item(i);

            String name = XMLUtil.getAttributeValue(ele, "name");
            String description = XMLUtil.getAttributeValue(ele, "description");

            Property property = new Property(name);
            property.setDescription(description);

            String onInvalid = XMLUtil.getAttributeValue(ele, "onInvalid");

            if (onInvalid != null && onInvalid.length() > 0) {
                property.setOnInvalid(onInvalid);
            } else {
                property.setOnInvalid(DEFAULT_ONINVALID);
            }

            Element regExpListNode = (Element) ele.getElementsByTagName("regexp-list").item(0);


            if (regExpListNode != null) {
                NodeList regExpList = regExpListNode.getElementsByTagName("regexp");

                /*
                     * First go through the allowed regular expressions.
                     */
                for (int j = 0; j < regExpList.getLength(); j++) {
                    Element regExpNode = (Element) regExpList.item(j);

                    String regExpName = XMLUtil.getAttributeValue(regExpNode, "name");
                    String value = XMLUtil.getAttributeValue(regExpNode, "value");

                    AntiSamyPattern pattern = commonRegularExpressions1.get(regExpName);

                    if (pattern != null) {

                        property.addAllowedRegExp(pattern.getPattern());
                    } else if (value != null) {
                        property.addAllowedRegExp(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));

                    } else {

                        throw new PolicyException("Regular expression '" + regExpName + "' was referenced as a common regexp in definition of '" + property.getName() + "', but does not exist in <common-regexp>");
                    }

                }
            }

            Element literalListNode = (Element) ele.getElementsByTagName("literal-list").item(0);

            if (literalListNode != null) {

                NodeList literalList = literalListNode.getElementsByTagName("literal");
                /*
                     * Then go through the allowed constants.
                     */
                for (int j = 0; j < literalList.getLength(); j++) {
                    Element literalNode = (Element) literalList.item(j);
                    property.addAllowedValue(XMLUtil.getAttributeValue(literalNode, "value"));
                }

            }

            Element shorthandListNode = (Element) ele.getElementsByTagName("shorthand-list").item(0);
            if (shorthandListNode != null) {

                NodeList shorthandList = shorthandListNode.getElementsByTagName("shorthand");
                /*
                     * Then go through the allowed constants.
                     */
                for (int j = 0; j < shorthandList.getLength(); j++) {
                    Element shorthandNode = (Element) shorthandList.item(j);
                    property.addShorthandRef(XMLUtil.getAttributeValue(shorthandNode, "name"));
                }

            }

            cssRules1.put(name.toLowerCase(), property);

        }
    }


    /**
     * A simple method for returning on of the <global-attribute> entries by
     * name.
     *
     * @param name The name of the global-attribute we want to look up.
     * @return An Attribute associated with the global-attribute lookup name specified.
     */
    public Attribute getGlobalAttributeByName(String name) {

        return globalAttributes.get(name.toLowerCase());

    }

    /**
     * Return all the allowed empty tags configured in the Policy.
     *
     * @return A String array of all the he allowed empty tags configured in the Policy.
     */
    public TagMatcher getAllowedEmptyTags() {
        return allowedEmptyTagsMatcher;
    }

    /**
     * Return all the tags that are required to be closed with an end tag, even if they have no child content.
     *
     * @return A String array of all the tags that are required to be closed with an end tag, even if they have no child content.
     */
    public TagMatcher getRequiresClosingTags() {
        return requiresClosingTagsMatcher;
    }

    /**
     * Return a directive value based on a lookup name.
     *
     * @return A String object containing the directive associated with the lookup name, or null if none is found.
     */
    public String getDirective(String name) {
        return directives.get(name);
    }

    /**
     * Set a directive for a value based on a name.
     *
     * @param name  A directive to set a value for.
     * @param value The new value for the directive.
     */
    public Policy changeDirective(String name, String value) {
        Map<String, String> directives = new HashMap<String, String>(this.directives);
        directives.put(name, value);
        return new Policy(this, Collections.unmodifiableMap(directives), tagRules);
    }

    public Policy addTagRule(Tag tag) {
        Map<String, Tag> newTagRules = new HashMap<String, Tag>(tagRules);
        newTagRules.put(tag.getName().toLowerCase(), tag);
        return  new Policy(this, this.directives, newTagRules);

    }


    /**
     * Returns the maximum input size. If this value is not specified by
     * the policy, the <code>DEFAULT_MAX_INPUT_SIZE</code> is used.
     *
     * @return the maximium input size.
     */
    public int getMaxInputSize() {
        int maxInputSize = Policy.DEFAULT_MAX_INPUT_SIZE;

        try {
            maxInputSize = Integer.parseInt(getDirective("maxInputSize"));
        } catch (NumberFormatException ignore) {
        }

        return maxInputSize;
    }

    /**
     * Set the base directory to use to resolve relative file paths when including other policy files.
     *
     * @param newValue The new base url
     */
    public static void setBaseURL(URL newValue) {
        baseUrl = newValue;
    }

    /**
     * Resolves public & system ids to files stored within the JAR.
     */
    public static InputSource resolveEntity(final String systemId) throws IOException, SAXException {
        InputSource source;

        // Can't resolve public id, but might be able to resolve relative
        // system id, since we have a base URI.
        if (systemId != null && baseUrl != null) {
            URL url;

            try {
                url = new URL(baseUrl, systemId);
                source = new InputSource(url.openStream());
                source.setSystemId(systemId);
                return source;
            } catch (MalformedURLException except) {
                try {
                    String absURL = URIUtils.resolveAsString(systemId, baseUrl.toString());
                    url = new URL(absURL);
                    source = new InputSource(url.openStream());
                    source.setSystemId(systemId);
                    return source;
                } catch (MalformedURLException ex2) {
                    // nothing to do
                }
            } catch (java.io.FileNotFoundException fnfe) {
                try {
                    String absURL = URIUtils.resolveAsString(systemId, baseUrl.toString());
                    url = new URL(absURL);
                    source = new InputSource(url.openStream());
                    source.setSystemId(systemId);
                    return source;
                } catch (MalformedURLException ex2) {
                    // nothing to do
                }
            }
            return null;
        }

        // No resolving.
        return null;
    }

}
