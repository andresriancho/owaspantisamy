/*
* Copyright (c) 2009, Jerry Hoff
* 
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions are met:
* - Redistributions of source code must retain the above copyright notice, 
* 	 this list of conditions and the following disclaimer.
* - Redistributions in binary form must reproduce the above copyright notice,
*   this list of conditions and the following disclaimer in the documentation
*   and/or other materials provided with the distribution.
* - Neither the name of OWASP nor the names of its contributors may be used to
*   endorse or promote products derived from this software without specific
*   prior written permission.
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

using System;

//using Pattern = java.util.regex.Pattern;

using CleanResults = org.owasp.validator.html.CleanResults;
using Policy = org.owasp.validator.html.Policy;
using AntiSamyPattern = org.owasp.validator.html.model.AntiSamyPattern;
using Property = org.owasp.validator.html.model.Property;
using HTMLEntityEncoder = org.owasp.validator.html.util.HTMLEntityEncoder;
using AttributeCondition = org.w3c.css.sac.AttributeCondition;
using CombinatorCondition = org.w3c.css.sac.CombinatorCondition;
using Condition = org.w3c.css.sac.Condition;
using ConditionalSelector = org.w3c.css.sac.ConditionalSelector;
using DescendantSelector = org.w3c.css.sac.DescendantSelector;
using LexicalUnit = org.w3c.css.sac.LexicalUnit;
using NegativeCondition = org.w3c.css.sac.NegativeCondition;
using NegativeSelector = org.w3c.css.sac.NegativeSelector;
using Selector = org.w3c.css.sac.Selector;
using SiblingSelector = org.w3c.css.sac.SiblingSelector;
using SimpleSelector = org.w3c.css.sac.SimpleSelector;
using ElementSelector = org.w3c.css.sac.ElementSelector;
using System.Collections;
using System.Text.RegularExpressions;

namespace org.owasp.validator.css
{

    /// <summary> Encapsulates all the neceesary operations for validating individual eleements
    /// of a stylesheet (namely: selectors, conditions and properties).
    /// 
    /// </summary>

    public class CssValidator
    {

        /// <summary> The policy file to use for validation</summary>
        private Policy policy;

        /// <summary> Constructs a validator for CSS selectors, conditions and properties based
        /// on the given policy.
        /// 
        /// </summary>
        /// <param name="policy">the policy file to use in this validator
        /// </param>
        public CssValidator(Policy policy)
        {
            this.policy = policy;
        }

        /// <summary> Determines whether the given property (both name and value) are valid
        /// according to this validator's policy.
        /// 
        /// </summary>
        /// <param name="name">the name of the property
        /// </param>
        /// <param name="lu">the value of the property
        /// </param>
        /// <returns> true if this property name/value is valid; false otherwise
        /// </returns>
        public virtual bool isValidProperty(string name, LexicalUnit lu)
        {
            bool isValid = false;
            Property property = null;

            if (name != null)
            {
                property = policy.getPropertyByName(name.ToLower());
            }

            // if we were able to find the property by name, validate the value
            if (property != null)
            {

                // validate all values attached to this property
                isValid = true;
                while (lu != null)
                {
                    System.String value_Renamed = lexicalValueToString(lu);

                    if (value_Renamed == null || !validateValue(property, value_Renamed))
                    {
                        isValid = false;
                        break;
                    }

                    lu = lu.getNextLexicalUnit();
                }
            }

            return isValid;
        }

        /// <summary> Determines whether the given selector name is valid according to this
        /// validator's policy.
        /// 
        /// </summary>
        /// <param name="selectorName">the name of the selector
        /// </param>
        /// <param name="selector">the object representation of the selector
        /// </param>
        /// <param name="results">the <code>CleanResults</code> object to add any error
        /// messages to
        /// </param>
        /// <returns> true if this selector name is valid; false otherwise
        /// </returns>
        public virtual bool isValidSelector(System.String selectorName, Selector selector, CleanResults results)
        {
            
            // determine correct behavior
            switch (selector.getSelectorType())
            {
                
                case CssValidator.SAC_ANY_NODE_SELECTOR:
                case CssValidator.SAC_ELEMENT_NODE_SELECTOR:
                case CssValidator.SAC_PSEUDO_ELEMENT_SELECTOR:
                case CssValidator.SAC_ROOT_NODE_SELECTOR:
                    // these selectors are the most base selectors
                    return validateSimpleSelector((SimpleSelector)selector, results);
                   
                case CssValidator.SAC_CHILD_SELECTOR:
                case CssValidator.SAC_DESCENDANT_SELECTOR:
                    // these are compound selectors - decompose into simple selectors
                    DescendantSelector descSelector = (DescendantSelector)selector;
                    return isValidSelector(selectorName, descSelector.getSimpleSelector(), results) & isValidSelector(selectorName, descSelector.getAncestorSelector(), results);

                case CssValidator.SAC_CONDITIONAL_SELECTOR:
                    // this is a compound selector - decompose into simple selectors
                    ConditionalSelector condSelector = (ConditionalSelector)selector;
                    return isValidSelector(selectorName, condSelector.getSimpleSelector(), results) & isValidCondition(selectorName, condSelector.getCondition(), results);

                case CssValidator.SAC_DIRECT_ADJACENT_SELECTOR:
                    // this is a compound selector - decompose into simple selectors
                    SiblingSelector sibSelector = (SiblingSelector)selector;
                    return isValidSelector(selectorName, sibSelector.getSiblingSelector(), results) & isValidSelector(selectorName, sibSelector.getSelector(), results);

                case CssValidator.SAC_NEGATIVE_SELECTOR:
                    // this is a compound selector with one simple selector
                    return validateSimpleSelector((NegativeSelector)selector, results);

                case CssValidator.SAC_CDATA_SECTION_NODE_SELECTOR:
                case CssValidator.SAC_COMMENT_NODE_SELECTOR:
                case CssValidator.SAC_PROCESSING_INSTRUCTION_NODE_SELECTOR:
                case CssValidator.SAC_TEXT_NODE_SELECTOR:
                default:
                    results.addErrorMessage("Unknown selector in selector " + HTMLEntityEncoder.htmlEntityEncode(selectorName) + " encountered");
                    return false;
            }
        }

        /// <summary> Validates a basic selector against the policy
        /// 
        /// </summary>
        /// <param name="selector">the object representation of the selector
        /// </param>
        /// <param name="results">the <code>CleanResults</code> object to add any error
        /// messages to
        /// </param>
        /// <returns> true if this selector name is valid; false otherwise
        /// </returns>
        private bool validateSimpleSelector(SimpleSelector selector, CleanResults results)
        {
            // ensure the name follows the valid pattern and is not blacklisted
            // by the exclusion pattern.
            // NOTE: intentionally using non-short-circuited AND operator to
            // generate all relevant error messages
            //return policy.getRegularExpression("cssElementSelector").Pattern.matcher(selector.toString().toLowerCase()).matches() & !policy.getRegularExpression("cssElementExclusion").Pattern.matcher(selector.toString().toLowerCase()).matches();

            string name = ((ElementSelector)selector).getLocalName().ToLower();

            string css = (policy.getRegularExpression("cssElementSelector") != null ? policy.getRegularExpression("cssElementSelector") : "");
            string exc = (policy.getRegularExpression("cssElementExclusion") != null ? policy.getRegularExpression("cssElementExclusion") : "");

            css = "^" + css + "$";
            exc = "^" + exc + "$";

            Match m1 = Regex.Match(name, css);
            Match m2 = Regex.Match(name, exc);

            return m1.Success & !m2.Success;

        }

        /// <summary> Determines whether the given condition is valid according to this
        /// validator's policy.
        /// 
        /// </summary>
        /// <param name="selectorName">the name of the selector that contains this condition
        /// </param>
        /// <param name="condition">the object representation of this condition
        /// </param>
        /// <param name="results">the <code>CleanResults</code> object to add any error
        /// messages to
        /// </param>
        /// <returns> true if this condition is valid; false otherwise
        /// </returns>
        public virtual bool isValidCondition(string selectorName, Condition condition, CleanResults results)
        {
            switch (condition.getConditionType())
            {

                //case CssValidator.SAC_AND_CONDITION:
                case CssValidator.SAC_OR_CONDITION:
                    // these are compound condition - decompose into simple conditions
                    CombinatorCondition comboCondition = (CombinatorCondition)condition;
                    return isValidCondition(selectorName, comboCondition.getFirstCondition(), results) & isValidCondition(selectorName, comboCondition.getSecondCondition(), results);

                case CssValidator.SAC_CLASS_CONDITION:
                    // this is a basic class condition; compare condition against
                    // valid pattern and is not blacklisted by exclusion pattern
                    return validateCondition((AttributeCondition)condition, policy.getRegularExpression("cssClassSelector"), policy.getRegularExpression("cssClassExclusion"), results);

                case CssValidator.SAC_ID_CONDITION:
                    // this is a basic ID condition; compare condition against
                    // valid pattern and is not blacklisted by exclusion pattern
                    return validateCondition((AttributeCondition)condition, policy.getRegularExpression("cssIDSelector"), policy.getRegularExpression("cssIDExclusion"), results);

                case CssValidator.SAC_PSEUDO_CLASS_CONDITION:
                    // this is a basic psuedo element condition; compare condition
                    // against valid pattern and is not blacklisted by exclusion pattern
                    return validateCondition((AttributeCondition)condition, policy.getRegularExpression("cssPseudoElementSelector"), policy.getRegularExpression("cssPsuedoElementExclusion"), results);

                case CssValidator.SAC_BEGIN_HYPHEN_ATTRIBUTE_CONDITION:
                case CssValidator.SAC_ONE_OF_ATTRIBUTE_CONDITION:
                case CssValidator.SAC_ATTRIBUTE_CONDITION:
                    // this is a basic class condition; compare condition against
                    // valid pattern and is not blacklisted by exclusion pattern
                    return validateCondition((AttributeCondition)condition, policy.getRegularExpression("cssAttributeSelector"), policy.getRegularExpression("cssAttributeExclusion"), results);

                case CssValidator.SAC_NEGATIVE_CONDITION:
                    // this is a compound condition; decompose to simple condition
                    return isValidCondition(selectorName, ((NegativeCondition)condition).getCondition(), results);

                case CssValidator.SAC_ONLY_CHILD_CONDITION:
                case CssValidator.SAC_ONLY_TYPE_CONDITION:
                    // :only-child and :only-of-type are constants
                    return true;

                case CssValidator.SAC_POSITIONAL_CONDITION:
                case CssValidator.SAC_CONTENT_CONDITION:
                case CssValidator.SAC_LANG_CONDITION:
                default:
                    results.addErrorMessage("Unknown condition for selector " + HTMLEntityEncoder.htmlEntityEncode(selectorName) + " encountered");
                    return false;
            }
        }

        /// <summary> Validates a basic condition against the white list pattern and the
        /// blacklist pattern
        /// 
        /// </summary>
        /// <param name="condition">the object representation of the condition
        /// </param>
        /// <param name="pattern">the positive pattern of valid conditions
        /// </param>
        /// <param name="exclusionPattern">the negative pattern of excluded conditions
        /// </param>
        /// <param name="results">the <code>CleanResults</code> object to add any error
        /// messages to
        /// </param>
        /// <returns> true if this selector name is valid; false otherwise
        /// </returns>
        private bool validateCondition(AttributeCondition condition, string pattern, string exclusionPattern, CleanResults results)
        {
            // check that the name of the condition matches valid pattern and does
            // not match exclusion pattern
            // NOTE: intentionally using non-short-circuited AND operator to
            // generate all relevant error messages
            //return pattern.Pattern.matcher(condition.toString().toLowerCase()).matches() & !exclusionPattern.Pattern.matcher(condition.toString().toLowerCase()).matches();
            return true;
        }

        /// <summary> Determines whether the given property value is valid according to this
        /// validator's policy.
        /// 
        /// </summary>
        /// <param name="property">the object representation of the property and its associated
        /// policy
        /// </param>
        /// <param name="value">the string representation of the value
        /// </param>
        /// <returns> true if the property is valid; false otherwise
        /// </returns>
        private bool validateValue(Property property, System.String value_Renamed)
        {
            bool isValid = false;

            // normalize the value to lowercase
            value_Renamed = value_Renamed.ToLower();

            // check if the value matches any of the allowed literal values
            System.Collections.IEnumerator allowedValues = property.AllowedValues.GetEnumerator();
            //UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
            while (allowedValues.MoveNext() && !isValid)
            {
                //UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
                System.String allowedValue = (System.String)allowedValues.Current;

                if (allowedValue != null && allowedValue.Equals(value_Renamed))
                {
                    isValid = true;
                }
            }

            // check if the value matches any of the allowed regular expressions
            System.Collections.IEnumerator allowedRegexps = property.AllowedRegExp.GetEnumerator();
            //UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
            while (allowedRegexps.MoveNext() && !isValid)
            {
                //UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
                //Pattern pattern = (Pattern)allowedRegexps.Current;

                //if (pattern != null && pattern.matcher(value_Renamed).matches())
                //{
                //    isValid = true;
                //}
            }

            // check if the value matches any of the allowed shorthands
            IEnumerator shorthandRefs = property.ShorthandRefs.GetEnumerator();
            //UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
            while (shorthandRefs.MoveNext() && !isValid)
            {
                //UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
                string shorthandRef = (string)shorthandRefs.Current;
                Property shorthand = policy.getPropertyByName(shorthandRef);

                if (shorthand != null)
                {
                    isValid = validateValue(shorthand, value_Renamed);
                }
            }

            return isValid;
        }

        /// <summary> Converts the given lexical unit to a <code>String</code>
        /// representation. This method does not perform any validation - it is meant
        /// to be used in conjunction with the validator/logging methods.
        /// 
        /// </summary>
        /// <param name="lu">the lexical unit to convert
        /// </param>
        /// <returns> a <code>String</code> representation of the given lexical unit
        /// </returns>
        public virtual System.String lexicalValueToString(LexicalUnit lu)
        {
            switch (lu.getLexicalUnitType())
            {

                case CssValidator.SAC_PERCENTAGE:
                case CssValidator.SAC_DIMENSION:
                case CssValidator.SAC_EM:
                case CssValidator.SAC_EX:
                case CssValidator.SAC_PIXEL:
                case CssValidator.SAC_INCH:
                case CssValidator.SAC_CENTIMETER:
                case CssValidator.SAC_MILLIMETER:
                case CssValidator.SAC_POINT:
                case CssValidator.SAC_PICA:
                case CssValidator.SAC_DEGREE:
                case CssValidator.SAC_GRADIAN:
                case CssValidator.SAC_RADIAN:
                case CssValidator.SAC_MILLISECOND:
                case CssValidator.SAC_SECOND:
                case CssValidator.SAC_HERTZ:
                case CssValidator.SAC_KILOHERTZ:
                    // these are all measurements
                    return lu.getFloatValue() + lu.getDimensionUnitText();

                case CssValidator.SAC_INTEGER:
                    // just a number
                    return System.Convert.ToString(lu.getIntegerValue());

                case CssValidator.SAC_REAL:
                    // just a number
                    return System.Convert.ToString(lu.getFloatValue());

                case CssValidator.SAC_STRING_VALUE:
                case CssValidator.SAC_IDENT:
                    // just a string/identifier
                    return lu.getStringValue();

                case CssValidator.SAC_URI:
                    // this is a URL
                    return "url(" + lu.getStringValue() + ")";

                case CssValidator.SAC_RGBCOLOR:
                    // this is a rgb encoded color
                    System.Text.StringBuilder sb = new System.Text.StringBuilder("rgb(");
                    LexicalUnit param = lu.getParameters();
                    sb.Append(param.getIntegerValue()); // R value
                    sb.Append(',');
                    param = param.getNextLexicalUnit(); // comma
                    param = param.getNextLexicalUnit(); // G value
                    sb.Append(param.getIntegerValue());
                    sb.Append(',');
                    param = param.getNextLexicalUnit(); // comma
                    param = param.getNextLexicalUnit(); // B value
                    sb.Append(param.getIntegerValue());
                    sb.Append(')');

                    return sb.ToString();

                case CssValidator.SAC_INHERIT:
                    // constant
                    return "inherit";

                case CssValidator.SAC_ATTR:
                case CssValidator.SAC_COUNTER_FUNCTION:
                case CssValidator.SAC_COUNTERS_FUNCTION:
                case CssValidator.SAC_FUNCTION:
                case CssValidator.SAC_RECT_FUNCTION:
                case CssValidator.SAC_SUB_EXPRESSION:
                case CssValidator.SAC_UNICODERANGE:
                default:
                    // these are properties that shouldn't be necessary for most run
                    // of the mill HTML/CSS
                    return null;
            }
        }
            /**
     * This condition checks one of two conditions.
     * @see CombinatorCondition
     */    
    public const short SAC_OR_CONDITION		        = 1;

    /**
     * This condition checks that a condition can't be applied to a node.
     * @see NegativeCondition
     */    
    public const short SAC_NEGATIVE_CONDITION		= 2;

    /**
     * This condition checks a specified position.
     * example:
     * <pre class="example">
     *   :first-child
     * </pre>
     * @see PositionalCondition
     */    
    public const short SAC_POSITIONAL_CONDITION		= 3;

    /**
     * This condition checks an attribute.
     * example:
     * <pre class="example">
     *   [simple]
     *   [restart="never"]
     * </pre>
     * @see AttributeCondition
     */    
    public const short SAC_ATTRIBUTE_CONDITION		= 4;
    /**
     * This condition checks an id attribute.
     * example:
     * <pre class="example">
     *   #myId
     * </pre>
     * @see AttributeCondition
     */    
    public const short SAC_ID_CONDITION		        = 5;
    /**
     * This condition checks the language of the node.
     * example:
     * <pre class="example">
     *   :lang(fr)
     * </pre>
     * @see LangCondition
     */    
    public const short SAC_LANG_CONDITION		= 6;
    /**
     * This condition checks for a value in a space-separated values in a
     * specified attribute
     * example:
     * <pre class="example">
     *   [values~="10"]
     * </pre>
     * @see AttributeCondition
     */
    public const short SAC_ONE_OF_ATTRIBUTE_CONDITION	= 7;
    /**
     * This condition checks if the value is in a hypen-separated list of values
     * in a specified attribute.
     * example:
     * <pre class="example">
     *   [languages|="fr"]
     * </pre>
     * @see AttributeCondition
     */
    public const short SAC_BEGIN_HYPHEN_ATTRIBUTE_CONDITION = 8;
    /**
     * This condition checks for a specified class.
     * example:
     * <pre class="example">
     *   .example
     * </pre>
     * @see AttributeCondition
     */
    public const short SAC_CLASS_CONDITION		= 9;
    /**
     * This condition checks for the link pseudo class.
     * example:
     * <pre class="example">
     *   :link
     *   :visited
     *   :hover
     * </pre>
     * @see AttributeCondition
     */
    public const short SAC_PSEUDO_CLASS_CONDITION	= 10;
    /**
     * This condition checks if a node is the only one in the node list.
     */
    public const short SAC_ONLY_CHILD_CONDITION		= 11;
    /**
     * This condition checks if a node is the only one of his type.
     */
    public const short SAC_ONLY_TYPE_CONDITION		= 12;
    /**
     * This condition checks the content of a node.
     * @see ContentCondition
     */
    public const short SAC_CONTENT_CONDITION		= 13;

            /**
     * ,
     */
    public const short SAC_OPERATOR_COMMA	= 0;
    /**
     * +
     */
    public const short SAC_OPERATOR_PLUS		= 1;
    /**
     * -
     */
    public const short SAC_OPERATOR_MINUS	= 2;
    /**
     * *
     */
    public const short SAC_OPERATOR_MULTIPLY	= 3;
    /**
     * /
     */
    public const short SAC_OPERATOR_SLASH	= 4;
    /**
     * %
     */
    public const short SAC_OPERATOR_MOD		= 5;
    /**
     * ^
     */
    public const short SAC_OPERATOR_EXP		= 6;
    /**
     * <
     */
    public const short SAC_OPERATOR_LT		= 7;
    /**
     * >
     */
    public const short SAC_OPERATOR_GT		= 8;
    /**
     * <=
     */
    public const short SAC_OPERATOR_LE		= 9;
    /**
     * >=
     */
    public const short SAC_OPERATOR_GE		= 10;
    /**
     * ~
     */
    public const short SAC_OPERATOR_TILDE	= 11;
    
    /**
     * identifier <code>inherit</code>.
     */
    public const short SAC_INHERIT		= 12;
    /**
     * Integers.
     * @see #getIntegerValue
     */
    public const short SAC_INTEGER		= 13;
    /**
     * reals.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_REAL		        = 14;
    /**
     * Relative length<code>em</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_EM		= 15;
    /**
     * Relative length<code>ex</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_EX		= 16;
    /**
     * Relative length <code>px</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_PIXEL		= 17;
    /**
     * Absolute length <code>in</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_INCH		= 18;
    /**
     * Absolute length <code>cm</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_CENTIMETER	= 19;
    /**
     * Absolute length <code>mm</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_MILLIMETER	= 20;
    /**
     * Absolute length <code>pt</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_POINT		= 21;
    /**
     * Absolute length <code>pc</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_PICA		= 22;
    /**
     * Percentage.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_PERCENTAGE		= 23;
    /**
     * URI: <code>uri(...)</code>.
     * @see #getStringValue
     */
    public const short SAC_URI		        = 24;
    /**
     * function <code>counter</code>.
     * @see #getFunctionName
     * @see #getParameters
     */
    public const short SAC_COUNTER_FUNCTION	= 25;
    /**
     * function <code>counters</code>.
     * @see #getFunctionName
     * @see #getParameters
     */
    public const short SAC_COUNTERS_FUNCTION	= 26;
    /**
     * RGB Colors.
     * <code>rgb(0, 0, 0)</code> and <code>#000</code>
     * @see #getFunctionName
     * @see #getParameters
     */
    public const short SAC_RGBCOLOR		= 27;
    /**
     * Angle <code>deg</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_DEGREE		= 28;
    /**
     * Angle <code>grad</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_GRADIAN		= 29;
    /**
     * Angle <code>rad</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_RADIAN		= 30;
    /**
     * Time <code>ms</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_MILLISECOND		= 31;
    /**
     * Time <code>s</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_SECOND		= 32;
    /**
     * Frequency <code>Hz</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_HERTZ		        = 33;
    /**
     * Frequency <code>kHz</code>.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_KILOHERTZ		= 34;
    
    /**
     * any identifier except <code>inherit</code>.
     * @see #getStringValue
     */
    public const short SAC_IDENT		        = 35;
    /**
     * A string.
     * @see #getStringValue
     */
    public const short SAC_STRING_VALUE		= 36;
    /**
     * Attribute: <code>attr(...)</code>.
     * @see #getStringValue
     */
    public const short SAC_ATTR		        = 37;
    /**
     * function <code>rect</code>.
     * @see #getFunctionName
     * @see #getParameters
     */
    public const short SAC_RECT_FUNCTION		= 38;
    /**
     * A unicode range. @@TO BE DEFINED
     */
    public const short SAC_UNICODERANGE		= 39;
    
    /**
     * sub expressions
     * <code>(a)</code> <code>(a + b)</code> <code>(normal/none)</code>
     * @see #getSubValues
     */
    public const short SAC_SUB_EXPRESSION	= 40;
    
    /**
     * unknown function.
     * @see #getFunctionName
     * @see #getParameters
     */
    public const short SAC_FUNCTION		= 41;
    /**
     * unknown dimension.
     * @see #getFloatValue
     * @see #getDimensionUnitText
     */
    public const short SAC_DIMENSION		= 42;

        /**
     * This is a conditional selector.
     * example:
     * <pre class="example">
     *   simple[role="private"]
     *   .part1
     *   H1#myId
     *   P:lang(fr).p1
     * </pre>
     *
     * @see ConditionalSelector
     */
    public const short SAC_CONDITIONAL_SELECTOR		= 0;

    /**
     * This selector matches any node.
     * @see SimpleSelector
     */    
    public const short SAC_ANY_NODE_SELECTOR		= 1;

    /**
     * This selector matches the root node.
     * @see SimpleSelector
     */    
    public const short SAC_ROOT_NODE_SELECTOR		= 2;

    /**
     * This selector matches only node that are different from a specified one.
     * @see NegativeSelector
     */    
    public const short SAC_NEGATIVE_SELECTOR		= 3;

    /**
     * This selector matches only element node.
     * example:
     * <pre class="example">
     *   H1
     *   animate
     * </pre>
     * @see ElementSelector
     */
    public const short SAC_ELEMENT_NODE_SELECTOR		= 4;

    /**
     * This selector matches only text node.
     * @see CharacterDataSelector
     */
    public const short SAC_TEXT_NODE_SELECTOR		= 5;

    /**
     * This selector matches only cdata node.
     * @see CharacterDataSelector
     */
    public const short SAC_CDATA_SECTION_NODE_SELECTOR	= 6;

    /**
     * This selector matches only processing instruction node.
     * @see ProcessingInstructionSelector
     */
    public const short SAC_PROCESSING_INSTRUCTION_NODE_SELECTOR	= 7;

    /**
     * This selector matches only comment node.
     * @see CharacterDataSelector
     */    
    public const short SAC_COMMENT_NODE_SELECTOR		= 8;
    /**
     * This selector matches the 'first line' pseudo element.
     * example:
     * <pre class="example">
     *   :first-line
     * </pre>
     * @see ElementSelector
     */
    public const short SAC_PSEUDO_ELEMENT_SELECTOR	= 9;

    /* combinator selectors */

    /**
     * This selector matches an arbitrary descendant of some ancestor element.
     * example:
     * <pre class="example">
     *   E F
     * </pre>
     * @see DescendantSelector
     */    
    public const short SAC_DESCENDANT_SELECTOR		= 10;

    /**
     * This selector matches a childhood relationship between two elements.
     * example:
     * <pre class="example">
     *   E > F
     * </pre>
     * @see DescendantSelector
     */    
    public const short SAC_CHILD_SELECTOR		= 11;
    /**
     * This selector matches two selectors who shared the same parent in the
     * document tree and the element represented by the first sequence
     * immediately precedes the element represented by the second one.
     * example:
     * <pre class="example">
     *   E + F
     * </pre>
     * @see SiblingSelector
     */
    public const short SAC_DIRECT_ADJACENT_SELECTOR	= 12;


    }
}
