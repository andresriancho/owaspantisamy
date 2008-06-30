/*
* Copyright (c) 2007-2008, Arshan Dabirsiaghi, Jason Li
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
//UPGRADE_TODO: The type 'java.util.regex.Pattern' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Pattern = java.util.regex.Pattern;
using CleanResults = org.owasp.validator.html.CleanResults;
using Policy = org.owasp.validator.html.Policy;
using AntiSamyPattern = org.owasp.validator.html.model.AntiSamyPattern;
using Property = org.owasp.validator.html.model.Property;
using HTMLEntityEncoder = org.owasp.validator.html.util.HTMLEntityEncoder;
//UPGRADE_TODO: The type 'org.w3c.css.sac.AttributeCondition' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using AttributeCondition = org.w3c.css.sac.AttributeCondition;
//UPGRADE_TODO: The type 'org.w3c.css.sac.CombinatorCondition' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using CombinatorCondition = org.w3c.css.sac.CombinatorCondition;
//UPGRADE_TODO: The type 'org.w3c.css.sac.Condition' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Condition = org.w3c.css.sac.Condition;
//UPGRADE_TODO: The type 'org.w3c.css.sac.ConditionalSelector' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using ConditionalSelector = org.w3c.css.sac.ConditionalSelector;
//UPGRADE_TODO: The type 'org.w3c.css.sac.DescendantSelector' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using DescendantSelector = org.w3c.css.sac.DescendantSelector;
//UPGRADE_TODO: The type 'org.w3c.css.sac.LexicalUnit' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using LexicalUnit = org.w3c.css.sac.LexicalUnit;
//UPGRADE_TODO: The type 'org.w3c.css.sac.NegativeCondition' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using NegativeCondition = org.w3c.css.sac.NegativeCondition;
//UPGRADE_TODO: The type 'org.w3c.css.sac.NegativeSelector' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using NegativeSelector = org.w3c.css.sac.NegativeSelector;
//UPGRADE_TODO: The type 'org.w3c.css.sac.Selector' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Selector = org.w3c.css.sac.Selector;
//UPGRADE_TODO: The type 'org.w3c.css.sac.SiblingSelector' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using SiblingSelector = org.w3c.css.sac.SiblingSelector;
//UPGRADE_TODO: The type 'org.w3c.css.sac.SimpleSelector' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using SimpleSelector = org.w3c.css.sac.SimpleSelector;
namespace org.owasp.validator.css
{
	
	/// <summary> Encapsulates all the neceesary operations for validating individual eleements
	/// of a stylesheet (namely: selectors, conditions and properties).
	/// 
	/// </summary>
	/// <author>  Jason Li
	/// 
	/// </author>
	public class CssValidator
	{
		
		/// <summary> The policy file to use for validation</summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'policy '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
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
		public virtual bool isValidProperty(System.String name, LexicalUnit lu)
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
				
				case Selector.SAC_ANY_NODE_SELECTOR: 
				case Selector.SAC_ELEMENT_NODE_SELECTOR: 
				case Selector.SAC_PSEUDO_ELEMENT_SELECTOR: 
				case Selector.SAC_ROOT_NODE_SELECTOR: 
					// these selectors are the most base selectors
					return validateSimpleSelector((SimpleSelector) selector, results);
				
				case Selector.SAC_CHILD_SELECTOR: 
				case Selector.SAC_DESCENDANT_SELECTOR: 
					// these are compound selectors - decompose into simple selectors
					DescendantSelector descSelector = (DescendantSelector) selector;
					return isValidSelector(selectorName, descSelector.getSimpleSelector(), results) & isValidSelector(selectorName, descSelector.getAncestorSelector(), results);
				
				case Selector.SAC_CONDITIONAL_SELECTOR: 
					// this is a compound selector - decompose into simple selectors
					ConditionalSelector condSelector = (ConditionalSelector) selector;
					return isValidSelector(selectorName, condSelector.getSimpleSelector(), results) & isValidCondition(selectorName, condSelector.getCondition(), results);
				
				case Selector.SAC_DIRECT_ADJACENT_SELECTOR: 
					// this is a compound selector - decompose into simple selectors
					SiblingSelector sibSelector = (SiblingSelector) selector;
					return isValidSelector(selectorName, sibSelector.getSiblingSelector(), results) & isValidSelector(selectorName, sibSelector.getSelector(), results);
				
				case Selector.SAC_NEGATIVE_SELECTOR: 
					// this is a compound selector with one simple selector
					return validateSimpleSelector((NegativeSelector) selector, results);
				
				case Selector.SAC_CDATA_SECTION_NODE_SELECTOR: 
				case Selector.SAC_COMMENT_NODE_SELECTOR: 
				case Selector.SAC_PROCESSING_INSTRUCTION_NODE_SELECTOR: 
				case Selector.SAC_TEXT_NODE_SELECTOR: 
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
			return policy.getRegularExpression("cssElementSelector").Pattern.matcher(selector.toString().toLowerCase()).matches() & !policy.getRegularExpression("cssElementExclusion").Pattern.matcher(selector.toString().toLowerCase()).matches();
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
		public virtual bool isValidCondition(System.String selectorName, Condition condition, CleanResults results)
		{
			switch (condition.getConditionType())
			{
				
				case Condition.SAC_AND_CONDITION: 
				case Condition.SAC_OR_CONDITION: 
					// these are compound condition - decompose into simple conditions
					CombinatorCondition comboCondition = (CombinatorCondition) condition;
					return isValidCondition(selectorName, comboCondition.getFirstCondition(), results) & isValidCondition(selectorName, comboCondition.getSecondCondition(), results);
				
				case Condition.SAC_CLASS_CONDITION: 
					// this is a basic class condition; compare condition against
					// valid pattern and is not blacklisted by exclusion pattern
					return validateCondition((AttributeCondition) condition, policy.getRegularExpression("cssClassSelector"), policy.getRegularExpression("cssClassExclusion"), results);
				
				case Condition.SAC_ID_CONDITION: 
					// this is a basic ID condition; compare condition against
					// valid pattern and is not blacklisted by exclusion pattern
					return validateCondition((AttributeCondition) condition, policy.getRegularExpression("cssIDSelector"), policy.getRegularExpression("cssIDExclusion"), results);
				
				case Condition.SAC_PSEUDO_CLASS_CONDITION: 
					// this is a basic psuedo element condition; compare condition
					// against valid pattern and is not blacklisted by exclusion pattern
					return validateCondition((AttributeCondition) condition, policy.getRegularExpression("cssPseudoElementSelector"), policy.getRegularExpression("cssPsuedoElementExclusion"), results);
				
				case Condition.SAC_BEGIN_HYPHEN_ATTRIBUTE_CONDITION: 
				case Condition.SAC_ONE_OF_ATTRIBUTE_CONDITION: 
				case Condition.SAC_ATTRIBUTE_CONDITION: 
					// this is a basic class condition; compare condition against
					// valid pattern and is not blacklisted by exclusion pattern
					return validateCondition((AttributeCondition) condition, policy.getRegularExpression("cssAttributeSelector"), policy.getRegularExpression("cssAttributeExclusion"), results);
				
				case Condition.SAC_NEGATIVE_CONDITION: 
					// this is a compound condition; decompose to simple condition
					return isValidCondition(selectorName, ((NegativeCondition) condition).getCondition(), results);
				
				case Condition.SAC_ONLY_CHILD_CONDITION: 
				case Condition.SAC_ONLY_TYPE_CONDITION: 
					// :only-child and :only-of-type are constants
					return true;
				
				case Condition.SAC_POSITIONAL_CONDITION: 
				case Condition.SAC_CONTENT_CONDITION: 
				case Condition.SAC_LANG_CONDITION: 
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
		private bool validateCondition(AttributeCondition condition, AntiSamyPattern pattern, AntiSamyPattern exclusionPattern, CleanResults results)
		{
			// check that the name of the condition matches valid pattern and does
			// not match exclusion pattern
			// NOTE: intentionally using non-short-circuited AND operator to
			// generate all relevant error messages
			return pattern.Pattern.matcher(condition.toString().toLowerCase()).matches() & !exclusionPattern.Pattern.matcher(condition.toString().toLowerCase()).matches();
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
				System.String allowedValue = (System.String) allowedValues.Current;
				
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
				Pattern pattern = (Pattern) allowedRegexps.Current;
				
				if (pattern != null && pattern.matcher(value_Renamed).matches())
				{
					isValid = true;
				}
			}
			
			// check if the value matches any of the allowed shorthands
			System.Collections.IEnumerator shorthandRefs = property.ShorthandRefs.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (shorthandRefs.MoveNext() && !isValid)
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String shorthandRef = (System.String) shorthandRefs.Current;
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
				
				case LexicalUnit.SAC_PERCENTAGE: 
				case LexicalUnit.SAC_DIMENSION: 
				case LexicalUnit.SAC_EM: 
				case LexicalUnit.SAC_EX: 
				case LexicalUnit.SAC_PIXEL: 
				case LexicalUnit.SAC_INCH: 
				case LexicalUnit.SAC_CENTIMETER: 
				case LexicalUnit.SAC_MILLIMETER: 
				case LexicalUnit.SAC_POINT: 
				case LexicalUnit.SAC_PICA: 
				case LexicalUnit.SAC_DEGREE: 
				case LexicalUnit.SAC_GRADIAN: 
				case LexicalUnit.SAC_RADIAN: 
				case LexicalUnit.SAC_MILLISECOND: 
				case LexicalUnit.SAC_SECOND: 
				case LexicalUnit.SAC_HERTZ: 
				case LexicalUnit.SAC_KILOHERTZ: 
					// these are all measurements
					return lu.getFloatValue() + lu.getDimensionUnitText();
				
				case LexicalUnit.SAC_INTEGER: 
					// just a number
					return System.Convert.ToString(lu.getIntegerValue());
				
				case LexicalUnit.SAC_REAL: 
					// just a number
					return System.Convert.ToString(lu.getFloatValue());
				
				case LexicalUnit.SAC_STRING_VALUE: 
				case LexicalUnit.SAC_IDENT: 
					// just a string/identifier
					return lu.getStringValue();
				
				case LexicalUnit.SAC_URI: 
					// this is a URL
					return "url(" + lu.getStringValue() + ")";
				
				case LexicalUnit.SAC_RGBCOLOR: 
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
				
				case LexicalUnit.SAC_INHERIT: 
					// constant
					return "inherit";
				
				case LexicalUnit.SAC_ATTR: 
				case LexicalUnit.SAC_COUNTER_FUNCTION: 
				case LexicalUnit.SAC_COUNTERS_FUNCTION: 
				case LexicalUnit.SAC_FUNCTION: 
				case LexicalUnit.SAC_RECT_FUNCTION: 
				case LexicalUnit.SAC_SUB_EXPRESSION: 
				case LexicalUnit.SAC_UNICODERANGE: 
				default: 
					// these are properties that shouldn't be necessary for most run
					// of the mill HTML/CSS
					return null;
				}
		}
	}
}