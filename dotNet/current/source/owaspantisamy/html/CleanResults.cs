/*
* Copyright (c) 2008, Jerry Hoff
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
using System;
using System.Xml;
using System.Collections;

namespace org.owasp.validator.html
{

    /// <summary> This class contains the results of a scan.
    /// 
    /// The list of error messages (<code>errorMessages</code>) will let the user know
    /// what, if any HTML errors existed, and what, if any, security or
    /// validation-related errors existed, and what was done about them.
    /// </summary>

    public class CleanResults
    {
        private ArrayList errorMessages = new ArrayList();
        private string cleanHTML;
        private DateTime startOfScan;
        private DateTime endOfScan;
        private XmlDocumentFragment cleanXMLDocumentFragment;

        public CleanResults()
        {
        }

        public CleanResults(DateTime startOfScan, DateTime endOfScan, string cleanHTML, XmlDocumentFragment XMLDocumentFragment, ArrayList errorMessages)
        {
            this.startOfScan = startOfScan;
            this.endOfScan = endOfScan;
            this.cleanXMLDocumentFragment = XMLDocumentFragment;
            this.cleanHTML = cleanHTML;
            this.errorMessages = errorMessages;
        }
        public CleanResults(DateTime date)
        {
            this.startOfScan = date;
        }

        public XmlDocumentFragment getCleanXMLDocumentFragment()
        {
            return cleanXMLDocumentFragment;
        }

        public void setCleanHTML(String cleanHTML)
        {
            this.cleanHTML = cleanHTML;
        }

     /**
	 * Return the filtered HTML as a String.
	 * @return A String object which contains the serialized, safe HTML.
	 */
        public String getCleanHTML()
        {
            return cleanHTML;
        }

        /**
         * Return a list of error messages.
         * @return An ArrayList object which contain the error messages after a scan.
         */
        public ArrayList getErrorMessages()
        {
            return errorMessages;
        }

        /**
         * Return the time when scan finished.
         * @return A Date object indicating the moment the scan finished.
         */
        public DateTime getEndOfScan()
        {

            return endOfScan;
        }

        /**
         * Return the time when scan started.
         * @return A Date object indicating the moment the scan started.
         */
        public DateTime getStartOfScan()
        {
            return startOfScan;
        }

        /**
         * Return the time elapsed during the scan.
         * @return A double primitive indicating the amount of time elapsed between the beginning and end of the scan in seconds.
         */
        public double getScanTime()
        {
            return (endOfScan.Millisecond - startOfScan.Millisecond) / 1000D;
        }

        /**
         * Add an error message to the aggregate list of error messages during filtering.
         * @param msg An error message to append to the list of aggregate error messages during filtering.
         */
        public void addErrorMessage(String msg)
        {
            errorMessages.Add(msg);
        }

        /**
         * Return the number of errors encountered during filtering.
         */
        public int getNumberOfErrors()
        {
            return errorMessages.Count;
        }
    }
}