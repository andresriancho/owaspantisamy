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
using System.Xml.Serialization;
using System.IO;
using System.Net;
using System.Text;
using org.owasp.validator.html.scan;

namespace org.owasp.validator.html
{
    /// <summary> 
    /// This is the only class from which the outside world should be calling. The <code>scan()</code> method holds
    /// the meat and potatoes of AntiSamy. The file contains a number of ways for <code>scan()</code>'ing depending
    /// on the accessibility of the policy file.
    /// </summary>

    public class AntiSamy
    {
        private string inputEncoding = AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM;
        private string outputEncoding = AntiSamyDOMScanner.DEFAULT_ENCODING_ALGORITHM;

        /// <summary> The meat and potatoes. The <code>scan()</code> family of methods are the only methods the outside world should
        /// be calling to invoke AntiSamy.
        /// 
        /// </summary>
        /// <param name="taintedHTML">Untrusted HTML which may contain malicious code.
        /// </param>
        /// <param name="inputEncoding">The encoding of the input.
        /// </param>
        /// <param name="outputEncoding">The encoding that the output should be in.
        /// </param>
        /// <returns> A <code>CleanResults</code> object which contains information about the scan (including the results).
        /// </returns>
        /// <throws>  <code>ScanException</code> When there is a problem encountered while scanning the HTML. </throws>
        /// <throws>  <code>PolicyException</code> When there is a problem reading the policy file. </throws>

        public virtual CleanResults scan(string taintedHTML)
        {
            Policy policy = null;

            /*
            * Get or reload the policy document (antisamy.xml). We'll need to pass that to the
            * scanner so it knows what to look for.
            */

            policy = Policy.getInstance();

            AntiSamyDOMScanner antiSamy = new AntiSamyDOMScanner(policy);

            /*
            * Go get 'em!
            */
            return antiSamy.scan(taintedHTML, inputEncoding, outputEncoding);
        }


        // <summary> This method wraps <code>scan()</code> using the Policy object passed in.</summary>
        /*		public CleanResults scan(string taintedHTML, Policy policy)
                {
                    return new AntiSamyDOMScanner(policy).scan(taintedHTML, inputEncoding, outputEncoding);
                }
        */

        /// <summary> This method wraps <code>scan()</code> using the Policy object passed in.</summary>
        public virtual CleanResults scan(string taintedHTML, string filename)
        {
            Policy policy = null;

            /*
            * Get or reload the policy document (antisamy.xml). We'll need to pass that to the
            * scanner so it knows what to look for.
            */

            policy = Policy.getInstance(filename);

            AntiSamyDOMScanner antiSamy = new AntiSamyDOMScanner(policy);

            /*
            * Go get 'em!
            */

            return antiSamy.scan(taintedHTML, inputEncoding, outputEncoding);
        }

        /// <summary> This method wraps <code>scan()</code> using the policy File object passed in.</summary>
        public virtual CleanResults scan(string taintedHTML, Policy policy)
        {

            AntiSamyDOMScanner antiSamy = new AntiSamyDOMScanner(policy);

            /*
            * Go get 'em!
            */

            return antiSamy.scan(taintedHTML, inputEncoding, outputEncoding);
        }

        /// <summary> Main method for testing AntiSamy.</summary>
        /// <param name="args">Command line arguments. Only 1 argument is processed, and it should be a URL or filename to run through AntiSamy using the default policy location.
        /// </param>

        [STAThread]
        static void Main(string[] args)
        {

            string filename;
            filename = args[0];

            if (args.Length == 0)
            {
                System.Console.Error.WriteLine("Please specify a URL or file name to filter - thanks!");
                System.Console.ReadLine();
                return;
            }
            
            try
            {

                string buff = "";
                if (!File.Exists(filename))
                {
                    WebClient client = new WebClient();
                    byte[] bytes;
                    try
                    {
                        bytes = client.DownloadData(filename);
                    }
                    catch (WebException we)
                    {
                        Console.WriteLine("Encountered an IOException while reading URL: ");
                        Console.WriteLine(we.StackTrace);
                        return;
                    }
                    buff = Encoding.ASCII.GetString(bytes);
                }
                else
                {
                    FileStream fileStream = null;
                    StreamReader streamReader = null;
                    try
                    {
                        fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.None);
                        streamReader = new StreamReader(fileStream);
                        buff = streamReader.ReadToEnd();

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Please specify a valid file name to filter - thanks!");
                        Console.WriteLine(ex.StackTrace);
                    }
                    finally
                    {
                        if (fileStream != null) fileStream.Close();
                        if (streamReader != null) streamReader.Close();
                    }
                }

                AntiSamy _as = new AntiSamy();
                CleanResults test = _as.scan(buff);

                Console.WriteLine("[1] Finished scan [" + test.getCleanHTML().Length + " bytes] in " + test.getScanTime() + " seconds\n");
                Console.WriteLine("[2] Clean HTML fragment:\n" + test.getCleanHTML());
                Console.WriteLine("[3] Error Messages (" + test.getNumberOfErrors() + "):");


                for (int i = 0; i < test.getErrorMessages().Count; i++)
                {
                    string s = test.getErrorMessages()[i].ToString();
                    Console.WriteLine(s);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine(e.StackTrace);
            }
            Console.ReadLine();
        }

        public string InputEncoding
        {
            get { return inputEncoding; }
            set { inputEncoding = value; }
        }
        public string OutputEncoding
        {
            get { return outputEncoding; }
            set { outputEncoding = value; }
        }
    }
}