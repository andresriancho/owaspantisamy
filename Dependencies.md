# Introduction #

AntiSamy relies on 3rd party libraries to properly perform tasks like HTML parsing, XML processing, and more. Those libraries and the versions used in testing are shown below.

# Details #

The required dependencies are as follows:
  * Apache Batik-CSS 1.7
  * NekoHTML 1.9.16
    * NekoHTML Transitively depends on xerces:xercesImpl:jar:2.9.1
  * Apache Commons HTTP-Client 3.1 (only needed for testing or if your policy allow stylesheets)
  * JUnit 4.11 (only needed for testing)