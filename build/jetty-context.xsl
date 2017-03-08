<?xml version="1.0" encoding="UTF-8"?>
<!-- @author: Jochen Graf -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output method="xml" indent="yes" 
  omit-xml-declaration="no" 
  doctype-public="-//Mort Bay Consulting//DTD Configure 1.2//EN" 
  doctype-system="http://jetty.mortbay.org/configure_1_2.dtd"/>


  <xsl:template match="//Configure[@id='exist-webapp-context']/Set[@name='contextPath']/text()">
    <xsl:text>/</xsl:text>
  </xsl:template>

  <xsl:template match="@*|*|comment()" priority="-2">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>  

</xsl:stylesheet>
