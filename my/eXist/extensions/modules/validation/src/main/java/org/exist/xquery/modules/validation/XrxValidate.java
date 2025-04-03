package org.exist.xquery.functions.validation;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.xerces.xni.parser.XMLEntityResolver;
import org.exist.Namespaces;
import org.exist.dom.QName;
import org.exist.dom.memtree.DocumentImpl;
import org.exist.dom.memtree.MemTreeBuilder;
import org.exist.dom.memtree.NodeImpl;
import org.exist.resolver.ResolverFactory;
import org.exist.resolver.XercesXmlResolverAdapter;
import org.exist.storage.BrokerPool;
import org.exist.util.Configuration;
import org.exist.util.XMLReaderObjectFactory;
import org.exist.validation.GrammarPool;
import org.exist.validation.resolver.SearchResourceResolver;
import org.xmlresolver.Resolver;
import org.xmlresolver.XMLResolverConfiguration;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.Cardinality;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BooleanValue;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.FunctionReturnSequenceType;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.SequenceType;
import org.exist.xquery.value.Type;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.AttributesImpl;
import org.xmlresolver.Resolver;

import static com.evolvedbinary.j8fu.tuple.Tuple.Tuple;

public class XrxValidate extends BasicFunction {

	private  BrokerPool brokerPool;
	private  XMLEntityResolver entityResolver;
	private  GrammarPool grammarPool;

	public final static FunctionSignature signatures[] = {
        new FunctionSignature(
                new QName("xrx-instance", ValidationModule.NAMESPACE_URI, ValidationModule.PREFIX), 
	                "Validate document by parsing $instance. Optionally " +
	                "grammar caching can be enabled. Supported grammars types " +
	                "are '.xsd'.",
                new SequenceType[]{
                    new FunctionParameterSequenceType("instance", Type.ITEM, Cardinality.EXACTLY_ONE, 
                    		"The document referenced as xs:anyURI, a node (element or result of fn:doc()) " +
                            "or as a Java file object."),
                    new FunctionParameterSequenceType("enable-grammar-cache", Type.BOOLEAN, Cardinality.EXACTLY_ONE, 
                    		"Set the flag to true() to enable grammar caching."),
                    new FunctionParameterSequenceType("grammars", Type.ITEM, Cardinality.ZERO_OR_MORE, 
                    		"The catalogs referenced as xs:anyURI's.")},
                new FunctionReturnSequenceType(Type.NODE, Cardinality.EXACTLY_ONE, ""))	
	};
	
	public XrxValidate(XQueryContext context, FunctionSignature signature) {
        super(context, signature);
        this.brokerPool = context.getBroker().getBrokerPool();
	}

	@Override
	public Sequence eval(Sequence[] args, Sequence contextSequence) throws XPathException {

		XrxValidationHandler handler = new XrxValidationHandler();
		XrxValidationReport report = new XrxValidationReport();
		handler.setXrxValidationReport(report);
		
        InputSource instance = null;
		
		try {
			
			report.start();
			
			XMLReader xmlReader = getXMLReader();
			
            xmlReader.setContentHandler(handler);
            xmlReader.setErrorHandler(report);
            
    		instance = Shared.getInputSource(args[0].itemAt(0), context);
    		
            // handle catalog
            if (args.length == 2) {
                LOG.debug("No Catalog specified");

            } else if (args[2].isEmpty()) {
                // Use system catalog
                LOG.debug("Using system catalog.");
                Configuration config = brokerPool.getConfiguration();

                this.entityResolver = (XMLEntityResolver) config.getProperty(XMLReaderObjectFactory.CATALOG_RESOLVER);
                setXmlReaderEnitityResolver(xmlReader, this.entityResolver);

            } else {
                // Get URL for catalog
                String catalogUrls[] = Shared.getUrls(args[2]);
                String singleUrl = catalogUrls[0];

                if (singleUrl.endsWith("/")) {
                    // Search grammar in collection specified by URL. Just one collection is used.
                    LOG.debug("Search for grammar in " + singleUrl);
                    this.entityResolver = new SearchResourceResolver( this.brokerPool, context.getSubject(),catalogUrls[0]);
                    setXmlReaderEnitityResolver(xmlReader, this.entityResolver);

                } else if (singleUrl.endsWith(".xml")) {
                    LOG.debug("Using catalogs " + getStrings(catalogUrls));
		    final Resolver localResolver = ResolverFactory.newResolver(Arrays.asList(Tuple(singleUrl, Optional.empty())));
                    setXmlReaderEnitityResolver(xmlReader, localResolver);

                } else {
                    LOG.error("Catalog URLs should end on / or .xml");
                }

            }
            
            boolean useCache = ((BooleanValue) args[1].itemAt(0)).getValue();
            if (useCache) {
                LOG.debug("Grammar caching enabled.");
                Configuration config = brokerPool.getConfiguration();
                this.grammarPool = (GrammarPool) config.getProperty(XMLReaderObjectFactory.GRAMMER_POOL);
                xmlReader.setProperty(XMLReaderObjectFactory.APACHE_PROPERTIES_INTERNAL_GRAMMARPOOL, this.grammarPool);
            }
            
    		xmlReader.parse(instance);
			
		} catch (ParserConfigurationException e) {
			LOG.error(e.getMessage());
		} catch (SAXException e) {
			LOG.error(e.getMessage());
		} catch (MalformedURLException e) {
			LOG.error(e.getMessage());
		} catch (IOException e) {
			LOG.error(e.getMessage());
		} catch (URISyntaxException e) {
			LOG.error(e.getMessage());
		}
		finally {
            report.stop();

            Shared.closeInputSource(instance);			
		}
		
		MemTreeBuilder builder = context.getDocumentBuilder();
        NodeImpl result = writeReport(report, handler, builder);
        return result;
	}
	
	private XMLReader getXMLReader() throws ParserConfigurationException, SAXException {
		
		SAXParserFactory factory = SAXParserFactory.newInstance();
		factory.setNamespaceAware(true);
		factory.setValidating(true);
		SAXParser saxParser = factory.newSAXParser();
		XMLReader xmlReader = saxParser.getXMLReader();

        setXmlReaderFeature(xmlReader, Namespaces.SAX_VALIDATION, true);
        setXmlReaderFeature(xmlReader, Namespaces.SAX_VALIDATION_DYNAMIC, false);
        setXmlReaderFeature(xmlReader, XMLReaderObjectFactory.APACHE_FEATURES_VALIDATION_SCHEMA, true);
        setXmlReaderFeature(xmlReader, XMLReaderObjectFactory.APACHE_PROPERTIES_LOAD_EXT_DTD, true);
        setXmlReaderFeature(xmlReader, Namespaces.SAX_NAMESPACES_PREFIXES, true);
        
		return xmlReader;
	}

    private void setXmlReaderFeature(XMLReader xmlReader, String featureName, boolean value){

        try {
            xmlReader.setFeature(featureName, value);
        } catch (SAXNotRecognizedException ex) {
            LOG.error(ex.getMessage());
        } catch (SAXNotSupportedException ex) {
            LOG.error(ex.getMessage());
        }
    }
    
    private void setXmlReaderEnitityResolver(XMLReader xmlReader, Object entityResolver ){

        try {
	    XercesXmlResolverAdapter.setXmlReaderEntityResolver(xmlReader, (XMLEntityResolver)entityResolver);
            //xmlReader.setProperty(XMLReaderObjectFactory.APACHE_PROPERTIES_ENTITYRESOLVER, entityResolver);

        } catch (SAXNotRecognizedException ex) {
            LOG.error(ex.getMessage());

        } catch (SAXNotSupportedException ex) {
            LOG.error(ex.getMessage());
        }
    }
    
	private NodeImpl writeReport(XrxValidationReport report, XrxValidationHandler handler, MemTreeBuilder builder) {
		
		// root element
		int nodeNr = builder.startElement("", "report", "report", null);

		// validation status
        builder.startElement("", "status", "status", null);
        if (handler.isValid()) {
            builder.characters("valid");
        } else {
            builder.characters("invalid");
        }
        builder.endElement();
        
        // validation duration
        AttributesImpl durationAttribs = new AttributesImpl();
        durationAttribs.addAttribute("", "unit", "unit", "CDATA", "msec");
        builder.startElement("", "duration", "duration", durationAttribs);
        builder.characters("" + report.getValidationDuration());
        builder.endElement();		

        AttributesImpl attribs = new AttributesImpl();

        // iterate validation report items, write message
        List cr = handler.getValidationReportItemList();
        for (Iterator iter = cr.iterator(); iter.hasNext();) {
            XrxValidationReportItem vri = (XrxValidationReportItem) iter.next();

            // construct attributes
            attribs.addAttribute("", "level", "level", "CDATA", vri.getTypeText());
            attribs.addAttribute("", "line", "line", "CDATA", Integer.toString(vri.getLineNumber()));
            attribs.addAttribute("", "column", "column", "CDATA", Integer.toString(vri.getColumnNumber()));
            attribs.addAttribute("", "nodeId", "nodeId", "CDATA", vri.getNodeId());

            if (vri.getRepeat() > 1) {
                attribs.addAttribute("", "repeat", "repeat", "CDATA", Integer.toString(vri.getRepeat()));
            }
            
            // write message
            builder.startElement("", "message", "message", attribs);
            builder.characters(vri.getMessage());
            builder.endElement();

            // reuse attributes
            attribs.clear();
        }
        
        // end root element
		builder.endElement();
		
		return ((DocumentImpl) builder.getDocument()).getNode(nodeNr);
	}
	
    private static String getStrings(String[] data) {
        StringBuilder sb = new StringBuilder();
        for (String field : data) {
            sb.append(field);
            sb.append(" ");
        }
        return sb.toString();
    }	
}
