/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidraps4loader;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.*;
import org.xml.sax.SAXException;

import generic.util.Path;
import ghidra.app.plugin.assembler.sleigh.util.GhidraDBTransaction;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.framework.model.DomainFolder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfException;

public class GhidraPS4Loader extends BinaryLoader {
	private String databasePath = Paths.get((new Path(Path.GHIDRA_HOME)).getPathAsString(), "ps4database.xml").toString();
	
	private Document parsePS4Database() throws ParserConfigurationException, IOException, SAXException {
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    //factory.setValidating(true);
	    factory.setIgnoringElementContentWhitespace(true);
	    
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    File file = new File(databasePath);
	    Document doc = builder.parse(file);
	    
	    return doc;
	}
	
	private String getNameForNID(Document database, String nid) {
		String result = "__import_" + nid;
		
		NodeList nidlist = database.getElementsByTagName("DynlibDatabase").item(0).getChildNodes();
		for(int j = 0; j < nidlist.getLength(); j++) {
			Node node = nidlist.item(j);
		    if (node.getNodeType() == Node.ELEMENT_NODE) {
		    	String obf = node.getAttributes().getNamedItem("obf").getNodeValue();
		    	String sym = node.getAttributes().getNamedItem("sym").getNodeValue();
		    	if(!sym.equals("") && !nid.equals("")) {
		    		if(obf.equals(nid)) {
		    			result = sym;
		    			break;
		    		}
		    	}
		    }
		}
		
		return result;
	}
	
	@Override
	public String getName() {
		return "PlayStation 4 ELF";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		ElfHeader elfHeader;
		try {
			elfHeader = PS4ElfParser.getElfHeader(provider);
		} catch (ElfException e) {
			return loadSpecs;
		}

		File dbfile = new File(databasePath);
		boolean exists = dbfile.exists();
		if(!exists) {
			return loadSpecs;
		}
		
		int type = elfHeader.e_type();
		int machine = elfHeader.e_machine();
		
		// TODO: support all the different types
		//if(type != PS4_ELF_TYPE || machine != PS4_MACHINE_TYPE) {
		//	return loadSpecs;
		//}
		
		loadSpecs.add(new LoadSpec(this, 0x400000, new LanguageCompilerSpecPair("x86:LE:64:default", "gcc"), true));

		return loadSpecs;
	}

	@Override
	protected List<Program> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException {
        LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
        Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
        CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);
        Address baseAddress = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        List<Program> results = new ArrayList<Program>();
        boolean success = false;
		
		Program program = createProgram(provider, programName, baseAddress, getName(), importerLanguage, importerCompilerSpec, consumer);
		
		try {
			success = this.loadInto(provider, loadSpec, options, log, program, monitor, MemoryConflictHandler.ALWAYS_OVERWRITE);
		} finally {
			if(!success) {
				program.release(consumer);
			}
		}
		
        if (success) {
        	// Start a transaction on the program database
        	GhidraDBTransaction trans = new GhidraDBTransaction(program, "PlayStation 4 Loader");
        	
        	// Function manager
        	FunctionManager funcManager = program.getFunctionManager();
        	
        	// ELF Header
    		ElfHeader elfHeader;
    		try {
    			elfHeader = PS4ElfParser.getElfHeader(provider);
    		} catch (ElfException e) {
    			throw new IOException("Failed to parse ELF header!");
    		}
    		
    		// TODO: fix this, make it dynamic
    		long endOfHeader = 0x4000;
    		
        	// Load all the imports from the XML file
    		Document ps4database;
        	try {
        		ps4database = parsePS4Database();
			} catch (Exception e) {
				throw new IOException("Failed to load 'ps4database.xml'!");
			}
        	
        	// Parse all the imports
        	Map<Long, String> imports = PS4ElfParser.getSonyElfImports(provider, elfHeader);
        	if(imports.size() > 0) {
	        	// Label all the imports
	        	for(Map.Entry<Long, String> importEntry : imports.entrySet()) {
	        		Long address = endOfHeader + importEntry.getKey();
	        		String nid = importEntry.getValue();
	        		
	        		Address addr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(address);

	        		// Label the import
	        		String name = getNameForNID(ps4database, nid);
	        		AddressSet addrSet = new AddressSet(addr);
	        		try {
        				 funcManager.createFunction(name, addr, addrSet, SourceType.IMPORTED);
					} catch (Exception ex) {
						ex.printStackTrace();
						System.out.println("error: could not created imported function '" + name + "'!");
					}
	        	}
        	}
        	
        	// the entry point
        	long entryAddress = endOfHeader + elfHeader.e_entry();
        	Address entryAddr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(entryAddress);
        	AddressSet addrSet = new AddressSet(entryAddr);
        	try {
				 funcManager.createFunction("entrypoint", entryAddr, addrSet, SourceType.IMPORTED);
			} catch (Exception ex) {
				System.out.println("error: could not set up entrypoint function!");
			}
        	
        	trans.commit();
        	trans.close();
        	
        	// Add the program to the results
        	results.add(program);
        }
		
		return results;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}