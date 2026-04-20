package ghidra.app.util.sourcelanguage;

import java.io.*;
import java.util.*;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.xml.sax.SAXException;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.database.SpecExtension;
import ghidra.program.database.SpecExtension.DocInfo;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;

/**
 * A service for applying source language-related {@link ExtensionPoint}s a {@link Program}
 */
public class SourceLanguageService {

	/**
	 * An entry from a spec extension configuration file
	 * 
	 * @param processor The name of the processor
	 * @param endian The processor endianness ("little" or "big") (could be empty or null)
	 * @param size The processor size (i.e., "32, "64", etc) (could be empty or null)
	 * @param variant The processor variant (could be empty or null)
	 * @param formats The names of the binary file formats (could be empty or null)
	 * @param directory The directory path (relative to the config file) of the spec extension files
	 *   to add
	 */
	private record ExtensionEntry(String processor, String endian, String size, String variant,
			String[] formats, String directory) {}
	
	/**
	 *  {@return the {@link SourceLanguage}s found in the given {@link Program}}
	 *  
	 *  @param program The {@link Program}
	 *  @param monitor The {@link TaskMonitor}
	 *  @throws CancelledException if the user cancelled the operation
	 */
	public static List<SourceLanguage> getSourceLanguages(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<SourceLanguage> ret = new ArrayList<>();
		for (SourceLanguage sourceLanguage : ClassSearcher.getInstances(SourceLanguage.class)) {
			try {
				if (sourceLanguage.existsIn(program, monitor)) {
					ret.add(sourceLanguage);
				}
			}
			catch (IOException e) {
				Msg.error(SourceLanguageService.class,
					"Problem checking for " + sourceLanguage.getName(), e);
			}
		}
		return ret;
	}

	public static int addSpecExtensions(Program program, SourceLanguage sourceLanguage,
			MessageLog log, TaskMonitor monitor) throws LanguageNotFoundException {
		int count = 0;
		for (SourceLanguageSpecExtension slse : ClassSearcher
				.getInstances(SourceLanguageSpecExtension.class)) {
			String name = sourceLanguage.getName();
			if (!slse.getCompatibleSourceLanguage().equals(name)) {
				continue;
			}

			ResourceFile configFile;
			try {
				configFile = slse.getSpecExtensionConfig();
			}
			catch (FileNotFoundException e) {
				log.appendMsg("Failed to find spec extension config file for: " + name);
				continue;
			}

			try (JsonReader reader =
				new JsonReader(new InputStreamReader(configFile.getInputStream()))) {
				ExtensionEntry[] entries = new Gson().fromJson(reader, ExtensionEntry[].class);
				if (entries == null) {
					throw new EOFException(configFile + " was at end of file");
				}
				for (ExtensionEntry entry : entries) {
					if (entry != null) {
						count += processExtensionEntry(entry, configFile, program, log, monitor);
					}
				}
			}
			catch (LanguageNotFoundException e) {
				throw e;
			}
			catch (IOException e) {
				log.appendException(e);
			}
		}
		return count;
	}

	private static int processExtensionEntry(ExtensionEntry entry, ResourceFile configFile,
			Program program, MessageLog log, TaskMonitor monitor)
			throws LanguageNotFoundException, IOException {
		LanguageDescription desc = program.getLanguageCompilerSpecPair().getLanguageDescription();
		String programProcessor = desc.getProcessor().toString();
		String programEndian = desc.getEndian().toString();
		String programSize = Integer.toString(desc.getSize());
		String programVariant = desc.getVariant();
		String programFormat = program.getExecutableFormat();
		if (!entry.processor().equals(programProcessor)) {
			return 0;
		}
		if (!StringUtils.isEmpty(entry.endian()) && !entry.endian().equals(programEndian)) {
			return 0;
		}
		if (!StringUtils.isEmpty(entry.size()) && !entry.size().equals(programSize)) {
			return 0;
		}
		if (!StringUtils.isEmpty(entry.variant()) && !entry.variant().equals(programVariant)) {
			return 0;
		}
		if (ArrayUtils.isEmpty(entry.formats()) &&
			Arrays.stream(entry.formats()).noneMatch(programFormat::equals)) {
			return 0;
		}

		int extensionCount = 0;
		ResourceFile dir = new ResourceFile(configFile.getParentFile(), entry.directory());
		ResourceFile[] files = dir.listFiles();
		if (files != null) {
			for (ResourceFile file : files) {
				byte[] bytes = file.getInputStream().readAllBytes();
				String xml = new String(bytes);
				try {
					SpecExtension extension = new SpecExtension(program);
					DocInfo docInfo = extension.testExtensionDocument(xml);
					if (SpecExtension.getCompilerSpecExtension(program, docInfo) == null) {
						extension.addReplaceCompilerSpecExtension(xml, monitor);
						extensionCount++;
					}
				}
				catch (SleighException | SAXException | XmlParseException | LockException e) {
					log.appendMsg("Failed to load spec extension: " + file, e.getMessage());
				}
			}
		}
		return extensionCount;
	}

	/**
	 * {@return any {@link SourceLanguageDataArchive}s that are compatible with the given
	 * source language}
	 * 
	 * @param sourceLanguageName The name of the source language to get data archives for
	 */
	public static List<SourceLanguageDataArchive> getSourceLanguageDataArchives(
			String sourceLanguageName) {
		return ClassSearcher.getInstances(SourceLanguageDataArchive.class)
				.stream()
				.filter(e -> e.getCompatibleSourceLanguage().equals(sourceLanguageName))
				.toList();
	}

}
