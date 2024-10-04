package ghidra.markdown;

import java.io.*;
import java.util.List;
import java.util.Map;

import org.commonmark.Extension;
import org.commonmark.ext.heading.anchor.HeadingAnchorExtension;
import org.commonmark.node.Link;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.*;

public class MarkdownToHtml {

	public static void main(String[] args) throws Exception {

		if (args.length != 2) {
			throw new Exception("Expected 2 arguments, got " + args.length);
		}

		File inFile = new File(args[0]);
		File outFile = new File(args[1]);

		if (!inFile.getName().endsWith(".md")) {
			throw new Exception("First argument doesn't not end with .md");
		}

		if (!outFile.getParentFile().isDirectory() && !outFile.getParentFile().mkdirs()) {
			throw new Exception("Failed to create: " + outFile.getParent());
		}

		List<Extension> extensions = List.of(HeadingAnchorExtension.create());
		Parser parser = Parser.builder().extensions(extensions).build();
		HtmlRenderer renderer = HtmlRenderer.builder()
				.extensions(extensions)
				.attributeProviderFactory(new LinkAttributeProvider())
				.build();
		Node document = parser.parseReader(new FileReader(inFile));
		
		String html = renderer.render(document);
		try (PrintWriter out = new PrintWriter(outFile)) {
			out.write(html);
		}
	}
	
	/**
	 * Class to help adjust links to Markdown files to instead become links to HTML files
	 */
	private static class LinkAttributeProvider
			implements AttributeProvider, AttributeProviderFactory {

		@Override
		public AttributeProvider create(AttributeProviderContext attributeProviderContext) {
			return new LinkAttributeProvider();
		}
		
		@Override
		public void setAttributes(Node node, String tagName, Map<String, String> attributes) {
			if (node instanceof Link) {
				String href = attributes.get("href");
				if (href != null && !href.startsWith("#") && href.toLowerCase().endsWith(".md")) {
					attributes.put("href", href.substring(0, href.length() - 2) + "html");
				}
			}
		}
	}
}