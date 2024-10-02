package ghidra.markdown;

import java.io.*;
import java.util.List;

import org.commonmark.Extension;
import org.commonmark.ext.heading.anchor.HeadingAnchorExtension;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

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
		HtmlRenderer renderer = HtmlRenderer.builder().extensions(extensions).build();
		Node document = parser.parseReader(new FileReader(inFile));
		String html = renderer.render(document);

		try (PrintWriter out = new PrintWriter(outFile)) {
			out.write(html);
		}
	}
}