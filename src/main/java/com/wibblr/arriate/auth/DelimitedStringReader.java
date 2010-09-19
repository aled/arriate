package com.wibblr.arriate.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;

public class DelimitedStringReader extends BufferedReader {
	private int bytesRead = 0;
	
	public DelimitedStringReader(Reader r) {
		super(r);
	}

	public int bytesRead() {
		return bytesRead;
	}
	
	// Reads until the delimiter or EOF.
	// Returns null when there are no more strings to read (i.e. when
	// this method is called and -1 is the very next value returned from read()
	public String next(char delimiter) throws IOException {
		int c = read(); bytesRead++;
		
		if (c == -1) { 
			return null;
		}
		
		StringBuffer sb = new StringBuffer();
		while (c != -1 && c != delimiter) {
			sb.append((char)c);
			c = read(); bytesRead++;
		}
		return sb.toString();
	}
} 
