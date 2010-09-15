package com.wibblr.arriate.auth;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.apache.commons.codec.DecoderException;

public class ParameterParser {
	
	public static HashMap<String, String> parse(InputStream is) throws IOException, DecoderException {
		HashMap<String, String> parameters = new HashMap<String, String>();
		DelimitedStringReader rdr = new DelimitedStringReader(new InputStreamReader(is));
		
		while (rdr.ready()) {
			parameters.put(OAuth10.decodeParameter(rdr.next('=')), OAuth10.decodeParameter(rdr.next('&')));
		}	
		return parameters;
	}
}
