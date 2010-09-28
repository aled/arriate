package com.wibblr.arriate.osm.api06
import scala.io.Source

import scala.xml.pull._;
import java.io.InputStream

class UserDetails(
		var id: Long,
		val displayName: String,
		val accountCreated: Long,
		val homeLatitude: Double,
		val homeLongitude: Double,
		val description: String,
		val languages: List[String]) {
}

object UserDetails {
/*	
<osm version="0.6" generator="OpenStreetMap server">
 <user display_name="Max Muster" account_created="2006-07-21T19:28:26Z" id="1234">
   <home lat="49.4733718952806" lon="8.89285988577866" zoom="3"/>
   <description>The description of your profile</description>
   <languages>
     <lang>de-DE</lang>
     <lang>de</lang>
     <lang>en-US</lang>
     <lang>en</lang>
   </languages>
 </user>
</osm>
*/
	def deserialize(xml: InputStream): UserDetails = {
		new XMLEventReader(Source.fromInputStream(xml)).foreach(matchEvent);
		
		return null; // new UserDetails();
	}
	
	def matchEvent(event: XMLEvent) = {
		event match {
			case EvElemStart(_, _, _, _) => { println(event) }
			case EvElemEnd(_, _) => { println(event) }
			case _ => { println(event) }
		}
	}
}

