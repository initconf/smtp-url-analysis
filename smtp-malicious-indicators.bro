module Phish; 

#@load smtp-encoded-subject.bro  

#####redef SMTP::generate_md5 += /application\/*/;

export { 
	
	redef enum Notice::Type += {
                ##### Indicates that an MD5 sum was calculated for an HTTP response body.
                Malicious_MD5,
                Malicious_Attachment,
                Malicious_Indicator,
		Malicious_Mailfrom,
		Malicious_Mailto,
		Malicious_from,
		Malicious_reply_to,
		Malicious_subject,
		Malicious_rcptto,
		Malicious_path,
		Malicious_Decoded_Subject, 
	}; 

type smtp_MaliciousIdx: record {
        indicator: string; 
};

# md5sum	description 

type smtp_maliciousVal: record {
        indicator: string; 
        description: string &optional &default="null";
};

        global smtp_malicious_indicators: table[string] of smtp_maliciousVal &synchronized &redef ; 
        #####global smtp_md5hash_feed="/usr/local/bro-2.1/share/bro/site/feeds/smtp_malicious_indicators.out" &redef ; 
        global smtp_md5hash_feed="/YURT/feeds/BRO-feeds/smtp_malicious_indicators.out" &redef ; 

############### feeds for flagging sender and subject which are part of log_smtp event

hook Notice::policy(n: Notice::Info)
{

           if ( n$note == Phish::Malicious_MD5)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_Attachment)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_Mailfrom)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_Mailto)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_from)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_reply_to)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_subject)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_rcptto)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_Decoded_Subject)
                 add n$actions[Notice::ACTION_EMAIL];

           if ( n$note == Phish::Malicious_Indicator)
                 add n$actions[Notice::ACTION_EMAIL];
}

} ##### end of export 

#event Input::update_finished(name: string, source: string)                                                         
event Input::end_of_data(name: string, source: string)                                                         
{                                                                         

	log_reporter(fmt("EVENT: Input::update_finished: VARS: name: %s, source: %s", name, source),10);

        #print fmt("digested  %s records in smtp_malicious_indicators", |smtp_malicious_indicators|);
        #####print smtp_malicious_indicators;                                                 
} 

event bro_init() &priority=10
{
        Input::add_table([$source=smtp_md5hash_feed, $name="smtp_malicious_indicators", $idx=smtp_MaliciousIdx, $val=smtp_maliciousVal,  $destination=smtp_malicious_indicators,  $mode=Input::REREAD]);
}

event SMTP::log_smtp (rec: SMTP::Info)
{ 

	log_reporter(fmt("EVENT: SMTP::log_smtp: VARS: rec: %s", rec),10); 

	if ( ! connection_exists(rec$id) )
                return;

	local c = lookup_connection(rec$id);
	local pat = />|<| /;

	if (rec?$rcptto) 
	{ 
		for (rcptto in rec$rcptto)
		{ 
			rcptto =  strip(gsub(rcptto, pat, "")); 
			#####print fmt ("rcpt_to: %s", rcptto); 
			if ( rcptto in smtp_malicious_indicators )
			{
				#####print fmt ("DDDDD: reciept to is %s", rcptto ); 
			       NOTICE([$note=Malicious_rcptto, $msg=fmt("Malicious rectto :: %s, %s", smtp_malicious_indicators[rcptto], rcptto), $conn=c, $sub=rcptto, $identifier=cat(rcptto),$suppress_for=1 mins]);
			}
		} 
	} 		

	if (rec?$to) { 
		for (to in rec$to) { 
			to =  strip(gsub(to, pat, "")); 
			#####print fmt ("to: %s", to) ; 
			if(to in smtp_malicious_indicators) { 
			  NOTICE([$note=Malicious_Mailto, $msg=fmt("Malicious to:: %s, %s", smtp_malicious_indicators[to], to), $conn=c, $sub=to, $identifier=cat(to),$suppress_for=1 mins]);
			} 
		} 	
	} 
			

	if ( rec?$mailfrom )
	{ 
		local mailfrom=strip(gsub(rec$mailfrom, pat, ""));
		if (mailfrom in smtp_malicious_indicators )
		{ 
			#####print fmt ("mailfrom: %s", rec$mailfrom) ; 
			NOTICE([$note=Malicious_Mailfrom, $msg=fmt("Malicious MailFrom :: %s, %s", smtp_malicious_indicators[mailfrom], rec$mailfrom), $conn=c, $sub=rec$mailfrom, $identifier=cat(rec$mailfrom),$suppress_for=1 mins]);
		} 
	} 

	if ( rec?$from ) 
	{ 
		#####print fmt ("from: %s", rec$from); 

		if (rec$from in smtp_malicious_indicators) 
		{ 
		NOTICE([$note=Malicious_from, $msg=fmt("Malicious Sender :: %s, %s", smtp_malicious_indicators[rec$from],  rec$from), $conn=c, $sub=rec$from, $identifier=cat(rec$from),$suppress_for=1 mins]);
		} 
	} 

	if ( rec?$reply_to && rec$reply_to in smtp_malicious_indicators ) 
	{ 
		NOTICE([$note=Malicious_reply_to, $msg=fmt("Malicious reply_to:: %s, %s", smtp_malicious_indicators[rec$reply_to], rec$reply_to), $conn=c, $sub=rec$reply_to, $identifier=cat(rec$reply_to),$suppress_for=1 mins]);
	} 

	if ( rec?$subject && rec$subject in smtp_malicious_indicators ) 
	{ 
		NOTICE([$note=Malicious_subject, $msg=fmt("Malicious Subject:: %s, %s", smtp_malicious_indicators[rec$subject], rec$subject), $conn=c, $sub=rec$subject, $identifier=cat(rec$subject),$suppress_for=1 mins]);
	} 


#	if (rec?$decoded_subject && rec$decoded_subject in smtp_malicious_indicators) 
#        { 
#                #####print fmt ("decoded subject: %s", rec$decoded_subject); 
#                NOTICE([$note=Malicious_Decoded_Subject, $msg=fmt("Known Malicious Decoded Subject:: %s %s, %s, %s", smtp_malicious_indicators[rec$decoded_subject], rec$decoded_subject, rec$from, rec$to), 
#                                                                $conn=c, $sub=rec$decoded_subject, $identifier=cat(rec$decoded_subject),$suppress_for=1 mins]);
#        } 


##### path is a vector of addr 
#	if (rec?$path)
#	{ 
#	 	for (path in rec$path)
#		{ 
#			#####print fmt ("path :%s", |path-1|) ; 
#			if (/path/ in smtp_malicious_indicators) { 
#				NOTICE([$note=Malicious_path, $msg=fmt("Malicious Path:: %s %s", smtp_malicious_indicators[path], path), $conn=c, $sub=path, $identifier=cat(path),$suppress_for=1 mins]);
#			} 
#		} 
#	} 

}  ##### end of policy 

