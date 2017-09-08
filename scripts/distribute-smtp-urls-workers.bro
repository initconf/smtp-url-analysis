module Phish;

export {

	global Phish::m_w_smtpurls_add: event (link: string, mail_info: mi); 
	global Phish::w_m_smtpurls_new: event (link: string, mail_info: mi); 
	global Phish::m_w_add_url_to_bloom: event(link: string) ; 
	global Phish::w_m_url_click_in_bloom: event (link: string, c: connection);  

	global EXTEND_LINK_EXPIRE = 60 mins ; 
	
}

@if ( Cluster::is_enabled() )

@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Phish::m_w_smtpurls_add|Phish::m_w_add_url_to_bloom/;
redef Cluster::worker2manager_events += /Phish::w_m_smtpurls_new|Phish::w_m_url_click|Phish::w_m_url_click_in_bloom/;
@endif

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
event Phish::m_w_add_url_to_bloom(link: string)
{
	log_reporter(fmt("EVENT: Phish::m_w_add_url_to_bloom: added to bloomfilter - link: %s", link),10); 
	bloomfilter_add(mail_links_bloom, link);
} 
@endif 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event Phish::w_m_url_click_in_bloom(link: string, c: connection)
{
	log_reporter(fmt("EVENT: Phish::w_m_url_click_in_bloom : link: %s", link),10); 
	### extract the mail_info for the database now 
	
	if (link !in tmp_link_cache)
		tmp_link_cache[link] = c ; 

	@ifdef (Phish::sql_read_mail_links_db) 
		event Phish::sql_read_mail_links_db(link);
	@endif 

}
@endif 

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
function mail_links_expire_func(t: table[string] of mi, link: string): interval 
{
	log_reporter(fmt("EVENT: function Phish::mail_links_expire_func [ worker ] : link: %s", link),10); 
	bloomfilter_add(mail_links_bloom, link);
	return 0 secs ;
} 
@endif 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
function mail_links_expire_func(t: table[string] of mi, link: string): interval 
{
	log_reporter(fmt("EVENT: function Phish::mail_links_expire_func [ manager ] : link: %s", link),10); 
	# check if seen = 0 , we don't want to rewrite an already expired entry back 
	# into the database 
		
	local seen = bloomfilter_lookup(mail_links_bloom, link);
	
	if  ( seen > 0 ) 
	{ 
		log_reporter(fmt("mail_links_expire_func: bloomed link : %s, %s",link, t[link]),0); 
		return 0 secs ; 
	} 

	### There is not much value to store urls with uninteresting_fqdn into the database either 
	### or may be there is but still slight more optimization . Disable if not desired

	local domain = extract_host(link);
	seen = bloomfilter_lookup(uninteresting_fqdns, domain);

	if ( seen > 0) 
	{ 
		#log_reporter(fmt("mail_links_expire_func: uninteresting_fqdns : %s, %s",link, t[link]),0); 
		return 0 secs ; 
	} 


	### no need to store https URLs either since we'd never see their clicks in HTTP 
	if ( /^https:\/\// in link)
	{
		#log_reporter(fmt("mail_links_expire_func: https: %s, %s",link, t[link]),10); 
		return 0 secs ; 
	}  

	### time to write to the database now 	

	@ifdef (Phish::sql_write_mail_links_db)
	if (Phish::sql_write_mail_links_db(link, t[link]) ) 
	{ 
		bloomfilter_add(mail_links_bloom, link); 
		event Phish::m_w_add_url_to_bloom(link); 
		return 0 secs; 
	} 
	else
	{ 
		log_reporter(fmt("Failure in writing to DATABASE so keeping in the mail_links table itself : link: %s, t[link]:%s", link,t[link]),0); 
		return EXTEND_LINK_EXPIRE ; 
	} 
	@endif 
	

	return EXTEND_LINK_EXPIRE ;

	} 
@endif 


####### (1) New URL comes in an email 
event  Phish::process_smtp_urls(c:connection, url:string)
	{

	log_reporter(fmt("EVENT: Phish::process_smtp_urls : url: %s", url),10);

	if (! c?$smtp) 
		return ;

	# check to see if url is already in bloom
	# no need to process URL further since its already in bloomfilter 

	local seen = bloomfilter_lookup(mail_links_bloom, url);
	
        if  ( seen > 0 )
	{	
	      #log_reporter(fmt("EVENT: Phish::process_smtp_urls : bloomed url: %s", url),10);
               return ; 
	} 

	local to_list="" ; 

	if (c?$smtp && c$smtp?$to) 
		{
		for (to in c$smtp$to) { to_list += fmt (" %s ", to); }
		} 

	local mail_info: mi ; 
	#mail_info$referrer=set() &mergeable ; 

	mail_info$ts = c$smtp$ts ; 
	mail_info$uid= c$smtp?$uid ? fmt("%s", c$smtp$uid) : "" ; 
	mail_info$from=c$smtp?$from ? escape_string(fmt("%s", c$smtp$from)) : "" ; 
	mail_info$to=fmt("%s", to_list); 
	mail_info$subject=c$smtp?$subject ? escape_string(fmt("%s", c$smtp$subject)) : "" ; 
	mail_info$referrer = vector(); 

	local link  = escape_string(url) ; 

	if (OPTIMIZATION && (ignore_file_types in link || ignore_fp_links in link || /^https:\/\// in link )  ) 
		return ; 

	if (link !in mail_links) 
	{
		mail_links[link]=mail_info ; 

		@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
			event Phish::w_m_smtpurls_new(link, mail_info);
		@endif
	} 
}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event Phish::w_m_smtpurls_new(link: string, mail_info: mi)
{

	local seen = bloomfilter_lookup(mail_links_bloom, link);

        if  ( seen > 0 )
               return ;


	### send to all workers 
	event Phish::m_w_smtpurls_add (link, mail_info); 

	### lets add the link to mail_links on manager 
	# so that when time to expire link comes
	# we use only manager to read/write to the database 
	# RareEvents are tracked only on manager so we avoid contension
	#### between workers attempting to read/write the db

	if (link !in mail_links ) 
	{
		#log_reporter(fmt("w_m_smtpurls_new: link: %s, mail_info: %s", link, mail_info),5); 
		mail_links[link] = mail_info ;
	} 
}
@endif 

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
event Phish::m_w_smtpurls_add (link: string, mail_info: mi)
{

	log_reporter(fmt("EVENT: Phish::m_w_smtpurls_add: link: %s, mail_info: %s", link, mail_info),10); 
	local seen = bloomfilter_lookup(mail_links_bloom, link);

        if  ( seen > 0 )
               return ;

	if (link !in mail_links ) 
	{
               	mail_links[link] = mail_info ;
		#log_reporter(fmt("EVENT: Phish::m_w_smtpurls_add: link: %s, mail_links[link]: %s", link, mail_links[link]),0); 
	} 
}
@endif 
