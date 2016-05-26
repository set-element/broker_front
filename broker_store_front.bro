# Scott Campbell, March 2016
# Implementation of broker front end as an interface for looking at 
#  historical user data and new addresses, countries and AS's.
# 
# This works in conjunction with the broker_store_back.bro as this is
#  the front end of the pair.  The data itself is stored in the back end
#  as sqlite3 db data.
#

@load base/frameworks/broker
@load remote_logging/remote_logger_c

module USER_HIST_FRONT;

export {

	redef enum Notice::Type += {
		User_NewAS,	# Generic new AS
		User_NewASOdd,	# New AS for somone who normally should not
		User_NewCountry,# New country.	
		#
		User_NewAuthType,# New auth type
		User_OutlierAuthType,# New auth type
		};

	# This is used for dealing with the front end of the 
	#   BrokerStore.
	global h: opaque of BrokerStore::Handle;

	# These are for the table copying routines
	type bro_set: set[string];
	type bro_table: table[string] of count;
	type bro_vector: vector of string;

	type uid_login: record {
		orig_host: table[string] of count;
		orig_as: table[string] of count;
		orig_auth: table[string] of count;
		orig_cc: set[string];
		login_count: count &default=0;
		last_seen: time &default=double_to_time(0.00);
		};

	# This is the table that represents the "local" version of
	#  the data set.  Keep in sync with the back end.
	global uid_cache: table[string] of uid_login;

	#
	global broker_type = BrokerStore::SQLITE &redef; # storage backend to use
	global broker_name = "HostStore" &redef; #  name for the data store
	global broker_options: BrokerStore::BackendOptions; #  box-o-options
	global broker_storedb: string = "/tmp/store.sqlite" &redef;

	global broker_port: port = 9999/tcp &redef;
	global broker_host: string = "127.0.0.1" &redef;
	global broker_refresh_interval: interval = 1sec &redef;

	# Main interface for the historical data
	global process_login: function(uid: string, a: string, auth: string);

        global BROKER_ACTUAL = F &redef;
	redef exit_only_after_terminate = T;

	# Set parameters for defining "outlier"
	global outlier_threshold = 25 &redef;
	global outlier_ratio = 0.04 &redef;

	} # end of export



function init_login_record() : uid_login
	{
	local r: uid_login;
	local oh:table[string] of count;
	local oas:table[string] of count;
	local oau:table[string] of count;
	local occ:set[string];

	r$orig_host = oh;
	r$orig_as = oas;
	r$orig_auth = oau;
	r$orig_cc = occ;
	r$login_count = 1;
	r$last_seen = network_time();

	#print fmt("init login record");
	return r;

	}

function comm_table_to_bro_table_recurse(it: opaque of BrokerComm::TableIterator,
                                rval: bro_table): bro_table
	{
	if ( BrokerComm::table_iterator_last(it) )
		return rval;

	local item = BrokerComm::table_iterator_value(it);
	rval[BrokerComm::refine_to_string(item$key)] = BrokerComm::refine_to_count(item$val);
	BrokerComm::table_iterator_next(it);
	return comm_table_to_bro_table_recurse(it, rval);
	}

function comm_table_to_bro_table(d: BrokerComm::Data): bro_table
	{
	return comm_table_to_bro_table_recurse(BrokerComm::table_iterator(d),
	                                       bro_table());
	}

function comm_set_to_bro_set_recurse(it: opaque of BrokerComm::SetIterator,
                            rval: bro_set): bro_set
	{
	if ( BrokerComm::set_iterator_last(it) )
		return rval;

	add rval[BrokerComm::refine_to_string(BrokerComm::set_iterator_value(it))];
	BrokerComm::set_iterator_next(it);
	return comm_set_to_bro_set_recurse(it, rval);
	}


function comm_set_to_bro_set(d: BrokerComm::Data): bro_set
	{
	return comm_set_to_bro_set_recurse(BrokerComm::set_iterator(d), bro_set());
	}

function auth_outlier_test(r: uid_login, uid: string)
	{
	# look for something unusual in the login auth type
	#
	# this test will only be called in the event that a new auth type
	#  arrives since it is quite normal for stolen creds to use password
	#  related auth which is not always the case.
	
	# basic "you must be this high to play" test
	if ( r$login_count < outlier_threshold )
		return;

	# so there is more data
	local ret_string = "";
	local trigger = 0;

	for ( a in r$orig_auth ) {
		ret_string = fmt("%s[%s] %s", a, r$orig_auth[a], ret_string);

		# do we still need to do this float thing??
		if ( (1.00000 * 1) / (1.0000 * r$orig_auth[a]) < outlier_ratio )
			trigger = 1;
		}

	if ( trigger == 1 ) {

		NOTICE([$note=User_OutlierAuthType,
			$msg=fmt("%s New/Unlikely authentication event %s", uid, ret_string)]);

		local t_Info4: BrokLog::Info;

		t_Info4$ts = network_time();
		t_Info4$note = "User_OutlierAuthType";
		t_Info4$user = uid;
		t_Info4$misc = ret_string;

		event do_write(t_Info4);
		}

	return;
	}


function refresh_cache(uid: string)
	{
	# Because it is far simpler to interact with a native bro table 
	#  object, this function checks to see if the uid is available in
	#  the uid_cache table and if not, will set up the appropriate entries
	#  in prep for the analysis which should happen in O(~5sec).  
	#
	# If changes are introduced, write the diffs back to the broker
	#  back object.
	# 
	# type uid_login: record {
	#	orig_host: table[string] of count &default=table();
	#	orig_as: table[string] of count &default=table();
	#	orig_auth: table[string] of count &default=table();
	#	orig_cc: set[string] &default=set();
	#	login_count: count &default=0;
	#	last_seen: time &default=double_to_time(0.00);
	#	};
	#
	#
	local comm_uid =  BrokerComm::data(uid);

	# if uid is in local table, just scoop it up and bail
	if ( uid in uid_cache )
		{
		#print fmt("CACHE lookup HIT for %s", uid); 
		return;
		}

	# Otherwise we will need something to put in the uid_cache	
	local r: uid_login = init_login_record();

	# Go to the data store gather it up and 
	#  put in local table.  If not in data store, gen new
	#  record and put in both store and table.
	#
	when ( local res = BrokerStore::lookup(h, comm_uid) )
		{
		if ( res$result?$d )
			{
			# Record is in place so look up values and return 
			#  them unmodified
			print fmt("SUCCESS lookup: %s", uid);
			local il: BrokerComm::Data;
		
			il = BrokerComm::record_lookup( res$result, 0);
			r$orig_host = comm_table_to_bro_table(il);
			il = BrokerComm::record_lookup( res$result, 1);
			r$orig_as = comm_table_to_bro_table(il);
			il = BrokerComm::record_lookup( res$result, 2);
			r$orig_auth = comm_table_to_bro_table(il);
			il = BrokerComm::record_lookup( res$result, 3);
			r$orig_cc = comm_set_to_bro_set(il);
			il = BrokerComm::record_lookup( res$result, 4);
			r$login_count =  BrokerComm::refine_to_count(il);
			il = BrokerComm::record_lookup( res$result, 5);
 			r$last_seen =  BrokerComm::refine_to_time(il);

			uid_cache[uid] = r;
			}
		else {
			# The uid was not found so add it to the store
			print fmt("FAIL lookup: %s", uid);
			local comm_rec = BrokerComm::data(r);
			uid_cache[uid] = r;
			BrokerStore::insert(h, comm_uid, comm_rec);
			}

		return;

		}
	timeout 5sec
		{ print "timeout in refresh cache"; return; }

	return;
	}

event _login_transaction(uid: string, a: string, auth: string)
	{
	local _a = to_addr(a);

	local asn = lookup_asn(_a);
	local t_as = fmt("AS%s", asn);
	t_as = ( |t_as| > 0 ) ? t_as : "UNKNOWN";

	local t_geo: geo_location = lookup_location(_a);
	local t_cc = ( t_geo?$country_code ) ? t_geo$country_code : "UNKNOWN";

	# For some reason the call to process_login did not do what it was 
	#  supposed to so start over.  Add a feature here to stop the 
	#  madness after a number of loops...
	if ( uid !in uid_cache ) 
		{
		schedule 5sec { _login_transaction(uid,a,auth) };
		return;
		}

	local r: uid_login = uid_cache[uid];

	# Update address information
	if ( a !in r$orig_host ) {
		r$orig_host[a] = 1;
		}
	else {
		++r$orig_host[a];
		}

	# Update AS information
	if ( t_as !in r$orig_as ) {
		r$orig_as[t_as] = 1;

		# fill in some hopefully useful values
		local t_region = ( t_geo?$region ) ? t_geo$region : "UNKNOWN";
		local t_city = ( t_geo?$city ) ? t_geo$city : "UNKNOWN";

		NOTICE([$note=User_NewAS, 
			$msg=fmt("user: %s AS: %s", uid, t_as)]);

		local t_Info: BrokLog::Info;
		t_Info$ts = current_time();
		t_Info$note = "User_NewAS";
		t_Info$user = uid;
		t_Info$AS = t_as;
		t_Info$City = t_city;
		t_Info$Region = t_region;

		event do_write(t_Info);

		}
	else {
		++r$orig_as[t_as];
		}

	# Update Country information
	# Data is a set for now
	if ( t_cc !in r$orig_cc ) {

		# fill in some hopefully useful values
		local t_cregion = ( t_geo?$region ) ? t_geo$region : "UNKNOWN";
		local t_ccity = ( t_geo?$city ) ? t_geo$city : "UNKNOWN";

		# gen list of current countries
		local t_val = "";
		for (x in r$orig_cc) {
			t_val = fmt("%s %s", t_val, x);
			}

		NOTICE([$note=User_NewCountry, 
			$msg=fmt("user: %s CC: %s CITY: %s  REGION: %s PREV_CC: %s", 
				uid, t_cc, t_ccity, t_cregion, t_val)]);

		local t_Info2: BrokLog::Info;
		t_Info2$ts = current_time();
		t_Info2$note = "User_NewCountry";
		t_Info2$user = uid;
		t_Info2$CC = t_cc;
		t_Info2$City = t_ccity;
		t_Info2$Region = t_cregion;
		t_Info2$PrevCC = t_val;

		event do_write(t_Info2);

		add r$orig_cc[t_cc];
		}

	# Update user auth type data
	if ( auth !in r$orig_auth ) {

		NOTICE([$note=User_NewAuthType, 
			$msg=fmt("user: %s auth: %s", uid, auth)]);

		r$orig_auth[auth] = 1;

		local t_Info3: BrokLog::Info;
		t_Info3$ts = current_time();
		t_Info3$note = "User_NewAuthType";
		t_Info3$user = uid;
		t_Info3$auth = auth;

		event do_write(t_Info3);

		auth_outlier_test(r,uid);
		}
	else {
		++r$orig_auth[auth];
		}

	++r$login_count;
	r$last_seen = current_time();

	local t_r = BrokerComm::data(r);
	local comm_uid =  BrokerComm::data(uid);

	# sync cache
	uid_cache[uid] = r;
	# and push back to the store
	BrokerStore::insert(h, comm_uid, t_r);

	}

event USER_CORE::auth_transaction(ts: time, key: string, id: conn_id, uid: string, host: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string)
	{
	# This function does the work of record keeping and getting
	#  the transaction processed.  login_transaction() has no
	#  buisness being called without the cache check.
	#
	# Only run this for successful auth 
	if ( svc_resp != "ACCEPTED" )
		return;


	# First queue up the records for the uid
	local a = fmt("%s", id$orig_h);
	if ( uid in uid_cache ) {
		event _login_transaction(uid,a,svc_auth);
		}
	else {
		refresh_cache(uid);
		schedule 5sec { _login_transaction(uid,a,svc_auth) };
		}
	}

event bro_init()
	{
	print fmt("FRONT BROKER");
	BrokerComm::enable();
	BrokerComm::listen(broker_port, broker_host);
	BrokerComm::subscribe_to_events("bro/event");
	h = BrokerStore::create_frontend("HostStore");
	
	}

