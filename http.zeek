@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/http

# add a new notice type for the script
global baseline: table[addr] of double;
redef enum Notice::Type += { HTTP_Flood };

# load http event
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	# observe the connections
	SumStats::observe("HTTP request", SumStats::Key($host=c$id$orig_h),
	                  SumStats::Observation($num=1));
	}

event zeek_init()
	{
	# reducer to summarize the connections
	local r1 = SumStats::Reducer($stream="HTTP request",
	                             $apply=set(SumStats::SUM));

	SumStats::create([
	    $name="Possible HTTP Attack",
	    $epoch=2min,
	    $reducers=set(r1),
	    # set threshold for the first epoch for a secure start
	    $threshold=300.0,
	    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	        {
	        return result["HTTP request"]$sum;
	        },
	    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	        {
	        # raise the notice only during startup time
	        if ( key$host !in baseline )
	            {
	            print "threshold crossed";
	            NOTICE([$note=HTTP_Flood,
	                    $msg=fmt("%s is sending a high amount of HTTP requests",
	                             key$host),
	                    $src=key$host,
	                    $identifier=cat(key$host)]);
	            }
	        },
	    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	        {
	        local current_baseline = result["HTTP request"]$sum;

	        if ( key$host in baseline && current_baseline > baseline[key$host] * 5 )
	            {
	            print "anomaly crossed";
	            NOTICE([$note=HTTP_Flood,
	                    $msg=fmt("%s is sending an unusual amount of HTTP requests (anomaly)",
	                             key$host),
	                    $src=key$host,
	                    $identifier=cat(key$host)]);
	            }
	        else
	            {
	            baseline[key$host] = current_baseline;
	            }
	        }
	]);
	}