@load base/frameworks/sumstats
@load base/frameworks/notice

# add a new notice type for the script
global baseline: table[addr] of double;
redef enum Notice::Type += { UDP_Flood };

# load udp event
event udp_request(u: connection)
{
    # observe the connections
    SumStats::observe("udp request", SumStats::Key($host=u$id$orig_h),
    SumStats::Observation($num=1));
}

event zeek_init()
{
    # reducer to summarize the connections
    local r1 = SumStats::Reducer($stream="udp request", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="possible udp flood",
        $epoch=2min,
        $reducers=set(r1),
        # set threshold for the first epoch for a secure start
        $threshold=1000.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
        {
            return result["udp request"]$sum;
        },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
        {
            # raise the notice if threshold is exceeded only for startup time
            if ( key$host !in baseline )
            {
                print "threshold crossed";
                NOTICE([$note=UDP_Flood, $msg=fmt("%s is sending an unusual amount of udp traffic",
                    key$host), $src=key$host,
                    $identifier=cat(key$host)]);
            }
        },
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
        {
            local current_baseline = result["udp request"]$sum;
            if ( key$host in baseline && current_baseline > baseline[key$host] * 5 )
            {
                print "anomaly detected";
                NOTICE([$note=UDP_Flood, $msg=fmt("%s is sending an unusual amount of udp traffic",
                    key$host), $src=key$host,
                    $identifier=cat(key$host)]);
            }
            else
                baseline[key$host] = current_baseline;
        }
    ]);
}
