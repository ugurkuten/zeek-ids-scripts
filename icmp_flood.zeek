@load base/frameworks/sumstats
@load base/frameworks/notice

# add a new notice type for the script
global baseline: table[addr] of double;
redef enum Notice::Type += { ICMP_Flood };

# load udp event
event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
    # observe the connections 
    
    SumStats::observe("icmp request", 
                      SumStats::Key($host=c$id$orig_h), 
                      SumStats::Observation($num=1));
    }
    

event zeek_init()
    {
    # reducer to summarize the connections
    local r1 = SumStats::Reducer($stream="icmp request", 
                                 $apply=set(SumStats::SUM));
    SumStats::create([$name = "possible icmp flood",
                      $epoch = 2min,
                      $reducers = set(r1),
                      # set threshold at the moment
                      $threshold = 400.0,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        return result["icmp request"]$sum;
                        },
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        # raise the notice if threshold is exceeded only for startup time
                        if(key$host !in baseline){
                        print "threshold crossed";
                        NOTICE([$note= ICMP_Flood,
                                $msg=fmt("%s is sending an high ammount of ICMP ping requests", key$host),
                                $src=key$host,
                                $identifier=cat(key$host)]);
                        }
                        },
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local current_baseline = result["icmp request"]$sum;
                        if(key$host in baseline && current_baseline > baseline[key$host] * 5){
                            print "anomaly detected";
                            NOTICE([$note= ICMP_Flood,
                                    $msg=fmt("%s is sending an unusual ammount of ICMP requests", key$host),
                                    $src=key$host,
                                    $identifier=cat(key$host)]);
                       }else
                            baseline[key$host] = current_baseline;
                        }]);
    }
