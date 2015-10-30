/* This program uses libtrace to produce various RTT estimations.
 *
 * Author: Anna-Kaisa Pietilainen
 */
#include <libtrace.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <math.h>

// from libtcptools
#include <sessionmanager.h>
#include <rttnsequence.h>

// See: http://www.wikiwand.com/en/Standard_deviation#/Rapid_calculation_methods
#define _stddev(cnt, sum, ssq) sqrt(((double)(cnt)*ssq - sum*sum)/((double)(cnt*(cnt - 1))))

// packets per report (define this or interval)
uint64_t packet_count=UINT64_MAX;
// report interval (in seconds)
double packet_interval=UINT32_MAX;
// number of report periods (default infinite)
uint64_t report_periods=UINT64_MAX;
uint64_t reported=0;

int report_rel_time = 0;

double last_report_ts = 0;

double last_packet_ts = 0;

struct {
  uint64_t count;
  double sum;
  double ssq;
  double min;
  double max;
} reports[2];

// as in enum libtrace_direction_t
static int OUT = 0;
static int IN = 1;

// note ACKs to OUT direction measure RTT of "inside", ACKs
// to IN direction measure RTT of "outside", hence OUT reports 
// are about "inside" and IN reports about "outside"
static void print_report_hdr() {
  fprintf(stdout, "ts,in samples,in min,in max,in avg,in std,out samples,out min,out max,out avg,out std\n");
};

static void reset_report() {
  int dir;
  for (dir = 0; dir < 2; dir++) {  
    reports[dir].count = 0;
    reports[dir].min = -1.0;
    reports[dir].max = -1.0;
    reports[dir].sum = 0;
    reports[dir].ssq = 0;
  }
}

static void print_report(double ts) {
  int i;
  fprintf(stdout, "%.03f",ts);
  for (i = 0; i < 2; i++) {
    double mean = 0.0;
    double std = 0.0;
    if (reports[i].count > 2) {
      mean = reports[i].sum / reports[i].count;
      std = _stddev(reports[i].count, reports[i].sum, reports[i].ssq);
    }
    fprintf(stdout, ",%" PRIu64 ",%f,%f,%f,%f",
	    reports[i].count,
	    reports[i].min,
	    reports[i].max,
	    mean,
	    std);
  }
  fprintf(stdout, "\n");
  reset_report();
  ++reported;
}

static void per_packet(libtrace_packet_t *packet, tcp_session_t *session)
{
    int dir;
    double ts, rttsample;

    if (session == NULL) {
      return; // was not a tcp packet
    }

    ts = trace_get_seconds(packet);
    dir = trace_get_direction(packet);   
    if (!(dir==OUT || dir==IN))
      return;

    if (last_report_ts == 0) {
       last_report_ts = ts;
    }

    // time interval based reporting
    while (packet_interval != UINT32_MAX && 
	   last_report_ts+packet_interval<ts && 
	   (report_periods == UINT64_MAX || reported < report_periods)) {
      last_report_ts+=packet_interval;
      if (report_rel_time) {
	print_report(packet_interval);
      } else {
	print_report(last_report_ts);
      }
    }

    // did this packet create a new sample ?
    if (ts == rtt_n_sequence_last_sample_ts(session->data[0]) &&
	dir == rtt_n_sequence_last_sample_dir(session->data[0])) 
    {
      // update RTT stats if we got a valid sample
      rttsample = rtt_n_sequence_last_sample_value(session->data[0]);
      if (rttsample > 0) {
	rttsample = rttsample * 1000.0; // in ms
	reports[dir].count += 1;
	reports[dir].sum += rttsample;
	reports[dir].ssq += (rttsample*rttsample);
	if (reports[dir].min < 0 || rttsample < reports[dir].min)
	  reports[dir].min = rttsample;
	if (reports[dir].max < 0 || rttsample > reports[dir].max)
	  reports[dir].max = rttsample;
      }
    }

    if (packet_count != UINT64_MAX &&  
	(reports[OUT].count+reports[IN].count) > 0 && 
	(reports[OUT].count+reports[IN].count)%packet_count == 0 &&
	(report_periods == UINT64_MAX || reported < report_periods)) {
      if (report_rel_time) {
	print_report(ts-last_report_ts);
      } else {
	print_report(ts);
      }
      last_report_ts = ts;
    }

    last_packet_ts = ts;
}

static void usage(char *argv0)
{
  fprintf(stderr,"usage: %s [-i iv| --interval] [-c samples| --count] [-e periods| --exit] [-r | --relative] [ --filter | -f bpfexp ]\n\t\t[ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

int main(int argc, char *argv[])
{
  libtrace_t *trace;
  libtrace_packet_t *packet;
  libtrace_filter_t *filter=NULL;
  session_manager_t *sm;
  uint64_t f;

  while(1) {
    int option_index;
    struct option long_options[] = {
      { "filter",	1, 0, 'f' },
      { "interval",	1, 0, 'i' },
      { "count",        1, 0, 'c' },
      { "exit",         1, 0, 'e' },			
      { "relative",     0, 0, 'r' },
      { "help",		0, 0, 'h' },
      { "libtrace-help",0, 0, 'H' },
      { NULL,		0, 0, 0 }
    };

    int c= getopt_long(argc, argv, "c:e:f:i:hHr",
		       long_options, &option_index);

    if (c==-1)
      break;

    switch (c) {
    case 'f':
      filter=trace_create_filter(optarg);
      break;
    case 'i':
      packet_interval=atof(optarg);
      break;
    case 'c':
      packet_count=atoi(optarg);
      packet_interval=UINT32_MAX; // make sure only one is defined
      break;
    case 'e':
      report_periods=atoi(optarg);
      break;      
    case 'r':
      report_rel_time = 1;
      break;
    case 'H':
      trace_help();
      return 1;
    default:
      fprintf(stderr,"Unknown option: %c\n",c);
      /* FALL THRU */
    case 'h':
      usage(argv[0]);
      return 1;
    }
  }

  if (optind>=argc) {
    fprintf(stderr,"Missing input uri\n");
    usage(argv[0]);
    return 1;
  }

  while (optind<argc) {
    // create tcp session manager
    sm = session_manager_create();
    // create and register the data-ack based RTT module
    session_manager_register_module(sm,rtt_n_sequence_module()); 

    fprintf(stderr, "Processing %s\n",argv[optind]);
    trace = trace_create(argv[optind]);
    ++optind;

    if (trace_is_err(trace)) {
      trace_perror(trace,"Opening trace file");
      return 1;
    }

    if (filter && trace_config(trace,TRACE_OPTION_FILTER,filter)==1) {
	trace_perror(trace,"Configuring filter");
    }

    if (trace_start(trace)) {
      trace_perror(trace,"Starting trace");
      trace_destroy(trace);
      return 1;
    }

    packet = trace_create_packet();

    print_report_hdr();
    reset_report();
    last_report_ts = 0;
    last_packet_ts = 0;

    while (trace_read_packet(trace,packet)>0) {      
      per_packet(packet,session_manager_update(sm,packet));
      if (report_periods != UINT64_MAX && reported >= report_periods) {
	break;
      }
    }

    // remaining pkts (or all if no period set)
    if ((reports[OUT].count+reports[IN].count) > 0 || 
	(packet_interval == UINT32_MAX && packet_count == UINT64_MAX)) {
      double ts = trace_get_seconds(packet);
      if (report_rel_time) {
	print_report(ts-last_report_ts);
      } else {
	print_report(ts);
      }
    }

    trace_destroy_packet(packet);

    if (trace_is_err(trace)) {
      trace_perror(trace,"Reading packets");
    }

    // some stats
    f=trace_get_received_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets on input\n",f);
    f=trace_get_filtered_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets filtered\n",f);
    f=trace_get_dropped_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets dropped\n",f);
    f=trace_get_accepted_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets accepted\n",f);

    trace_destroy(trace);
    session_manager_destroy(sm);
  }

  return 0;
}
