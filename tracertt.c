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

#include <sessionmanager.h>
#include <rttnsequence.h>

// See: http://www.wikiwand.com/en/Standard_deviation#/Rapid_calculation_methods
#define _stddev(cnt, sum, ssq) sqrt(((double)(cnt)*ssq - sum*sum)/((double)(cnt*(cnt - 1))))

double packet_interval=UINT32_MAX;

double next_print_ts=0;
double last_packet_ts=0;

struct {
  uint64_t count;
  double sum;
  double ssq;
  double min;
  double max;
} stats[2];

static void print_hdr() {
  fprintf(stdout, "ts,in samples,in min,in max,in avg,in std,out samples,out min,out max,out avg,out std\n");
};

static void print_stats(double ts) {
  int i;
  fprintf(stdout, "%.03f",ts);
  for (i = 0; i < 2; i++) {
    double mean = 0.0;
    double std = 0.0;
    if (stats[i].count > 1) {
      mean = stats[i].sum / stats[i].count;
      std = _stddev(stats[i].count, stats[i].sum, stats[i].ssq);
    }
    fprintf(stdout, ",%" PRIu64 ",%f,%f,%f,%f",
	    stats[i].count,
	    stats[i].min,
	    stats[i].max,
	    mean,
	    std);

    stats[i].count = 0;
    stats[i].min = -1.0;
    stats[i].max = -1.0;
    stats[i].sum = 0.0;
    stats[i].ssq = 0.0;
  }
  fprintf(stdout, "\n");
}

static void per_packet(libtrace_packet_t *packet, tcp_session_t *session)
{
    int dir;
    double ts, rttsample;

    if (session == NULL)
      return; // was not a tcp packet

    dir = trace_get_direction(packet);   
    if (!(dir==0 || dir==1))
      return;

    ts = trace_get_seconds(packet);

    if (packet_interval != UINT32_MAX) {
      if (next_print_ts == 0) {
	next_print_ts = ts+packet_interval;
      }
                                
      while (next_print_ts<ts) {
	print_stats(next_print_ts);
	next_print_ts+=packet_interval;
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
	stats[dir].count += 1;
	stats[dir].sum += rttsample;
	stats[dir].ssq += (rttsample*rttsample);
	if (stats[dir].min < 0 || rttsample < stats[dir].min)
	  stats[dir].min = rttsample;
	if (stats[dir].max < 0 || rttsample > stats[dir].max)
	  stats[dir].max = rttsample;
      }
    }
    last_packet_ts = ts;
}

static void usage(char *argv0)
{
  fprintf(stderr,"usage: %s [-i iv| --interval] [ --filter | -f bpfexp ]\n\t\t[ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

int main(int argc, char *argv[])
{
  int i;
  libtrace_t *trace;
  libtrace_packet_t *packet;
  libtrace_filter_t *filter=NULL;
  session_manager_t *sm;

  while(1) {
    int option_index;
    struct option long_options[] = {
      { "filter",		1, 0, 'f' },
      { "interval",		1, 0, 'i' },
      { "help",		0, 0, 'h' },
      { "libtrace-help",	0, 0, 'H' },
      { NULL,			0, 0, 0 }
    };

    int c= getopt_long(argc, argv, "f:i:hH",
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

    trace = trace_create(argv[optind]);
    ++optind;

    if (trace_is_err(trace)) {
      trace_perror(trace,"Opening trace file");
      return 1;
    }

    if (filter)
      if (trace_config(trace,TRACE_OPTION_FILTER,filter)) {
	trace_perror(trace,"ignoring: ");
      }

    if (trace_start(trace)) {
      trace_perror(trace,"Starting trace");
      trace_destroy(trace);
      return 1;
    }

    packet = trace_create_packet();

    print_hdr();
    next_print_ts=0;
    last_packet_ts=0;

    for (i = 0; i < 2; i++) {
      stats[i].count = 0;
      stats[i].min = -1.0;
      stats[i].max = -1.0;
      stats[i].sum = 0.0;
      stats[i].ssq = 0.0;
    }

    while (trace_read_packet(trace,packet)>0) {      
      per_packet(packet,session_manager_update(sm,packet));
    }

    print_stats(last_packet_ts);

    trace_destroy_packet(packet);

    if (trace_is_err(trace)) {
      trace_perror(trace,"Reading packets");
    }

    trace_destroy(trace);
    session_manager_destroy(sm);
  }

  return 0;
}
